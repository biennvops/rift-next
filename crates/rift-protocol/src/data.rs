//! Dedicated small framing for independent binary data streams.

use std::io;

use rift_core::TransferId;
use serde::{Deserialize, Serialize};
use thiserror::Error;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

use crate::{FRAME_LENGTH_PREFIX_LEN, MAX_TRANSFER_BYTES};

/// Maximum encoded data header payload, excluding its four-byte length prefix.
pub const MAX_DATA_STREAM_HEADER_LEN: usize = 256;

/// The feature/version discriminator at the start of each binary stream.
///
/// One fresh unidirectional stream carries one attempt: header, raw suffix, FIN.
/// Header validity alone does not establish authorization or local acceptance.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub enum DataStreamHeader {
    /// Blob transfer v1, encoded as Postcard enum discriminant zero.
    BlobV1 {
        /// The logical transfer this attempt belongs to.
        transfer_id: TransferId,
        /// The receiver's previously accepted durable partial-file length.
        offset: u64,
        /// Exact raw byte count following this header, before FIN.
        remaining_len: u64,
    },
}

impl DataStreamHeader {
    /// Checks the declared range against the immutable file length.
    ///
    /// The receiver must separately check peer, transfer ID, durable acceptance,
    /// current expected offset, and exclusive attempt ownership before reading bytes.
    pub fn validate(&self, total_len: u64) -> Result<(), DataHeaderError> {
        let Self::BlobV1 {
            offset,
            remaining_len,
            ..
        } = *self;
        if total_len > MAX_TRANSFER_BYTES {
            return Err(DataHeaderError::FileTooLarge);
        }
        if offset > total_len {
            return Err(DataHeaderError::InvalidOffset);
        }
        if remaining_len != total_len - offset {
            return Err(DataHeaderError::RemainingLengthMismatch);
        }
        Ok(())
    }

    fn validate_bounds(&self) -> Result<(), DataHeaderError> {
        let Self::BlobV1 {
            offset,
            remaining_len,
            ..
        } = *self;
        let total_len = offset
            .checked_add(remaining_len)
            .ok_or(DataHeaderError::FileTooLarge)?;
        self.validate(total_len)
    }
}

/// Failure of the dedicated data header codec, never a payload-stream result.
#[derive(Debug, Error)]
pub enum DataHeaderError {
    /// The four-byte prefix could not be read completely.
    #[error("data header prefix is truncated or unreadable")]
    Prefix(#[source] io::Error),
    /// The declared header could not be read completely.
    #[error("data header payload is truncated or unreadable")]
    Payload(#[source] io::Error),
    /// The header length exceeded the dedicated small bound.
    #[error("data header length {0} exceeds 256 bytes")]
    TooLarge(usize),
    /// A complete in-memory frame did not have exactly its declared length.
    #[error("data header frame length mismatch")]
    FrameLengthMismatch,
    /// The header's Postcard representation was malformed or unsupported.
    #[error("malformed or unsupported data header")]
    Decode(#[source] postcard::Error),
    /// Postcard could not encode into the fixed header buffer.
    #[error("data header encoding failed")]
    Encode(#[source] postcard::Error),
    /// Bytes remained inside the header frame after decoding one value.
    #[error("trailing bytes inside data header")]
    TrailingPayload,
    /// The header write failed.
    #[error("data header write failed")]
    Write(#[source] io::Error),
    /// The implied or known total length exceeded the protocol ceiling.
    #[error("data stream range exceeds 1 TiB")]
    FileTooLarge,
    /// The accepted offset exceeded the immutable length.
    #[error("data stream offset exceeds file length")]
    InvalidOffset,
    /// The suffix did not exactly cover the immutable file's remaining bytes.
    #[error("data stream remaining length mismatch")]
    RemainingLengthMismatch,
}

/// Encodes a data header without using the much larger control-frame limit.
pub fn encode_data_header(header: &DataStreamHeader) -> Result<Vec<u8>, DataHeaderError> {
    header.validate_bounds()?;
    let mut buffer = [0_u8; MAX_DATA_STREAM_HEADER_LEN];
    let payload = postcard::to_slice(header, &mut buffer).map_err(DataHeaderError::Encode)?;
    let mut frame = Vec::with_capacity(FRAME_LENGTH_PREFIX_LEN + payload.len());
    frame.extend_from_slice(&(payload.len() as u32).to_be_bytes());
    frame.extend_from_slice(payload);
    Ok(frame)
}

/// Decodes exactly one complete header frame, with no raw file bytes attached.
pub fn decode_data_header(frame: &[u8]) -> Result<DataStreamHeader, DataHeaderError> {
    let prefix = frame
        .get(..FRAME_LENGTH_PREFIX_LEN)
        .ok_or_else(|| DataHeaderError::Prefix(io::Error::from(io::ErrorKind::UnexpectedEof)))?;
    let length = header_length([prefix[0], prefix[1], prefix[2], prefix[3]])?;
    let payload = &frame[FRAME_LENGTH_PREFIX_LEN..];
    if payload.len() != length {
        return Err(DataHeaderError::FrameLengthMismatch);
    }
    decode_header_payload(payload)
}

/// Reads only the bounded header, leaving all following raw bytes in the reader.
///
/// The stream owner must impose a deadline; cancellation after a partial header
/// requires stopping this attempt rather than restarting the codec on the same stream.
pub async fn read_data_header<R: AsyncRead + Unpin>(
    reader: &mut R,
) -> Result<DataStreamHeader, DataHeaderError> {
    let mut prefix = [0; FRAME_LENGTH_PREFIX_LEN];
    reader
        .read_exact(&mut prefix)
        .await
        .map_err(DataHeaderError::Prefix)?;
    let length = header_length(prefix)?;
    let mut buffer = [0; MAX_DATA_STREAM_HEADER_LEN];
    reader
        .read_exact(&mut buffer[..length])
        .await
        .map_err(DataHeaderError::Payload)?;
    decode_header_payload(&buffer[..length])
}

/// Writes one small header before the stream's raw suffix bytes.
pub async fn write_data_header<W: AsyncWrite + Unpin>(
    writer: &mut W,
    header: &DataStreamHeader,
) -> Result<(), DataHeaderError> {
    let frame = encode_data_header(header)?;
    writer
        .write_all(&frame)
        .await
        .map_err(DataHeaderError::Write)
}

fn header_length(prefix: [u8; FRAME_LENGTH_PREFIX_LEN]) -> Result<usize, DataHeaderError> {
    let length = u32::from_be_bytes(prefix) as usize;
    if length > MAX_DATA_STREAM_HEADER_LEN {
        return Err(DataHeaderError::TooLarge(length));
    }
    Ok(length)
}

fn decode_header_payload(payload: &[u8]) -> Result<DataStreamHeader, DataHeaderError> {
    let (header, trailing) =
        postcard::take_from_bytes::<DataStreamHeader>(payload).map_err(DataHeaderError::Decode)?;
    if !trailing.is_empty() {
        return Err(DataHeaderError::TrailingPayload);
    }
    header.validate_bounds()?;
    Ok(header)
}

#[cfg(test)]
mod tests {
    use std::{
        pin::Pin,
        task::{Context, Poll},
    };

    use super::*;

    fn header(offset: u64, remaining_len: u64) -> DataStreamHeader {
        DataStreamHeader::BlobV1 {
            transfer_id: TransferId::from_bytes([0xab; 16]),
            offset,
            remaining_len,
        }
    }

    fn frame(payload: &[u8]) -> Vec<u8> {
        let mut frame = (payload.len() as u32).to_be_bytes().to_vec();
        frame.extend_from_slice(payload);
        frame
    }

    #[test]
    fn ranges_are_exact_and_bounded_without_integer_overflow() -> Result<(), DataHeaderError> {
        assert_eq!(MAX_DATA_STREAM_HEADER_LEN, 256);
        for total in [0, 1, 65536, MAX_TRANSFER_BYTES] {
            for offset in [0, total / 2, total] {
                let header = header(offset, total - offset);
                header.validate(total)?;
                assert_eq!(decode_data_header(&encode_data_header(&header)?)?, header);
            }
        }
        assert!(matches!(
            header(2, 0).validate(1),
            Err(DataHeaderError::InvalidOffset)
        ));
        assert!(matches!(
            header(0, 2).validate(1),
            Err(DataHeaderError::RemainingLengthMismatch)
        ));
        assert!(matches!(
            header(0, 0).validate(MAX_TRANSFER_BYTES + 1),
            Err(DataHeaderError::FileTooLarge)
        ));
        for header in [
            header(u64::MAX, 1),
            header(MAX_TRANSFER_BYTES, 1),
            header(0, u64::MAX),
        ] {
            assert!(matches!(
                encode_data_header(&header),
                Err(DataHeaderError::FileTooLarge)
            ));
            let raw = postcard::to_stdvec(&header).map_err(DataHeaderError::Encode)?;
            assert!(matches!(
                decode_data_header(&frame(&raw)),
                Err(DataHeaderError::FileTooLarge)
            ));
        }
        Ok(())
    }

    #[tokio::test]
    async fn reads_one_header_without_consuming_payload() -> Result<(), Box<dyn std::error::Error>>
    {
        let expected = header(17, 3);
        let mut wire = Vec::new();
        write_data_header(&mut wire, &expected).await?;
        wire.extend_from_slice(b"abc");
        let mut reader = wire.as_slice();
        assert_eq!(read_data_header(&mut reader).await?, expected);
        assert_eq!(reader, b"abc");
        Ok(())
    }

    #[tokio::test]
    async fn truncated_prefix_and_payload_are_distinct() -> Result<(), DataHeaderError> {
        let encoded = encode_data_header(&header(1, 3))?;
        for length in 0..encoded.len() {
            let result = read_data_header(&mut &encoded[..length]).await;
            if length < 4 {
                assert!(matches!(result, Err(DataHeaderError::Prefix(_))));
                assert!(matches!(
                    decode_data_header(&encoded[..length]),
                    Err(DataHeaderError::Prefix(_))
                ));
            } else {
                assert!(matches!(result, Err(DataHeaderError::Payload(_))));
                assert!(matches!(
                    decode_data_header(&encoded[..length]),
                    Err(DataHeaderError::FrameLengthMismatch)
                ));
            }
        }
        Ok(())
    }

    #[tokio::test]
    async fn oversized_prefix_never_reads_payload() {
        for length in [257_u32, 1024 * 1024, u32::MAX] {
            let mut wire = length.to_be_bytes().to_vec();
            wire.extend_from_slice(b"untouched");
            let mut reader = wire.as_slice();
            assert!(matches!(
                read_data_header(&mut reader).await,
                Err(DataHeaderError::TooLarge(_))
            ));
            assert_eq!(reader, b"untouched");
            assert!(matches!(
                decode_data_header(&wire),
                Err(DataHeaderError::TooLarge(_))
            ));
        }
    }

    #[tokio::test]
    async fn malformed_unknown_and_trailing_headers_fail_closed() -> Result<(), DataHeaderError> {
        for payload in [vec![], vec![1], vec![255; 10], vec![0; 18]] {
            let encoded = frame(&payload);
            assert!(matches!(
                decode_data_header(&encoded),
                Err(DataHeaderError::Decode(_))
            ));
            assert!(matches!(
                read_data_header(&mut encoded.as_slice()).await,
                Err(DataHeaderError::Decode(_))
            ));
        }
        let valid = encode_data_header(&header(0, 0))?;
        for length in [valid.len() - 3, MAX_DATA_STREAM_HEADER_LEN] {
            let mut payload = valid[4..].to_vec();
            payload.resize(length, 0);
            let encoded = frame(&payload);
            assert!(matches!(
                decode_data_header(&encoded),
                Err(DataHeaderError::TrailingPayload)
            ));
            assert!(matches!(
                read_data_header(&mut encoded.as_slice()).await,
                Err(DataHeaderError::TrailingPayload)
            ));
        }
        let mut extra = valid;
        extra.push(0);
        assert!(matches!(
            decode_data_header(&extra),
            Err(DataHeaderError::FrameLengthMismatch)
        ));
        Ok(())
    }

    struct FailedWriter;

    impl AsyncWrite for FailedWriter {
        fn poll_write(
            self: Pin<&mut Self>,
            _: &mut Context<'_>,
            _: &[u8],
        ) -> Poll<io::Result<usize>> {
            Poll::Ready(Err(io::Error::from(io::ErrorKind::BrokenPipe)))
        }
        fn poll_flush(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
            Poll::Ready(Ok(()))
        }
        fn poll_shutdown(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
            Poll::Ready(Ok(()))
        }
    }

    #[tokio::test]
    async fn write_failure_is_typed_and_invalid_ranges_write_nothing() {
        assert!(matches!(
            write_data_header(&mut FailedWriter, &header(0, 0)).await,
            Err(DataHeaderError::Write(_))
        ));
        let mut output = Vec::new();
        assert!(matches!(
            write_data_header(&mut output, &header(u64::MAX, 1)).await,
            Err(DataHeaderError::FileTooLarge)
        ));
        assert!(output.is_empty());
    }
}
