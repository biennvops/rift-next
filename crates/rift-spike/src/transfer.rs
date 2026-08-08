//! Streaming binary/blob transfer over a dedicated QUIC stream.

use std::{
    io,
    path::{Path, PathBuf},
};

use blake3::Hasher;
use iroh::endpoint::SendStream;
use serde::{Deserialize, Serialize};
use thiserror::Error;
use tokio::{
    fs,
    io::{AsyncRead, AsyncReadExt, AsyncWriteExt},
};

use crate::protocol::{self, FrameError};

pub const STREAM_BUFFER_SIZE: usize = 64 * 1024;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct TransferMetadata {
    pub file_name: String,
    pub byte_len: u64,
    pub blake3: [u8; 32],
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TransferResult {
    pub output_path: PathBuf,
    pub byte_len: u64,
    pub blake3: [u8; 32],
}

#[derive(Debug, Error)]
pub enum TransferError {
    #[error("transfer framing failed: {0}")]
    Frame(#[from] FrameError),
    #[error("transfer I/O failed: {0}")]
    Io(#[from] io::Error),
    #[error("transfer stream could not be finished: {0}")]
    Finish(String),
    #[error("invalid transfer file name: {0:?}")]
    InvalidFileName(String),
    #[error("transfer length mismatch: expected {expected} bytes, received {actual}")]
    LengthMismatch { expected: u64, actual: u64 },
    #[error("transfer hash mismatch: expected {expected}, received {actual}")]
    HashMismatch { expected: String, actual: String },
}

pub async fn metadata_for_file(path: &Path) -> Result<TransferMetadata, TransferError> {
    let metadata = fs::metadata(path).await?;
    let file_name = path
        .file_name()
        .ok_or_else(|| TransferError::InvalidFileName(path.display().to_string()))?
        .to_string_lossy()
        .into_owned();
    validate_file_name(&file_name)?;

    Ok(TransferMetadata {
        file_name,
        byte_len: metadata.len(),
        blake3: hash_file(path).await?,
    })
}

pub async fn hash_file(path: &Path) -> Result<[u8; 32], TransferError> {
    let mut file = fs::File::open(path).await?;
    let mut hasher = Hasher::new();
    let mut buffer = [0; STREAM_BUFFER_SIZE];
    loop {
        let count = AsyncReadExt::read(&mut file, &mut buffer).await?;
        if count == 0 {
            break;
        }
        hasher.update(&buffer[..count]);
    }
    Ok(*hasher.finalize().as_bytes())
}

pub async fn send_file(
    send: &mut SendStream,
    path: &Path,
    metadata: &TransferMetadata,
) -> Result<u64, TransferError> {
    protocol::write_value(send, metadata).await?;

    let mut file = fs::File::open(path).await?;
    let mut hasher = Hasher::new();
    let mut buffer = [0; STREAM_BUFFER_SIZE];
    let mut total = 0_u64;
    loop {
        let count = AsyncReadExt::read(&mut file, &mut buffer).await?;
        if count == 0 {
            break;
        }
        send.write_all(&buffer[..count])
            .await
            .map_err(|error| TransferError::Io(io::Error::other(error.to_string())))?;
        hasher.update(&buffer[..count]);
        total = total.saturating_add(count as u64);
    }

    if total != metadata.byte_len {
        return Err(TransferError::LengthMismatch {
            expected: metadata.byte_len,
            actual: total,
        });
    }
    let actual_hash = *hasher.finalize().as_bytes();
    verify_payload(metadata.byte_len, total, metadata.blake3, actual_hash)?;

    send.finish()
        .map_err(|error| TransferError::Finish(error.to_string()))?;
    Ok(total)
}

pub async fn receive_file<R>(
    recv: &mut R,
    receive_dir: &Path,
) -> Result<TransferResult, TransferError>
where
    R: AsyncRead + Unpin,
{
    let metadata: TransferMetadata = protocol::read_value(recv).await?;
    validate_file_name(&metadata.file_name)?;
    fs::create_dir_all(receive_dir).await?;

    let output_path = receive_dir.join(&metadata.file_name);
    let temporary_path = receive_dir.join(format!(".{}.part", metadata.file_name));
    let result = receive_to_temporary(recv, &temporary_path, &metadata).await;
    match result {
        Ok((byte_len, blake3)) => {
            if let Err(error) = verify_payload(metadata.byte_len, byte_len, metadata.blake3, blake3)
            {
                let _ = fs::remove_file(&temporary_path).await;
                return Err(error);
            }
            fs::rename(&temporary_path, &output_path).await?;
            Ok(TransferResult {
                output_path,
                byte_len,
                blake3,
            })
        }
        Err(error) => {
            let _ = fs::remove_file(&temporary_path).await;
            Err(error)
        }
    }
}

async fn receive_to_temporary<R>(
    recv: &mut R,
    temporary_path: &Path,
    metadata: &TransferMetadata,
) -> Result<(u64, [u8; 32]), TransferError>
where
    R: AsyncRead + Unpin,
{
    let mut file = fs::File::create(temporary_path).await?;
    let mut hasher = Hasher::new();
    let mut buffer = [0; STREAM_BUFFER_SIZE];
    let mut total = 0_u64;

    loop {
        let count = AsyncReadExt::read(recv, &mut buffer).await?;
        if count == 0 {
            break;
        }
        let count = count as u64;
        if count > metadata.byte_len.saturating_sub(total) {
            return Err(TransferError::LengthMismatch {
                expected: metadata.byte_len,
                actual: total.saturating_add(count),
            });
        }
        file.write_all(&buffer[..count as usize]).await?;
        hasher.update(&buffer[..count as usize]);
        total = total.saturating_add(count);
    }
    file.flush().await?;
    Ok((total, *hasher.finalize().as_bytes()))
}

pub fn verify_payload(
    expected_len: u64,
    actual_len: u64,
    expected_hash: [u8; 32],
    actual_hash: [u8; 32],
) -> Result<(), TransferError> {
    if expected_len != actual_len {
        return Err(TransferError::LengthMismatch {
            expected: expected_len,
            actual: actual_len,
        });
    }
    if expected_hash != actual_hash {
        return Err(TransferError::HashMismatch {
            expected: hex::encode(expected_hash),
            actual: hex::encode(actual_hash),
        });
    }
    Ok(())
}

fn validate_file_name(file_name: &str) -> Result<(), TransferError> {
    if file_name.is_empty()
        || file_name == "."
        || file_name == ".."
        || file_name.contains('/')
        || file_name.contains('\\')
    {
        return Err(TransferError::InvalidFileName(file_name.to_owned()));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncWriteExt, duplex};

    #[tokio::test]
    async fn metadata_hashes_a_file_without_loading_it_as_a_whole_buffer()
    -> Result<(), Box<dyn std::error::Error>> {
        let directory = tempfile::tempdir()?;
        let path = directory.path().join("payload.bin");
        fs::write(&path, b"rift transfer").await?;
        let metadata = metadata_for_file(&path).await?;
        assert_eq!(metadata.file_name, "payload.bin");
        assert_eq!(metadata.byte_len, 13);
        assert_eq!(metadata.blake3, hash_file(&path).await?);
        assert_eq!(STREAM_BUFFER_SIZE, 64 * 1024);
        Ok(())
    }

    #[test]
    fn length_and_hash_verification_report_distinct_failures() {
        assert!(matches!(
            verify_payload(2, 1, [1; 32], [1; 32]),
            Err(TransferError::LengthMismatch { .. })
        ));
        assert!(matches!(
            verify_payload(1, 1, [1; 32], [2; 32]),
            Err(TransferError::HashMismatch { .. })
        ));
    }

    #[tokio::test]
    async fn truncated_payload_is_rejected_and_partial_output_is_removed()
    -> Result<(), Box<dyn std::error::Error>> {
        let directory = tempfile::tempdir()?;
        let receive_dir = directory.path().join("received");
        let payload = b"complete payload";
        let metadata = TransferMetadata {
            file_name: "payload.bin".to_owned(),
            byte_len: payload.len() as u64 + 1,
            blake3: *blake3::hash(payload).as_bytes(),
        };
        let (mut writer, mut reader) = duplex(4096);
        let frame = protocol::encode_frame(&metadata)?;
        writer.write_all(&frame).await?;
        writer.write_all(payload).await?;
        writer.shutdown().await?;

        let error = receive_file(&mut reader, &receive_dir)
            .await
            .expect_err("truncated payload must fail");
        assert!(matches!(error, TransferError::LengthMismatch { .. }));
        assert!(!receive_dir.join("payload.bin").exists());
        Ok(())
    }

    #[test]
    fn unsafe_file_names_are_rejected() {
        assert!(matches!(
            validate_file_name("../payload.bin"),
            Err(TransferError::InvalidFileName(_))
        ));
        assert!(matches!(
            validate_file_name("folder\\payload.bin"),
            Err(TransferError::InvalidFileName(_))
        ));
    }
}
