//! Bounded, portable metadata for the M6 single-file transfer contract.

use std::fmt;

use serde::{Deserialize, Deserializer, Serialize, de};
use thiserror::Error;

/// Maximum UTF-8 byte length of a portable presentation filename.
pub const MAX_TRANSFER_FILE_NAME_LEN: usize = 255;

/// Hard protocol file-length ceiling (1 TiB); daemon policy may be stricter.
pub const MAX_TRANSFER_BYTES: u64 = 1 << 40;

/// A presentation filename component, never a destination path.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(transparent)]
pub struct TransferFileName(String);

impl TransferFileName {
    /// Validates a borrowed component before allocating owned storage.
    pub fn new(value: &str) -> Result<Self, TransferMetadataError> {
        if value.is_empty() || value.len() > MAX_TRANSFER_FILE_NAME_LEN {
            return Err(TransferMetadataError::FileNameLength);
        }
        if value.ends_with(['.', ' '])
            || value.bytes().any(|byte| {
                byte.is_ascii_control()
                    || matches!(
                        byte,
                        b'/' | b'\\' | b'<' | b'>' | b':' | b'"' | b'|' | b'?' | b'*'
                    )
            })
        {
            return Err(TransferMetadataError::UnsafeFileName);
        }
        let stem = value
            .split('.')
            .next()
            .unwrap_or_default()
            .trim_end_matches(' ');
        if ["CON", "PRN", "AUX", "NUL"]
            .iter()
            .any(|reserved| stem.eq_ignore_ascii_case(reserved))
            || ["COM", "LPT"].iter().any(|prefix| {
                stem.get(..3)
                    .is_some_and(|part| part.eq_ignore_ascii_case(prefix))
                    && stem.get(3..).is_some_and(|suffix| {
                        matches!(
                            suffix,
                            "1" | "2" | "3" | "4" | "5" | "6" | "7" | "8" | "9" | "¹" | "²" | "³"
                        )
                    })
            })
        {
            return Err(TransferMetadataError::UnsafeFileName);
        }
        Ok(Self(value.to_owned()))
    }

    /// Returns the portable presentation component.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl<'de> Deserialize<'de> for TransferFileName {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct FileNameVisitor;

        impl de::Visitor<'_> for FileNameVisitor {
            type Value = TransferFileName;

            fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str("a portable filename component of 1 to 255 UTF-8 bytes")
            }

            fn visit_str<E: de::Error>(self, value: &str) -> Result<Self::Value, E> {
                TransferFileName::new(value).map_err(E::custom)
            }
        }

        deserializer.deserialize_str(FileNameVisitor)
    }
}

/// Immutable metadata shared by all attempts under one transfer identifier.
///
/// Field order is filename, unsigned length, then the 32 raw BLAKE3 bytes.
/// No source path or filesystem metadata is part of this wire type.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct TransferMetadata {
    file_name: TransferFileName,
    #[serde(deserialize_with = "deserialize_byte_len")]
    byte_len: u64,
    blake3: [u8; 32],
}

impl TransferMetadata {
    /// Constructs immutable metadata, rejecting lengths above the hard ceiling.
    pub fn new(
        file_name: TransferFileName,
        byte_len: u64,
        blake3: [u8; 32],
    ) -> Result<Self, TransferMetadataError> {
        validate_byte_len(byte_len)?;
        Ok(Self {
            file_name,
            byte_len,
            blake3,
        })
    }

    /// Returns the validated portable filename.
    pub const fn file_name(&self) -> &TransferFileName {
        &self.file_name
    }

    /// Returns the exact expected byte count, including zero for empty files.
    pub const fn byte_len(&self) -> u64 {
        self.byte_len
    }

    /// Returns the expected BLAKE3 digest of the entire file.
    pub const fn blake3(&self) -> &[u8; 32] {
        &self.blake3
    }
}

fn validate_byte_len(byte_len: u64) -> Result<(), TransferMetadataError> {
    if byte_len > MAX_TRANSFER_BYTES {
        return Err(TransferMetadataError::FileTooLarge);
    }
    Ok(())
}

fn deserialize_byte_len<'de, D: Deserializer<'de>>(deserializer: D) -> Result<u64, D::Error> {
    let byte_len = u64::deserialize(deserializer)?;
    validate_byte_len(byte_len).map_err(de::Error::custom)?;
    Ok(byte_len)
}

/// A bounded metadata failure without peer-controlled text or local paths.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum TransferMetadataError {
    /// The filename was empty or exceeded its UTF-8 byte bound.
    #[error("transfer filename must contain 1 to 255 UTF-8 bytes")]
    FileNameLength,
    /// The filename was not a portable, safe component.
    #[error("transfer filename is not a portable component")]
    UnsafeFileName,
    /// The file exceeded the hard protocol limit.
    #[error("transfer length exceeds 1 TiB")]
    FileTooLarge,
}

/// Replayable terminal outcomes. Variant order is part of protocol v1.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub enum TransferTerminalStatus {
    /// Exact length/hash verified and the received file durably published.
    Completed,
    /// The receiver declined the offer.
    Rejected,
    /// Either peer cancelled the logical transfer.
    Cancelled,
    /// A nonretryable transfer failure, without local diagnostic details.
    Failed(TransferFailureCode),
}

/// Stable coarse failures. Variant order is part of protocol v1.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub enum TransferFailureCode {
    /// The received content did not match the immutable digest.
    Integrity,
    /// The sender's file no longer matched the immutable metadata.
    SourceChanged,
    /// A local I/O operation failed.
    Io,
    /// A bounded resource could not be acquired.
    Resource,
    /// The transfer violated its framing or sequencing contract.
    Protocol,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn messages() -> Result<Vec<crate::ControlMessage>, TransferMetadataError> {
        use crate::ControlMessage;
        let transfer_id = rift_core::TransferId::from_bytes([0x12; 16]);
        let mut messages = vec![
            ControlMessage::TransferOffer {
                transfer_id,
                metadata: TransferMetadata::new(
                    TransferFileName::new("file.txt")?,
                    65536,
                    [0xab; 32],
                )?,
            },
            ControlMessage::TransferAccept {
                transfer_id,
                offset: 0,
            },
            ControlMessage::TransferAccept {
                transfer_id,
                offset: 32768,
            },
            ControlMessage::TransferTerminalAck { transfer_id },
        ];
        for status in [
            TransferTerminalStatus::Completed,
            TransferTerminalStatus::Rejected,
            TransferTerminalStatus::Cancelled,
            TransferTerminalStatus::Failed(TransferFailureCode::Integrity),
            TransferTerminalStatus::Failed(TransferFailureCode::SourceChanged),
            TransferTerminalStatus::Failed(TransferFailureCode::Io),
            TransferTerminalStatus::Failed(TransferFailureCode::Resource),
            TransferTerminalStatus::Failed(TransferFailureCode::Protocol),
        ] {
            messages.push(ControlMessage::TransferTerminal {
                transfer_id,
                status,
            });
        }
        Ok(messages)
    }

    #[tokio::test]
    async fn transfer_messages_are_not_pairing_and_round_trip_one_frame_at_a_time()
    -> Result<(), Box<dyn std::error::Error>> {
        use crate::*;
        for message in messages()? {
            let (discriminant, name) = match &message {
                ControlMessage::TransferOffer { .. } => (10, "TransferOffer"),
                ControlMessage::TransferAccept { .. } => (11, "TransferAccept"),
                ControlMessage::TransferTerminal { .. } => (12, "TransferTerminal"),
                ControlMessage::TransferTerminalAck { .. } => (13, "TransferTerminalAck"),
                _ => return Err("unexpected fixture message".into()),
            };
            let mut wire = encode_message(&message)?;
            assert_eq!(wire[4], discriminant);
            assert_eq!(message.kind().to_string(), name);
            assert_eq!(message.clone().into_pairing(), Err(message.kind()));
            assert_eq!(decode_message(&wire)?, message);
            let mut written = Vec::new();
            write_message(&mut written, &message).await?;
            assert_eq!(written, wire);
            wire.extend_from_slice(&encode_message(&ControlMessage::Ping { nonce: 42 })?);
            let mut reader = wire.as_slice();
            assert_eq!(read_message(&mut reader).await?, message);
            assert_eq!(
                read_message(&mut reader).await?,
                ControlMessage::Ping { nonce: 42 }
            );
            assert!(reader.is_empty());
        }
        Ok(())
    }

    #[test]
    fn truncated_and_trailing_transfer_messages_are_rejected()
    -> Result<(), Box<dyn std::error::Error>> {
        for message in messages()? {
            let payload = postcard::to_stdvec(&message)?;
            for length in 0..payload.len() {
                let mut wire = (length as u32).to_be_bytes().to_vec();
                wire.extend_from_slice(&payload[..length]);
                assert!(crate::decode_message(&wire).is_err());
            }
            let mut wire = ((payload.len() + 1) as u32).to_be_bytes().to_vec();
            wire.extend_from_slice(&payload);
            wire.push(0);
            assert!(matches!(
                crate::decode_message(&wire),
                Err(crate::FrameError::TrailingPayload { remaining: 1 })
            ));
        }
        Ok(())
    }

    #[test]
    fn unsupported_terminal_failure_and_message_discriminants_are_rejected() {
        let mut terminal = vec![12];
        terminal.extend_from_slice(&[0; 16]);
        for suffix in [&[4][..], &[3, 5], &[3, 255], &[255]] {
            let mut payload = terminal.clone();
            payload.extend_from_slice(suffix);
            let mut wire = (payload.len() as u32).to_be_bytes().to_vec();
            wire.extend_from_slice(&payload);
            assert!(matches!(
                crate::decode_message(&wire),
                Err(crate::FrameError::Decode(_))
            ));
        }
        assert!(matches!(
            crate::decode_message(&[0, 0, 0, 1, 14]),
            Err(crate::FrameError::Decode(_))
        ));
    }

    #[test]
    fn raw_offer_cannot_bypass_metadata_bounds() -> Result<(), Box<dyn std::error::Error>> {
        for (name, length) in [
            ("a".repeat(256), 0_u64),
            ("../escape".to_owned(), 0),
            ("a".to_owned(), MAX_TRANSFER_BYTES + 1),
        ] {
            let mut payload = vec![10];
            payload.extend_from_slice(&[0; 16]);
            payload.extend_from_slice(&postcard::to_stdvec(&(name, length, [0_u8; 32]))?);
            let mut wire = (payload.len() as u32).to_be_bytes().to_vec();
            wire.extend_from_slice(&payload);
            assert!(matches!(
                crate::decode_message(&wire),
                Err(crate::FrameError::Decode(_))
            ));
        }
        Ok(())
    }

    #[test]
    fn portable_names_and_utf8_byte_boundary() -> Result<(), Box<dyn std::error::Error>> {
        for name in [
            "file.txt",
            ".hidden",
            "Mötley 🦀",
            "COM0",
            "COM10.txt",
            "LPT0",
            "console",
            "nulled.txt",
        ] {
            assert_eq!(TransferFileName::new(name)?.as_str(), name);
        }
        let max = format!("{}a", "é".repeat(127));
        assert_eq!(max.len(), 255);
        assert_eq!(TransferFileName::new(&max)?.as_str(), max);
        assert_eq!(
            TransferFileName::new(&"é".repeat(128)),
            Err(TransferMetadataError::FileNameLength)
        );
        assert_eq!(
            TransferFileName::new(""),
            Err(TransferMetadataError::FileNameLength)
        );
        Ok(())
    }

    #[test]
    fn rejects_paths_controls_and_windows_reserved_components() {
        for name in [
            ".",
            "..",
            "../file",
            "a/b",
            "a\\b",
            "/file",
            "C:file",
            "a<",
            "a>",
            "a\"",
            "a|",
            "a?",
            "a*",
            "a.",
            "a ",
            "CON",
            "con.txt",
            "PrN",
            "AUX.tar.gz",
            "NUL",
            "con .txt",
            "COM¹.txt",
            "LPT².txt",
            "COM³",
        ] {
            assert_eq!(
                TransferFileName::new(name),
                Err(TransferMetadataError::UnsafeFileName),
                "{name:?}"
            );
        }
        for byte in (0..=31).chain([127]) {
            assert_eq!(
                TransferFileName::new(&format!("a{}b", char::from(byte))),
                Err(TransferMetadataError::UnsafeFileName)
            );
        }
        for prefix in ["com", "LPT"] {
            for digit in 1..=9 {
                for suffix in ["", ".txt"] {
                    assert_eq!(
                        TransferFileName::new(&format!("{prefix}{digit}{suffix}")),
                        Err(TransferMetadataError::UnsafeFileName)
                    );
                }
            }
        }
    }

    #[test]
    fn metadata_bounds_and_exact_serialization() -> Result<(), Box<dyn std::error::Error>> {
        assert_eq!(MAX_TRANSFER_BYTES, 1_099_511_627_776);
        for byte_len in [0, 1, MAX_TRANSFER_BYTES] {
            let metadata =
                TransferMetadata::new(TransferFileName::new("a")?, byte_len, [0xab; 32])?;
            assert_eq!(metadata.byte_len(), byte_len);
            assert_eq!(metadata.file_name().as_str(), "a");
            assert_eq!(metadata.blake3(), &[0xab; 32]);
            let encoded = postcard::to_stdvec(&metadata)?;
            assert_eq!(
                encoded,
                postcard::to_stdvec(&("a", byte_len, [0xab_u8; 32]))?
            );
            assert_eq!(
                postcard::from_bytes::<TransferMetadata>(&encoded)?,
                metadata
            );
            assert_eq!(
                serde_json::from_str::<TransferMetadata>(&serde_json::to_string(&metadata)?)?,
                metadata
            );
        }
        assert_eq!(
            TransferMetadata::new(TransferFileName::new("a")?, MAX_TRANSFER_BYTES + 1, [0; 32]),
            Err(TransferMetadataError::FileTooLarge)
        );
        Ok(())
    }

    #[test]
    fn wire_deserialization_cannot_bypass_validation() -> Result<(), Box<dyn std::error::Error>> {
        for name in [
            "../escape".to_owned(),
            "a".repeat(256),
            "NUL.txt".to_owned(),
        ] {
            let encoded = postcard::to_stdvec(&(name.as_str(), 0_u64, [0_u8; 32]))?;
            assert!(postcard::from_bytes::<TransferMetadata>(&encoded).is_err());
        }
        for byte_len in [MAX_TRANSFER_BYTES + 1, u64::MAX] {
            let encoded = postcard::to_stdvec(&("a", byte_len, [0_u8; 32]))?;
            assert!(postcard::from_bytes::<TransferMetadata>(&encoded).is_err());
        }
        let encoded = postcard::to_stdvec(&("a", 0_u64, [0_u8; 32]))?;
        for len in 0..encoded.len() {
            assert!(postcard::from_bytes::<TransferMetadata>(&encoded[..len]).is_err());
        }
        assert!(postcard::from_bytes::<TransferFileName>(&[1, 0xff]).is_err());
        Ok(())
    }
}
