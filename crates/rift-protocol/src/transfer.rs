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

#[cfg(test)]
mod tests {
    use super::*;

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
