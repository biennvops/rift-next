//! Bounded local-only source paths shared by IPC and private transfer storage.

use std::{fmt, path::Path};

use serde::{Deserialize, Deserializer, Serialize, de};
use thiserror::Error;

/// Maximum UTF-8 byte length of a local transfer source path.
pub const MAX_SOURCE_PATH_LEN: usize = 4096;

/// An absolute native UTF-8 path, not a network filename or authorization token.
///
/// Serialization intentionally exposes the path for authenticated local IPC and
/// private manifests only. Debug is always redacted; Display is not implemented.
/// Validation is lexical and never opens, canonicalizes, or follows the path.
#[derive(Clone, Eq, PartialEq, Serialize)]
#[serde(transparent)]
pub struct SourcePath(String);

impl SourcePath {
    /// Validates the byte bound and native absolute-path syntax before allocation.
    pub fn new(value: &str) -> Result<Self, SourcePathError> {
        if value.is_empty() || value.len() > MAX_SOURCE_PATH_LEN {
            return Err(SourcePathError::Length);
        }
        if value.as_bytes().contains(&0) {
            return Err(SourcePathError::Nul);
        }
        if !Path::new(value).is_absolute() {
            return Err(SourcePathError::NotAbsolute);
        }
        Ok(Self(value.to_owned()))
    }

    /// Validates a native path without lossy conversion of non-UTF-8 components.
    pub fn from_path(value: &Path) -> Result<Self, SourcePathError> {
        Self::new(value.to_str().ok_or(SourcePathError::NonUtf8)?)
    }

    /// Borrows the local native path for source-file operations only.
    pub fn as_path(&self) -> &Path {
        Path::new(&self.0)
    }
}

impl fmt::Debug for SourcePath {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("SourcePath([REDACTED])")
    }
}

impl<'de> Deserialize<'de> for SourcePath {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct PathVisitor;

        impl de::Visitor<'_> for PathVisitor {
            type Value = SourcePath;

            fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str("an absolute local UTF-8 source path of at most 4096 bytes")
            }

            fn visit_str<E: de::Error>(self, value: &str) -> Result<Self::Value, E> {
                SourcePath::new(value).map_err(E::custom)
            }
        }

        deserializer.deserialize_str(PathVisitor)
    }
}

/// Path validation failures never contain supplied path text.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum SourcePathError {
    /// Empty or over the UTF-8 byte bound.
    #[error("source path must contain 1 to 4096 UTF-8 bytes")]
    Length,
    /// Not absolute according to the local platform's native path syntax.
    #[error("source path must be absolute")]
    NotAbsolute,
    /// Native paths with non-UTF-8 components are unsupported.
    #[error("source path must be UTF-8")]
    NonUtf8,
    /// NUL is not a valid native filesystem path byte.
    #[error("source path contains a NUL byte")]
    Nul,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn absolute(suffix: &str) -> String {
        if cfg!(windows) {
            format!("C:\\{suffix}")
        } else {
            format!("/{suffix}")
        }
    }

    #[test]
    fn paths_are_native_absolute_bounded_and_unmodified() -> Result<(), Box<dyn std::error::Error>>
    {
        let text = absolute("private/../Mötley 🦀.txt");
        let path = SourcePath::new(&text)?;
        assert_eq!(path.as_path().to_str(), Some(text.as_str()));
        assert_eq!(SourcePath::from_path(Path::new(&text))?, path);
        assert_eq!(format!("{path:?}"), "SourcePath([REDACTED])");
        assert_eq!(format!("{path:#?}"), "SourcePath([REDACTED])");
        assert!(!format!("{path:?}").contains("private"));
        let prefix = absolute("");
        let max = format!("{prefix}{}", "a".repeat(MAX_SOURCE_PATH_LEN - prefix.len()));
        assert!(SourcePath::new(&max).is_ok());
        assert_eq!(
            SourcePath::new(&format!("{max}a")),
            Err(SourcePathError::Length)
        );
        let unicode = absolute(&"é".repeat(2048));
        assert_eq!(SourcePath::new(&unicode), Err(SourcePathError::Length));
        for value in ["private.txt", "./private", "../private"] {
            assert_eq!(SourcePath::new(value), Err(SourcePathError::NotAbsolute));
        }
        assert_eq!(SourcePath::new(""), Err(SourcePathError::Length));
        assert_eq!(
            SourcePath::new(&absolute("secret\0file")),
            Err(SourcePathError::Nul)
        );
        Ok(())
    }

    #[cfg(windows)]
    #[test]
    fn windows_drive_relative_and_root_relative_paths_are_not_absolute() {
        for value in ["C:secret", "\\secret", "/secret"] {
            assert_eq!(SourcePath::new(value), Err(SourcePathError::NotAbsolute));
        }
        assert!(SourcePath::new("\\\\server\\share\\file").is_ok());
    }

    #[cfg(unix)]
    #[test]
    fn native_non_utf8_path_is_rejected_without_lossy_conversion() {
        use std::{ffi::OsStr, os::unix::ffi::OsStrExt};
        let path = Path::new(OsStr::from_bytes(b"/private/\xff"));
        assert_eq!(SourcePath::from_path(path), Err(SourcePathError::NonUtf8));
    }

    #[test]
    fn local_serialization_round_trips_but_never_bypasses_validation()
    -> Result<(), Box<dyn std::error::Error>> {
        let text = absolute("private/🦀.txt");
        let path = SourcePath::new(&text)?;
        let json = serde_json::to_string(&path)?;
        assert_eq!(json, serde_json::to_string(&text)?);
        assert_eq!(serde_json::from_str::<SourcePath>(&json)?, path);
        let payload = postcard::to_stdvec(&path)?;
        assert_eq!(payload, postcard::to_stdvec(&text)?);
        assert_eq!(postcard::from_bytes::<SourcePath>(&payload)?, path);
        for length in 0..payload.len() {
            assert!(postcard::from_bytes::<SourcePath>(&payload[..length]).is_err());
        }
        for invalid in [
            String::new(),
            "secret-relative".to_owned(),
            absolute("secret\0file"),
            absolute(&"x".repeat(4096)),
        ] {
            let json = serde_json::to_string(&invalid)?;
            let error = serde_json::from_str::<SourcePath>(&json)
                .err()
                .ok_or("accepted invalid path")?;
            assert!(!error.to_string().contains("secret"));
            assert!(postcard::from_bytes::<SourcePath>(&postcard::to_stdvec(&invalid)?).is_err());
        }
        Ok(())
    }
}
