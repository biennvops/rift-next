//! Initial metadata preparation from an already opened local source.

use rift_core::SourcePath;
use rift_protocol::{
    MAX_TRANSFER_BYTES, TransferFileName, TransferMetadata, TransferMetadataError,
};
use thiserror::Error;
use tokio::fs::File;

use crate::{AttemptControl, TransferIoError, hash_source};

/// Prepares immutable offer metadata using bounded cancellable hashing.
///
/// The caller must open `path` read-only and pass that same handle, under its owned
/// preparation-work limit. This function never opens a path: opening special files
/// or following a concurrently replaced path requires platform-specific admission
/// at the runtime boundary. Regular-file checks use the actual handle, not a racy
/// path metadata check. Symlink metadata is never preserved or transmitted.
///
/// The configured maximum must be nonzero and at most 1 TiB. Oversized and
/// nonregular handles are rejected before hashing. Success leaves the handle at
/// EOF; `send_payload` will seek and revalidate it again before streaming. This
/// function does not freeze the source or create durable state or a transfer ID.
pub async fn prepare_source(
    source: &mut File,
    path: &SourcePath,
    max_file_bytes: u64,
    control: &mut AttemptControl,
) -> Result<TransferMetadata, SourcePreparationError> {
    if max_file_bytes == 0 || max_file_bytes > MAX_TRANSFER_BYTES {
        return Err(SourcePreparationError::InvalidLimit);
    }
    let name = path
        .as_path()
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or(SourcePreparationError::MissingFileName)?;
    let name = TransferFileName::new(name)?;
    let before = control
        .step(source.metadata())
        .await?
        .map_err(|error| TransferIoError::LocalIo(error.kind()))?;
    if !before.is_file() {
        return Err(SourcePreparationError::NotRegular);
    }
    let length = before.len();
    if length > max_file_bytes {
        return Err(SourcePreparationError::TooLarge);
    }
    let digest = hash_source(source, length, control).await?;
    let after = control
        .step(source.metadata())
        .await?
        .map_err(|error| TransferIoError::LocalIo(error.kind()))?;
    if after.len() != length {
        return Err(TransferIoError::SourceChanged.into());
    }
    Ok(TransferMetadata::new(name, length, digest)?)
}

/// Preparation failures with no local path or peer-controlled name in diagnostics.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum SourcePreparationError {
    /// The configured maximum is outside its supported range.
    #[error("source size limit must be nonzero and at most 1 TiB")]
    InvalidLimit,
    /// The local path has no final filename component.
    #[error("source path has no filename")]
    MissingFileName,
    /// The filename is not portable, or metadata violates the protocol ceiling.
    #[error("invalid source metadata: {0}")]
    Metadata(#[from] TransferMetadataError),
    /// The opened handle is not a regular file.
    #[error("transfer source must be a regular file")]
    NotRegular,
    /// The handle's initial size exceeds configured policy.
    #[error("transfer source exceeds configured size limit")]
    TooLarge,
    /// Hashing, metadata I/O, cancellation, or the progress-idle deadline failed.
    #[error("source preparation failed: {0}")]
    Io(#[from] TransferIoError),
}

#[cfg(test)]
mod tests {
    use std::{io, time::Duration};

    use tokio::{
        io::{AsyncSeekExt, AsyncWriteExt},
        sync::watch,
    };

    use super::*;

    type TestResult = Result<(), Box<dyn std::error::Error + Send + Sync>>;

    fn control() -> Result<(watch::Sender<bool>, AttemptControl), TransferIoError> {
        let (sender, receiver) = watch::channel(false);
        Ok((
            sender,
            AttemptControl::new(receiver, Duration::from_secs(1))?,
        ))
    }

    #[tokio::test]
    async fn regular_files_prepare_exact_metadata_without_modifying_source() -> TestResult {
        let directory = tempfile::tempdir()?;
        for length in [0, 1, 65536, 65537] {
            let native_path = directory.path().join(format!("file-{length}.bin"));
            let bytes = vec![42; length];
            tokio::fs::write(&native_path, &bytes).await?;
            let path = SourcePath::from_path(&native_path)?;
            let mut source = File::open(&native_path).await?;
            let (_sender, mut control) = control()?;
            let metadata = prepare_source(&mut source, &path, 65537, &mut control).await?;
            assert_eq!(metadata.file_name().as_str(), format!("file-{length}.bin"));
            assert_eq!(metadata.byte_len(), length as u64);
            assert_eq!(metadata.blake3(), blake3::hash(&bytes).as_bytes());
            assert_eq!(source.stream_position().await?, length as u64);
            assert_eq!(tokio::fs::read(&native_path).await?, bytes);
            let mut wire = Vec::new();
            crate::send_payload(&mut source, &mut wire, &metadata, 0, &mut control, |_| {}).await?;
            assert_eq!(wire, bytes);
            assert!(
                !format!("{metadata:?}").contains(
                    directory
                        .path()
                        .to_str()
                        .ok_or("non-UTF-8 temp directory")?
                )
            );
        }
        Ok(())
    }

    #[tokio::test]
    async fn size_policy_is_checked_before_hashing_and_accepts_its_exact_boundary() -> TestResult {
        let directory = tempfile::tempdir()?;
        let native_path = directory.path().join("file.bin");
        tokio::fs::write(&native_path, b"abcd").await?;
        let path = SourcePath::from_path(&native_path)?;
        let mut source = File::open(&native_path).await?;
        let (_sender, mut control) = control()?;
        source.seek(io::SeekFrom::Start(2)).await?;
        for limit in [0, MAX_TRANSFER_BYTES + 1, u64::MAX] {
            assert_eq!(
                prepare_source(&mut source, &path, limit, &mut control).await,
                Err(SourcePreparationError::InvalidLimit)
            );
            assert_eq!(source.stream_position().await?, 2);
        }
        assert_eq!(
            prepare_source(&mut source, &path, 3, &mut control).await,
            Err(SourcePreparationError::TooLarge)
        );
        assert_eq!(source.stream_position().await?, 2);
        assert_eq!(
            prepare_source(&mut source, &path, 4, &mut control)
                .await?
                .byte_len(),
            4
        );
        assert_eq!(
            prepare_source(&mut source, &path, MAX_TRANSFER_BYTES, &mut control)
                .await?
                .byte_len(),
            4
        );
        Ok(())
    }

    #[tokio::test]
    async fn portable_name_failures_never_echo_the_private_path() -> TestResult {
        let directory = tempfile::tempdir()?;
        let native_path = directory.path().join("actual.bin");
        tokio::fs::write(&native_path, b"abc").await?;
        let mut source = File::open(&native_path).await?;
        let (_sender, mut control) = control()?;
        // Invalid names need not exist to exercise pre-I/O validation on Windows.
        for name in ["secret:file", "CON", "private?name"] {
            let path = SourcePath::from_path(&directory.path().join(name))?;
            let result = prepare_source(&mut source, &path, 3, &mut control).await;
            assert_eq!(
                result,
                Err(SourcePreparationError::Metadata(
                    TransferMetadataError::UnsafeFileName
                ))
            );
            let error = result.err().ok_or("accepted invalid name")?;
            assert!(!format!("{error} {error:?}").contains(name));
            assert_eq!(source.stream_position().await?, 0);
        }
        let root = if cfg!(windows) { "C:\\" } else { "/" };
        assert_eq!(
            prepare_source(&mut source, &SourcePath::new(root)?, 3, &mut control).await,
            Err(SourcePreparationError::MissingFileName)
        );
        Ok(())
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn nonregular_handles_are_rejected_before_reading() -> TestResult {
        let directory = tempfile::tempdir()?;
        let (_sender, mut control) = control()?;
        for native_path in [directory.path(), std::path::Path::new("/dev/null")] {
            let mut source = File::open(native_path).await?;
            let path = SourcePath::from_path(native_path)?;
            assert_eq!(
                prepare_source(&mut source, &path, MAX_TRANSFER_BYTES, &mut control).await,
                Err(SourcePreparationError::NotRegular)
            );
        }
        Ok(())
    }

    #[tokio::test]
    async fn preparation_observes_cancellation_and_read_errors() -> TestResult {
        let directory = tempfile::tempdir()?;
        let native_path = directory.path().join("file.bin");
        tokio::fs::write(&native_path, b"abc").await?;
        let path = SourcePath::from_path(&native_path)?;
        let mut source = File::open(&native_path).await?;
        let (sender, mut control) = control()?;
        sender.send(true)?;
        assert_eq!(
            prepare_source(&mut source, &path, 3, &mut control).await,
            Err(SourcePreparationError::Io(TransferIoError::Cancelled))
        );
        assert_eq!(source.stream_position().await?, 0);
        sender.send(false)?;
        let mut write_only = File::options().write(true).open(&native_path).await?;
        assert!(matches!(
            prepare_source(&mut write_only, &path, 3, &mut control).await,
            Err(SourcePreparationError::Io(TransferIoError::LocalIo(_)))
        ));
        Ok(())
    }

    #[tokio::test]
    async fn changed_source_cannot_send_under_prepared_metadata() -> TestResult {
        let directory = tempfile::tempdir()?;
        let native_path = directory.path().join("file.bin");
        tokio::fs::write(&native_path, b"abc").await?;
        let path = SourcePath::from_path(&native_path)?;
        let mut source = File::open(&native_path).await?;
        let (_sender, mut control) = control()?;
        let metadata = prepare_source(&mut source, &path, 3, &mut control).await?;
        let mut writer = File::options().write(true).open(&native_path).await?;
        writer.write_all(b"xyz").await?;
        writer.flush().await?;
        let mut output = Vec::new();
        assert_eq!(
            crate::send_payload(&mut source, &mut output, &metadata, 0, &mut control, |_| {}).await,
            Err(TransferIoError::SourceChanged)
        );
        assert!(output.is_empty());
        assert_eq!(metadata.blake3(), blake3::hash(b"abc").as_bytes());
        Ok(())
    }
}
