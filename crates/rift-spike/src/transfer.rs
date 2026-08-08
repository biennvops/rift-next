//! Streaming binary/blob transfer over a dedicated QUIC stream.

use std::{
    io,
    path::{Path, PathBuf},
    sync::atomic::{AtomicU64, Ordering},
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
static TEMP_FILE_COUNTER: AtomicU64 = AtomicU64::new(0);

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
    #[error("transfer destination already exists: {0}")]
    DestinationExists(PathBuf),
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
    let (temporary_path, temporary_file) = create_temporary_file(receive_dir, &metadata.file_name)?;
    let mut temporary = StagedFile::new(temporary_path, temporary_file);
    let result = receive_to_temporary(recv, temporary.file_mut(), &metadata).await;
    temporary.close_file();
    match result {
        Ok((byte_len, blake3)) => {
            if let Err(error) = verify_payload(metadata.byte_len, byte_len, metadata.blake3, blake3)
            {
                temporary.remove().await;
                return Err(error);
            }
            let temporary_path = temporary.path().to_owned();
            match fs::hard_link(&temporary_path, &output_path).await {
                Ok(()) => {
                    temporary.remove().await;
                    Ok(TransferResult {
                        output_path,
                        byte_len,
                        blake3,
                    })
                }
                Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {
                    temporary.remove().await;
                    Err(TransferError::DestinationExists(output_path))
                }
                Err(error) => {
                    temporary.remove().await;
                    Err(error.into())
                }
            }
        }
        Err(error) => {
            temporary.remove().await;
            Err(error)
        }
    }
}

struct StagedFile {
    path: Option<PathBuf>,
    file: Option<fs::File>,
}

impl StagedFile {
    fn new(path: PathBuf, file: fs::File) -> Self {
        Self {
            path: Some(path),
            file: Some(file),
        }
    }

    #[allow(
        clippy::expect_used,
        reason = "a staged file owns its path until cleanup"
    )]
    fn path(&self) -> &Path {
        self.path.as_deref().expect("staged file path was removed")
    }

    #[allow(
        clippy::expect_used,
        reason = "a staged file is open until receive completion"
    )]
    fn file_mut(&mut self) -> &mut fs::File {
        self.file.as_mut().expect("staged file was closed")
    }

    fn close_file(&mut self) {
        self.file.take();
    }

    async fn remove(&mut self) {
        self.close_file();
        let Some(path) = self.path.clone() else {
            return;
        };
        match fs::remove_file(path).await {
            Ok(()) => {
                self.path.take();
            }
            Err(error) if error.kind() == io::ErrorKind::NotFound => {
                self.path.take();
            }
            Err(_) => {}
        }
    }
}

impl Drop for StagedFile {
    fn drop(&mut self) {
        self.file.take();
        if let Some(path) = self.path.take() {
            let _ = std::fs::remove_file(path);
        }
    }
}

fn create_temporary_file(
    receive_dir: &Path,
    file_name: &str,
) -> Result<(PathBuf, fs::File), TransferError> {
    loop {
        let counter = TEMP_FILE_COUNTER.fetch_add(1, Ordering::Relaxed);
        let temporary_path = receive_dir.join(format!(
            ".{file_name}.{}.{}.part",
            std::process::id(),
            counter
        ));
        match std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&temporary_path)
        {
            Ok(file) => return Ok((temporary_path, fs::File::from_std(file))),
            Err(error) if error.kind() == io::ErrorKind::AlreadyExists => continue,
            Err(error) => return Err(error.into()),
        }
    }
}

async fn receive_to_temporary<R>(
    recv: &mut R,
    file: &mut fs::File,
    metadata: &TransferMetadata,
) -> Result<(u64, [u8; 32]), TransferError>
where
    R: AsyncRead + Unpin,
{
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
    #![allow(clippy::expect_used)]

    use std::{path::Path, time::Duration};

    use super::*;
    use tokio::{
        io::{AsyncWriteExt, duplex},
        time,
    };

    async fn staging_file_exists(
        receive_dir: &Path,
        file_name: &str,
    ) -> Result<bool, std::io::Error> {
        let mut entries = match fs::read_dir(receive_dir).await {
            Ok(entries) => entries,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(false),
            Err(error) => return Err(error),
        };
        let prefix = format!(".{file_name}.");
        while let Some(entry) = entries.next_entry().await? {
            let name = entry.file_name();
            let name = name.to_string_lossy();
            if name.starts_with(&prefix) && name.ends_with(".part") {
                return Ok(true);
            }
        }
        Ok(false)
    }

    async fn wait_for_staging_file(
        receive_dir: &Path,
        file_name: &str,
    ) -> Result<(), Box<dyn std::error::Error>> {
        time::timeout(Duration::from_secs(5), async {
            loop {
                if staging_file_exists(receive_dir, file_name).await? {
                    return Ok::<(), std::io::Error>(());
                }
                time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await??;
        Ok(())
    }

    async fn assert_no_staging_file(
        receive_dir: &Path,
        file_name: &str,
    ) -> Result<(), Box<dyn std::error::Error>> {
        assert!(!staging_file_exists(receive_dir, file_name).await?);
        Ok(())
    }

    #[tokio::test]
    async fn cancelling_receive_removes_partial_staging_file()
    -> Result<(), Box<dyn std::error::Error>> {
        let directory = tempfile::tempdir()?;
        let receive_dir = directory.path().join("received");
        let payload = vec![0x42; 64 * 1024];
        let metadata = TransferMetadata {
            file_name: "cancelled.bin".to_owned(),
            byte_len: payload.len() as u64,
            blake3: *blake3::hash(&payload).as_bytes(),
        };
        let (mut writer, reader) = duplex(4096);
        writer
            .write_all(&protocol::encode_frame(&metadata)?)
            .await?;
        writer.write_all(&payload[..1024]).await?;
        let task_receive_dir = receive_dir.clone();
        let task = tokio::spawn(async move {
            let mut reader = reader;
            receive_file(&mut reader, &task_receive_dir).await
        });

        wait_for_staging_file(&receive_dir, &metadata.file_name).await?;
        task.abort();
        let error = task.await.expect_err("receive task should be cancelled");
        assert!(error.is_cancelled());
        assert_no_staging_file(&receive_dir, &metadata.file_name).await?;
        Ok(())
    }

    #[tokio::test]
    async fn receive_deadline_removes_partial_staging_file()
    -> Result<(), Box<dyn std::error::Error>> {
        let directory = tempfile::tempdir()?;
        let receive_dir = directory.path().join("received");
        let payload = vec![0x24; 64 * 1024];
        let metadata = TransferMetadata {
            file_name: "timed-out.bin".to_owned(),
            byte_len: payload.len() as u64,
            blake3: *blake3::hash(&payload).as_bytes(),
        };
        let (mut writer, reader) = duplex(4096);
        writer
            .write_all(&protocol::encode_frame(&metadata)?)
            .await?;
        writer.write_all(&payload[..1024]).await?;
        let task_receive_dir = receive_dir.clone();
        let task = tokio::spawn(async move {
            let mut reader = reader;
            time::timeout(
                Duration::from_millis(250),
                receive_file(&mut reader, &task_receive_dir),
            )
            .await
        });

        wait_for_staging_file(&receive_dir, &metadata.file_name).await?;
        let result = task.await?;
        assert!(result.is_err(), "receive deadline should expire");
        assert_no_staging_file(&receive_dir, &metadata.file_name).await?;
        Ok(())
    }

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

    #[tokio::test]
    async fn concurrent_same_name_transfers_use_unique_staging_and_reject_collision()
    -> Result<(), Box<dyn std::error::Error>> {
        let directory = tempfile::tempdir()?;
        let receive_dir = directory.path().join("received");
        let payload = vec![0x42; 1024];
        let metadata = TransferMetadata {
            file_name: "payload.bin".to_owned(),
            byte_len: payload.len() as u64,
            blake3: *blake3::hash(&payload).as_bytes(),
        };
        let (mut writer_a, mut reader_a) = duplex(4096);
        let (mut writer_b, mut reader_b) = duplex(4096);
        let frame = protocol::encode_frame(&metadata)?;
        for writer in [&mut writer_a, &mut writer_b] {
            writer.write_all(&frame).await?;
            writer.write_all(&payload).await?;
            writer.shutdown().await?;
        }

        let first = receive_file(&mut reader_a, &receive_dir);
        let second = receive_file(&mut reader_b, &receive_dir);
        let (first, second) = tokio::join!(first, second);
        let results = [first, second];
        assert_eq!(results.iter().filter(|result| result.is_ok()).count(), 1);
        assert_eq!(
            results
                .iter()
                .filter(|result| matches!(result, Err(TransferError::DestinationExists(_))))
                .count(),
            1
        );
        assert_eq!(fs::read(receive_dir.join("payload.bin")).await?, payload);
        let mut entries = fs::read_dir(&receive_dir).await?;
        while let Some(entry) = entries.next_entry().await? {
            assert_ne!(entry.file_name(), ".payload.bin.part");
        }
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
