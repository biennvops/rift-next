use std::{future::Future, io, time::Duration};

use blake3::Hasher;
use rift_protocol::{MAX_TRANSFER_BYTES, TransferMetadata};
use thiserror::Error;
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncSeek, AsyncSeekExt, AsyncWrite, AsyncWriteExt},
    sync::watch,
    time,
};

/// Fixed buffer shared by hashing and payload loops; never scales with file length.
pub const STREAM_BUFFER_SIZE: usize = 64 * 1024;

/// Controls one owned attempt, with cancellation and a progress-idle deadline.
///
/// Set the watch value to true to cancel; dropping every sender also cancels. The
/// supervisor must still join the worker before reusing its capacity or staging file.
/// Each completed partial read/write resets the deadline; there is no total timeout.
pub struct AttemptControl {
    cancel: watch::Receiver<bool>,
    idle_timeout: Duration,
}

impl AttemptControl {
    /// Constructs an attempt control, rejecting a zero idle timeout.
    pub fn new(
        cancel: watch::Receiver<bool>,
        idle_timeout: Duration,
    ) -> Result<Self, TransferIoError> {
        if idle_timeout.is_zero() {
            return Err(TransferIoError::InvalidIdleTimeout);
        }
        Ok(Self {
            cancel,
            idle_timeout,
        })
    }

    pub(crate) async fn step<F, T>(
        &mut self,
        operation: F,
    ) -> Result<io::Result<T>, TransferIoError>
    where
        F: Future<Output = io::Result<T>>,
    {
        tokio::task::consume_budget().await;
        if *self.cancel.borrow() || self.cancel.has_changed().is_err() {
            return Err(TransferIoError::Cancelled);
        }
        let cancel = &mut self.cancel;
        tokio::select! {
            biased;
            () = async {
                loop {
                    if cancel.changed().await.is_err() || *cancel.borrow_and_update() {
                        break;
                    }
                }
            } => Err(TransferIoError::Cancelled),
            result = time::timeout(self.idle_timeout, operation) => {
                result.map_err(|_| TransferIoError::IdleTimeout)
            }
        }
    }
}

/// Stable I/O outcomes; no local path or raw diagnostic string crosses this API.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum TransferIoError {
    /// The owner cancelled this attempt, or its cancellation sender disappeared.
    #[error("transfer attempt cancelled")]
    Cancelled,
    /// No I/O progress occurred within the configured deadline.
    #[error("transfer attempt idle timeout")]
    IdleTimeout,
    /// An idle deadline must be nonzero.
    #[error("transfer idle timeout must be nonzero")]
    InvalidIdleTimeout,
    /// A length or offset was not valid for the immutable file.
    #[error("invalid transfer range")]
    InvalidRange,
    /// The source length or digest changed under the existing transfer ID.
    #[error("transfer source changed")]
    SourceChanged,
    /// The receive stream reached clean EOF before the promised bytes arrived.
    #[error("transfer payload ended before its declared length")]
    ShortPayload,
    /// More bytes arrived after the declared suffix.
    #[error("transfer payload exceeded its declared length")]
    ExtraPayload,
    /// Whole-file content, including the staged prefix, did not match the digest.
    #[error("transfer integrity mismatch")]
    Integrity,
    /// The current staging length was not the accepted offset.
    #[error("staged transfer prefix does not match accepted offset")]
    InvalidPartial,
    /// Local source or staging I/O failed; this is not a transport interruption.
    #[error("local transfer I/O failed: {0:?}")]
    LocalIo(io::ErrorKind),
    /// Stream I/O failed rather than reaching a clean FIN.
    #[error("transfer stream I/O failed: {0:?}")]
    StreamIo(io::ErrorKind),
}

fn local_io(error: io::Error) -> TransferIoError {
    TransferIoError::LocalIo(error.kind())
}

fn stream_io(error: io::Error) -> TransferIoError {
    TransferIoError::StreamIo(error.kind())
}

/// Hashes an exactly sized source from the beginning using one fixed buffer.
///
/// A clean short read or an extra byte returns SourceChanged. The caller opens and
/// validates a regular file and obtains its initial length before invoking this
/// routine. The source is never modified and remains at EOF on success.
pub async fn hash_source<R>(
    source: &mut R,
    byte_len: u64,
    control: &mut AttemptControl,
) -> Result<[u8; 32], TransferIoError>
where
    R: AsyncRead + AsyncSeek + Unpin,
{
    if byte_len > MAX_TRANSFER_BYTES {
        return Err(TransferIoError::InvalidRange);
    }
    control
        .step(source.seek(io::SeekFrom::Start(0)))
        .await?
        .map_err(local_io)?;
    let mut hasher = Hasher::new();
    hash_prefix(source, byte_len, &mut hasher, control).await?;
    require_source_eof(source, control).await?;
    Ok(*hasher.finalize().as_bytes())
}

async fn hash_prefix<R: AsyncRead + Unpin>(
    reader: &mut R,
    length: u64,
    hasher: &mut Hasher,
    control: &mut AttemptControl,
) -> Result<(), TransferIoError> {
    let mut buffer = vec![0; STREAM_BUFFER_SIZE];
    let mut remaining = length;
    while remaining != 0 {
        let count = remaining.min(STREAM_BUFFER_SIZE as u64) as usize;
        let read = control
            .step(reader.read(&mut buffer[..count]))
            .await?
            .map_err(local_io)?;
        if read == 0 {
            return Err(TransferIoError::SourceChanged);
        }
        hasher.update(&buffer[..read]);
        remaining -= read as u64;
    }
    Ok(())
}

async fn require_source_eof<R: AsyncRead + Unpin>(
    source: &mut R,
    control: &mut AttemptControl,
) -> Result<(), TransferIoError> {
    let mut extra = [0];
    if control
        .step(source.read(&mut extra))
        .await?
        .map_err(local_io)?
        != 0
    {
        return Err(TransferIoError::SourceChanged);
    }
    Ok(())
}

/// Revalidates the source, then sends only the accepted suffix with bounded I/O.
///
/// The whole file is hashed before any stream write, and again while sending
/// (rehashing the prefix on resume). A mismatch is SourceChanged. Success does not
/// finish the QUIC stream: its owner must finish only after this joined result.
/// Progress callbacks are synchronous, lossy-notification hooks, never terminal results.
pub async fn send_payload<R, W, P>(
    source: &mut R,
    stream: &mut W,
    metadata: &TransferMetadata,
    offset: u64,
    control: &mut AttemptControl,
    progress: P,
) -> Result<(), TransferIoError>
where
    R: AsyncRead + AsyncSeek + Unpin,
    W: AsyncWrite + Unpin,
    P: FnMut(u64),
{
    if offset > metadata.byte_len() {
        return Err(TransferIoError::InvalidRange);
    }
    if hash_source(source, metadata.byte_len(), control).await? != *metadata.blake3() {
        return Err(TransferIoError::SourceChanged);
    }
    control
        .step(source.seek(io::SeekFrom::Start(0)))
        .await?
        .map_err(local_io)?;
    let mut hasher = Hasher::new();
    hash_prefix(source, offset, &mut hasher, control).await?;
    let mut progress = Progress::new(metadata.byte_len(), offset, progress);
    let mut buffer = vec![0; STREAM_BUFFER_SIZE];
    let mut total = offset;
    while total < metadata.byte_len() {
        let count = (metadata.byte_len() - total).min(STREAM_BUFFER_SIZE as u64) as usize;
        let read = control
            .step(source.read(&mut buffer[..count]))
            .await?
            .map_err(local_io)?;
        if read == 0 {
            return Err(TransferIoError::SourceChanged);
        }
        hasher.update(&buffer[..read]);
        let mut written = 0;
        while written < read {
            let count = control
                .step(stream.write(&buffer[written..read]))
                .await?
                .map_err(stream_io)?;
            if count == 0 {
                return Err(TransferIoError::StreamIo(io::ErrorKind::WriteZero));
            }
            written += count;
            total += count as u64;
            progress.observe(total);
        }
    }
    require_source_eof(source, control).await?;
    if hasher.finalize().as_bytes() != metadata.blake3() {
        return Err(TransferIoError::SourceChanged);
    }
    Ok(())
}

/// Appends one exact suffix to an exclusively owned accepted staging file.
///
/// Validates actual staging length, rehashes its prefix from disk, reads exactly
/// the expected suffix and clean EOF, verifies whole-file BLAKE3, and flushes. It
/// never calls sync, publishes a file, or records Completed. The owner must join,
/// sync, and decide whether to preserve a paused partial or delete a terminal one.
/// Cancellation can leave a partially buffered write; never reuse this file before
/// that owner's flush/sync/reconciliation. A stream reset is distinct from clean EOF.
pub async fn receive_payload<R, S, P>(
    stream: &mut R,
    staging: &mut S,
    metadata: &TransferMetadata,
    offset: u64,
    control: &mut AttemptControl,
    progress: P,
) -> Result<(), TransferIoError>
where
    R: AsyncRead + Unpin,
    S: AsyncRead + AsyncWrite + AsyncSeek + Unpin,
    P: FnMut(u64),
{
    if offset > metadata.byte_len() {
        return Err(TransferIoError::InvalidRange);
    }
    let actual = control
        .step(staging.seek(io::SeekFrom::End(0)))
        .await?
        .map_err(local_io)?;
    if actual != offset {
        return Err(TransferIoError::InvalidPartial);
    }
    control
        .step(staging.seek(io::SeekFrom::Start(0)))
        .await?
        .map_err(local_io)?;
    let mut hasher = Hasher::new();
    hash_prefix(staging, offset, &mut hasher, control)
        .await
        .map_err(|error| {
            if error == TransferIoError::SourceChanged {
                TransferIoError::InvalidPartial
            } else {
                error
            }
        })?;
    let mut progress = Progress::new(metadata.byte_len(), offset, progress);
    let mut buffer = vec![0; STREAM_BUFFER_SIZE];
    let mut total = offset;
    while total < metadata.byte_len() {
        let count = (metadata.byte_len() - total).min(STREAM_BUFFER_SIZE as u64) as usize;
        let read = control
            .step(stream.read(&mut buffer[..count]))
            .await?
            .map_err(stream_io)?;
        if read == 0 {
            return Err(TransferIoError::ShortPayload);
        }
        hasher.update(&buffer[..read]);
        let mut written = 0;
        while written < read {
            let count = control
                .step(staging.write(&buffer[written..read]))
                .await?
                .map_err(local_io)?;
            if count == 0 {
                return Err(TransferIoError::LocalIo(io::ErrorKind::WriteZero));
            }
            written += count;
            total += count as u64;
            progress.observe(total);
        }
    }
    let mut extra = [0];
    if control
        .step(stream.read(&mut extra))
        .await?
        .map_err(stream_io)?
        != 0
    {
        return Err(TransferIoError::ExtraPayload);
    }
    if hasher.finalize().as_bytes() != metadata.blake3() {
        return Err(TransferIoError::Integrity);
    }
    control.step(staging.flush()).await?.map_err(local_io)?;
    Ok(())
}

struct Progress<P> {
    last: u64,
    step: u64,
    callback: P,
}

impl<P: FnMut(u64)> Progress<P> {
    fn new(total: u64, offset: u64, callback: P) -> Self {
        Self {
            last: offset,
            step: (1024 * 1024).max(total.div_ceil(100)),
            callback,
        }
    }

    fn observe(&mut self, total: u64) {
        if total - self.last >= self.step {
            self.last = total;
            (self.callback)(total);
        }
    }
}

#[cfg(test)]
mod tests;
