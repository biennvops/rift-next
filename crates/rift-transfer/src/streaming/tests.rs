use std::{
    pin::Pin,
    task::{Context, Poll},
};

use rift_protocol::TransferFileName;
use tokio::io::ReadBuf;

use super::*;

type TestResult = Result<(), Box<dyn std::error::Error + Send + Sync>>;

fn control() -> Result<(watch::Sender<bool>, AttemptControl), TransferIoError> {
    let (sender, receiver) = watch::channel(false);
    Ok((
        sender,
        AttemptControl::new(receiver, Duration::from_secs(1))?,
    ))
}

fn metadata(bytes: &[u8]) -> Result<TransferMetadata, rift_protocol::TransferMetadataError> {
    TransferMetadata::new(
        TransferFileName::new("payload.bin")?,
        bytes.len() as u64,
        *blake3::hash(bytes).as_bytes(),
    )
}

#[tokio::test]
async fn empty_tiny_and_multiple_buffer_transfers_round_trip() -> TestResult {
    assert_eq!(STREAM_BUFFER_SIZE, 65536);
    for length in [0, 1, 7, 65535, 65536, 65537, 4 * 65536 + 19] {
        let bytes: Vec<u8> = (0..length).map(|index| (index % 251) as u8).collect();
        let metadata = metadata(&bytes)?;
        let (_sender, mut control) = control()?;
        let mut source = io::Cursor::new(bytes.clone());
        assert_eq!(
            hash_source(&mut source, length as u64, &mut control).await?,
            *metadata.blake3()
        );
        for offset in [0, length / 2, length] {
            let mut wire = Vec::new();
            send_payload(
                &mut source,
                &mut wire,
                &metadata,
                offset as u64,
                &mut control,
                |_| {},
            )
            .await?;
            assert_eq!(wire, bytes[offset..]);
            let mut staging = io::Cursor::new(bytes[..offset].to_vec());
            receive_payload(
                &mut wire.as_slice(),
                &mut staging,
                &metadata,
                offset as u64,
                &mut control,
                |_| {},
            )
            .await?;
            assert_eq!(staging.into_inner(), bytes);
        }
        assert_eq!(source.into_inner(), bytes);
    }
    Ok(())
}

#[tokio::test]
async fn source_revalidation_fails_before_stream_writes() -> TestResult {
    let metadata = metadata(b"abc")?;
    for source in [b"ab".as_slice(), b"abcd", b"abx"] {
        let (_sender, mut control) = control()?;
        let mut output = Vec::new();
        assert_eq!(
            send_payload(
                &mut io::Cursor::new(source),
                &mut output,
                &metadata,
                0,
                &mut control,
                |_| {}
            )
            .await,
            Err(TransferIoError::SourceChanged)
        );
        assert!(output.is_empty());
    }
    Ok(())
}

struct MutatingSource {
    data: io::Cursor<Vec<u8>>,
    seeks: usize,
}

impl AsyncRead for MutatingSource {
    fn poll_read(
        mut self: Pin<&mut Self>,
        _: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let read = io::Read::read(&mut self.data, buf.initialize_unfilled())?;
        buf.advance(read);
        Poll::Ready(Ok(()))
    }
}

impl AsyncSeek for MutatingSource {
    fn start_seek(mut self: Pin<&mut Self>, position: io::SeekFrom) -> io::Result<()> {
        self.seeks += 1;
        if self.seeks == 2 {
            self.data.get_mut()[0] = b'x';
        }
        io::Seek::seek(&mut self.data, position)?;
        Ok(())
    }
    fn poll_complete(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<u64>> {
        Poll::Ready(Ok(self.data.position()))
    }
}

#[tokio::test]
async fn source_mutation_after_preflight_is_detected_during_attempt() -> TestResult {
    let (_sender, mut control) = control()?;
    let metadata = metadata(b"abc")?;
    let mut source = MutatingSource {
        data: io::Cursor::new(b"abc".to_vec()),
        seeks: 0,
    };
    let mut output = Vec::new();
    assert_eq!(
        send_payload(&mut source, &mut output, &metadata, 1, &mut control, |_| {}).await,
        Err(TransferIoError::SourceChanged)
    );
    assert_eq!(output, b"bc");
    Ok(())
}

#[tokio::test]
async fn clean_short_extra_and_corrupt_payloads_are_terminal_failures() -> TestResult {
    let metadata = metadata(b"abc")?;
    for (bytes, expected) in [
        (b"ab".as_slice(), TransferIoError::ShortPayload),
        (b"abcd", TransferIoError::ExtraPayload),
        (b"abx", TransferIoError::Integrity),
    ] {
        let (_sender, mut control) = control()?;
        let mut staging = io::Cursor::new(Vec::new());
        assert_eq!(
            receive_payload(
                &mut &*bytes,
                &mut staging,
                &metadata,
                0,
                &mut control,
                |_| {}
            )
            .await,
            Err(expected)
        );
        assert!(staging.get_ref().len() <= 3);
    }
    Ok(())
}

#[tokio::test]
async fn resume_rehashes_real_staging_prefix_and_never_trusts_cached_progress() -> TestResult {
    let directory = tempfile::tempdir()?;
    let path = directory.path().join(".part");
    tokio::fs::write(&path, b"ab").await?;
    let mut staging = tokio::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open(&path)
        .await?;
    let (_sender, mut control) = control()?;
    let metadata = metadata(b"abcdef")?;
    receive_payload(
        &mut b"cdef".as_slice(),
        &mut staging,
        &metadata,
        2,
        &mut control,
        |_| {},
    )
    .await?;
    staging.sync_all().await?;
    assert_eq!(tokio::fs::read(&path).await?, b"abcdef");
    drop(staging);
    tokio::fs::write(&path, b"ax").await?;
    let mut staging = tokio::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open(&path)
        .await?;
    assert_eq!(
        receive_payload(
            &mut b"cdef".as_slice(),
            &mut staging,
            &metadata,
            2,
            &mut control,
            |_| {}
        )
        .await,
        Err(TransferIoError::Integrity)
    );
    Ok(())
}

#[tokio::test]
async fn invalid_offsets_and_staging_lengths_fail_before_stream_read() -> TestResult {
    let metadata = metadata(b"abc")?;
    let (_sender, mut control) = control()?;
    let mut wire = b"abc".as_slice();
    let mut staging = io::Cursor::new(Vec::new());
    assert_eq!(
        receive_payload(&mut wire, &mut staging, &metadata, 4, &mut control, |_| {}).await,
        Err(TransferIoError::InvalidRange)
    );
    for offset in [1, 3] {
        assert_eq!(
            receive_payload(
                &mut wire,
                &mut staging,
                &metadata,
                offset,
                &mut control,
                |_| {}
            )
            .await,
            Err(TransferIoError::InvalidPartial)
        );
    }
    assert_eq!(wire, b"abc");
    staging = io::Cursor::new(b"abcd".to_vec());
    assert_eq!(
        receive_payload(&mut wire, &mut staging, &metadata, 3, &mut control, |_| {}).await,
        Err(TransferIoError::InvalidPartial)
    );
    let mut output = Vec::new();
    assert_eq!(
        send_payload(
            &mut staging,
            &mut output,
            &metadata,
            u64::MAX,
            &mut control,
            |_| {}
        )
        .await,
        Err(TransferIoError::InvalidRange)
    );
    assert!(output.is_empty());
    assert_eq!(
        hash_source(&mut staging, MAX_TRANSFER_BYTES + 1, &mut control).await,
        Err(TransferIoError::InvalidRange)
    );
    Ok(())
}

#[tokio::test(start_paused = true)]
async fn pending_read_and_missing_fin_have_idle_deadlines() -> TestResult {
    for bytes in [b"".as_slice(), b"abc"] {
        let (_sender, mut control) = control()?;
        let (mut remote, mut stream) = tokio::io::duplex(8);
        remote.write_all(bytes).await?;
        let mut staging = io::Cursor::new(Vec::new());
        let start = time::Instant::now();
        assert_eq!(
            receive_payload(
                &mut stream,
                &mut staging,
                &metadata(b"abc")?,
                0,
                &mut control,
                |_| {}
            )
            .await,
            Err(TransferIoError::IdleTimeout)
        );
        assert_eq!(time::Instant::now() - start, Duration::from_secs(1));
        assert_eq!(staging.into_inner(), bytes);
    }
    Ok(())
}

#[tokio::test(start_paused = true)]
async fn stalled_write_times_out_without_a_total_transfer_deadline() -> TestResult {
    let (_sender, mut control) = control()?;
    let (_remote, mut stream) = tokio::io::duplex(1);
    let mut source = io::Cursor::new(b"abc");
    assert_eq!(
        send_payload(
            &mut source,
            &mut stream,
            &metadata(b"abc")?,
            0,
            &mut control,
            |_| {}
        )
        .await,
        Err(TransferIoError::IdleTimeout)
    );
    Ok(())
}

struct SlowReader {
    remaining: usize,
    delay: Pin<Box<time::Sleep>>,
}

impl AsyncRead for SlowReader {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        if self.remaining == 0 {
            return Poll::Ready(Ok(()));
        }
        if self.delay.as_mut().poll(cx).is_pending() {
            return Poll::Pending;
        }
        buf.put_slice(&[0]);
        self.remaining -= 1;
        self.delay
            .as_mut()
            .reset(time::Instant::now() + Duration::from_millis(900));
        Poll::Ready(Ok(()))
    }
}

#[tokio::test(start_paused = true)]
async fn slow_continuous_progress_outlives_the_idle_timeout() -> TestResult {
    let (_sender, mut control) = control()?;
    let mut stream = SlowReader {
        remaining: 4,
        delay: Box::pin(time::sleep(Duration::from_millis(900))),
    };
    let mut staging = io::Cursor::new(Vec::new());
    let start = time::Instant::now();
    receive_payload(
        &mut stream,
        &mut staging,
        &metadata(&[0; 4])?,
        0,
        &mut control,
        |_| {},
    )
    .await?;
    assert_eq!(time::Instant::now() - start, Duration::from_millis(3600));
    assert_eq!(staging.into_inner(), [0; 4]);
    Ok(())
}

#[tokio::test]
async fn cancellation_and_owner_loss_fail_closed_before_io() -> TestResult {
    let (sender, receiver) = watch::channel(false);
    assert!(matches!(
        AttemptControl::new(receiver.clone(), Duration::ZERO),
        Err(TransferIoError::InvalidIdleTimeout)
    ));
    let mut control = AttemptControl::new(receiver.clone(), Duration::from_secs(1))?;
    sender.send(true)?;
    let mut data = io::Cursor::new(b"abc");
    assert_eq!(
        hash_source(&mut data, 3, &mut control).await,
        Err(TransferIoError::Cancelled)
    );
    sender.send(false)?;
    drop(sender);
    let mut control = AttemptControl::new(receiver, Duration::from_secs(1))?;
    assert_eq!(
        hash_source(&mut io::Cursor::new(b"abc"), 3, &mut control).await,
        Err(TransferIoError::Cancelled)
    );
    Ok(())
}

#[tokio::test]
async fn cancellation_interrupts_a_blocked_read_without_detaching_work() -> TestResult {
    let (sender, mut control) = control()?;
    let (remote, mut stream) = tokio::io::duplex(1);
    let mut staging = io::Cursor::new(Vec::new());
    let metadata = metadata(b"abc")?;
    let (result, cancelled) = tokio::join!(
        receive_payload(
            &mut stream,
            &mut staging,
            &metadata,
            0,
            &mut control,
            |_| {}
        ),
        async {
            tokio::task::yield_now().await;
            sender.send(true)
        }
    );
    cancelled?;
    assert_eq!(result, Err(TransferIoError::Cancelled));
    assert!(staging.into_inner().is_empty());
    drop(remote);
    Ok(())
}

#[tokio::test]
async fn cancelled_partial_is_resumable_after_owner_reconciliation() -> TestResult {
    let bytes = vec![7; 2 * 1024 * 1024];
    let metadata = metadata(&bytes)?;
    let (sender, mut control) = control()?;
    let mut staging = io::Cursor::new(Vec::new());
    let mut cancel_result = Ok(());
    assert_eq!(
        receive_payload(
            &mut bytes.as_slice(),
            &mut staging,
            &metadata,
            0,
            &mut control,
            |_| {
                cancel_result = sender.send(true);
            }
        )
        .await,
        Err(TransferIoError::Cancelled)
    );
    cancel_result?;
    let offset = staging.get_ref().len();
    assert_eq!(offset, 1024 * 1024);
    let (new_sender, receiver) = watch::channel(false);
    let mut control = AttemptControl::new(receiver, Duration::from_secs(1))?;
    receive_payload(
        &mut &bytes[offset..],
        &mut staging,
        &metadata,
        offset as u64,
        &mut control,
        |_| {},
    )
    .await?;
    assert_eq!(staging.into_inner(), bytes);
    drop(new_sender);
    Ok(())
}

#[test]
fn progress_threshold_is_bounded_and_does_not_encode_terminal_state() {
    for total in [0, 1, 1024 * 1024, 256 * 1024 * 1024, MAX_TRANSFER_BYTES] {
        let mut observed = Vec::new();
        let mut progress = Progress::new(total, 0, |value| observed.push(value));
        assert_eq!(progress.step, (1024 * 1024).max(total.div_ceil(100)));
        for index in 0..=1000 {
            progress.observe(total * index / 1000);
        }
        assert!(observed.len() <= 100);
        assert!(observed.windows(2).all(|pair| pair[0] < pair[1]));
        if total < 1024 * 1024 {
            assert!(observed.is_empty());
        }
    }
}

struct FailedStream;

impl AsyncRead for FailedStream {
    fn poll_read(
        self: Pin<&mut Self>,
        _: &mut Context<'_>,
        _: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Poll::Ready(Err(io::Error::from(io::ErrorKind::ConnectionReset)))
    }
}

impl AsyncWrite for FailedStream {
    fn poll_write(self: Pin<&mut Self>, _: &mut Context<'_>, _: &[u8]) -> Poll<io::Result<usize>> {
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
async fn reset_and_stream_write_errors_are_not_clean_fin() -> TestResult {
    let (_sender, mut control) = control()?;
    let mut staging = io::Cursor::new(Vec::new());
    assert_eq!(
        receive_payload(
            &mut FailedStream,
            &mut staging,
            &metadata(b"abc")?,
            0,
            &mut control,
            |_| {}
        )
        .await,
        Err(TransferIoError::StreamIo(io::ErrorKind::ConnectionReset))
    );
    let mut source = io::Cursor::new(b"abc");
    assert_eq!(
        send_payload(
            &mut source,
            &mut FailedStream,
            &metadata(b"abc")?,
            0,
            &mut control,
            |_| {}
        )
        .await,
        Err(TransferIoError::StreamIo(io::ErrorKind::BrokenPipe))
    );
    Ok(())
}

struct ZeroFile {
    len: u64,
    position: u64,
    max_read: usize,
    max_write: usize,
}

impl ZeroFile {
    fn new(len: u64) -> Self {
        Self {
            len,
            position: 0,
            max_read: 0,
            max_write: 0,
        }
    }
}

impl AsyncRead for ZeroFile {
    fn poll_read(
        mut self: Pin<&mut Self>,
        _: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        self.max_read = self.max_read.max(buf.remaining());
        let count = (self.len - self.position).min(buf.remaining() as u64) as usize;
        buf.initialize_unfilled_to(count).fill(0);
        buf.advance(count);
        self.position += count as u64;
        Poll::Ready(Ok(()))
    }
}

impl AsyncSeek for ZeroFile {
    fn start_seek(mut self: Pin<&mut Self>, position: io::SeekFrom) -> io::Result<()> {
        self.position = match position {
            io::SeekFrom::Start(value) => value,
            io::SeekFrom::End(0) => self.len,
            _ => return Err(io::Error::from(io::ErrorKind::InvalidInput)),
        };
        Ok(())
    }
    fn poll_complete(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<u64>> {
        Poll::Ready(Ok(self.position))
    }
}

impl AsyncWrite for ZeroFile {
    fn poll_write(
        mut self: Pin<&mut Self>,
        _: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        self.max_write = self.max_write.max(buf.len());
        // Force short successful writes to cover progress within a buffer.
        let count = buf.len().min(10001);
        self.position += count as u64;
        self.len = self.len.max(self.position);
        Poll::Ready(Ok(count))
    }
    fn poll_flush(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }
    fn poll_shutdown(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }
}

#[tokio::test]
async fn synthetic_large_transfer_never_requests_payload_sized_buffers() -> TestResult {
    let length = 64 * 1024 * 1024;
    let (_sender, mut control) = control()?;
    let mut source = ZeroFile::new(length);
    let digest = hash_source(&mut source, length, &mut control).await?;
    let metadata = TransferMetadata::new(TransferFileName::new("large.bin")?, length, digest)?;
    let offset = 32 * 1024 * 1024;
    let mut stream = ZeroFile::new(0);
    send_payload(
        &mut source,
        &mut stream,
        &metadata,
        offset,
        &mut control,
        |_| {},
    )
    .await?;
    assert_eq!(stream.len, length - offset);
    assert_eq!(source.max_read, STREAM_BUFFER_SIZE);
    assert_eq!(stream.max_write, STREAM_BUFFER_SIZE);
    stream.position = 0;
    let mut staging = ZeroFile::new(offset);
    receive_payload(
        &mut stream,
        &mut staging,
        &metadata,
        offset,
        &mut control,
        |_| {},
    )
    .await?;
    assert_eq!(staging.len, length);
    assert_eq!(stream.max_read, STREAM_BUFFER_SIZE);
    assert_eq!(staging.max_read, STREAM_BUFFER_SIZE);
    assert_eq!(staging.max_write, STREAM_BUFFER_SIZE);
    Ok(())
}

#[tokio::test]
async fn always_ready_large_hash_yields_to_owner_cancellation() -> TestResult {
    let (sender, mut control) = control()?;
    let mut source = ZeroFile::new(64 * 1024 * 1024);
    let (result, cancelled) = tokio::join!(
        hash_source(&mut source, 64 * 1024 * 1024, &mut control),
        async { sender.send(true) }
    );
    cancelled?;
    assert_eq!(result, Err(TransferIoError::Cancelled));
    assert!(source.position < source.len);
    Ok(())
}

#[derive(Clone, Copy)]
enum FileFault {
    Read,
    Seek,
    Write,
    WriteZero,
    Flush,
    ShortPrefix,
}

struct FaultyFile {
    data: io::Cursor<Vec<u8>>,
    fault: FileFault,
}

impl AsyncRead for FaultyFile {
    fn poll_read(
        mut self: Pin<&mut Self>,
        _: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        if matches!(self.fault, FileFault::Read) {
            return Poll::Ready(Err(io::Error::from(io::ErrorKind::PermissionDenied)));
        }
        if matches!(self.fault, FileFault::ShortPrefix) {
            return Poll::Ready(Ok(()));
        }
        let count = io::Read::read(&mut self.data, buf.initialize_unfilled())?;
        buf.advance(count);
        Poll::Ready(Ok(()))
    }
}

impl AsyncSeek for FaultyFile {
    fn start_seek(mut self: Pin<&mut Self>, position: io::SeekFrom) -> io::Result<()> {
        if matches!(self.fault, FileFault::Seek) {
            return Err(io::Error::from(io::ErrorKind::PermissionDenied));
        }
        io::Seek::seek(&mut self.data, position)?;
        Ok(())
    }
    fn poll_complete(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<u64>> {
        Poll::Ready(Ok(self.data.position()))
    }
}

impl AsyncWrite for FaultyFile {
    fn poll_write(
        mut self: Pin<&mut Self>,
        _: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        match self.fault {
            FileFault::Write => Poll::Ready(Err(io::Error::from(io::ErrorKind::PermissionDenied))),
            FileFault::WriteZero => Poll::Ready(Ok(0)),
            _ => Poll::Ready(io::Write::write(&mut self.data, buf)),
        }
    }
    fn poll_flush(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
        if matches!(self.fault, FileFault::Flush) {
            Poll::Ready(Err(io::Error::from(io::ErrorKind::PermissionDenied)))
        } else {
            Poll::Ready(Ok(()))
        }
    }
    fn poll_shutdown(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }
}

#[tokio::test]
async fn source_staging_io_and_write_zero_failures_are_local_not_network_pauses() -> TestResult {
    let (_sender, mut control) = control()?;
    for fault in [FileFault::Read, FileFault::Seek] {
        let mut source = FaultyFile {
            data: io::Cursor::new(b"abc".to_vec()),
            fault,
        };
        assert_eq!(
            hash_source(&mut source, 3, &mut control).await,
            Err(TransferIoError::LocalIo(io::ErrorKind::PermissionDenied))
        );
    }
    for fault in [
        FileFault::Seek,
        FileFault::Write,
        FileFault::WriteZero,
        FileFault::Flush,
    ] {
        let mut staging = FaultyFile {
            data: io::Cursor::new(Vec::new()),
            fault,
        };
        let expected = if matches!(fault, FileFault::WriteZero) {
            io::ErrorKind::WriteZero
        } else {
            io::ErrorKind::PermissionDenied
        };
        assert_eq!(
            receive_payload(
                &mut b"abc".as_slice(),
                &mut staging,
                &metadata(b"abc")?,
                0,
                &mut control,
                |_| {}
            )
            .await,
            Err(TransferIoError::LocalIo(expected))
        );
    }
    for (fault, expected) in [
        (
            FileFault::Read,
            TransferIoError::LocalIo(io::ErrorKind::PermissionDenied),
        ),
        (FileFault::ShortPrefix, TransferIoError::InvalidPartial),
    ] {
        let mut staging = FaultyFile {
            data: io::Cursor::new(b"a".to_vec()),
            fault,
        };
        assert_eq!(
            receive_payload(
                &mut b"bc".as_slice(),
                &mut staging,
                &metadata(b"abc")?,
                1,
                &mut control,
                |_| {}
            )
            .await,
            Err(expected)
        );
    }
    let mut source = io::Cursor::new(b"abc");
    let mut stream = FaultyFile {
        data: io::Cursor::new(Vec::new()),
        fault: FileFault::WriteZero,
    };
    assert_eq!(
        send_payload(
            &mut source,
            &mut stream,
            &metadata(b"abc")?,
            0,
            &mut control,
            |_| {}
        )
        .await,
        Err(TransferIoError::StreamIo(io::ErrorKind::WriteZero))
    );
    Ok(())
}

#[tokio::test]
async fn cancellation_interrupts_a_blocked_write() -> TestResult {
    let (sender, mut control) = control()?;
    let (remote, mut stream) = tokio::io::duplex(1);
    let mut source = io::Cursor::new(b"abc");
    let metadata = metadata(b"abc")?;
    let (result, cancelled) = tokio::join!(
        send_payload(&mut source, &mut stream, &metadata, 0, &mut control, |_| {}),
        async {
            tokio::task::yield_now().await;
            sender.send(true)
        }
    );
    cancelled?;
    assert_eq!(result, Err(TransferIoError::Cancelled));
    drop(remote);
    Ok(())
}

async fn write_zeros(file: &mut tokio::fs::File, length: u64) -> io::Result<()> {
    let buffer = [0; STREAM_BUFFER_SIZE];
    let mut remaining = length;
    while remaining != 0 {
        let count = remaining.min(STREAM_BUFFER_SIZE as u64) as usize;
        file.write_all(&buffer[..count]).await?;
        remaining -= count as u64;
    }
    file.flush().await
}

#[tokio::test]
#[ignore = "measurement only; exercised by benchmark-smoke"]
async fn streaming_benchmark() -> TestResult {
    let directory = tempfile::tempdir()?;
    let source_path = directory.path().join("source");
    let mut source = tokio::fs::OpenOptions::new()
        .create_new(true)
        .read(true)
        .write(true)
        .open(&source_path)
        .await?;
    let length = 8 * 1024 * 1024;
    write_zeros(&mut source, length).await?;
    source.sync_all().await?;
    let (sender, receiver) = watch::channel(false);
    let mut control = AttemptControl::new(receiver.clone(), Duration::from_secs(60))?;
    let started = time::Instant::now();
    let digest = hash_source(&mut source, length, &mut control).await?;
    println!(
        "production.transfer_engine.prehash_seconds={:.6}",
        started.elapsed().as_secs_f64()
    );
    let metadata = TransferMetadata::new(TransferFileName::new("source")?, length, digest)?;
    for offset in [0, length / 2] {
        let destination = directory.path().join(format!("partial-{offset}"));
        let mut staging = tokio::fs::OpenOptions::new()
            .create_new(true)
            .read(true)
            .write(true)
            .open(destination)
            .await?;
        write_zeros(&mut staging, offset).await?;
        let started = time::Instant::now();
        hash_source(&mut staging, offset, &mut control).await?;
        println!(
            "production.transfer_engine.offset_{offset}.prefix_rehash_seconds={:.6}",
            started.elapsed().as_secs_f64()
        );
        let mut send_control = AttemptControl::new(receiver.clone(), Duration::from_secs(60))?;
        let mut receive_control = AttemptControl::new(receiver.clone(), Duration::from_secs(60))?;
        let (mut send, mut recv) = tokio::io::duplex(STREAM_BUFFER_SIZE);
        let started = time::Instant::now();
        let (sent, received) = tokio::join!(
            async {
                send_payload(
                    &mut source,
                    &mut send,
                    &metadata,
                    offset,
                    &mut send_control,
                    |_| {},
                )
                .await?;
                send.shutdown().await.map_err(stream_io)
            },
            receive_payload(
                &mut recv,
                &mut staging,
                &metadata,
                offset,
                &mut receive_control,
                |_| {}
            )
        );
        sent?;
        received?;
        println!(
            "production.transfer_engine.offset_{offset}.attempt_with_revalidation_seconds={:.6}",
            started.elapsed().as_secs_f64()
        );
        let started = time::Instant::now();
        staging.sync_all().await?;
        println!(
            "production.transfer_engine.offset_{offset}.sync_seconds={:.6}",
            started.elapsed().as_secs_f64()
        );
        assert_eq!(staging.metadata().await?.len(), length);
    }
    println!("production.transfer_engine.bytes={length}");
    println!("production.transfer_engine.buffer_bytes={STREAM_BUFFER_SIZE}");
    drop(sender);
    Ok(())
}

#[test]
fn composed_payload_futures_do_not_embed_streaming_buffers_on_the_stack() -> TestResult {
    let (_sender, mut control) = control()?;
    let mut source = io::Cursor::new(b"abc");
    let mut stream = Vec::new();
    let mut staging = io::Cursor::new(Vec::new());
    let metadata = metadata(b"abc")?;
    assert!(std::mem::size_of_val(&hash_source(&mut source, 3, &mut control)) < 16 * 1024);
    assert!(
        std::mem::size_of_val(&send_payload(
            &mut source,
            &mut stream,
            &metadata,
            0,
            &mut control,
            |_| {}
        )) < 16 * 1024
    );
    assert!(
        std::mem::size_of_val(&receive_payload(
            &mut b"abc".as_slice(),
            &mut staging,
            &metadata,
            0,
            &mut control,
            |_| {}
        )) < 16 * 1024
    );
    Ok(())
}

#[tokio::test]
async fn bounded_duplex_round_trip_uses_real_files_and_joined_futures() -> TestResult {
    let directory = tempfile::tempdir()?;
    let source_path = directory.path().join("source");
    let output_path = directory.path().join(".part");
    let bytes = vec![9; 3 * STREAM_BUFFER_SIZE + 7];
    tokio::fs::write(&source_path, &bytes).await?;
    let mut source = tokio::fs::File::open(&source_path).await?;
    let mut staging = tokio::fs::OpenOptions::new()
        .create_new(true)
        .read(true)
        .write(true)
        .open(&output_path)
        .await?;
    let (sender, mut send_control) = control()?;
    let mut receive_control = AttemptControl::new(sender.subscribe(), Duration::from_secs(1))?;
    let metadata = metadata(&bytes)?;
    let (mut send, mut recv) = tokio::io::duplex(1024);
    let (sent, received) = tokio::join!(
        async {
            send_payload(
                &mut source,
                &mut send,
                &metadata,
                0,
                &mut send_control,
                |_| {},
            )
            .await?;
            send.shutdown().await.map_err(stream_io)
        },
        receive_payload(
            &mut recv,
            &mut staging,
            &metadata,
            0,
            &mut receive_control,
            |_| {}
        )
    );
    sent?;
    received?;
    staging.sync_all().await?;
    assert_eq!(tokio::fs::read(&output_path).await?, bytes);
    assert_eq!(tokio::fs::read(&source_path).await?, bytes);
    Ok(())
}
