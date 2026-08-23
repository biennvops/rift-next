use std::{error::Error, io, time::Duration};

use rift_daemon::{Daemon, DaemonConfig, DaemonError};
use rift_ipc::{
    ClientMessage, FrameError, IPC_PROTOCOL_VERSION, MAX_IPC_FRAME_LEN, Request, RuntimeDescriptor,
    ServerMessage, read_json_frame, write_json_frame,
};
use tempfile::TempDir;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

type TestResult<T = ()> = Result<T, Box<dyn Error + Send + Sync>>;

#[cfg(unix)]
type ClientStream = tokio::net::UnixStream;
#[cfg(windows)]
type ClientStream = tokio::net::windows::named_pipe::NamedPipeClient;

fn test_config(directory: &TempDir) -> DaemonConfig {
    let mut config = DaemonConfig::new(directory.path(), "ipc-test");
    config.bind_addr =
        Some("127.0.0.1:0".parse().unwrap_or_else(|_| {
            std::net::SocketAddr::new(std::net::Ipv4Addr::LOCALHOST.into(), 0)
        }));
    config.connection_timeout = Duration::from_secs(2);
    config.handshake_timeout = Duration::from_secs(2);
    config.pairing_timeout = Duration::from_secs(2);
    config.shutdown_timeout = Duration::from_secs(5);
    config.max_inflight_connections = 2;
    config
}

struct RunningDaemon {
    handle: rift_daemon::DaemonHandle,
    descriptor: RuntimeDescriptor,
    task: tokio::task::JoinHandle<Result<(), DaemonError>>,
}

impl RunningDaemon {
    async fn start(directory: &TempDir) -> TestResult<Self> {
        let daemon = Daemon::start(test_config(directory)).await?;
        let handle = daemon.handle();
        let descriptor = daemon.runtime_descriptor().clone();
        let task = tokio::spawn(daemon.run_until_shutdown());
        Ok(Self {
            handle,
            descriptor,
            task,
        })
    }

    async fn assert_healthy(&self) -> TestResult {
        let response = self.handle.request(Request::GetStatus {}).await?;
        assert!(matches!(response, rift_ipc::Response::Status { .. }));
        Ok(())
    }

    async fn shutdown(self) -> TestResult {
        self.handle.shutdown().await?;
        self.task.await??;
        Ok(())
    }
}

#[cfg(unix)]
async fn connect(descriptor: &RuntimeDescriptor) -> io::Result<ClientStream> {
    tokio::net::UnixStream::connect(&descriptor.ipc.address).await
}

#[cfg(windows)]
async fn connect(descriptor: &RuntimeDescriptor) -> io::Result<ClientStream> {
    tokio::net::windows::named_pipe::ClientOptions::new().open(&descriptor.ipc.address)
}

async fn authenticate(
    descriptor: &RuntimeDescriptor,
    version: u16,
    token: String,
) -> TestResult<ClientStream> {
    let mut stream = connect(descriptor).await?;
    write_json_frame(&mut stream, &ClientMessage::Authenticate { version, token }).await?;
    Ok(stream)
}

async fn assert_disconnected(mut stream: ClientStream) -> TestResult {
    let result = tokio::time::timeout(
        Duration::from_secs(2),
        read_json_frame::<_, ServerMessage>(&mut stream),
    )
    .await?;
    assert!(result.is_err());
    Ok(())
}

#[tokio::test]
async fn valid_descriptor_token_authenticates_and_serves_status() -> TestResult {
    let directory = TempDir::new()?;
    let running = RunningDaemon::start(&directory).await?;
    let descriptor_bytes = tokio::fs::read(running.handle.runtime_descriptor_path()).await?;
    let descriptor: RuntimeDescriptor = serde_json::from_slice(&descriptor_bytes)?;
    assert_eq!(descriptor, running.descriptor);

    let mut stream = authenticate(
        &descriptor,
        IPC_PROTOCOL_VERSION,
        descriptor.auth_token.clone(),
    )
    .await?;
    assert_eq!(
        read_json_frame::<_, ServerMessage>(&mut stream).await?,
        ServerMessage::Authenticated {
            version: IPC_PROTOCOL_VERSION
        }
    );
    write_json_frame(
        &mut stream,
        &ClientMessage::Request {
            id: 42,
            request: Request::GetStatus {},
        },
    )
    .await?;
    assert!(matches!(
        read_json_frame::<_, ServerMessage>(&mut stream).await?,
        ServerMessage::Response { id: 42, .. }
    ));
    drop(stream);
    running.shutdown().await
}

#[tokio::test]
async fn invalid_auth_and_malformed_clients_are_isolated() -> TestResult {
    tokio::time::timeout(Duration::from_secs(20), async {
        let directory = TempDir::new()?;
        let running = RunningDaemon::start(&directory).await?;

        let wrong_token = "ff".repeat(32);
        let stream = authenticate(&running.descriptor, IPC_PROTOCOL_VERSION, wrong_token).await?;
        assert_disconnected(stream).await?;
        running.assert_healthy().await?;

        let stream = authenticate(
            &running.descriptor,
            IPC_PROTOCOL_VERSION + 1,
            running.descriptor.auth_token.clone(),
        )
        .await?;
        assert_disconnected(stream).await?;
        running.assert_healthy().await?;

        let mut stream = connect(&running.descriptor).await?;
        write_json_frame(
            &mut stream,
            &ClientMessage::Request {
                id: 1,
                request: Request::GetStatus {},
            },
        )
        .await?;
        assert_disconnected(stream).await?;
        running.assert_healthy().await?;

        let mut stream = connect(&running.descriptor).await?;
        let oversized = u32::try_from(MAX_IPC_FRAME_LEN + 1)?;
        stream.write_all(&oversized.to_be_bytes()).await?;
        assert_disconnected(stream).await?;
        running.assert_healthy().await?;

        let mut stream = connect(&running.descriptor).await?;
        stream.write_all(&1_u32.to_be_bytes()).await?;
        stream.write_all(b"{").await?;
        assert_disconnected(stream).await?;
        running.assert_healthy().await?;

        running.shutdown().await?;
        Ok::<_, Box<dyn Error + Send + Sync>>(())
    })
    .await
    .map_err(|_| "invalid IPC client isolation test timed out")??;
    Ok(())
}

#[tokio::test]
async fn shutdown_event_is_flushed_before_authenticated_ipc_closes() -> TestResult {
    let directory = TempDir::new()?;
    let running = RunningDaemon::start(&directory).await?;
    let mut stream = authenticate(
        &running.descriptor,
        IPC_PROTOCOL_VERSION,
        running.descriptor.auth_token.clone(),
    )
    .await?;
    assert!(matches!(
        read_json_frame::<_, ServerMessage>(&mut stream).await?,
        ServerMessage::Authenticated { .. }
    ));

    let wait_for_event = async {
        loop {
            match read_json_frame::<_, ServerMessage>(&mut stream).await? {
                ServerMessage::Event {
                    event: rift_ipc::Event::DaemonShuttingDown,
                } => break Ok::<_, Box<dyn Error + Send + Sync>>(()),
                ServerMessage::Event { .. } => {}
                message => {
                    break Err(io::Error::other(format!(
                        "unexpected shutdown IPC message: {message:?}"
                    ))
                    .into());
                }
            }
        }
    };
    let (event, shutdown) = tokio::join!(wait_for_event, running.handle.shutdown());
    event?;
    shutdown?;
    assert!(
        read_json_frame::<_, ServerMessage>(&mut stream)
            .await
            .is_err()
    );
    running.task.await??;
    assert!(!directory.path().join("runtime.json").exists());
    Ok(())
}

#[tokio::test]
async fn unauthenticated_client_hits_deadline_without_daemon_failure() -> TestResult {
    let directory = TempDir::new()?;
    let running = RunningDaemon::start(&directory).await?;
    let mut stream = connect(&running.descriptor).await?;
    let mut byte = [0_u8; 1];
    let read = tokio::time::timeout(Duration::from_secs(7), stream.read(&mut byte)).await??;
    assert_eq!(read, 0);
    running.assert_healthy().await?;
    running.shutdown().await
}

#[test]
fn oversized_error_variant_remains_typed() {
    let error = FrameError::FrameTooLarge {
        actual: MAX_IPC_FRAME_LEN + 1,
        maximum: MAX_IPC_FRAME_LEN,
    };
    assert!(error.to_string().contains("maximum"));
}
