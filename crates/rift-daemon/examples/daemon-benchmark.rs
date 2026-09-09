use std::{
    io,
    time::{Duration, Instant},
};

use rift_core::DeviceId;
use rift_daemon::{Daemon, DaemonConfig};
use rift_identity::IdentityStore;
use rift_ipc::{
    ClientMessage, IPC_PROTOCOL_VERSION, Request, RuntimeDescriptor, ServerMessage,
    read_json_frame, write_json_frame,
};
use rift_trust::TrustStore;

#[cfg(unix)]
type ClientStream = tokio::net::UnixStream;
#[cfg(windows)]
type ClientStream = tokio::net::windows::named_pipe::NamedPipeClient;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let status_iterations = argument(1, 10)?;
    let trust_records = argument(2, 100)?;
    if status_iterations == 0 || trust_records == 0 {
        return Err("benchmark iteration counts must be greater than zero".into());
    }

    let directory = tempfile::tempdir()?;
    let cold_start = Instant::now();
    let daemon = Daemon::start(config(directory.path(), "benchmark-cold")).await?;
    let cold_seconds = cold_start.elapsed().as_secs_f64();
    let descriptor = daemon.runtime_descriptor().clone();
    let handle = daemon.handle();
    let runtime = tokio::spawn(daemon.run_until_shutdown());
    let mut client = authenticated_client(&descriptor).await?;

    let status_start = Instant::now();
    for iteration in 0..status_iterations {
        let id = u64::try_from(iteration)?;
        write_json_frame(
            &mut client,
            &ClientMessage::Request {
                id,
                request: Request::GetStatus {},
            },
        )
        .await?;
        match read_json_frame::<_, ServerMessage>(&mut client).await? {
            ServerMessage::Response {
                id: response_id,
                result: rift_ipc::Response::Status { .. },
            } if response_id == id => {}
            message => {
                return Err(io::Error::other(format!(
                    "IPC GetStatus benchmark received {message:?}"
                ))
                .into());
            }
        }
    }
    let status_seconds = status_start.elapsed().as_secs_f64();
    drop(client);
    handle.shutdown().await?;
    runtime.await??;

    let warm_start = Instant::now();
    let warm = Daemon::start(config(directory.path(), "benchmark-warm")).await?;
    let warm_seconds = warm_start.elapsed().as_secs_f64();
    let warm_handle = warm.handle();
    let warm_runtime = tokio::spawn(warm.run_until_shutdown());
    warm_handle.shutdown().await?;
    warm_runtime.await??;

    let replay_directory = tempfile::tempdir()?;
    IdentityStore::load_or_create(replay_directory.path().join("identity.key"))?;
    let trust = TrustStore::open(replay_directory.path().join("trust.journal")).await?;
    for record in 0..trust_records {
        let mut bytes = [0_u8; 32];
        bytes[..8].copy_from_slice(&u64::try_from(record)?.to_be_bytes());
        trust.revoke(DeviceId::from_bytes(bytes)).await?;
    }
    drop(trust);
    let replay_start = Instant::now();
    let replay = Daemon::start(config(replay_directory.path(), "benchmark-replay")).await?;
    let replay_seconds = replay_start.elapsed().as_secs_f64();
    let replay_handle = replay.handle();
    let replay_runtime = tokio::spawn(replay.run_until_shutdown());
    replay_handle.shutdown().await?;
    replay_runtime.await??;

    println!("production.daemon.cold_start_seconds={cold_seconds:.6}");
    println!("production.daemon.warm_restart_seconds={warm_seconds:.6}");
    println!(
        "production.daemon.ipc_get_status_round_trip_seconds={:.6}",
        status_seconds / status_iterations as f64
    );
    println!("production.daemon.ipc_get_status_iterations={status_iterations}");
    println!("production.daemon.trust_replay_records={trust_records}");
    println!("production.daemon.trust_replay_start_seconds={replay_seconds:.6}");
    Ok(())
}

#[cfg(unix)]
async fn connect(descriptor: &RuntimeDescriptor) -> io::Result<ClientStream> {
    tokio::net::UnixStream::connect(&descriptor.ipc.address).await
}

#[cfg(windows)]
async fn connect(descriptor: &RuntimeDescriptor) -> io::Result<ClientStream> {
    tokio::net::windows::named_pipe::ClientOptions::new().open(&descriptor.ipc.address)
}

async fn authenticated_client(
    descriptor: &RuntimeDescriptor,
) -> Result<ClientStream, Box<dyn std::error::Error + Send + Sync>> {
    let mut client = connect(descriptor).await?;
    write_json_frame(
        &mut client,
        &ClientMessage::Authenticate {
            version: IPC_PROTOCOL_VERSION,
            token: descriptor.auth_token.clone(),
        },
    )
    .await?;
    if !matches!(
        read_json_frame::<_, ServerMessage>(&mut client).await?,
        ServerMessage::Authenticated {
            version: IPC_PROTOCOL_VERSION
        }
    ) {
        return Err("daemon rejected benchmark IPC authentication".into());
    }
    Ok(client)
}

fn argument(
    index: usize,
    default: usize,
) -> Result<usize, Box<dyn std::error::Error + Send + Sync>> {
    match std::env::args().nth(index) {
        Some(value) => value.parse().map_err(Into::into),
        None => Ok(default),
    }
}

fn config(path: &std::path::Path, name: &str) -> DaemonConfig {
    let mut config = DaemonConfig::new(path, name);
    config.bind_addr = Some(std::net::SocketAddr::new(
        std::net::Ipv4Addr::LOCALHOST.into(),
        0,
    ));
    config.connection_timeout = Duration::from_secs(2);
    config.handshake_timeout = Duration::from_secs(2);
    config.max_inflight_connections = 1;
    config
}
