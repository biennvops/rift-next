use std::time::{Duration, Instant};

use rift_core::DeviceId;
use rift_daemon::{Daemon, DaemonConfig};
use rift_identity::IdentityStore;
use rift_ipc::Request;
use rift_trust::TrustStore;

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
    let handle = daemon.handle();
    let runtime = tokio::spawn(daemon.run_until_shutdown());

    let status_start = Instant::now();
    for _ in 0..status_iterations {
        let response = handle.request(Request::GetStatus {}).await?;
        if !matches!(response, rift_ipc::Response::Status { .. }) {
            return Err("GetStatus benchmark received the wrong response".into());
        }
    }
    let status_seconds = status_start.elapsed().as_secs_f64();
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
        "production.daemon.get_status_round_trip_seconds={:.6}",
        status_seconds / status_iterations as f64
    );
    println!("production.daemon.get_status_iterations={status_iterations}");
    println!("production.daemon.trust_replay_records={trust_records}");
    println!("production.daemon.trust_replay_start_seconds={replay_seconds:.6}");
    Ok(())
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
