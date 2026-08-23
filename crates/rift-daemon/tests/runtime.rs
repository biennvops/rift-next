use std::{error::Error, time::Duration};

use rift_daemon::{Daemon, DaemonConfig, DaemonError};
use rift_ipc::{Request, Response, RuntimeState};
use tempfile::TempDir;

type TestResult<T = ()> = Result<T, Box<dyn Error + Send + Sync>>;

fn test_config(directory: &TempDir, name: &str) -> DaemonConfig {
    let mut config = DaemonConfig::new(directory.path(), name);
    config.bind_addr =
        Some("127.0.0.1:0".parse().unwrap_or_else(|_| {
            std::net::SocketAddr::new(std::net::Ipv4Addr::LOCALHOST.into(), 0)
        }));
    config.connection_timeout = Duration::from_secs(2);
    config.handshake_timeout = Duration::from_secs(2);
    config.pairing_timeout = Duration::from_secs(2);
    config.shutdown_timeout = Duration::from_secs(5);
    config.max_inflight_connections = 4;
    config
}

struct RunningDaemon {
    handle: rift_daemon::DaemonHandle,
    task: tokio::task::JoinHandle<Result<(), DaemonError>>,
}

impl RunningDaemon {
    fn spawn(daemon: Daemon) -> Self {
        let handle = daemon.handle();
        let task = tokio::spawn(daemon.run_until_shutdown());
        Self { handle, task }
    }

    async fn shutdown(self) -> TestResult {
        self.handle.shutdown().await?;
        self.task.await??;
        Ok(())
    }
}

#[tokio::test]
async fn identity_singleton_status_shutdown_and_restart_compose() -> TestResult {
    tokio::time::timeout(Duration::from_secs(20), async {
        let directory = TempDir::new()?;
        let config = test_config(&directory, "daemon-a");
        let daemon = Daemon::start(config.clone()).await?;
        let first_id = daemon.handle().device_id();
        let first_identity = tokio::fs::read(directory.path().join("identity.key")).await?;
        let first_descriptor = tokio::fs::read(directory.path().join("runtime.json")).await?;
        assert!(directory.path().join("runtime.json").exists());
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(
                std::fs::metadata(directory.path())?.permissions().mode() & 0o777,
                0o700
            );
            for path in [
                directory.path().join("identity.key"),
                directory.path().join("runtime.json"),
                directory.path().join("ipc.sock"),
            ] {
                assert_eq!(std::fs::metadata(path)?.permissions().mode() & 0o777, 0o600);
            }
        }

        let second = Daemon::start(config.clone()).await;
        assert!(matches!(second, Err(DaemonError::AlreadyRunning)));
        assert_eq!(
            tokio::fs::read(directory.path().join("identity.key")).await?,
            first_identity
        );
        assert_eq!(
            tokio::fs::read(directory.path().join("runtime.json")).await?,
            first_descriptor
        );

        let running = RunningDaemon::spawn(daemon);
        let Response::Status { status } = running.handle.request(Request::GetStatus {}).await?
        else {
            return Err("GetStatus returned the wrong response type".into());
        };
        assert_eq!(status.device_id, first_id);
        assert_eq!(status.state, RuntimeState::Running);
        assert_eq!(status.active_sessions, 0);
        running.shutdown().await?;
        assert!(!directory.path().join("runtime.json").exists());
        #[cfg(unix)]
        assert!(!directory.path().join("ipc.sock").exists());

        let restarted = Daemon::start(config).await?;
        assert_eq!(restarted.handle().device_id(), first_id);
        assert_eq!(
            tokio::fs::read(directory.path().join("identity.key")).await?,
            first_identity
        );
        RunningDaemon::spawn(restarted).shutdown().await?;
        Ok::<_, Box<dyn Error + Send + Sync>>(())
    })
    .await
    .map_err(|_| "daemon lifecycle test timed out")??;
    Ok(())
}

#[cfg(unix)]
#[tokio::test]
async fn overlong_unix_socket_path_is_typed_and_not_published() -> TestResult {
    let parent = TempDir::new()?;
    let data_dir = parent.path().join("x".repeat(120));
    let mut config = DaemonConfig::new(&data_dir, "long-path");
    config.bind_addr =
        Some("127.0.0.1:0".parse().unwrap_or_else(|_| {
            std::net::SocketAddr::new(std::net::Ipv4Addr::LOCALHOST.into(), 0)
        }));
    let result = Daemon::start(config).await;
    assert!(matches!(result, Err(DaemonError::IpcAddressTooLong { .. })));
    assert!(!data_dir.join("runtime.json").exists());
    assert!(!data_dir.join("ipc.sock").exists());
    Ok(())
}

#[tokio::test]
async fn corrupt_identity_fails_startup_without_replacement() -> TestResult {
    let directory = TempDir::new()?;
    let config = test_config(&directory, "daemon-a");
    let daemon = Daemon::start(config.clone()).await?;
    RunningDaemon::spawn(daemon).shutdown().await?;
    let path = directory.path().join("identity.key");
    let mut corrupt = tokio::fs::read(&path).await?;
    let last = corrupt
        .last_mut()
        .ok_or_else(|| std::io::Error::other("identity file was empty"))?;
    *last ^= 1;
    tokio::fs::write(&path, &corrupt).await?;

    let result = Daemon::start(config).await;
    assert!(matches!(
        result,
        Err(DaemonError::Identity(
            rift_identity::IdentityError::ChecksumMismatch
        ))
    ));
    assert_eq!(tokio::fs::read(path).await?, corrupt);
    Ok(())
}

#[tokio::test]
async fn existing_trust_without_identity_fails_without_regeneration() -> TestResult {
    let directory = TempDir::new()?;
    let config = test_config(&directory, "daemon-a");
    let daemon = Daemon::start(config.clone()).await?;
    RunningDaemon::spawn(daemon).shutdown().await?;
    tokio::fs::remove_file(directory.path().join("identity.key")).await?;

    let result = Daemon::start(config).await;
    assert!(matches!(
        result,
        Err(DaemonError::IdentityMissingWithExistingState)
    ));
    assert!(!directory.path().join("identity.key").exists());
    Ok(())
}
