use std::{io, path::PathBuf};

use anyhow::Context;
use clap::{Parser, ValueEnum};
use rift_daemon::{Daemon, DaemonConfig};
use rift_transport_iroh::RelayConfiguration;
use tracing_subscriber::EnvFilter;

#[derive(Debug, Parser)]
#[command(
    name = "riftd",
    about = "Run the Rift resident daemon in the foreground"
)]
struct Arguments {
    /// Explicit Rift data directory owned by this daemon.
    #[arg(long)]
    data_dir: PathBuf,
    /// Local display name advertised to pairing peers.
    #[arg(long)]
    device_name: String,
    /// Production relay selection.
    #[arg(long, value_enum, default_value_t = RelayArgument::Disabled)]
    relay: RelayArgument,
    /// Tracing filter directive; RUST_LOG is used when omitted.
    #[arg(long)]
    log: Option<String>,
}

#[derive(Clone, Copy, Debug, ValueEnum)]
enum RelayArgument {
    Disabled,
    Default,
    Staging,
}

impl From<RelayArgument> for RelayConfiguration {
    fn from(value: RelayArgument) -> Self {
        match value {
            RelayArgument::Disabled => Self::Disabled,
            RelayArgument::Default => Self::Default,
            RelayArgument::Staging => Self::Staging,
        }
    }
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let arguments = Arguments::parse();
    let filter = match arguments.log {
        Some(filter) => EnvFilter::try_new(filter).context("invalid --log tracing filter")?,
        None => EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")),
    };
    tracing_subscriber::fmt()
        .with_env_filter(filter)
        .try_init()
        .map_err(|error| anyhow::anyhow!("unable to initialize tracing: {error}"))?;

    let mut config = DaemonConfig::new(arguments.data_dir, arguments.device_name);
    config.relay = arguments.relay.into();
    let daemon = Daemon::start(config)
        .await
        .context("daemon startup failed")?;
    let handle = daemon.handle();
    let mut runtime = Box::pin(daemon.run_until_shutdown());

    tokio::select! {
        result = &mut runtime => result.context("daemon runtime failed")?,
        signal = shutdown_signal() => {
            signal.context("unable to install or receive shutdown signal")?;
            let (request, result) = tokio::join!(handle.shutdown(), &mut runtime);
            request.context("daemon rejected shutdown request")?;
            result.context("daemon shutdown failed")?;
        }
    }
    Ok(())
}

#[cfg(unix)]
async fn shutdown_signal() -> io::Result<()> {
    use tokio::signal::unix::{SignalKind, signal};

    let mut terminate = signal(SignalKind::terminate())?;
    tokio::select! {
        result = tokio::signal::ctrl_c() => result,
        received = terminate.recv() => {
            if received.is_some() {
                Ok(())
            } else {
                Err(io::Error::other("SIGTERM signal stream closed"))
            }
        }
    }
}

#[cfg(not(unix))]
async fn shutdown_signal() -> io::Result<()> {
    tokio::signal::ctrl_c().await
}
