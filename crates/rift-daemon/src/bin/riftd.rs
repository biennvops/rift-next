use std::{io, path::PathBuf};

use anyhow::Context;
use clap::{Parser, ValueEnum};
use rift_daemon::{Daemon, DaemonConfig};
use rift_transport_iroh::{AddressLookupConfiguration, RelayConfiguration};
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
    /// Explicit reachability publication/lookup through Number 0 infrastructure.
    #[arg(long, value_enum, default_value_t = LookupArgument::Disabled)]
    address_lookup: LookupArgument,
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

#[derive(Clone, Copy, Debug, ValueEnum)]
enum LookupArgument {
    Disabled,
    N0,
}

impl From<LookupArgument> for AddressLookupConfiguration {
    fn from(value: LookupArgument) -> Self {
        match value {
            LookupArgument::Disabled => Self::Disabled,
            LookupArgument::N0 => Self::N0,
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
    config.address_lookup = arguments.address_lookup.into();
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn address_lookup_is_explicit_and_independent_from_relay_arguments() -> anyhow::Result<()> {
        let defaults =
            Arguments::try_parse_from(["riftd", "--data-dir", "unused", "--device-name", "test"])?;
        assert!(matches!(defaults.address_lookup, LookupArgument::Disabled));
        assert!(matches!(defaults.relay, RelayArgument::Disabled));
        let n0 = Arguments::try_parse_from([
            "riftd",
            "--data-dir",
            "unused",
            "--device-name",
            "test",
            "--address-lookup",
            "n0",
        ])?;
        assert!(matches!(
            AddressLookupConfiguration::from(n0.address_lookup),
            AddressLookupConfiguration::N0
        ));
        assert!(matches!(
            RelayConfiguration::from(n0.relay),
            RelayConfiguration::Disabled
        ));
        assert!(
            Arguments::try_parse_from([
                "riftd",
                "--data-dir",
                "unused",
                "--device-name",
                "test",
                "--address-lookup",
                "implicit"
            ])
            .is_err()
        );
        Ok(())
    }
}
