use anyhow::{Context, Result};
use iroh_relay::server::{Server, testing::server_config};
use tokio::signal;

#[tokio::main]
async fn main() -> Result<()> {
    let server = Server::spawn(server_config())
        .await
        .context("unable to start local Iroh relay")?;
    let relay_url = server
        .https_url()
        .context("local relay did not expose an HTTPS URL")?;
    println!("Relay URL: {relay_url}");
    println!(
        "Pass --relay-url {relay_url} --insecure-relay-tls --relay-only to rift-spike run/send"
    );
    signal::ctrl_c()
        .await
        .context("unable to listen for Ctrl-C")?;
    server
        .shutdown()
        .await
        .context("unable to shut down local Iroh relay")?;
    Ok(())
}
