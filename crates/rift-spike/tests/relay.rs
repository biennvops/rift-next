use std::time::Duration;

use anyhow::{Context, Result};
use iroh_relay::server::{Server, testing::server_config};
use rift_spike::{
    identity::NodeIdentity,
    network::{self, NetworkConfig, RelayModeConfig},
    protocol::{self, Capability, ControlChannel, LocalHandshake},
};
use tokio::{sync::oneshot, time};

const TEST_TIMEOUT: Duration = Duration::from_secs(15);

#[tokio::test]
async fn relay_only_endpoints_establish_an_authenticated_control_connection() -> Result<()> {
    time::timeout(TEST_TIMEOUT, async {
        let relay = Server::spawn(server_config()).await?;
        let relay_url = relay
            .https_url()
            .context("local relay did not expose an HTTPS URL")?;
        let sender_identity = NodeIdentity::ephemeral();
        let receiver_identity = NodeIdentity::ephemeral();
        let config = |url| NetworkConfig {
            relay_mode: RelayModeConfig::Disabled,
            relay_only: true,
            relay_url: Some(url),
        };
        let sender = network::bind_endpoint(&sender_identity, config(relay_url.clone())).await?;
        let receiver =
            network::bind_endpoint(&receiver_identity, config(relay_url.clone())).await?;
        assert!(network::wait_for_relay(&sender, TEST_TIMEOUT).await);
        assert!(network::wait_for_relay(&receiver, TEST_TIMEOUT).await);
        let receiver_address = receiver.addr();
        assert!(receiver_address.relay_urls().next().is_some());

        let (ready_tx, ready_rx) = oneshot::channel();
        let (done_tx, done_rx) = oneshot::channel();
        let receiver_id = receiver_identity.node_id_bytes();
        let receiver_task = tokio::spawn(async move {
            let incoming = receiver
                .accept()
                .await
                .context("relay receiver endpoint closed before accepting")?;
            let connection = incoming.await.context("relay receiver connection failed")?;
            let (send, recv) = connection.accept_bi().await?;
            let mut control = ControlChannel { send, recv };
            let peer = protocol::exchange_handshake(
                &mut control,
                &LocalHandshake {
                    node_id: receiver_id,
                    device_name: "relay-receiver".to_owned(),
                    platform: "test".to_owned(),
                    capabilities: vec![Capability::BinaryBlobStream],
                },
                *connection.remote_id().as_bytes(),
            )
            .await?;
            assert_eq!(peer.node_id, *connection.remote_id().as_bytes());
            ready_tx
                .send(())
                .map_err(|_| anyhow::anyhow!("relay sender dropped ready signal"))?;
            done_rx
                .await
                .map_err(|_| anyhow::anyhow!("relay sender dropped completion signal"))?;
            connection.close(0_u32.into(), b"relay test complete");
            receiver.close().await;
            Ok::<(), anyhow::Error>(())
        });

        let connection = time::timeout(
            TEST_TIMEOUT,
            network::connect(&sender, receiver_address, TEST_TIMEOUT),
        )
        .await
        .context("relay connection timed out")??;
        assert!(connection.paths().iter().any(|path| path.is_relay()));
        let (send, recv) = connection.open_bi().await?;
        let mut control = ControlChannel { send, recv };
        let peer = protocol::exchange_handshake(
            &mut control,
            &LocalHandshake {
                node_id: sender_identity.node_id_bytes(),
                device_name: "relay-sender".to_owned(),
                platform: "test".to_owned(),
                capabilities: vec![Capability::BinaryBlobStream],
            },
            *connection.remote_id().as_bytes(),
        )
        .await?;
        assert_eq!(peer.device_name, "relay-receiver");
        ready_rx
            .await
            .map_err(|_| anyhow::anyhow!("relay receiver dropped ready signal"))?;
        done_tx
            .send(())
            .map_err(|_| anyhow::anyhow!("relay receiver dropped completion signal"))?;
        control
            .send
            .finish()
            .map_err(|error| anyhow::anyhow!(error.to_string()))?;
        connection.close(0_u32.into(), b"relay test complete");
        sender.close().await;
        let receiver_result = time::timeout(TEST_TIMEOUT, receiver_task)
            .await
            .context("relay receiver task did not finish")??;
        receiver_result?;
        relay.shutdown().await?;
        Ok::<(), anyhow::Error>(())
    })
    .await
    .context("relay networking scenario timed out")??;
    Ok(())
}
