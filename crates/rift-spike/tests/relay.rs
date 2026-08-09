use std::{net::SocketAddr, time::Duration};

use anyhow::{Context, Result};
use iroh_relay::server::{Server, testing::server_config};
use rift_spike::{
    identity::NodeIdentity,
    network::{self, NetworkConfig, RelayModeConfig},
    protocol::{self, Capability, ControlChannel, ControlMessage, LocalHandshake},
};
use tokio::{sync::oneshot, time};

const TEST_TIMEOUT: Duration = Duration::from_secs(15);
const STAGE_TIMEOUT: Duration = Duration::from_secs(4);

fn fault_transport_config() -> iroh::endpoint::QuicTransportConfig {
    iroh::endpoint::QuicTransportConfig::builder()
        .keep_alive_interval(Duration::from_millis(100))
        .default_path_keep_alive_interval(Duration::from_millis(100))
        .default_path_max_idle_timeout(Duration::from_secs(2))
        .build()
}

#[tokio::test]
async fn direct_path_outage_falls_back_to_relay_on_live_connection() -> Result<()> {
    time::timeout(TEST_TIMEOUT, async {
        let relay = Server::spawn(server_config()).await?;
        let relay_url = relay
            .https_url()
            .context("local relay did not expose an HTTPS URL")?;
        let sender_identity = NodeIdentity::ephemeral();
        let receiver_identity = NodeIdentity::ephemeral();
        let config = |url| NetworkConfig {
            relay_mode: RelayModeConfig::Disabled,
            relay_only: false,
            relay_url: Some(url),
            insecure_relay_tls: true,
        };
        let transport_config = fault_transport_config();
        let sender = network::bind_loopback_endpoint_with_transport(
            &sender_identity,
            config(relay_url.clone()),
            Some(transport_config.clone()),
        )
        .await?;
        let receiver = network::bind_loopback_endpoint_with_transport(
            &receiver_identity,
            config(relay_url.clone()),
            Some(transport_config),
        )
        .await?;
        assert!(network::wait_for_relay(&sender, TEST_TIMEOUT).await);
        assert!(network::wait_for_relay(&receiver, TEST_TIMEOUT).await);
        let receiver_socket = receiver
            .bound_sockets()
            .into_iter()
            .find(SocketAddr::is_ipv4)
            .context("receiver did not bind an IPv4 socket")?;
        let proxy = network::UdpFaultInjector::start(receiver_socket).await?;
        let receiver_address = network::peer_with_ip_proxy(&receiver.addr(), proxy.address())?;
        assert!(receiver_address.relay_urls().next().is_some());

        let (ready_tx, ready_rx) = oneshot::channel();
        let (message_tx, message_rx) = oneshot::channel();
        let (done_tx, done_rx) = oneshot::channel();
        let receiver_id = receiver_identity.node_id_bytes();
        let receiver_task = tokio::spawn(async move {
            let incoming = receiver
                .accept()
                .await
                .context("fault-injection receiver endpoint closed before accepting")?;
            let connection = incoming
                .await
                .context("fault-injection receiver connection failed")?;
            let (send, recv) = connection.accept_bi().await?;
            let mut control = ControlChannel { send, recv };
            protocol::exchange_handshake(
                &mut control,
                &LocalHandshake {
                    node_id: receiver_id,
                    device_name: "fault-receiver".to_owned(),
                    platform: "test".to_owned(),
                    capabilities: vec![Capability::BinaryBlobStream],
                },
                *connection.remote_id().as_bytes(),
            )
            .await?;
            network::wait_for_open_path(&connection, true, STAGE_TIMEOUT)
                .await
                .context("relay path was not ready on receiver before direct fault")?;
            ready_tx
                .send(())
                .map_err(|_| anyhow::anyhow!("fault-injection sender dropped ready signal"))?;
            let message: ControlMessage =
                time::timeout(STAGE_TIMEOUT, protocol::read_value(&mut control.recv))
                    .await
                    .context("fault-injection control message timed out")??;
            message_tx
                .send(message)
                .map_err(|_| anyhow::anyhow!("fault-injection sender dropped message result"))?;
            connection.close(0_u32.into(), b"fault-injection complete");
            done_rx
                .await
                .map_err(|_| anyhow::anyhow!("fault-injection sender dropped completion signal"))?;
            Ok::<(), anyhow::Error>(())
        });

        let connection = time::timeout(
            STAGE_TIMEOUT,
            network::connect(&sender, receiver_address, STAGE_TIMEOUT),
        )
        .await
        .context("fault-injection direct connection timed out")??;
        network::wait_for_selected_path(&connection, false, STAGE_TIMEOUT)
            .await
            .context("direct path was not selected")?;
        let (send, recv) = connection.open_bi().await?;
        let mut control = ControlChannel { send, recv };
        time::timeout(
            STAGE_TIMEOUT,
            protocol::exchange_handshake(
                &mut control,
                &LocalHandshake {
                    node_id: sender_identity.node_id_bytes(),
                    device_name: "fault-sender".to_owned(),
                    platform: "test".to_owned(),
                    capabilities: vec![Capability::BinaryBlobStream],
                },
                *connection.remote_id().as_bytes(),
            ),
        )
        .await
        .context("fault-injection sender handshake timed out")??;
        time::timeout(STAGE_TIMEOUT, ready_rx)
            .await
            .context("fault-injection receiver ready signal timed out")?
            .map_err(|_| anyhow::anyhow!("fault-injection receiver dropped ready signal"))?;
        network::wait_for_open_path(&connection, true, STAGE_TIMEOUT)
            .await
            .context("relay path was not ready before direct fault")?;
        proxy.cut();
        sender.network_change().await;
        protocol::write_value(
            &mut control.send,
            &ControlMessage::TransferAck {
                byte_len: 1,
                blake3: [7; 32],
            },
        )
        .await?;
        network::wait_for_selected_path(&connection, true, STAGE_TIMEOUT)
            .await
            .context("relay path was not selected after direct outage")?;
        let message = time::timeout(STAGE_TIMEOUT, message_rx)
            .await
            .context("fault-injection receiver did not observe relay recovery")??;
        assert_eq!(
            message,
            ControlMessage::TransferAck {
                byte_len: 1,
                blake3: [7; 32],
            }
        );
        connection.close(0_u32.into(), b"fault-injection complete");
        drop(control);
        drop(connection);
        sender.close().await;
        done_tx
            .send(())
            .map_err(|_| anyhow::anyhow!("fault-injection receiver dropped completion signal"))?;
        let receiver_result = time::timeout(TEST_TIMEOUT, receiver_task)
            .await
            .context("fault-injection receiver task did not finish")??;
        receiver_result?;
        relay.shutdown().await?;
        Ok::<(), anyhow::Error>(())
    })
    .await
    .context("live direct-path outage scenario timed out")??;
    Ok(())
}

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
            insecure_relay_tls: true,
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
            let message: ControlMessage =
                time::timeout(TEST_TIMEOUT, protocol::read_value(&mut control.recv))
                    .await
                    .context("relay Ping timed out")??;
            let ControlMessage::Ping { nonce } = message else {
                anyhow::bail!("relay receiver expected Ping, received {message:?}");
            };
            protocol::write_value(&mut control.send, &ControlMessage::Pong { nonce }).await?;
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
        protocol::write_value(&mut control.send, &ControlMessage::Ping { nonce: 7 }).await?;
        let response: ControlMessage =
            time::timeout(TEST_TIMEOUT, protocol::read_value(&mut control.recv))
                .await
                .context("relay Pong timed out")??;
        assert_eq!(response, ControlMessage::Pong { nonce: 7 });
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
