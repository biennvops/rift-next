use std::{
    net::{IpAddr, Ipv4Addr, SocketAddr},
    time::Duration,
};

use anyhow::{Context, Result};
use rift_spike::{
    identity::NodeIdentity,
    network::{self, NetworkConfig, RelayModeConfig},
    protocol::{self, Capability, ControlChannel, ControlMessage, LocalHandshake},
    transfer,
};
use tokio::{fs, sync::oneshot, time};

const TEST_TIMEOUT: Duration = Duration::from_secs(15);

#[tokio::test]
async fn two_direct_nodes_handshake_and_stream_a_binary_payload() -> Result<()> {
    time::timeout(TEST_TIMEOUT, async {
        let sender_dir = tempfile::tempdir()?;
        let receiver_dir = tempfile::tempdir()?;
        let sender_identity = NodeIdentity::load_or_create(sender_dir.path())?;
        let receiver_identity = NodeIdentity::load_or_create(receiver_dir.path())?;
        let payload_path = sender_dir.path().join("payload.bin");
        let payload = (0u8..=255)
            .cycle()
            .take(256 * 1024 + 17)
            .collect::<Vec<_>>();
        fs::write(&payload_path, &payload).await?;
        let metadata = transfer::metadata_for_file(&payload_path).await?;
        let receive_dir = receiver_dir.path().join("received");

        let sender = network::bind_endpoint(
            &sender_identity,
            NetworkConfig {
                relay_mode: RelayModeConfig::Disabled,
                relay_only: false,
                relay_url: None,
            },
        )
        .await?;
        let receiver = network::bind_endpoint(
            &receiver_identity,
            NetworkConfig {
                relay_mode: RelayModeConfig::Disabled,
                relay_only: false,
                relay_url: None,
            },
        )
        .await?;
        let receiver_port = receiver
            .bound_sockets()
            .into_iter()
            .find(SocketAddr::is_ipv4)
            .map(|address| address.port())
            .context("receiver did not bind an IPv4 socket")?;
        let receiver_address = iroh::EndpointAddr::from_parts(
            receiver_identity.node_id(),
            [iroh::TransportAddr::Ip(SocketAddr::new(
                IpAddr::V4(Ipv4Addr::LOCALHOST),
                receiver_port,
            ))],
        );
        let (verified_tx, verified_rx) = oneshot::channel();
        let (done_tx, done_rx) = oneshot::channel();
        let receiver_id = receiver_identity.node_id_bytes();
        let receiver_task = tokio::spawn(async move {
            let incoming = receiver
                .accept()
                .await
                .context("receiver endpoint closed before accepting")?;
            let connection = incoming.await.context("receiver connection failed")?;
            let (send, recv) = connection.accept_bi().await?;
            let mut control = ControlChannel { send, recv };
            let peer = protocol::exchange_handshake(
                &mut control,
                &LocalHandshake {
                    node_id: receiver_id,
                    device_name: "receiver".to_owned(),
                    platform: "test".to_owned(),
                    capabilities: vec![Capability::BinaryBlobStream],
                },
                *connection.remote_id().as_bytes(),
            )
            .await?;
            assert_eq!(peer.node_id, *connection.remote_id().as_bytes());
            assert_eq!(peer.device_name, "sender");

            let mut data = connection.accept_uni().await?;
            let result = transfer::receive_file(&mut data, &receive_dir).await?;
            let ack = ControlMessage::TransferAck {
                byte_len: result.byte_len,
                blake3: result.blake3,
            };
            protocol::write_value(&mut control.send, &ack).await?;
            verified_tx
                .send(result.clone())
                .map_err(|_| anyhow::anyhow!("test receiver dropped verification result"))?;
            done_rx
                .await
                .map_err(|_| anyhow::anyhow!("test sender dropped completion signal"))?;
            connection.close(0_u32.into(), b"test complete");
            receiver.close().await;
            Ok::<(), anyhow::Error>(())
        });

        let connection = time::timeout(
            TEST_TIMEOUT,
            network::connect(&sender, receiver_address.clone(), TEST_TIMEOUT),
        )
        .await
        .context("direct test connection timed out")??;
        let (send, recv) = connection.open_bi().await?;
        let mut control = ControlChannel { send, recv };
        let peer = protocol::exchange_handshake(
            &mut control,
            &LocalHandshake {
                node_id: sender_identity.node_id_bytes(),
                device_name: "sender".to_owned(),
                platform: "test".to_owned(),
                capabilities: vec![Capability::BinaryBlobStream],
            },
            *receiver_address.id.as_bytes(),
        )
        .await?;
        assert_eq!(peer.device_name, "receiver");
        assert_eq!(peer.platform, "test");
        assert!(peer.capabilities.contains(&Capability::BinaryBlobStream));

        let mut data = connection.open_uni().await?;
        let sent = transfer::send_file(&mut data, &payload_path, &metadata).await?;
        assert_eq!(sent, payload.len() as u64);
        let ack: ControlMessage =
            time::timeout(TEST_TIMEOUT, protocol::read_value(&mut control.recv))
                .await
                .context("transfer acknowledgement timed out")??;
        assert_eq!(
            ack,
            ControlMessage::TransferAck {
                byte_len: metadata.byte_len,
                blake3: metadata.blake3,
            }
        );
        done_tx
            .send(())
            .map_err(|_| anyhow::anyhow!("receiver dropped completion signal"))?;
        control
            .send
            .finish()
            .map_err(|error| anyhow::anyhow!(error.to_string()))?;
        connection.close(0_u32.into(), b"test complete");
        sender.close().await;

        let received = verified_rx.await?;
        assert_eq!(received.byte_len, payload.len() as u64);
        assert_eq!(received.blake3, metadata.blake3);
        assert_eq!(fs::read(received.output_path).await?, payload);
        let task_result = time::timeout(TEST_TIMEOUT, receiver_task)
            .await
            .context("receiver task did not finish")??;
        task_result?;
        Ok::<(), anyhow::Error>(())
    })
    .await
    .context("direct networking scenario timed out")??;
    Ok(())
}
