use std::{error::Error, time::Duration};

use rift_core::{DEVICE_ID_LEN, DeviceId};
use rift_protocol::{
    ControlMessage, HandshakeError, Hello, HelloMetadata, MAX_CONTROL_FRAME_LEN, MessageKind,
    PAIRING_COMMITMENT_LEN, PAIRING_ID_LEN, PAIRING_NONCE_LEN, PROTOCOL_VERSION, PairingCommitment,
    PairingMessage, encode_message, exchange_hello_with_timeout, read_message, write_message,
};
use rift_transport_iroh::{
    AuthenticatedConnection, BootstrappedConnection, ControlStream, EndpointConfig, RiftEndpoint,
    SecretKey, TransportError,
};

type TestResult<T = ()> = Result<T, Box<dyn Error + Send + Sync>>;

const TEST_CONNECTION_TIMEOUT: Duration = Duration::from_secs(2);
const TEST_HANDSHAKE_TIMEOUT: Duration = Duration::from_millis(150);

fn test_config() -> EndpointConfig {
    EndpointConfig {
        connection_timeout: TEST_CONNECTION_TIMEOUT,
        handshake_timeout: TEST_HANDSHAKE_TIMEOUT,
        ..EndpointConfig::direct()
    }
}

fn metadata(name: &str, platform: &str) -> HelloMetadata {
    HelloMetadata {
        device_name: name.to_owned(),
        platform: platform.to_owned(),
        capabilities: Vec::new(),
    }
}

fn device_id(byte: u8) -> DeviceId {
    DeviceId::from_bytes([byte; DEVICE_ID_LEN])
}

async fn bind_pair() -> TestResult<(RiftEndpoint, RiftEndpoint)> {
    let first = RiftEndpoint::bind(SecretKey::generate(), test_config()).await?;
    let second = RiftEndpoint::bind(SecretKey::generate(), test_config()).await?;
    Ok((first, second))
}

async fn assert_failed_bootstrap(
    client: &RiftEndpoint,
    server: &RiftEndpoint,
    message: ControlMessage,
) -> TestResult<TransportError> {
    let server_task = tokio::spawn({
        let server = server.clone();
        async move {
            server
                .accept_and_bootstrap(metadata("server", "test"))
                .await
        }
    });

    let connection = client.connect(server.local_addr()).await?;
    let mut control = connection.open_control().await?;
    write_message(&mut control.send, &message).await?;
    let server_result = server_task.await?;
    connection.close();
    let error = server_result
        .err()
        .ok_or("the malformed bootstrap unexpectedly succeeded")?;
    Ok(error)
}

async fn close_pair(first: &RiftEndpoint, second: &RiftEndpoint) {
    first.close().await;
    second.close().await;
}

#[tokio::test]
async fn production_endpoints_bootstrap_authenticate_and_use_ping_pong() -> TestResult {
    let (endpoint_a, endpoint_b) = bind_pair().await?;
    let accept_task = tokio::spawn({
        let endpoint_b = endpoint_b.clone();
        async move {
            endpoint_b
                .accept_and_bootstrap(metadata("laptop", "linux-x86_64"))
                .await
        }
    });

    let mut connection_a = endpoint_a
        .connect_and_bootstrap(endpoint_b.local_addr(), metadata("phone", "android-arm64"))
        .await?;
    let mut connection_b = accept_task.await??;

    assert_eq!(connection_a.local_device_id(), endpoint_a.device_id());
    assert_eq!(connection_b.local_device_id(), endpoint_b.device_id());
    assert_eq!(connection_a.remote_device_id(), endpoint_b.device_id());
    assert_eq!(connection_b.remote_device_id(), endpoint_a.device_id());
    assert_eq!(connection_a.peer_hello().device_name, "laptop");
    assert_eq!(connection_a.peer_hello().platform, "linux-x86_64");
    assert!(connection_a.peer_hello().capabilities.is_empty());
    assert_eq!(connection_b.peer_hello().device_name, "phone");
    assert_eq!(connection_b.peer_hello().platform, "android-arm64");

    let responder = tokio::spawn(async move {
        let nonce = connection_b.respond_to_ping().await?;
        Ok::<(BootstrappedConnection, u64), TransportError>((connection_b, nonce))
    });
    connection_a.ping(0xfeed_beef).await?;
    let (connection_b, nonce) = responder.await??;
    assert_eq!(nonce, 0xfeed_beef);

    connection_a.close();
    connection_b.close();
    close_pair(&endpoint_a, &endpoint_b).await;
    Ok(())
}

#[tokio::test]
async fn identity_spoof_is_rejected_against_authenticated_iroh_identity() -> TestResult {
    let (client, server) = bind_pair().await?;
    let spoofed_hello = ControlMessage::Hello(Hello {
        protocol_version: PROTOCOL_VERSION,
        device_id: server.device_id(),
        device_name: "spoof".to_owned(),
        platform: "test".to_owned(),
        capabilities: Vec::new(),
    });
    let error = assert_failed_bootstrap(&client, &server, spoofed_hello).await?;
    assert!(matches!(
        error,
        TransportError::Handshake(HandshakeError::IdentityMismatch {
            authenticated,
            hello
        }) if authenticated == client.device_id() && hello == server.device_id()
    ));
    close_pair(&client, &server).await;
    Ok(())
}

#[tokio::test]
async fn unsupported_version_is_rejected_without_downgrade() -> TestResult {
    let (client, server) = bind_pair().await?;
    let error = assert_failed_bootstrap(
        &client,
        &server,
        ControlMessage::Hello(Hello {
            protocol_version: 2,
            device_id: client.device_id(),
            device_name: "client".to_owned(),
            platform: "test".to_owned(),
            capabilities: Vec::new(),
        }),
    )
    .await?;
    assert!(matches!(
        error,
        TransportError::Handshake(HandshakeError::UnsupportedProtocolVersion(2))
    ));
    close_pair(&client, &server).await;
    Ok(())
}

#[tokio::test]
async fn oversized_frame_is_rejected_before_payload_read() -> TestResult {
    let (client, server) = bind_pair().await?;
    let server_task = tokio::spawn({
        let server = server.clone();
        async move {
            server
                .accept_and_bootstrap(metadata("server", "test"))
                .await
        }
    });
    let connection = client.connect(server.local_addr()).await?;
    let mut control = connection.open_control().await?;
    control
        .send
        .write_all(&(MAX_CONTROL_FRAME_LEN as u32 + 1).to_be_bytes())
        .await?;
    let error = server_task
        .await?
        .err()
        .ok_or("the oversized bootstrap unexpectedly succeeded")?;
    assert!(matches!(
        error,
        TransportError::Handshake(HandshakeError::Frame(
            rift_protocol::FrameError::FrameTooLarge { actual, maximum }
        )) if actual == MAX_CONTROL_FRAME_LEN + 1 && maximum == MAX_CONTROL_FRAME_LEN
    ));
    connection.close();
    close_pair(&client, &server).await;
    Ok(())
}

#[tokio::test]
async fn truncated_hello_is_reported_as_truncated_payload() -> TestResult {
    let (client, server) = bind_pair().await?;
    let server_task = tokio::spawn({
        let server = server.clone();
        async move {
            server
                .accept_and_bootstrap(metadata("server", "test"))
                .await
        }
    });
    let connection = client.connect(server.local_addr()).await?;
    {
        let mut control = connection.open_control().await?;
        control.send.write_all(&[0, 0, 0, 3, 1]).await?;
        let _server_hello = read_message(&mut control.recv).await?;
        assert!(control.send.finish().is_ok());
    }
    let error = server_task
        .await?
        .err()
        .ok_or("the truncated bootstrap unexpectedly succeeded")?;
    assert!(matches!(
        error,
        TransportError::Handshake(HandshakeError::Frame(
            rift_protocol::FrameError::TruncatedPayload(_)
        ))
    ));
    connection.close();
    close_pair(&client, &server).await;
    Ok(())
}

#[tokio::test]
async fn silent_peer_hits_a_bounded_control_stream_deadline() -> TestResult {
    let (client, server) = bind_pair().await?;
    let server_task = tokio::spawn({
        let server = server.clone();
        async move {
            server
                .accept_and_bootstrap(metadata("server", "test"))
                .await
        }
    });
    let connection = client.connect(server.local_addr()).await?;
    let _control = connection.open_control().await?;
    let error = server_task
        .await?
        .err()
        .ok_or("the silent bootstrap unexpectedly succeeded")?;
    assert!(matches!(error, TransportError::ControlStreamAcceptTimeout));
    connection.close();
    close_pair(&client, &server).await;
    Ok(())
}

#[tokio::test]
async fn unexpected_first_message_is_rejected_deterministically() -> TestResult {
    let (client, server) = bind_pair().await?;
    let error =
        assert_failed_bootstrap(&client, &server, ControlMessage::Ping { nonce: 9 }).await?;
    assert!(matches!(
        error,
        TransportError::Handshake(HandshakeError::UnexpectedMessage {
            expected: MessageKind::Hello,
            received: MessageKind::Ping
        })
    ));
    close_pair(&client, &server).await;
    Ok(())
}

#[tokio::test]
async fn failed_bootstrap_does_not_poison_endpoint_identity_or_future_connections() -> TestResult {
    let (client, server) = bind_pair().await?;
    let error =
        assert_failed_bootstrap(&client, &server, ControlMessage::Ping { nonce: 11 }).await?;
    assert!(matches!(
        error,
        TransportError::Handshake(HandshakeError::UnexpectedMessage { .. })
    ));

    let accept_task = tokio::spawn({
        let server = server.clone();
        async move {
            server
                .accept_and_bootstrap(metadata("server", "test"))
                .await
        }
    });
    let mut client_connection = client
        .connect_and_bootstrap(server.local_addr(), metadata("client", "test"))
        .await?;
    let mut server_connection = accept_task.await??;
    assert_eq!(server.device_id(), client_connection.remote_device_id());
    assert_eq!(client.device_id(), server_connection.remote_device_id());

    let responder = tokio::spawn(async move {
        let nonce = server_connection.respond_to_ping().await?;
        Ok::<(BootstrappedConnection, u64), TransportError>((server_connection, nonce))
    });
    client_connection.ping(12).await?;
    let (server_connection, nonce) = responder.await??;
    assert_eq!(nonce, 12);

    client_connection.close();
    server_connection.close();
    close_pair(&client, &server).await;
    Ok(())
}

async fn bootstrap_client_with_manual_server() -> TestResult<(
    RiftEndpoint,
    RiftEndpoint,
    BootstrappedConnection,
    AuthenticatedConnection,
    ControlStream,
)> {
    let (client, server) = bind_pair().await?;
    let server_task = tokio::spawn({
        let server = server.clone();
        async move {
            let connection = server.accept().await?;
            let remote_device_id = connection.remote_device_id();
            let mut control = connection.accept_control().await?;
            exchange_hello_with_timeout(
                &mut control,
                server.device_id(),
                &metadata("server", "test"),
                remote_device_id,
                TEST_HANDSHAKE_TIMEOUT,
            )
            .await?;
            Ok::<_, TransportError>((connection, control))
        }
    });
    let client_connection = client
        .connect_and_bootstrap(server.local_addr(), metadata("client", "test"))
        .await?;
    let (server_connection, control) = server_task.await??;
    Ok((
        client,
        server,
        client_connection,
        server_connection,
        control,
    ))
}

#[tokio::test]
async fn partial_pong_timeout_poisoned_connection_cannot_be_reused() -> TestResult {
    let (client, server, mut client_connection, server_connection, mut server_control) =
        bootstrap_client_with_manual_server().await?;
    let pong = encode_message(&ControlMessage::Pong { nonce: 1 })?;
    let ping_task = tokio::spawn(async move {
        let ping = read_message(&mut server_control.recv).await?;
        assert_eq!(ping, ControlMessage::Ping { nonce: 1 });
        server_control
            .send
            .write_all(&pong[..pong.len() - 1])
            .await?;
        tokio::time::sleep(TEST_HANDSHAKE_TIMEOUT + Duration::from_millis(25)).await;
        Ok::<_, Box<dyn Error + Send + Sync>>(server_control)
    });

    assert!(matches!(
        client_connection.ping(1).await,
        Err(TransportError::ControlTimeout)
    ));
    assert!(matches!(
        client_connection.ping(2).await,
        Err(TransportError::ControlConnectionPoisoned)
    ));

    client_connection.close();
    drop(ping_task.await??);
    server_connection.close();
    close_pair(&client, &server).await;
    Ok(())
}

#[tokio::test]
async fn sequencing_error_poisoned_connection_cannot_be_reused() -> TestResult {
    let (client, server, mut client_connection, server_connection, mut server_control) =
        bootstrap_client_with_manual_server().await?;
    write_message(&mut server_control.send, &ControlMessage::Pong { nonce: 9 }).await?;

    assert!(matches!(
        client_connection.respond_to_ping().await,
        Err(TransportError::Control(
            rift_protocol::ControlError::UnexpectedMessage {
                expected: MessageKind::Ping,
                received: MessageKind::Pong
            }
        ))
    ));
    assert!(matches!(
        client_connection.respond_to_ping().await,
        Err(TransportError::ControlConnectionPoisoned)
    ));

    client_connection.close();
    server_connection.close();
    close_pair(&client, &server).await;
    Ok(())
}

#[tokio::test]
async fn pairing_only_transport_exchanges_typed_messages() -> TestResult {
    let (client, server) = bind_pair().await?;
    let server_task = tokio::spawn({
        let server = server.clone();
        async move {
            server
                .accept_and_bootstrap(metadata("server", "test"))
                .await
        }
    });
    let mut client_connection = client
        .connect_and_bootstrap(server.local_addr(), metadata("client", "test"))
        .await?;
    let mut server_connection = server_task.await??;
    let pairing_id = [7; PAIRING_ID_LEN];
    let request = PairingMessage::Request {
        pairing_id,
        commitment: PairingCommitment::from_bytes([8; PAIRING_COMMITMENT_LEN]),
    };
    client_connection
        .send_pairing(request.clone(), TEST_HANDSHAKE_TIMEOUT)
        .await?;
    assert_eq!(
        server_connection
            .receive_pairing(TEST_HANDSHAKE_TIMEOUT)
            .await?,
        request
    );
    let response = PairingMessage::Response {
        pairing_id,
        commitment: PairingCommitment::from_bytes([9; PAIRING_COMMITMENT_LEN]),
    };
    server_connection
        .send_pairing(response.clone(), TEST_HANDSHAKE_TIMEOUT)
        .await?;
    assert_eq!(
        client_connection
            .receive_pairing(TEST_HANDSHAKE_TIMEOUT)
            .await?,
        response
    );
    let reveal = PairingMessage::Reveal {
        pairing_id,
        nonce: [10; PAIRING_NONCE_LEN],
    };
    client_connection
        .send_pairing(reveal.clone(), TEST_HANDSHAKE_TIMEOUT)
        .await?;
    assert_eq!(
        server_connection
            .receive_pairing(TEST_HANDSHAKE_TIMEOUT)
            .await?,
        reveal
    );

    client_connection.close();
    server_connection.close();
    close_pair(&client, &server).await;
    Ok(())
}

#[tokio::test]
async fn general_control_message_poisoned_pairing_only_connection() -> TestResult {
    let (client, server, mut client_connection, server_connection, mut server_control) =
        bootstrap_client_with_manual_server().await?;
    write_message(
        &mut server_control.send,
        &ControlMessage::Ping { nonce: 17 },
    )
    .await?;

    assert!(matches!(
        client_connection
            .receive_pairing(TEST_HANDSHAKE_TIMEOUT)
            .await,
        Err(TransportError::UnexpectedPairingMessage {
            received: MessageKind::Ping
        })
    ));
    assert!(matches!(
        client_connection
            .receive_pairing(TEST_HANDSHAKE_TIMEOUT)
            .await,
        Err(TransportError::ControlConnectionPoisoned)
    ));

    client_connection.close();
    server_connection.close();
    close_pair(&client, &server).await;
    Ok(())
}

#[tokio::test]
async fn pairing_receive_timeout_poisoned_connection() -> TestResult {
    let (client, server, mut client_connection, server_connection, _server_control) =
        bootstrap_client_with_manual_server().await?;

    assert!(matches!(
        client_connection
            .receive_pairing(Duration::from_millis(20))
            .await,
        Err(TransportError::ControlTimeout)
    ));
    assert!(matches!(
        client_connection
            .receive_pairing(TEST_HANDSHAKE_TIMEOUT)
            .await,
        Err(TransportError::ControlConnectionPoisoned)
    ));

    client_connection.close();
    server_connection.close();
    close_pair(&client, &server).await;
    Ok(())
}

#[test]
fn test_device_id_helper_uses_exactly_32_public_bytes() {
    assert_eq!(device_id(7).as_bytes(), &[7_u8; DEVICE_ID_LEN]);
}
