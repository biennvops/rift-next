use std::{error::Error, sync::Arc, time::Duration};

use rift_core::{TrustState, TrustedPeer};
use rift_protocol::{HelloMetadata, PAIRING_ID_LEN, PAIRING_NONCE_LEN, PairingMessage};
use rift_session::{
    InitiatorPairingMaterial, PairingError, PairingPhase, ResponderPairingMaterial,
    SessionAdmission, SessionConfig, SessionError, SessionManager, pairing_metadata,
};
use rift_transport_iroh::{BootstrappedConnection, EndpointConfig, RiftEndpoint, SecretKey};
use rift_trust::TrustStore;
use tempfile::TempDir;

const CONNECTION_TIMEOUT: Duration = Duration::from_secs(2);
const CONTROL_TIMEOUT: Duration = Duration::from_millis(250);
const PAIRING_TIMEOUT: Duration = Duration::from_millis(200);

type TestResult<T = ()> = Result<T, Box<dyn Error + Send + Sync>>;

fn config() -> EndpointConfig {
    EndpointConfig {
        connection_timeout: CONNECTION_TIMEOUT,
        handshake_timeout: CONTROL_TIMEOUT,
        ..EndpointConfig::direct()
    }
}

async fn bind_pair() -> TestResult<(RiftEndpoint, RiftEndpoint)> {
    bind_pair_with_keys(SecretKey::generate(), SecretKey::generate()).await
}

async fn bind_pair_with_keys(
    first: SecretKey,
    second: SecretKey,
) -> TestResult<(RiftEndpoint, RiftEndpoint)> {
    let first = RiftEndpoint::bind(first, config()).await?;
    let second = RiftEndpoint::bind(second, config()).await?;
    Ok((first, second))
}

async fn store(directory: &TempDir, name: &str) -> TestResult<Arc<TrustStore>> {
    Ok(Arc::new(
        TrustStore::open(directory.path().join(name)).await?,
    ))
}

fn manager(store: Arc<TrustStore>) -> TestResult<SessionManager> {
    Ok(SessionManager::with_config(
        store,
        SessionConfig {
            pairing_timeout: PAIRING_TIMEOUT,
        },
    )?)
}

async fn bootstrap_pair(
    endpoint_a: &RiftEndpoint,
    endpoint_b: &RiftEndpoint,
) -> TestResult<(BootstrappedConnection, BootstrappedConnection)> {
    bootstrap_pair_with_metadata(
        endpoint_a,
        endpoint_b,
        pairing_metadata("device-a", "test")?,
        pairing_metadata("device-b", "test")?,
    )
    .await
}

async fn bootstrap_pair_with_metadata(
    endpoint_a: &RiftEndpoint,
    endpoint_b: &RiftEndpoint,
    metadata_a: HelloMetadata,
    metadata_b: HelloMetadata,
) -> TestResult<(BootstrappedConnection, BootstrappedConnection)> {
    let accept = tokio::spawn({
        let endpoint_b = endpoint_b.clone();
        async move {
            let connection = endpoint_b.accept_and_bootstrap(metadata_b).await?;
            Ok::<_, Box<dyn Error + Send + Sync>>(connection)
        }
    });
    let connection_a = endpoint_a
        .connect_and_bootstrap(endpoint_b.local_addr(), metadata_a)
        .await?;
    let connection_b = accept.await??;
    Ok((connection_a, connection_b))
}

async fn pairable_pair(
    manager_a: &SessionManager,
    manager_b: &SessionManager,
    endpoint_a: &RiftEndpoint,
    endpoint_b: &RiftEndpoint,
) -> TestResult<(
    rift_session::PairableConnection,
    rift_session::PairableConnection,
)> {
    let (connection_a, connection_b) = bootstrap_pair(endpoint_a, endpoint_b).await?;
    let SessionAdmission::Pairable(pairable_a) = manager_a.admit(connection_a).await? else {
        return Err("peer A unexpectedly authorized before pairing".into());
    };
    let SessionAdmission::Pairable(pairable_b) = manager_b.admit(connection_b).await? else {
        return Err("peer B unexpectedly authorized before pairing".into());
    };
    Ok((pairable_a, pairable_b))
}

async fn pending_pair(
    pairable_a: rift_session::PairableConnection,
    pairable_b: rift_session::PairableConnection,
) -> TestResult<(rift_session::PendingPairing, rift_session::PendingPairing)> {
    let responder = tokio::spawn(async move {
        pairable_b
            .respond_to_pairing_with_material_for_test(
                ResponderPairingMaterial::from_bytes_for_test([3; PAIRING_NONCE_LEN]),
            )
            .await
    });
    let pending_a = pairable_a
        .initiate_pairing_with_material_for_test(InitiatorPairingMaterial::from_bytes_for_test(
            [1; PAIRING_ID_LEN],
            [2; PAIRING_NONCE_LEN],
        ))
        .await?;
    let pending_b = responder.await??;
    Ok((pending_a, pending_b))
}

async fn close_endpoints(first: &RiftEndpoint, second: &RiftEndpoint) {
    first.close().await;
    second.close().await;
}

#[tokio::test]
async fn unknown_authenticated_peers_are_pairable_not_authorized() -> TestResult {
    let directory = TempDir::new()?;
    let store_a = store(&directory, "a.trust").await?;
    let store_b = store(&directory, "b.trust").await?;
    let manager_a = manager(store_a)?;
    let manager_b = manager(store_b)?;
    let (endpoint_a, endpoint_b) = bind_pair().await?;
    let (pairable_a, pairable_b) =
        pairable_pair(&manager_a, &manager_b, &endpoint_a, &endpoint_b).await?;

    assert_eq!(pairable_a.remote_device_id(), endpoint_b.device_id());
    assert_eq!(pairable_b.remote_device_id(), endpoint_a.device_id());
    assert!(pairable_a.supports_pairing());
    assert!(pairable_b.supports_pairing());
    assert_eq!(pairable_a.peer_hello().device_name, "device-b");
    assert_eq!(pairable_b.peer_hello().device_name, "device-a");

    pairable_a.close();
    pairable_b.close();
    close_endpoints(&endpoint_a, &endpoint_b).await;
    Ok(())
}

#[tokio::test]
async fn successful_pairing_requires_local_confirmation_and_authorizes_both() -> TestResult {
    let directory = TempDir::new()?;
    let store_a = store(&directory, "a.trust").await?;
    let store_b = store(&directory, "b.trust").await?;
    let manager_a = manager(store_a.clone())?;
    let manager_b = manager(store_b.clone())?;
    let (endpoint_a, endpoint_b) = bind_pair().await?;
    let (pairable_a, pairable_b) =
        pairable_pair(&manager_a, &manager_b, &endpoint_a, &endpoint_b).await?;
    let (pending_a, pending_b) = pending_pair(pairable_a, pairable_b).await?;

    assert_eq!(pending_a.verification_code(), pending_b.verification_code());
    assert_eq!(pending_a.verification_code().to_string().len(), 6);
    assert_eq!(pending_a.peer().device_name, "device-b");
    assert_eq!(pending_b.peer().device_name, "device-a");
    assert_eq!(pending_a.phase(), PairingPhase::AwaitingLocalDecision);
    assert_eq!(store_a.state(endpoint_b.device_id()).await, None);
    assert_eq!(store_b.state(endpoint_a.device_id()).await, None);

    let (authorized_a, authorized_b) =
        tokio::try_join!(pending_a.confirm(true), pending_b.confirm(true))?;
    assert_eq!(authorized_a.remote_device_id(), endpoint_b.device_id());
    assert_eq!(authorized_b.remote_device_id(), endpoint_a.device_id());
    assert_eq!(
        store_a.state(endpoint_b.device_id()).await,
        Some(TrustState::Trusted)
    );
    assert_eq!(
        store_b.state(endpoint_a.device_id()).await,
        Some(TrustState::Trusted)
    );

    authorized_a.close();
    authorized_b.close();
    close_endpoints(&endpoint_a, &endpoint_b).await;
    Ok(())
}

#[tokio::test]
async fn dropping_pending_pairing_cannot_create_trust_from_remote_messages() -> TestResult {
    let directory = TempDir::new()?;
    let store_a = store(&directory, "a.trust").await?;
    let store_b = store(&directory, "b.trust").await?;
    let manager_a = manager(store_a.clone())?;
    let manager_b = manager(store_b.clone())?;
    let (endpoint_a, endpoint_b) = bind_pair().await?;
    let (pairable_a, pairable_b) =
        pairable_pair(&manager_a, &manager_b, &endpoint_a, &endpoint_b).await?;
    let (pending_a, pending_b) = pending_pair(pairable_a, pairable_b).await?;

    let remote_confirmation = tokio::spawn(async move { pending_b.confirm(true).await });
    drop(pending_a);
    assert!(remote_confirmation.await?.is_err());
    assert_eq!(store_a.state(endpoint_b.device_id()).await, None);
    assert_eq!(store_b.state(endpoint_a.device_id()).await, None);
    close_endpoints(&endpoint_a, &endpoint_b).await;
    Ok(())
}

#[tokio::test]
async fn revocation_during_confirmation_blocks_pairing_commit() -> TestResult {
    let directory = TempDir::new()?;
    let store_a = store(&directory, "a.trust").await?;
    let store_b = store(&directory, "b.trust").await?;
    let manager_a = manager(store_a.clone())?;
    let manager_b = manager(store_b.clone())?;
    let (endpoint_a, endpoint_b) = bind_pair().await?;
    let (pairable_a, pairable_b) =
        pairable_pair(&manager_a, &manager_b, &endpoint_a, &endpoint_b).await?;
    let (pending_a, pending_b) = pending_pair(pairable_a, pairable_b).await?;
    store_a.revoke(endpoint_b.device_id()).await?;

    let (result_a, result_b) = tokio::join!(pending_a.confirm(true), pending_b.confirm(true));
    assert!(matches!(result_a, Err(PairingError::Trust(_))));
    assert!(result_b.is_err());
    assert_eq!(
        store_a.state(endpoint_b.device_id()).await,
        Some(TrustState::Revoked)
    );
    assert_eq!(
        store_b.state(endpoint_a.device_id()).await,
        Some(TrustState::Trusted)
    );
    close_endpoints(&endpoint_a, &endpoint_b).await;
    Ok(())
}

#[tokio::test]
async fn one_sided_local_rejection_creates_no_trust() -> TestResult {
    let directory = TempDir::new()?;
    let store_a = store(&directory, "a.trust").await?;
    let store_b = store(&directory, "b.trust").await?;
    let manager_a = manager(store_a.clone())?;
    let manager_b = manager(store_b.clone())?;
    let (endpoint_a, endpoint_b) = bind_pair().await?;
    let (pairable_a, pairable_b) =
        pairable_pair(&manager_a, &manager_b, &endpoint_a, &endpoint_b).await?;
    let (pending_a, pending_b) = pending_pair(pairable_a, pairable_b).await?;

    let (result_a, result_b) = tokio::join!(pending_a.confirm(true), pending_b.confirm(false));
    assert!(matches!(result_a, Err(PairingError::Rejected { .. })));
    assert!(matches!(result_b, Err(PairingError::Rejected { .. })));
    assert_eq!(store_a.state(endpoint_b.device_id()).await, None);
    assert_eq!(store_b.state(endpoint_a.device_id()).await, None);

    close_endpoints(&endpoint_a, &endpoint_b).await;
    Ok(())
}

#[tokio::test]
async fn silent_pairing_peer_times_out_without_trust() -> TestResult {
    let directory = TempDir::new()?;
    let store_a = store(&directory, "a.trust").await?;
    let store_b = store(&directory, "b.trust").await?;
    let manager_a = manager(store_a.clone())?;
    let manager_b = manager(store_b.clone())?;
    let (endpoint_a, endpoint_b) = bind_pair().await?;
    let (pairable_a, pairable_b) =
        pairable_pair(&manager_a, &manager_b, &endpoint_a, &endpoint_b).await?;

    let result = pairable_a
        .initiate_pairing_with_material_for_test(InitiatorPairingMaterial::from_bytes_for_test(
            [1; PAIRING_ID_LEN],
            [2; PAIRING_NONCE_LEN],
        ))
        .await;
    assert!(matches!(
        result,
        Err(PairingError::Timeout {
            phase: PairingPhase::AwaitingResponse
        })
    ));
    assert_eq!(store_a.state(endpoint_b.device_id()).await, None);
    assert_eq!(store_b.state(endpoint_a.device_id()).await, None);
    pairable_b.close();

    close_endpoints(&endpoint_a, &endpoint_b).await;
    Ok(())
}

#[tokio::test]
async fn wrong_pairing_id_is_rejected_without_trust() -> TestResult {
    let directory = TempDir::new()?;
    let store_a = store(&directory, "a.trust").await?;
    let manager_a = manager(store_a.clone())?;
    let (endpoint_a, endpoint_b) = bind_pair().await?;
    let (connection_a, mut connection_b) = bootstrap_pair(&endpoint_a, &endpoint_b).await?;
    let SessionAdmission::Pairable(pairable_a) = manager_a.admit(connection_a).await? else {
        return Err("unknown peer bypassed authorization".into());
    };
    let wrong_id = [9; PAIRING_ID_LEN];
    let malicious = tokio::spawn(async move {
        let request = connection_b.receive_pairing(PAIRING_TIMEOUT).await?;
        assert!(matches!(request, PairingMessage::Request { .. }));
        connection_b
            .send_pairing(
                PairingMessage::Response {
                    pairing_id: wrong_id,
                    nonce: [3; PAIRING_NONCE_LEN],
                },
                PAIRING_TIMEOUT,
            )
            .await?;
        Ok::<_, Box<dyn Error + Send + Sync>>(connection_b)
    });

    let result = pairable_a
        .initiate_pairing_with_material_for_test(InitiatorPairingMaterial::from_bytes_for_test(
            [1; PAIRING_ID_LEN],
            [2; PAIRING_NONCE_LEN],
        ))
        .await;
    assert!(matches!(
        result,
        Err(PairingError::PairingIdMismatch {
            phase: PairingPhase::AwaitingResponse
        })
    ));
    assert_eq!(store_a.state(endpoint_b.device_id()).await, None);
    let connection_b = malicious.await??;
    connection_b.close();
    close_endpoints(&endpoint_a, &endpoint_b).await;
    Ok(())
}

#[tokio::test]
async fn pairing_requires_advertised_capability() -> TestResult {
    let directory = TempDir::new()?;
    let store_a = store(&directory, "a.trust").await?;
    let store_b = store(&directory, "b.trust").await?;
    let manager_a = manager(store_a.clone())?;
    let manager_b = manager(store_b)?;
    let (endpoint_a, endpoint_b) = bind_pair().await?;
    let (connection_a, connection_b) = bootstrap_pair_with_metadata(
        &endpoint_a,
        &endpoint_b,
        pairing_metadata("device-a", "test")?,
        HelloMetadata::new("device-b", "test", Vec::new())?,
    )
    .await?;
    let SessionAdmission::Pairable(pairable_a) = manager_a.admit(connection_a).await? else {
        return Err("unknown peer bypassed authorization".into());
    };
    let SessionAdmission::Pairable(pairable_b) = manager_b.admit(connection_b).await? else {
        return Err("unknown peer bypassed authorization".into());
    };

    assert!(!pairable_a.supports_pairing());
    assert!(matches!(
        pairable_a
            .initiate_pairing_with_material_for_test(
                InitiatorPairingMaterial::from_bytes_for_test(
                    [1; PAIRING_ID_LEN],
                    [2; PAIRING_NONCE_LEN]
                )
            )
            .await,
        Err(PairingError::PairingUnsupported(device_id)) if device_id == endpoint_b.device_id()
    ));
    assert_eq!(store_a.state(endpoint_b.device_id()).await, None);
    pairable_b.close();
    close_endpoints(&endpoint_a, &endpoint_b).await;
    Ok(())
}

#[tokio::test]
async fn durable_reconnect_authorizes_without_repairing() -> TestResult {
    let directory = TempDir::new()?;
    let key_a = SecretKey::generate();
    let key_b = SecretKey::generate();
    let store_a = store(&directory, "a.trust").await?;
    let store_b = store(&directory, "b.trust").await?;
    let manager_a = manager(store_a.clone())?;
    let manager_b = manager(store_b.clone())?;
    let (endpoint_a, endpoint_b) = bind_pair_with_keys(key_a.clone(), key_b.clone()).await?;
    let id_a = endpoint_a.device_id();
    let id_b = endpoint_b.device_id();
    let (pairable_a, pairable_b) =
        pairable_pair(&manager_a, &manager_b, &endpoint_a, &endpoint_b).await?;
    let (pending_a, pending_b) = pending_pair(pairable_a, pairable_b).await?;
    let (authorized_a, authorized_b) =
        tokio::try_join!(pending_a.confirm(true), pending_b.confirm(true))?;
    authorized_a.close();
    authorized_b.close();
    close_endpoints(&endpoint_a, &endpoint_b).await;
    drop(manager_a);
    drop(manager_b);
    drop(store_a);
    drop(store_b);

    let store_a = store(&directory, "a.trust").await?;
    let store_b = store(&directory, "b.trust").await?;
    let manager_a = manager(store_a)?;
    let manager_b = manager(store_b)?;
    let (endpoint_a, endpoint_b) = bind_pair_with_keys(key_a, key_b).await?;
    assert_eq!(endpoint_a.device_id(), id_a);
    assert_eq!(endpoint_b.device_id(), id_b);
    let (connection_a, connection_b) = bootstrap_pair(&endpoint_a, &endpoint_b).await?;
    let SessionAdmission::Authorized(authorized_a) = manager_a.admit(connection_a).await? else {
        return Err("durably trusted peer A was not authorized".into());
    };
    let SessionAdmission::Authorized(authorized_b) = manager_b.admit(connection_b).await? else {
        return Err("durably trusted peer B was not authorized".into());
    };
    authorized_a.close();
    authorized_b.close();
    close_endpoints(&endpoint_a, &endpoint_b).await;
    Ok(())
}

#[tokio::test]
async fn paired_peer_revocation_and_forget_apply_to_fresh_admission() -> TestResult {
    let directory = TempDir::new()?;
    let store_a = store(&directory, "a.trust").await?;
    let store_b = store(&directory, "b.trust").await?;
    let manager_a = manager(store_a.clone())?;
    let manager_b = manager(store_b.clone())?;
    let (endpoint_a, endpoint_b) = bind_pair().await?;
    let (pairable_a, pairable_b) =
        pairable_pair(&manager_a, &manager_b, &endpoint_a, &endpoint_b).await?;
    let (pending_a, pending_b) = pending_pair(pairable_a, pairable_b).await?;
    let (authorized_a, authorized_b) =
        tokio::try_join!(pending_a.confirm(true), pending_b.confirm(true))?;
    authorized_a.close();
    authorized_b.close();

    store_a.revoke(endpoint_b.device_id()).await?;
    let (connection_a, connection_b) = bootstrap_pair(&endpoint_a, &endpoint_b).await?;
    assert!(matches!(
        manager_a.admit(connection_a).await,
        Err(SessionError::PeerRevoked(device_id)) if device_id == endpoint_b.device_id()
    ));
    let SessionAdmission::Authorized(authorized_b) = manager_b.admit(connection_b).await? else {
        return Err("B's independent trust decision unexpectedly changed".into());
    };
    authorized_b.close();

    store_a.forget(endpoint_b.device_id()).await?;
    let (connection_a, connection_b) = bootstrap_pair(&endpoint_a, &endpoint_b).await?;
    let SessionAdmission::Pairable(pairable_a) = manager_a.admit(connection_a).await? else {
        return Err("forgotten peer was not pairing-only".into());
    };
    let SessionAdmission::Authorized(authorized_b) = manager_b.admit(connection_b).await? else {
        return Err("B's independent trust decision unexpectedly changed".into());
    };
    assert_eq!(store_a.state(endpoint_b.device_id()).await, None);
    pairable_a.close();
    authorized_b.close();
    close_endpoints(&endpoint_a, &endpoint_b).await;
    Ok(())
}

#[tokio::test]
async fn zero_pairing_timeout_configuration_is_rejected() -> TestResult {
    let directory = TempDir::new()?;
    let store = store(&directory, "trust").await?;
    assert!(matches!(
        SessionManager::with_config(
            store,
            SessionConfig {
                pairing_timeout: Duration::ZERO
            }
        ),
        Err(SessionError::InvalidPairingTimeout)
    ));
    Ok(())
}

#[tokio::test]
async fn trusted_peer_is_authorized_from_device_id_record() -> TestResult {
    let directory = TempDir::new()?;
    let store_a = store(&directory, "a.trust").await?;
    let (endpoint_a, endpoint_b) = bind_pair().await?;
    let peer_b = TrustedPeer {
        device_id: endpoint_b.device_id(),
        device_name: "stored device-b".to_owned(),
        platform: "stored platform".to_owned(),
    };
    store_a.trust(peer_b.clone()).await?;
    let manager_a = manager(store_a)?;
    let (connection_a, connection_b) = bootstrap_pair(&endpoint_a, &endpoint_b).await?;

    let SessionAdmission::Authorized(authorized) = manager_a.admit(connection_a).await? else {
        return Err("trusted peer was not authorized".into());
    };
    assert_eq!(authorized.remote_device_id(), endpoint_b.device_id());
    assert_eq!(authorized.trusted_peer(), &peer_b);
    assert_eq!(authorized.peer_hello().device_name, "device-b");

    authorized.close();
    connection_b.close();
    close_endpoints(&endpoint_a, &endpoint_b).await;
    Ok(())
}

#[tokio::test]
async fn revoked_peer_is_rejected_and_forget_returns_it_to_pairable() -> TestResult {
    let directory = TempDir::new()?;
    let store_a = store(&directory, "a.trust").await?;
    let (endpoint_a, endpoint_b) = bind_pair().await?;
    store_a.revoke(endpoint_b.device_id()).await?;
    let manager_a = manager(store_a.clone())?;
    let (connection_a, connection_b) = bootstrap_pair(&endpoint_a, &endpoint_b).await?;

    assert!(matches!(
        manager_a.admit(connection_a).await,
        Err(SessionError::PeerRevoked(device_id)) if device_id == endpoint_b.device_id()
    ));
    assert_eq!(
        store_a.state(endpoint_b.device_id()).await,
        Some(TrustState::Revoked)
    );
    connection_b.close();

    store_a.forget(endpoint_b.device_id()).await?;
    let (connection_a, connection_b) = bootstrap_pair(&endpoint_a, &endpoint_b).await?;
    let SessionAdmission::Pairable(pairable) = manager_a.admit(connection_a).await? else {
        return Err("forgotten peer did not return to unknown/pairable".into());
    };
    assert_eq!(store_a.state(endpoint_b.device_id()).await, None);
    pairable.close();
    connection_b.close();
    close_endpoints(&endpoint_a, &endpoint_b).await;
    Ok(())
}
