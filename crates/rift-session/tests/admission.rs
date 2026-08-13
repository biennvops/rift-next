use std::{error::Error, sync::Arc, time::Duration};

use rift_core::{TrustState, TrustedPeer};
use rift_session::{SessionAdmission, SessionError, SessionManager, pairing_metadata};
use rift_transport_iroh::{EndpointConfig, RiftEndpoint, SecretKey};
use rift_trust::TrustStore;
use tempfile::TempDir;

const CONNECTION_TIMEOUT: Duration = Duration::from_secs(2);
const CONTROL_TIMEOUT: Duration = Duration::from_millis(250);

type TestResult<T = ()> = Result<T, Box<dyn Error + Send + Sync>>;

fn config() -> EndpointConfig {
    EndpointConfig {
        connection_timeout: CONNECTION_TIMEOUT,
        handshake_timeout: CONTROL_TIMEOUT,
        ..EndpointConfig::direct()
    }
}

async fn bind_pair() -> TestResult<(RiftEndpoint, RiftEndpoint)> {
    let first = RiftEndpoint::bind(SecretKey::generate(), config()).await?;
    let second = RiftEndpoint::bind(SecretKey::generate(), config()).await?;
    Ok((first, second))
}

async fn store(directory: &TempDir, name: &str) -> TestResult<Arc<TrustStore>> {
    Ok(Arc::new(
        TrustStore::open(directory.path().join(name)).await?,
    ))
}

async fn bootstrap_pair(
    endpoint_a: &RiftEndpoint,
    endpoint_b: &RiftEndpoint,
) -> TestResult<(
    rift_transport_iroh::BootstrappedConnection,
    rift_transport_iroh::BootstrappedConnection,
)> {
    let accept = tokio::spawn({
        let endpoint_b = endpoint_b.clone();
        async move {
            let metadata = pairing_metadata("device-b", "test")?;
            let connection = endpoint_b.accept_and_bootstrap(metadata).await?;
            Ok::<_, Box<dyn Error + Send + Sync>>(connection)
        }
    });
    let connection_a = endpoint_a
        .connect_and_bootstrap(
            endpoint_b.local_addr(),
            pairing_metadata("device-a", "test")?,
        )
        .await?;
    let connection_b = accept.await??;
    Ok((connection_a, connection_b))
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
    let manager_a = SessionManager::new(store_a);
    let manager_b = SessionManager::new(store_b);
    let (endpoint_a, endpoint_b) = bind_pair().await?;
    let (connection_a, connection_b) = bootstrap_pair(&endpoint_a, &endpoint_b).await?;

    let admission_a = manager_a.admit(connection_a).await?;
    let admission_b = manager_b.admit(connection_b).await?;
    let SessionAdmission::Pairable(pairable_a) = admission_a else {
        return Err("unknown peer A bypassed authorization".into());
    };
    let SessionAdmission::Pairable(pairable_b) = admission_b else {
        return Err("unknown peer B bypassed authorization".into());
    };
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
    let manager_a = SessionManager::new(store_a);
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
    let manager_a = SessionManager::new(store_a.clone());
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
