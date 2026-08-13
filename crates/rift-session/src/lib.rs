//! Application admission above authenticated Rift transport.
//!
//! A bootstrapped connection is authenticated but not authorized. This crate is the
//! only production layer that combines a concrete [`BootstrappedConnection`] with
//! local trust policy. Unknown peers receive a pairing-only wrapper; revoked peers
//! are rejected; trusted peers receive [`AuthorizedConnection`].

use std::sync::Arc;

use rift_core::{DeviceId, TrustedPeer};
use rift_protocol::{Capability, Hello, HelloMetadata};
use rift_transport_iroh::BootstrappedConnection;
use rift_trust::{TrustEntry, TrustStore};
use thiserror::Error;
use tracing::{info, warn};

/// Failures during application admission.
#[derive(Debug, Error)]
pub enum SessionError {
    /// A revoked peer attempted a fresh application admission.
    #[error("peer {0} is revoked")]
    PeerRevoked(DeviceId),
    /// A trusted decision did not contain the required trusted-peer metadata.
    #[error("trust store is inconsistent for trusted peer {0}")]
    InconsistentTrustState(DeviceId),
}

/// The result of applying local trust policy to an authenticated connection.
pub enum SessionAdmission {
    /// A locally trusted peer may use application functionality.
    Authorized(AuthorizedConnection),
    /// An unknown peer is isolated to the pairing protocol.
    Pairable(PairableConnection),
}

/// A Hello-bootstrapped connection admitted by a durable local trust decision.
pub struct AuthorizedConnection {
    connection: BootstrappedConnection,
    peer: TrustedPeer,
}

impl AuthorizedConnection {
    /// Returns the authorized cryptographic peer identity.
    pub const fn remote_device_id(&self) -> DeviceId {
        self.peer.device_id
    }

    /// Returns the durable peer record that authorized this connection.
    pub const fn trusted_peer(&self) -> &TrustedPeer {
        &self.peer
    }

    /// Returns the validated Hello for feature negotiation after authorization.
    pub fn peer_hello(&self) -> &Hello {
        self.connection.peer_hello()
    }

    /// Closes this disposable authorized connection.
    pub fn close(&self) {
        self.connection.close();
    }
}

/// An authenticated unknown peer isolated to pairing behavior.
pub struct PairableConnection {
    connection: BootstrappedConnection,
}

impl PairableConnection {
    /// Returns the authenticated unknown peer identity.
    pub const fn remote_device_id(&self) -> DeviceId {
        self.connection.remote_device_id()
    }

    /// Returns peer-controlled display metadata validated by the Hello bounds.
    pub fn peer_hello(&self) -> &Hello {
        self.connection.peer_hello()
    }

    /// Returns whether this peer advertised pairing protocol v1.
    pub fn supports_pairing(&self) -> bool {
        self.connection
            .peer_hello()
            .capabilities
            .contains(&Capability::PAIRING_V1)
    }

    /// Closes this disposable pairing-only connection.
    pub fn close(&self) {
        self.connection.close();
    }
}

/// Admission policy backed by one durable local trust store.
pub struct SessionManager {
    trust_store: Arc<TrustStore>,
}

impl SessionManager {
    /// Creates an admission manager for one trust store.
    pub fn new(trust_store: Arc<TrustStore>) -> Self {
        Self { trust_store }
    }

    /// Applies the complete M3 admission rule to one authenticated bootstrap.
    pub async fn admit(
        &self,
        bootstrapped: BootstrappedConnection,
    ) -> Result<SessionAdmission, SessionError> {
        let device_id = bootstrapped.remote_device_id();
        let entry = self.trust_store.entry(device_id).await;
        match entry {
            Some(TrustEntry::Trusted(peer)) => {
                info!(remote_device_id = %device_id, "peer_authorized");
                Ok(SessionAdmission::Authorized(AuthorizedConnection {
                    connection: bootstrapped,
                    peer,
                }))
            }
            Some(TrustEntry::Revoked(_)) => {
                warn!(remote_device_id = %device_id, "peer_rejected_revoked");
                bootstrapped.close();
                Err(SessionError::PeerRevoked(device_id))
            }
            None => Ok(SessionAdmission::Pairable(PairableConnection {
                connection: bootstrapped,
            })),
        }
    }
}

/// Builds bounded local Hello metadata for a pairing-capable session endpoint.
pub fn pairing_metadata(
    device_name: impl Into<String>,
    platform: impl Into<String>,
) -> Result<HelloMetadata, rift_protocol::HandshakeError> {
    HelloMetadata::new(device_name, platform, vec![Capability::PAIRING_V1])
}

#[cfg(test)]
mod tests {
    use rift_core::TrustState;

    use super::*;

    #[test]
    fn pairing_metadata_advertises_only_pairing_v1() {
        let result = pairing_metadata("device", "platform");
        assert!(matches!(
            result,
            Ok(HelloMetadata { capabilities, .. })
                if capabilities == vec![Capability::PAIRING_V1]
        ));
    }

    #[test]
    fn trust_states_retain_binary_authorization_meaning() {
        assert_ne!(TrustState::Trusted, TrustState::Revoked);
    }
}
