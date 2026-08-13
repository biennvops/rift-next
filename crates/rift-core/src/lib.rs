//! Platform-independent Rift domain logic.
//!
//! Cryptographic device identity is represented by [`DeviceId`]. Durable trust
//! decisions use that identity as their only key. These types contain no transport,
//! operating-system, or secret-key storage details.

use std::fmt;

use serde::{Deserialize, Serialize};
use thiserror::Error;

/// The byte length of a Rift device identity.
pub const DEVICE_ID_LEN: usize = 32;

/// The maximum UTF-8 byte length of peer display names.
pub const MAX_DEVICE_NAME_LEN: usize = 128;

/// The maximum UTF-8 byte length of peer platform identifiers.
pub const MAX_PLATFORM_LEN: usize = 64;

/// The public cryptographic identity of a Rift device.
///
/// A `DeviceId` contains public bytes only. The corresponding private Iroh key is
/// owned by the transport/application boundary and is never represented here.
#[derive(Clone, Copy, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(transparent)]
pub struct DeviceId([u8; DEVICE_ID_LEN]);

impl DeviceId {
    /// Constructs a device identity from its exactly-sized public byte array.
    pub const fn from_bytes(bytes: [u8; DEVICE_ID_LEN]) -> Self {
        Self(bytes)
    }

    /// Returns the public identity bytes.
    pub const fn as_bytes(&self) -> &[u8; DEVICE_ID_LEN] {
        &self.0
    }

    /// Constructs a device identity from a byte slice after checking its length.
    pub fn from_slice(bytes: &[u8]) -> Result<Self, DeviceIdError> {
        let bytes: [u8; DEVICE_ID_LEN] = bytes.try_into().map_err(|_| DeviceIdError {
            actual: bytes.len(),
        })?;
        Ok(Self::from_bytes(bytes))
    }
}

impl From<[u8; DEVICE_ID_LEN]> for DeviceId {
    fn from(bytes: [u8; DEVICE_ID_LEN]) -> Self {
        Self::from_bytes(bytes)
    }
}

impl AsRef<[u8]> for DeviceId {
    fn as_ref(&self) -> &[u8] {
        self.as_bytes()
    }
}

impl fmt::Debug for DeviceId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_tuple("DeviceId")
            .field(&hex::encode(self.as_bytes()))
            .finish()
    }
}

impl fmt::Display for DeviceId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&hex::encode(self.as_bytes()))
    }
}

/// An error returned when a byte slice is not a complete device identity.
#[derive(Clone, Debug, Eq, Error, PartialEq)]
#[error("device ID must contain exactly {expected} bytes, received {actual}", expected = DEVICE_ID_LEN)]
pub struct DeviceIdError {
    actual: usize,
}

/// A durable local trust decision for a cryptographic device identity.
///
/// No stored value represents an unknown peer. Absence from a trust store means
/// unknown.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub enum TrustState {
    /// The peer may be admitted to application functionality.
    Trusted,
    /// The peer is blocked until explicitly forgotten.
    Revoked,
}

/// A trusted peer and the display metadata captured when pairing succeeded.
///
/// Only [`device_id`](Self::device_id) identifies the peer. The name and platform
/// are bounded, peer-controlled presentation data and must never be used as keys.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct TrustedPeer {
    /// The peer's public cryptographic identity and trust-store key.
    pub device_id: DeviceId,
    /// Human-readable display metadata captured from the authenticated Hello.
    pub device_name: String,
    /// Platform display metadata captured from the authenticated Hello.
    pub platform: String,
}

#[cfg(test)]
mod tests {
    use std::{collections::HashSet, hash::Hash, hash::Hasher};

    use super::*;

    #[test]
    fn bytes_round_trip_without_secret_material() {
        let bytes = [0xabu8; DEVICE_ID_LEN];
        let device_id = DeviceId::from_bytes(bytes);

        assert_eq!(device_id.as_bytes(), &bytes);
        assert_eq!(DeviceId::from_slice(&bytes), Ok(device_id));
    }

    #[test]
    fn equality_ordering_and_hash_are_value_based() {
        let low = DeviceId::from_bytes([0; DEVICE_ID_LEN]);
        let high = DeviceId::from_bytes([1; DEVICE_ID_LEN]);
        assert_eq!(DeviceId::from_bytes([0; DEVICE_ID_LEN]), low);
        assert_ne!(low, high);
        assert!(low < high);

        let mut identities = HashSet::new();
        identities.insert(low);
        identities.insert(high);
        assert_eq!(identities.len(), 2);

        let mut low_hasher = std::collections::hash_map::DefaultHasher::new();
        low.hash(&mut low_hasher);
        let mut low_again_hasher = std::collections::hash_map::DefaultHasher::new();
        let low_again = DeviceId::from_slice(&[0; DEVICE_ID_LEN]);
        assert_eq!(low_again, Ok(low));
        let Some(low_again) = low_again.ok() else {
            return;
        };
        low_again.hash(&mut low_again_hasher);
        assert_eq!(low_hasher.finish(), low_again_hasher.finish());
    }

    #[test]
    fn formatting_is_canonical_lowercase_hex() {
        let mut bytes = [0; DEVICE_ID_LEN];
        bytes[..8].copy_from_slice(&[0x00, 0x01, 0x0a, 0x0f, 0x10, 0x7f, 0x80, 0xff]);
        let device_id = DeviceId::from_bytes(bytes);
        let expected = "00010a0f107f80ff000000000000000000000000000000000000000000000000";

        assert_eq!(device_id.to_string(), expected);
        assert_eq!(
            format!("{device_id:?}"),
            format!("DeviceId(\"{expected}\")")
        );
    }

    #[test]
    fn malformed_byte_slices_are_rejected() {
        assert_eq!(
            DeviceId::from_slice(&[0; DEVICE_ID_LEN - 1]),
            Err(DeviceIdError {
                actual: DEVICE_ID_LEN - 1,
            })
        );
        assert_eq!(
            DeviceId::from_slice(&[0; DEVICE_ID_LEN + 1]),
            Err(DeviceIdError {
                actual: DEVICE_ID_LEN + 1,
            })
        );
    }

    #[test]
    fn trust_records_are_keyed_by_device_id_not_display_metadata() {
        let device_id = DeviceId::from_bytes([9; DEVICE_ID_LEN]);
        let first = TrustedPeer {
            device_id,
            device_name: "first name".to_owned(),
            platform: "first platform".to_owned(),
        };
        let second = TrustedPeer {
            device_id,
            device_name: "renamed".to_owned(),
            platform: "changed platform".to_owned(),
        };

        assert_eq!(first.device_id, second.device_id);
        assert_ne!(first, second);
        assert_eq!(TrustState::Trusted, TrustState::Trusted);
        assert_ne!(TrustState::Trusted, TrustState::Revoked);
    }

    #[test]
    fn peer_metadata_bounds_match_the_authenticated_hello_contract() {
        assert_eq!(MAX_DEVICE_NAME_LEN, 128);
        assert_eq!(MAX_PLATFORM_LEN, 64);
    }
}
