//! Platform-independent Rift domain logic.
//!
//! Cryptographic device identity is represented by [`DeviceId`]. It contains only
//! public identity bytes and has no dependency on a transport, operating system, or
//! secret-key storage mechanism.

use std::fmt;

use serde::{Deserialize, Serialize};
use thiserror::Error;

/// The byte length of a Rift device identity.
pub const DEVICE_ID_LEN: usize = 32;

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
}
