//! Persistent Iroh identity storage.
//!
//! Iroh's `SecretKey` is the node identity.  The small envelope used here is only a
//! corruption-detecting storage format; it does not add another certificate or PKI layer.

use std::{
    fs, io,
    path::{Path, PathBuf},
};

use iroh::{EndpointId, SecretKey};
use thiserror::Error;

const IDENTITY_FILE: &str = "identity.key";
const MAGIC: &[u8; 8] = b"RFTID001";
const FORMAT_VERSION: u8 = 1;
const SECRET_KEY_LEN: usize = 32;
const CHECKSUM_LEN: usize = 16;
const STORAGE_LEN: usize = MAGIC.len() + 1 + SECRET_KEY_LEN + CHECKSUM_LEN;

#[derive(Debug, Error)]
pub enum IdentityError {
    #[error("unable to access identity storage: {0}")]
    Io(#[from] io::Error),
    #[error("identity storage is malformed: {0}")]
    MalformedStorage(&'static str),
}

/// An Iroh identity and the location from which it was loaded.
#[derive(Clone)]
pub struct NodeIdentity {
    secret_key: SecretKey,
    storage_path: PathBuf,
}

impl NodeIdentity {
    /// Loads the identity in `data_dir`, creating it on first use.
    pub fn load_or_create(data_dir: impl AsRef<Path>) -> Result<Self, IdentityError> {
        let data_dir = data_dir.as_ref();
        fs::create_dir_all(data_dir)?;
        let storage_path = data_dir.join(IDENTITY_FILE);

        let secret_key = match fs::read(&storage_path) {
            Ok(bytes) => decode_storage(&bytes)?,
            Err(error) if error.kind() == io::ErrorKind::NotFound => {
                let secret_key = SecretKey::generate();
                write_storage(&storage_path, &secret_key)?;
                secret_key
            }
            Err(error) => return Err(error.into()),
        };

        Ok(Self {
            secret_key,
            storage_path,
        })
    }

    /// Creates an identity that is not persisted.  This is useful for local benchmarks/tests.
    pub fn ephemeral() -> Self {
        Self::from_secret_key(SecretKey::generate(), PathBuf::new())
    }

    pub fn secret_key(&self) -> &SecretKey {
        &self.secret_key
    }

    pub fn node_id(&self) -> EndpointId {
        self.secret_key.public()
    }

    pub fn node_id_bytes(&self) -> [u8; SECRET_KEY_LEN] {
        *self.node_id().as_bytes()
    }

    /// Returns a deterministic, compact manual-verification fingerprint.
    pub fn fingerprint(&self) -> String {
        let digest = blake3::hash(self.node_id().as_bytes());
        format!("blake3:{}", hex::encode(&digest.as_bytes()[..CHECKSUM_LEN]))
    }

    pub fn storage_path(&self) -> &Path {
        &self.storage_path
    }

    fn from_secret_key(secret_key: SecretKey, storage_path: PathBuf) -> Self {
        Self {
            secret_key,
            storage_path,
        }
    }
}

fn encode_storage(secret_key: &SecretKey) -> [u8; STORAGE_LEN] {
    let mut bytes = [0; STORAGE_LEN];
    bytes[..MAGIC.len()].copy_from_slice(MAGIC);
    bytes[MAGIC.len()] = FORMAT_VERSION;
    let secret_start = MAGIC.len() + 1;
    let secret_end = secret_start + SECRET_KEY_LEN;
    bytes[secret_start..secret_end].copy_from_slice(&secret_key.to_bytes());

    let checksum = blake3::hash(&bytes[..secret_end]);
    bytes[secret_end..].copy_from_slice(&checksum.as_bytes()[..CHECKSUM_LEN]);
    bytes
}

fn decode_storage(bytes: &[u8]) -> Result<SecretKey, IdentityError> {
    if bytes.len() != STORAGE_LEN {
        return Err(IdentityError::MalformedStorage("unexpected length"));
    }
    if &bytes[..MAGIC.len()] != MAGIC {
        return Err(IdentityError::MalformedStorage("invalid magic"));
    }
    if bytes[MAGIC.len()] != FORMAT_VERSION {
        return Err(IdentityError::MalformedStorage(
            "unsupported format version",
        ));
    }

    let secret_start = MAGIC.len() + 1;
    let secret_end = secret_start + SECRET_KEY_LEN;
    let expected_checksum = blake3::hash(&bytes[..secret_end]);
    if bytes[secret_end..] != expected_checksum.as_bytes()[..CHECKSUM_LEN] {
        return Err(IdentityError::MalformedStorage("checksum mismatch"));
    }

    let secret_bytes: [u8; SECRET_KEY_LEN] = bytes[secret_start..secret_end]
        .try_into()
        .map_err(|_| IdentityError::MalformedStorage("invalid secret key length"))?;
    Ok(SecretKey::from_bytes(&secret_bytes))
}

fn write_storage(path: &Path, secret_key: &SecretKey) -> Result<(), IdentityError> {
    let temporary_path = path.with_extension("key.tmp");
    fs::write(&temporary_path, encode_storage(secret_key))?;
    #[cfg(unix)]
    fs::set_permissions(&temporary_path, fs::Permissions::from_mode(0o600))?;
    fs::rename(temporary_path, path)?;
    Ok(())
}

#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn creates_and_reloads_the_same_identity() -> Result<(), Box<dyn std::error::Error>> {
        let directory = tempfile::tempdir()?;
        let first = NodeIdentity::load_or_create(directory.path())?;
        let first_id = first.node_id();
        let first_fingerprint = first.fingerprint();
        let first_secret = first.secret_key().to_bytes();

        let second = NodeIdentity::load_or_create(directory.path())?;
        assert_eq!(first_id, second.node_id());
        assert_eq!(first_fingerprint, second.fingerprint());
        assert_eq!(first_secret, second.secret_key().to_bytes());
        assert_eq!(first.storage_path(), directory.path().join(IDENTITY_FILE));
        Ok(())
    }

    #[test]
    fn fingerprint_is_stable_and_derived_from_the_public_identity() {
        let identity = NodeIdentity::ephemeral();
        let digest = blake3::hash(identity.node_id().as_bytes());
        let expected = format!("blake3:{}", hex::encode(&digest.as_bytes()[..CHECKSUM_LEN]));
        assert_eq!(identity.fingerprint(), expected);
        assert_eq!(identity.fingerprint(), identity.fingerprint());
    }

    #[test]
    fn malformed_identity_storage_is_rejected() -> Result<(), Box<dyn std::error::Error>> {
        let directory = tempfile::tempdir()?;
        let path = directory.path().join(IDENTITY_FILE);
        fs::write(&path, b"not an identity")?;
        assert!(matches!(
            NodeIdentity::load_or_create(directory.path()),
            Err(IdentityError::MalformedStorage(_))
        ));

        let identity = NodeIdentity::ephemeral();
        let mut encoded = encode_storage(identity.secret_key());
        encoded[STORAGE_LEN - 1] ^= 1;
        fs::write(&path, encoded)?;
        assert!(matches!(
            NodeIdentity::load_or_create(directory.path()),
            Err(IdentityError::MalformedStorage("checksum mismatch"))
        ));
        Ok(())
    }

    #[test]
    fn identity_ids_are_stable_for_a_reused_secret_key() {
        let secret = SecretKey::generate();
        let first = NodeIdentity::from_secret_key(secret.clone(), PathBuf::new());
        let second = NodeIdentity::from_secret_key(secret, PathBuf::new());
        assert_eq!(first.node_id(), second.node_id());
        assert_eq!(first.node_id_bytes(), second.node_id_bytes());
        assert_eq!(first.fingerprint(), second.fingerprint());
    }
}
