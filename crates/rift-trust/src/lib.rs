//! Durable local authorization state keyed only by [`DeviceId`].
//!
//! The store is a bounded, versioned append-only journal. One running Rift process
//! owns a store path in Foundation M3; cross-process coordination and compaction are
//! deliberately deferred. The journal contains public identities and bounded display
//! metadata, never Iroh keys, addresses, or transient pairing state.

use std::{
    collections::BTreeMap,
    io,
    path::{Path, PathBuf},
};

use rift_core::{DeviceId, MAX_DEVICE_NAME_LEN, MAX_PLATFORM_LEN, TrustState, TrustedPeer};
use serde::{Deserialize, Serialize};
use thiserror::Error;
use tokio::{
    fs::{File, OpenOptions},
    io::{AsyncReadExt, AsyncSeekExt, AsyncWriteExt, SeekFrom},
    sync::Mutex,
};
use tracing::info;

const JOURNAL_MAGIC: &[u8; 8] = b"RIFTTRST";
const JOURNAL_VERSION: u16 = 1;
const HEADER_LEN: usize = JOURNAL_MAGIC.len() + size_of::<u16>();
const LENGTH_PREFIX_LEN: usize = size_of::<u32>();
const CHECKSUM_LEN: usize = 32;

/// Maximum encoded Postcard bytes in one journal mutation.
pub const MAX_RECORD_LEN: usize = 1024;

/// Maximum journal bytes accepted or produced by one store.
pub const MAX_STORE_SIZE: usize = 16 * 1024 * 1024;

/// Maximum number of mutations replayed from one journal.
pub const MAX_RECORDS: usize = 100_000;

/// One durable mutation in the trust journal.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub enum TrustMutation {
    /// Trusts an identity and records its display metadata.
    Trust { peer: TrustedPeer },
    /// Blocks an identity until it is explicitly forgotten.
    Revoke { device_id: DeviceId },
    /// Removes the local decision and returns an identity to unknown.
    Forget { device_id: DeviceId },
}

/// One current entry returned while listing the store.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum TrustEntry {
    /// A trusted peer and its captured display metadata.
    Trusted(TrustedPeer),
    /// A revoked cryptographic identity.
    Revoked(DeviceId),
}

impl TrustEntry {
    /// Returns the cryptographic identity used as the store key.
    pub const fn device_id(&self) -> DeviceId {
        match self {
            Self::Trusted(peer) => peer.device_id,
            Self::Revoked(device_id) => *device_id,
        }
    }

    /// Returns the local authorization state.
    pub const fn state(&self) -> TrustState {
        match self {
            Self::Trusted(_) => TrustState::Trusted,
            Self::Revoked(_) => TrustState::Revoked,
        }
    }
}

/// Failures opening, replaying, or durably mutating a trust store.
#[derive(Debug, Error)]
pub enum TrustStoreError {
    /// A filesystem operation failed.
    #[error("trust-store {operation} failed: {source}")]
    Io {
        operation: &'static str,
        #[source]
        source: io::Error,
    },
    /// An existing file ended before the complete header arrived.
    #[error("trust-store header is truncated: received {actual} of {expected} bytes")]
    TruncatedHeader { actual: usize, expected: usize },
    /// The file does not contain the Rift trust-journal magic.
    #[error("trust-store header has invalid magic")]
    InvalidMagic,
    /// The journal version is not supported by this implementation.
    #[error("unsupported trust-store version {0}")]
    UnsupportedVersion(u16),
    /// The complete store exceeds its replay/allocation bound.
    #[error("trust-store size {actual} exceeds maximum {maximum}")]
    StoreTooLarge { actual: usize, maximum: usize },
    /// A declared record length exceeds the record bound.
    #[error("trust-store record {record} declares {actual} bytes; maximum is {maximum}")]
    RecordTooLarge {
        record: usize,
        actual: usize,
        maximum: usize,
    },
    /// Replay would exceed the mutation-count bound.
    #[error("trust store contains more than {maximum} records")]
    TooManyRecords { maximum: usize },
    /// A complete record failed checksum or Postcard validation.
    #[error("trust-store record {record} at byte {offset} is corrupt: {reason}")]
    CorruptRecord {
        record: usize,
        offset: usize,
        reason: &'static str,
    },
    /// A trusted peer's display metadata exceeds the authenticated Hello bounds.
    #[error("trusted-peer {field} has {actual} UTF-8 bytes; maximum is {maximum}")]
    MetadataTooLong {
        field: &'static str,
        actual: usize,
        maximum: usize,
    },
    /// Postcard could not encode a mutation.
    #[error("unable to encode trust mutation: {0}")]
    Encode(#[source] postcard::Error),
    /// A revoked identity cannot be trusted until it is explicitly forgotten.
    #[error("revoked peer {0} must be forgotten before it can be trusted again")]
    RevokedIdentity(DeviceId),
    /// A prior persistence failure poisoned this store instance.
    #[error("trust store is poisoned by a prior persistence failure")]
    StorePoisoned,
}

#[derive(Clone, Debug, Eq, PartialEq)]
enum StoredDecision {
    Trusted(TrustedPeer),
    Revoked,
}

struct StoreInner {
    file: File,
    decisions: BTreeMap<DeviceId, StoredDecision>,
    file_len: usize,
    record_count: usize,
    poisoned: bool,
    #[cfg(test)]
    fail_next_append: bool,
}

/// A single-process owner of one durable trust-journal path.
pub struct TrustStore {
    path: PathBuf,
    inner: Mutex<StoreInner>,
}

impl TrustStore {
    /// Creates or opens and fully validates a trust journal.
    ///
    /// An incomplete final record is truncated back to the last complete record.
    /// Any corruption in a complete record fails the entire open without exposing a
    /// partially replayed peer set.
    pub async fn open(path: impl AsRef<Path>) -> Result<Self, TrustStoreError> {
        let path = path.as_ref().to_path_buf();
        match OpenOptions::new()
            .read(true)
            .write(true)
            .create_new(true)
            .open(&path)
            .await
        {
            Ok(mut file) => {
                write_header(&mut file).await?;
                Ok(Self::from_parts(path, file, BTreeMap::new(), HEADER_LEN, 0))
            }
            Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {
                Self::open_existing(path).await
            }
            Err(source) => Err(io_error("create", source)),
        }
    }

    /// Returns the owned journal path.
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Returns one current decision for an identity.
    pub async fn entry(&self, device_id: DeviceId) -> Option<TrustEntry> {
        let inner = self.inner.lock().await;
        inner
            .decisions
            .get(&device_id)
            .map(|decision| match decision {
                StoredDecision::Trusted(peer) => TrustEntry::Trusted(peer.clone()),
                StoredDecision::Revoked => TrustEntry::Revoked(device_id),
            })
    }

    /// Returns the local decision, or `None` when the identity is unknown.
    pub async fn state(&self, device_id: DeviceId) -> Option<TrustState> {
        self.entry(device_id).await.map(|entry| entry.state())
    }

    /// Returns trusted metadata only when the current state is trusted.
    pub async fn peer(&self, device_id: DeviceId) -> Option<TrustedPeer> {
        match self.entry(device_id).await {
            Some(TrustEntry::Trusted(peer)) => Some(peer),
            Some(TrustEntry::Revoked(_)) | None => None,
        }
    }

    /// Lists current decisions in deterministic `DeviceId` order.
    pub async fn list(&self) -> Vec<TrustEntry> {
        let inner = self.inner.lock().await;
        inner
            .decisions
            .iter()
            .map(|(device_id, decision)| match decision {
                StoredDecision::Trusted(peer) => TrustEntry::Trusted(peer.clone()),
                StoredDecision::Revoked => TrustEntry::Revoked(*device_id),
            })
            .collect()
    }

    /// Durably trusts a peer before making the decision visible in memory.
    pub async fn trust(&self, peer: TrustedPeer) -> Result<(), TrustStoreError> {
        validate_peer(&peer)?;
        self.commit(TrustMutation::Trust { peer }).await
    }

    /// Durably revokes an identity. Revoking unknown or revoked peers is allowed.
    pub async fn revoke(&self, device_id: DeviceId) -> Result<(), TrustStoreError> {
        self.commit(TrustMutation::Revoke { device_id }).await?;
        info!(remote_device_id = %device_id, "peer_revoked");
        Ok(())
    }

    /// Removes any durable trust/revocation decision, making the identity unknown.
    pub async fn forget(&self, device_id: DeviceId) -> Result<(), TrustStoreError> {
        self.commit(TrustMutation::Forget { device_id }).await
    }

    async fn open_existing(path: PathBuf) -> Result<Self, TrustStoreError> {
        let mut file = OpenOptions::new()
            .read(true)
            .write(true)
            .open(&path)
            .await
            .map_err(|source| io_error("open", source))?;
        let metadata = file
            .metadata()
            .await
            .map_err(|source| io_error("inspect", source))?;
        let file_len = usize::try_from(metadata.len()).unwrap_or(usize::MAX);
        if file_len > MAX_STORE_SIZE {
            return Err(TrustStoreError::StoreTooLarge {
                actual: file_len,
                maximum: MAX_STORE_SIZE,
            });
        }

        let mut bytes = Vec::with_capacity(file_len);
        (&mut file)
            .take(
                u64::try_from(MAX_STORE_SIZE)
                    .unwrap_or(u64::MAX)
                    .saturating_add(1),
            )
            .read_to_end(&mut bytes)
            .await
            .map_err(|source| io_error("read", source))?;
        if bytes.len() > MAX_STORE_SIZE {
            return Err(TrustStoreError::StoreTooLarge {
                actual: bytes.len(),
                maximum: MAX_STORE_SIZE,
            });
        }
        let replay = replay(&bytes)?;
        if replay.valid_len != bytes.len() {
            file.set_len(u64::try_from(replay.valid_len).unwrap_or(u64::MAX))
                .await
                .map_err(|source| io_error("truncate incomplete tail", source))?;
            file.sync_data()
                .await
                .map_err(|source| io_error("sync recovered journal", source))?;
        }
        file.seek(SeekFrom::Start(
            u64::try_from(replay.valid_len).unwrap_or(u64::MAX),
        ))
        .await
        .map_err(|source| io_error("seek", source))?;

        Ok(Self::from_parts(
            path,
            file,
            replay.decisions,
            replay.valid_len,
            replay.record_count,
        ))
    }

    fn from_parts(
        path: PathBuf,
        file: File,
        decisions: BTreeMap<DeviceId, StoredDecision>,
        file_len: usize,
        record_count: usize,
    ) -> Self {
        Self {
            path,
            inner: Mutex::new(StoreInner {
                file,
                decisions,
                file_len,
                record_count,
                poisoned: false,
                #[cfg(test)]
                fail_next_append: false,
            }),
        }
    }

    async fn commit(&self, mutation: TrustMutation) -> Result<(), TrustStoreError> {
        validate_mutation(&mutation)?;
        let payload = postcard::to_stdvec(&mutation).map_err(TrustStoreError::Encode)?;
        if payload.len() > MAX_RECORD_LEN {
            return Err(TrustStoreError::RecordTooLarge {
                record: 0,
                actual: payload.len(),
                maximum: MAX_RECORD_LEN,
            });
        }
        let record = encode_record(&payload)?;

        let mut inner = self.inner.lock().await;
        if inner.poisoned {
            return Err(TrustStoreError::StorePoisoned);
        }
        if let TrustMutation::Trust { peer } = &mutation
            && matches!(
                inner.decisions.get(&peer.device_id),
                Some(StoredDecision::Revoked)
            )
        {
            return Err(TrustStoreError::RevokedIdentity(peer.device_id));
        }
        if inner.record_count >= MAX_RECORDS {
            return Err(TrustStoreError::TooManyRecords {
                maximum: MAX_RECORDS,
            });
        }
        let next_len = inner.file_len.saturating_add(record.len());
        if next_len > MAX_STORE_SIZE {
            return Err(TrustStoreError::StoreTooLarge {
                actual: next_len,
                maximum: MAX_STORE_SIZE,
            });
        }

        #[cfg(test)]
        if inner.fail_next_append {
            inner.fail_next_append = false;
            return Err(io_error(
                "append",
                io::Error::other("injected append failure"),
            ));
        }

        if let Err(error) = persist_record(&mut inner.file, &record).await {
            inner.poisoned = true;
            let previous_len = inner.file_len;
            let _rollback_result = inner
                .file
                .set_len(u64::try_from(previous_len).unwrap_or(u64::MAX))
                .await;
            return Err(error);
        }

        apply_mutation(&mut inner.decisions, &mutation);
        inner.file_len = next_len;
        inner.record_count += 1;
        Ok(())
    }

    #[cfg(test)]
    async fn inject_append_failure(&self) {
        self.inner.lock().await.fail_next_append = true;
    }
}

struct ReplayResult {
    decisions: BTreeMap<DeviceId, StoredDecision>,
    valid_len: usize,
    record_count: usize,
}

fn replay(bytes: &[u8]) -> Result<ReplayResult, TrustStoreError> {
    validate_header(bytes)?;
    let mut decisions = BTreeMap::new();
    let mut offset = HEADER_LEN;
    let mut record_count = 0;

    while offset < bytes.len() {
        let record_offset = offset;
        if bytes.len() - offset < LENGTH_PREFIX_LEN {
            break;
        }
        let declared = usize::try_from(u32::from_be_bytes([
            bytes[offset],
            bytes[offset + 1],
            bytes[offset + 2],
            bytes[offset + 3],
        ]))
        .unwrap_or(usize::MAX);
        if declared > MAX_RECORD_LEN {
            return Err(TrustStoreError::RecordTooLarge {
                record: record_count,
                actual: declared,
                maximum: MAX_RECORD_LEN,
            });
        }
        let record_len = LENGTH_PREFIX_LEN
            .checked_add(declared)
            .and_then(|length| length.checked_add(CHECKSUM_LEN))
            .unwrap_or(usize::MAX);
        if bytes.len() - offset < record_len {
            break;
        }
        if record_count >= MAX_RECORDS {
            return Err(TrustStoreError::TooManyRecords {
                maximum: MAX_RECORDS,
            });
        }

        offset += LENGTH_PREFIX_LEN;
        let payload_end = offset + declared;
        let payload = &bytes[offset..payload_end];
        let checksum_end = payload_end + CHECKSUM_LEN;
        let checksum = &bytes[payload_end..checksum_end];
        if checksum != blake3::hash(payload).as_bytes() {
            return Err(TrustStoreError::CorruptRecord {
                record: record_count,
                offset: record_offset,
                reason: "checksum mismatch",
            });
        }
        let (mutation, remaining): (TrustMutation, &[u8]) = postcard::take_from_bytes(payload)
            .map_err(|_| TrustStoreError::CorruptRecord {
                record: record_count,
                offset: record_offset,
                reason: "invalid mutation encoding",
            })?;
        if !remaining.is_empty() {
            return Err(TrustStoreError::CorruptRecord {
                record: record_count,
                offset: record_offset,
                reason: "trailing mutation bytes",
            });
        }
        validate_mutation(&mutation).map_err(|_| TrustStoreError::CorruptRecord {
            record: record_count,
            offset: record_offset,
            reason: "invalid trusted-peer metadata",
        })?;
        apply_mutation(&mut decisions, &mutation);
        record_count += 1;
        offset = checksum_end;
    }

    Ok(ReplayResult {
        decisions,
        valid_len: offset,
        record_count,
    })
}

fn validate_header(bytes: &[u8]) -> Result<(), TrustStoreError> {
    if bytes.len() < HEADER_LEN {
        return Err(TrustStoreError::TruncatedHeader {
            actual: bytes.len(),
            expected: HEADER_LEN,
        });
    }
    if &bytes[..JOURNAL_MAGIC.len()] != JOURNAL_MAGIC {
        return Err(TrustStoreError::InvalidMagic);
    }
    let version = u16::from_be_bytes([bytes[JOURNAL_MAGIC.len()], bytes[JOURNAL_MAGIC.len() + 1]]);
    if version != JOURNAL_VERSION {
        return Err(TrustStoreError::UnsupportedVersion(version));
    }
    Ok(())
}

fn validate_mutation(mutation: &TrustMutation) -> Result<(), TrustStoreError> {
    if let TrustMutation::Trust { peer } = mutation {
        validate_peer(peer)?;
    }
    Ok(())
}

fn validate_peer(peer: &TrustedPeer) -> Result<(), TrustStoreError> {
    for (field, actual, maximum) in [
        ("device_name", peer.device_name.len(), MAX_DEVICE_NAME_LEN),
        ("platform", peer.platform.len(), MAX_PLATFORM_LEN),
    ] {
        if actual > maximum {
            return Err(TrustStoreError::MetadataTooLong {
                field,
                actual,
                maximum,
            });
        }
    }
    Ok(())
}

fn apply_mutation(decisions: &mut BTreeMap<DeviceId, StoredDecision>, mutation: &TrustMutation) {
    match mutation {
        TrustMutation::Trust { peer } => {
            decisions.insert(peer.device_id, StoredDecision::Trusted(peer.clone()));
        }
        TrustMutation::Revoke { device_id } => {
            decisions.insert(*device_id, StoredDecision::Revoked);
        }
        TrustMutation::Forget { device_id } => {
            decisions.remove(device_id);
        }
    }
}

fn encode_record(payload: &[u8]) -> Result<Vec<u8>, TrustStoreError> {
    let length = u32::try_from(payload.len()).map_err(|_| TrustStoreError::RecordTooLarge {
        record: 0,
        actual: payload.len(),
        maximum: MAX_RECORD_LEN,
    })?;
    let mut record = Vec::with_capacity(LENGTH_PREFIX_LEN + payload.len() + CHECKSUM_LEN);
    record.extend_from_slice(&length.to_be_bytes());
    record.extend_from_slice(payload);
    record.extend_from_slice(blake3::hash(payload).as_bytes());
    Ok(record)
}

async fn write_header(file: &mut File) -> Result<(), TrustStoreError> {
    file.write_all(JOURNAL_MAGIC)
        .await
        .map_err(|source| io_error("write header", source))?;
    file.write_all(&JOURNAL_VERSION.to_be_bytes())
        .await
        .map_err(|source| io_error("write header", source))?;
    file.flush()
        .await
        .map_err(|source| io_error("flush header", source))?;
    file.sync_data()
        .await
        .map_err(|source| io_error("sync header", source))
}

async fn persist_record(file: &mut File, record: &[u8]) -> Result<(), TrustStoreError> {
    file.write_all(record)
        .await
        .map_err(|source| io_error("append", source))?;
    file.flush()
        .await
        .map_err(|source| io_error("flush", source))?;
    file.sync_data()
        .await
        .map_err(|source| io_error("sync", source))
}

fn io_error(operation: &'static str, source: io::Error) -> TrustStoreError {
    TrustStoreError::Io { operation, source }
}

#[cfg(test)]
mod tests {
    use std::error::Error;

    use rift_core::DEVICE_ID_LEN;
    use tempfile::TempDir;
    use tokio::fs;

    use super::*;

    type TestResult<T = ()> = Result<T, Box<dyn Error + Send + Sync>>;

    fn device_id(byte: u8) -> DeviceId {
        DeviceId::from_bytes([byte; DEVICE_ID_LEN])
    }

    fn peer(byte: u8, name: &str) -> TrustedPeer {
        TrustedPeer {
            device_id: device_id(byte),
            device_name: name.to_owned(),
            platform: "test-platform".to_owned(),
        }
    }

    fn store_path(directory: &TempDir) -> PathBuf {
        directory.path().join("trust.journal")
    }

    async fn append_bytes(path: &Path, bytes: &[u8]) -> TestResult {
        let mut file = OpenOptions::new().append(true).open(path).await?;
        file.write_all(bytes).await?;
        file.flush().await?;
        Ok(())
    }

    #[tokio::test]
    async fn creates_and_reopens_empty_store() -> TestResult {
        let directory = TempDir::new()?;
        let path = store_path(&directory);
        let store = TrustStore::open(&path).await?;
        assert_eq!(store.path(), path);
        assert!(store.list().await.is_empty());
        drop(store);

        let reopened = TrustStore::open(&path).await?;
        assert!(reopened.list().await.is_empty());
        assert_eq!(fs::metadata(path).await?.len(), HEADER_LEN as u64);
        Ok(())
    }

    #[tokio::test]
    async fn trust_revoke_and_forget_survive_reopen() -> TestResult {
        let directory = TempDir::new()?;
        let path = store_path(&directory);
        let store = TrustStore::open(&path).await?;
        let trusted = peer(1, "peer one");
        store.trust(trusted.clone()).await?;
        assert_eq!(
            store.state(trusted.device_id).await,
            Some(TrustState::Trusted)
        );
        assert_eq!(store.peer(trusted.device_id).await, Some(trusted.clone()));
        drop(store);

        let store = TrustStore::open(&path).await?;
        assert_eq!(store.peer(trusted.device_id).await, Some(trusted.clone()));
        store.revoke(trusted.device_id).await?;
        assert_eq!(
            store.state(trusted.device_id).await,
            Some(TrustState::Revoked)
        );
        assert_eq!(store.peer(trusted.device_id).await, None);
        drop(store);

        let store = TrustStore::open(&path).await?;
        assert_eq!(
            store.state(trusted.device_id).await,
            Some(TrustState::Revoked)
        );
        store.forget(trusted.device_id).await?;
        drop(store);

        let store = TrustStore::open(&path).await?;
        assert_eq!(store.state(trusted.device_id).await, None);
        assert_eq!(store.peer(trusted.device_id).await, None);
        Ok(())
    }

    #[tokio::test]
    async fn last_mutation_wins_for_duplicate_and_multiple_peers() -> TestResult {
        let directory = TempDir::new()?;
        let path = store_path(&directory);
        let store = TrustStore::open(&path).await?;
        store.trust(peer(1, "old name")).await?;
        store.trust(peer(2, "second")).await?;
        store.trust(peer(1, "new name")).await?;
        store.revoke(device_id(2)).await?;
        store.revoke(device_id(2)).await?;
        store.revoke(device_id(3)).await?;

        assert_eq!(store.peer(device_id(1)).await, Some(peer(1, "new name")));
        assert_eq!(store.state(device_id(2)).await, Some(TrustState::Revoked));
        assert_eq!(store.state(device_id(3)).await, Some(TrustState::Revoked));
        let entries = store.list().await;
        assert_eq!(entries.len(), 3);
        assert_eq!(entries[0].device_id(), device_id(1));
        assert_eq!(entries[0].state(), TrustState::Trusted);
        drop(store);

        let reopened = TrustStore::open(path).await?;
        assert_eq!(reopened.list().await, entries);
        Ok(())
    }

    #[tokio::test]
    async fn malformed_headers_and_versions_fail_closed() -> TestResult {
        let directory = TempDir::new()?;
        let truncated_path = directory.path().join("truncated");
        fs::write(&truncated_path, &JOURNAL_MAGIC[..4]).await?;
        assert!(matches!(
            TrustStore::open(truncated_path).await,
            Err(TrustStoreError::TruncatedHeader { .. })
        ));

        let magic_path = directory.path().join("magic");
        let mut invalid_magic = [0_u8; HEADER_LEN];
        invalid_magic[8..].copy_from_slice(&JOURNAL_VERSION.to_be_bytes());
        fs::write(&magic_path, invalid_magic).await?;
        assert!(matches!(
            TrustStore::open(magic_path).await,
            Err(TrustStoreError::InvalidMagic)
        ));

        let version_path = directory.path().join("version");
        let mut unsupported = JOURNAL_MAGIC.to_vec();
        unsupported.extend_from_slice(&(JOURNAL_VERSION + 1).to_be_bytes());
        fs::write(&version_path, unsupported).await?;
        assert!(matches!(
            TrustStore::open(version_path).await,
            Err(TrustStoreError::UnsupportedVersion(2))
        ));
        Ok(())
    }

    #[tokio::test]
    async fn oversized_record_declaration_is_rejected_before_payload_allocation() -> TestResult {
        let directory = TempDir::new()?;
        let path = store_path(&directory);
        drop(TrustStore::open(&path).await?);
        append_bytes(&path, &(MAX_RECORD_LEN as u32 + 1).to_be_bytes()).await?;

        assert!(matches!(
            TrustStore::open(path).await,
            Err(TrustStoreError::RecordTooLarge { actual, maximum, .. })
                if actual == MAX_RECORD_LEN + 1 && maximum == MAX_RECORD_LEN
        ));
        Ok(())
    }

    #[tokio::test]
    async fn checksum_mismatch_and_middle_corruption_fail_closed() -> TestResult {
        let directory = TempDir::new()?;
        let checksum_path = directory.path().join("checksum");
        let store = TrustStore::open(&checksum_path).await?;
        store.trust(peer(1, "first")).await?;
        drop(store);
        let mut bytes = fs::read(&checksum_path).await?;
        let last = bytes.len() - 1;
        bytes[last] ^= 0xff;
        fs::write(&checksum_path, bytes).await?;
        assert!(matches!(
            TrustStore::open(checksum_path).await,
            Err(TrustStoreError::CorruptRecord { record: 0, .. })
        ));

        let middle_path = directory.path().join("middle");
        let store = TrustStore::open(&middle_path).await?;
        store.trust(peer(1, "first")).await?;
        store.trust(peer(2, "second")).await?;
        drop(store);
        let mut bytes = fs::read(&middle_path).await?;
        bytes[HEADER_LEN + LENGTH_PREFIX_LEN] ^= 0x01;
        fs::write(&middle_path, bytes).await?;
        assert!(matches!(
            TrustStore::open(middle_path).await,
            Err(TrustStoreError::CorruptRecord { record: 0, .. })
        ));
        Ok(())
    }

    #[tokio::test]
    async fn incomplete_final_record_recovers_through_prior_commit() -> TestResult {
        let directory = TempDir::new()?;
        let path = store_path(&directory);
        let store = TrustStore::open(&path).await?;
        store.trust(peer(1, "committed")).await?;
        drop(store);
        let committed_len = fs::metadata(&path).await?.len();
        let payload = postcard::to_stdvec(&TrustMutation::Trust {
            peer: peer(2, "partial"),
        })?;
        let record = encode_record(&payload)?;
        append_bytes(&path, &record[..record.len() - 1]).await?;

        let reopened = TrustStore::open(&path).await?;
        assert_eq!(
            reopened.state(device_id(1)).await,
            Some(TrustState::Trusted)
        );
        assert_eq!(reopened.state(device_id(2)).await, None);
        assert_eq!(fs::metadata(path).await?.len(), committed_len);
        Ok(())
    }

    #[tokio::test]
    async fn incomplete_length_prefix_is_ignored_and_truncated() -> TestResult {
        let directory = TempDir::new()?;
        let path = store_path(&directory);
        drop(TrustStore::open(&path).await?);
        append_bytes(&path, &[0, 0, 0]).await?;

        let reopened = TrustStore::open(&path).await?;
        assert!(reopened.list().await.is_empty());
        assert_eq!(fs::metadata(path).await?.len(), HEADER_LEN as u64);
        Ok(())
    }

    #[tokio::test]
    async fn revocation_is_sticky_until_explicit_forget() -> TestResult {
        let directory = TempDir::new()?;
        let store = TrustStore::open(store_path(&directory)).await?;
        store.revoke(device_id(1)).await?;
        assert!(matches!(
            store.trust(peer(1, "blocked")).await,
            Err(TrustStoreError::RevokedIdentity(revoked)) if revoked == device_id(1)
        ));
        assert_eq!(store.state(device_id(1)).await, Some(TrustState::Revoked));

        store.forget(device_id(1)).await?;
        store.trust(peer(1, "allowed after forget")).await?;
        assert_eq!(store.state(device_id(1)).await, Some(TrustState::Trusted));
        Ok(())
    }

    #[tokio::test]
    async fn failed_append_does_not_change_visible_state() -> TestResult {
        let directory = TempDir::new()?;
        let store = TrustStore::open(store_path(&directory)).await?;
        store.inject_append_failure().await;
        assert!(matches!(
            store.trust(peer(1, "not committed")).await,
            Err(TrustStoreError::Io {
                operation: "append",
                ..
            })
        ));
        assert_eq!(store.state(device_id(1)).await, None);
        assert!(store.list().await.is_empty());
        Ok(())
    }

    #[tokio::test]
    async fn peer_metadata_is_bounded_before_persistence() -> TestResult {
        let directory = TempDir::new()?;
        let path = store_path(&directory);
        let store = TrustStore::open(&path).await?;
        let initial_len = fs::metadata(&path).await?.len();
        let mut oversized_name = peer(1, &"x".repeat(MAX_DEVICE_NAME_LEN + 1));
        assert!(matches!(
            store.trust(oversized_name.clone()).await,
            Err(TrustStoreError::MetadataTooLong {
                field: "device_name",
                ..
            })
        ));
        oversized_name.device_name = "valid".to_owned();
        oversized_name.platform = "x".repeat(MAX_PLATFORM_LEN + 1);
        assert!(matches!(
            store.trust(oversized_name).await,
            Err(TrustStoreError::MetadataTooLong {
                field: "platform",
                ..
            })
        ));
        assert_eq!(fs::metadata(path).await?.len(), initial_len);
        Ok(())
    }

    #[test]
    fn journal_schema_contains_only_public_peer_state() {
        let mutation = TrustMutation::Trust {
            peer: peer(7, "display metadata"),
        };
        let debug = format!("{mutation:?}");
        assert!(debug.contains("DeviceId"));
        assert!(!debug.contains("SecretKey"));
        assert_eq!(JOURNAL_VERSION, 1);
    }
}
