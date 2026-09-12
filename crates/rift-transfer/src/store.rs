//! Read-only validation of private active-transfer state before daemon recovery.

use std::{collections::BTreeMap, fs::Metadata, io, path::Path};

use rift_core::{DeviceId, TransferId};
use rift_protocol::TransferTerminalStatus;
use thiserror::Error;
use tokio::fs;

use crate::{
    AttemptControl, MAX_TRANSFER_RECORD_LEN, ManifestSource, TerminalOrigin, TransferIoError,
    TransferManifest, TransferRecord, TransferRecordError, read_transfer_record,
};

/// Hard bound on durable active records, including terminal receipts awaiting settlement.
pub const MAX_DURABLE_TRANSFERS: usize = 4096;
/// Hard bound on durable records for one peer, independent of worker capacity.
pub const MAX_DURABLE_TRANSFERS_PER_PEER: usize = 64;

/// Structurally validated disk state, not authorized runtime state or proof of output integrity.
///
/// Only the scanner can construct this value. The daemon must reconcile current durable
/// trust and partial/final files before restoring logical transfers or announcing readiness.
#[derive(Debug)]
pub struct StoredTransfer {
    manifest: TransferManifest,
    accepted: bool,
    terminal: Option<(TransferTerminalStatus, TerminalOrigin)>,
}

impl StoredTransfer {
    /// Immutable manifest, validated against the enclosing transfer-ID directory name.
    pub const fn manifest(&self) -> &TransferManifest {
        &self.manifest
    }

    /// Whether a valid receiver acceptance marker exists on disk.
    pub const fn accepted(&self) -> bool {
        self.accepted
    }

    /// Persisted terminal decision and its origin, if present.
    pub const fn terminal(&self) -> Option<(TransferTerminalStatus, TerminalOrigin)> {
        self.terminal
    }
}

/// Scans an existing `transfers/state` directory under the locked private data directory.
///
/// At most 4096 canonical ID directories, 64 per peer, and three named files per
/// directory are accepted. No partial snapshot is returned on any failure. Entries
/// are inspected incrementally, never collected into an unbounded directory listing.
/// The result is ordered by TransferId and contains no tasks or open file handles.
///
/// Unix directories/files must be exactly 0700/0600. Symlinks, Windows reparse points,
/// nonregular files, and Unix multiply-linked records fail closed. The caller owns
/// the private ancestors and singleton lock and must exclude concurrent mutations
/// for the entire scan; this is not a sandbox against a same-user filesystem attacker.
/// The scanner opens no payload or source files and creates, repairs, or deletes nothing.
/// Missing directories, incomplete records, and unknown temporary entries are errors,
/// not permission to forget durable acceptance or silently recreate the store.
pub async fn scan_transfer_state(
    state_directory: &Path,
    control: &mut AttemptControl,
) -> Result<BTreeMap<TransferId, StoredTransfer>, TransferStoreError> {
    validate_directory(state_directory, control).await?;
    let mut entries = control
        .step(fs::read_dir(state_directory))
        .await?
        .map_err(local_io)?;
    let mut records = BTreeMap::new();
    let mut peer_counts = BTreeMap::<DeviceId, usize>::new();
    while let Some(entry) = control
        .step(entries.next_entry())
        .await?
        .map_err(local_io)?
    {
        if records.len() == MAX_DURABLE_TRANSFERS {
            return Err(TransferStoreError::RecordLimit);
        }
        let name = entry.file_name();
        let id: TransferId = name
            .to_str()
            .ok_or(TransferStoreError::InvalidEntry)?
            .parse()
            .map_err(|_| TransferStoreError::InvalidEntry)?;
        let record = scan_record(&entry.path(), id, control).await?;
        let count = peer_counts.entry(record.manifest.peer).or_default();
        if *count == MAX_DURABLE_TRANSFERS_PER_PEER {
            return Err(TransferStoreError::PeerRecordLimit);
        }
        *count += 1;
        if records.insert(id, record).is_some() {
            return Err(TransferStoreError::InvalidEntry);
        }
    }
    Ok(records)
}

async fn scan_record(
    directory: &Path,
    id: TransferId,
    control: &mut AttemptControl,
) -> Result<StoredTransfer, TransferStoreError> {
    validate_directory(directory, control).await?;
    let mut entries = control
        .step(fs::read_dir(directory))
        .await?
        .map_err(local_io)?;
    let mut manifest = None;
    let mut accepted = None;
    let mut terminal = None;
    let mut count = 0;
    while let Some(entry) = control
        .step(entries.next_entry())
        .await?
        .map_err(local_io)?
    {
        count += 1;
        if count > 3 {
            return Err(TransferStoreError::InvalidEntry);
        }
        let name = entry.file_name();
        let name = name.to_str().ok_or(TransferStoreError::InvalidEntry)?;
        if !matches!(name, "manifest" | "accepted" | "terminal") {
            return Err(TransferStoreError::InvalidEntry);
        }
        let record = read_record(&entry.path(), control).await?;
        match (name, record) {
            ("manifest", TransferRecord::Manifest(value)) if manifest.is_none() => {
                manifest = Some(value)
            }
            ("accepted", value @ TransferRecord::Accepted { .. }) if accepted.is_none() => {
                accepted = Some(value)
            }
            ("terminal", value @ TransferRecord::Terminal { .. }) if terminal.is_none() => {
                terminal = Some(value)
            }
            _ => return Err(TransferStoreError::WrongRecordKind),
        }
    }
    let manifest = manifest.ok_or(TransferStoreError::MissingManifest)?;
    if manifest.transfer_id != id {
        return Err(TransferStoreError::ManifestIdMismatch);
    }
    if let Some(marker) = &accepted {
        marker.validate_marker(&manifest)?;
    }
    let outcome = if let Some(marker) = &terminal {
        marker.validate_marker(&manifest)?;
        let TransferRecord::Terminal { status, origin, .. } = marker else {
            return Err(TransferStoreError::WrongRecordKind);
        };
        if matches!(manifest.source, ManifestSource::Incoming)
            && ((*status == TransferTerminalStatus::Completed && accepted.is_none())
                || (*status == TransferTerminalStatus::Rejected && accepted.is_some()))
        {
            return Err(TransferStoreError::InconsistentMarkers);
        }
        Some((*status, *origin))
    } else {
        None
    };
    Ok(StoredTransfer {
        manifest,
        accepted: accepted.is_some(),
        terminal: outcome,
    })
}

async fn validate_directory(
    path: &Path,
    control: &mut AttemptControl,
) -> Result<(), TransferStoreError> {
    let metadata = control
        .step(fs::symlink_metadata(path))
        .await?
        .map_err(local_io)?;
    if is_link(&metadata) || !metadata.is_dir() {
        return Err(TransferStoreError::UnsafeEntry);
    }
    validate_permissions(&metadata, 0o700)
}

async fn read_record(
    path: &Path,
    control: &mut AttemptControl,
) -> Result<TransferRecord, TransferStoreError> {
    let before = control
        .step(fs::symlink_metadata(path))
        .await?
        .map_err(local_io)?;
    validate_file(&before)?;
    let mut file = control
        .step(fs::File::open(path))
        .await?
        .map_err(local_io)?;
    let opened = control.step(file.metadata()).await?.map_err(local_io)?;
    validate_file(&opened)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        if before.dev() != opened.dev() || before.ino() != opened.ino() {
            return Err(TransferStoreError::UnsafeEntry);
        }
    }
    Ok(read_transfer_record(&mut file, control).await?)
}

fn validate_file(metadata: &Metadata) -> Result<(), TransferStoreError> {
    if is_link(metadata) || !metadata.is_file() {
        return Err(TransferStoreError::UnsafeEntry);
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        if metadata.nlink() != 1 {
            return Err(TransferStoreError::UnsafeEntry);
        }
    }
    validate_permissions(metadata, 0o600)?;
    if metadata.len() > MAX_TRANSFER_RECORD_LEN as u64 {
        return Err(TransferStoreError::RecordTooLarge);
    }
    Ok(())
}

fn is_link(metadata: &Metadata) -> bool {
    #[cfg(windows)]
    {
        use std::os::windows::fs::MetadataExt;
        // FILE_ATTRIBUTE_REPARSE_POINT includes junctions, not just symbolic links.
        metadata.file_attributes() & 0x400 != 0
    }
    #[cfg(not(windows))]
    {
        metadata.file_type().is_symlink()
    }
}

fn validate_permissions(metadata: &Metadata, expected: u32) -> Result<(), TransferStoreError> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if metadata.permissions().mode() & 0o7777 != expected {
            return Err(TransferStoreError::InsecurePermissions);
        }
    }
    #[cfg(not(unix))]
    {
        let _ = (metadata, expected);
    }
    Ok(())
}

fn local_io(error: io::Error) -> TransferIoError {
    TransferIoError::LocalIo(error.kind())
}

/// Fail-closed startup validation errors; no private paths or raw diagnostics.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum TransferStoreError {
    /// Local filesystem I/O, owner cancellation, or idle timeout.
    #[error("transfer store I/O failed: {0}")]
    Io(#[from] TransferIoError),
    /// Corrupt or semantically mismatched record envelope.
    #[error("invalid transfer store record: {0}")]
    Record(#[from] TransferRecordError),
    /// More than 4096 active transfer directories exist.
    #[error("transfer store record limit exceeded")]
    RecordLimit,
    /// More than 64 records belong to one peer.
    #[error("transfer store per-peer record limit exceeded")]
    PeerRecordLimit,
    /// An unknown name, noncanonical ID, duplicate, or extra file was present.
    #[error("unexpected transfer store entry")]
    InvalidEntry,
    /// A symlink, reparse point, nonregular file, or multiply-linked file was present.
    #[error("unsafe transfer store entry")]
    UnsafeEntry,
    /// Unix permissions are not exactly private directory/file modes.
    #[error("insecure transfer store permissions")]
    InsecurePermissions,
    /// A file's on-disk length exceeds the envelope ceiling before reading it.
    #[error("transfer store record exceeds size bound")]
    RecordTooLarge,
    /// A record kind disagrees with its filename.
    #[error("transfer store record kind does not match filename")]
    WrongRecordKind,
    /// No immutable manifest exists for a state directory.
    #[error("transfer state directory has no manifest")]
    MissingManifest,
    /// Manifest identity disagrees with the canonical state-directory name.
    #[error("transfer manifest ID does not match directory")]
    ManifestIdMismatch,
    /// Completed incoming records require acceptance; rejected ones prohibit it.
    #[error("inconsistent transfer acceptance and terminal markers")]
    InconsistentMarkers,
}

#[cfg(test)]
mod tests;
