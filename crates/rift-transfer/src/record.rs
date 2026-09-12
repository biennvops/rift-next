//! Private on-disk transfer record encoding; no filesystem or durability operations.

use rift_core::{DeviceId, SourcePath, TransferId};
use rift_protocol::{TransferMetadata, TransferTerminalStatus};
use serde::{Deserialize, Serialize};
use thiserror::Error;
use tokio::io::{AsyncRead, AsyncReadExt};

use crate::{AttemptControl, TransferIoError};

/// Maximum Postcard payload length for any manifest or monotonic marker.
pub const MAX_TRANSFER_RECORD_PAYLOAD_LEN: usize = 8 * 1024;
const MAGIC: &[u8; 8] = b"RIFTXFER";
const VERSION: u16 = 1;
const HEADER_LEN: usize = 14;
const CHECKSUM_LEN: usize = 32;
/// Maximum complete record length, including header and checksum.
pub const MAX_TRANSFER_RECORD_LEN: usize =
    HEADER_LEN + MAX_TRANSFER_RECORD_PAYLOAD_LEN + CHECKSUM_LEN;

/// Persisted role; only an outgoing record can contain a local source path.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub enum ManifestSource {
    /// Locally offered file, whose private path is needed after restart.
    Outgoing(SourcePath),
    /// Remotely offered file; this is not evidence of local acceptance.
    Incoming,
}

/// Immutable active-transfer identity and metadata, without ephemeral progress.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct TransferManifest {
    /// Stable logical identifier, checked against the state-directory name by storage.
    pub transfer_id: TransferId,
    /// Durable remote identity, reconciled against trust before replay.
    pub peer: DeviceId,
    /// Exact immutable filename, byte length, and whole-file digest.
    pub metadata: TransferMetadata,
    /// Direction and, only for outgoing files, the redacted local source path.
    pub source: ManifestSource,
}

/// Which side decided a persisted terminal outcome.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub enum TerminalOrigin {
    /// Replay Terminal until the remote peer acknowledges it.
    Local,
    /// Acknowledge the peer's outcome and settle; do not originate another Terminal.
    Peer,
}

/// One complete immutable manifest or monotonic marker file.
///
/// Markers bind to the BLAKE3 digest of the complete encoded manifest, including its
/// envelope. This detects accidental marker substitution across peers, IDs, metadata,
/// or source paths. It is not authentication against a writer with local disk access.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub enum TransferRecord {
    /// Postcard discriminant zero; must be stored as `manifest`.
    Manifest(TransferManifest),
    /// Discriminant one; an incoming decision stored as `accepted` before payload I/O.
    Accepted {
        /// Digest returned by `TransferManifest::record_digest`.
        manifest_digest: [u8; 32],
    },
    /// Discriminant two; stored as `terminal`, never rewritten to another outcome.
    Terminal {
        /// Digest returned by `TransferManifest::record_digest`.
        manifest_digest: [u8; 32],
        /// Path-free wire-compatible terminal outcome.
        status: TransferTerminalStatus,
        /// Controls terminal replay versus acknowledgement after recovery.
        origin: TerminalOrigin,
    },
}

impl TransferManifest {
    /// Computes the binding for this exact versioned immutable manifest record.
    pub fn record_digest(&self) -> Result<[u8; 32], TransferRecordError> {
        let bytes = encode_transfer_record(&TransferRecord::Manifest(self.clone()))?;
        Ok(*blake3::hash(&bytes).as_bytes())
    }
}

impl TransferRecord {
    /// Validates a marker's manifest binding and sender/receiver role.
    ///
    /// The store must additionally check the expected filename/record kind, local
    /// acceptance before incoming completion, output integrity/publication, and trust.
    /// This method neither grants acceptance nor recovers a logical state machine.
    pub fn validate_marker(&self, manifest: &TransferManifest) -> Result<(), TransferRecordError> {
        let binding = match self {
            Self::Manifest(_) => return Err(TransferRecordError::NotMarker),
            Self::Accepted { manifest_digest }
            | Self::Terminal {
                manifest_digest, ..
            } => manifest_digest,
        };
        if binding != &manifest.record_digest()? {
            return Err(TransferRecordError::ManifestMismatch);
        }
        let incoming = matches!(manifest.source, ManifestSource::Incoming);
        match self {
            Self::Accepted { .. } if !incoming => Err(TransferRecordError::InvalidRole),
            Self::Terminal {
                status: TransferTerminalStatus::Completed | TransferTerminalStatus::Rejected,
                origin,
                ..
            } if incoming != (*origin == TerminalOrigin::Local) => {
                Err(TransferRecordError::InvalidRole)
            }
            _ => Ok(()),
        }
    }
}

/// Encodes one private record with fixed-capacity scratch storage.
///
/// Returned bytes may contain a local source path and must never be logged or sent
/// over the network. The caller owns private permissions, atomic creation, and sync.
pub fn encode_transfer_record(record: &TransferRecord) -> Result<Vec<u8>, TransferRecordError> {
    let mut scratch = [0; MAX_TRANSFER_RECORD_PAYLOAD_LEN];
    let payload =
        postcard::to_slice(record, &mut scratch).map_err(|_| TransferRecordError::Encode)?;
    let mut bytes = Vec::with_capacity(HEADER_LEN + payload.len() + CHECKSUM_LEN);
    bytes.extend_from_slice(MAGIC);
    bytes.extend_from_slice(&VERSION.to_be_bytes());
    bytes.extend_from_slice(&(payload.len() as u32).to_be_bytes());
    bytes.extend_from_slice(payload);
    let checksum = blake3::hash(&bytes);
    bytes.extend_from_slice(checksum.as_bytes());
    Ok(bytes)
}

/// Decodes exactly one bounded, checksummed private file; no trailing bytes allowed.
///
/// Checks header, length, and checksum before deserializing any owned path/filename.
/// A filesystem caller must bound its read by `MAX_TRANSFER_RECORD_LEN` rather than
/// read an untrusted file to an unbounded Vec before invoking this function.
pub fn decode_transfer_record(bytes: &[u8]) -> Result<TransferRecord, TransferRecordError> {
    let header = bytes.get(..HEADER_LEN).ok_or(TransferRecordError::Length)?;
    let length = payload_length(header)?;
    if bytes.len() != HEADER_LEN + length + CHECKSUM_LEN {
        return Err(TransferRecordError::Length);
    }
    let checksum_start = HEADER_LEN + length;
    if blake3::hash(&bytes[..checksum_start]).as_bytes() != &bytes[checksum_start..] {
        return Err(TransferRecordError::Checksum);
    }
    let (record, trailing) = postcard::take_from_bytes(&bytes[HEADER_LEN..checksum_start])
        .map_err(|_| TransferRecordError::Decode)?;
    if !trailing.is_empty() {
        return Err(TransferRecordError::TrailingPayload);
    }
    Ok(record)
}

fn payload_length(header: &[u8]) -> Result<usize, TransferRecordError> {
    if &header[..8] != MAGIC {
        return Err(TransferRecordError::Magic);
    }
    if u16::from_be_bytes([header[8], header[9]]) != VERSION {
        return Err(TransferRecordError::Version);
    }
    let length = u32::from_be_bytes([header[10], header[11], header[12], header[13]]) as usize;
    if length > MAX_TRANSFER_RECORD_PAYLOAD_LEN {
        return Err(TransferRecordError::TooLarge);
    }
    if length == 0 {
        return Err(TransferRecordError::Length);
    }
    Ok(length)
}

/// Reads exactly one bounded record from an already-open private state file.
///
/// Header limits are checked before allocating or reading the body. At most one
/// extra byte is read to reject trailing file contents. Cancellation or a partial
/// read error invalidates this operation: restart only after seeking/reopening the
/// file, not at the interrupted cursor. Each partial read resets the idle deadline.
///
/// The caller must validate that the handle is a regular private file, reject
/// symlinks/nonregular state entries, enforce store record counts, and own/join
/// the work. This routine opens no paths and grants no recovery authorization.
pub async fn read_transfer_record<R: AsyncRead + Unpin>(
    reader: &mut R,
    control: &mut AttemptControl,
) -> Result<TransferRecord, TransferRecordError> {
    let mut header = [0; HEADER_LEN];
    read_record_bytes(reader, &mut header, control).await?;
    let length = payload_length(&header)?;
    let mut bytes = vec![0; HEADER_LEN + length + CHECKSUM_LEN];
    bytes[..HEADER_LEN].copy_from_slice(&header);
    read_record_bytes(reader, &mut bytes[HEADER_LEN..], control).await?;
    let mut extra = [0];
    let count = control
        .step(reader.read(&mut extra))
        .await?
        .map_err(|error| TransferIoError::LocalIo(error.kind()))?;
    if count != 0 {
        return Err(TransferRecordError::Length);
    }
    decode_transfer_record(&bytes)
}

async fn read_record_bytes<R: AsyncRead + Unpin>(
    reader: &mut R,
    mut bytes: &mut [u8],
    control: &mut AttemptControl,
) -> Result<(), TransferRecordError> {
    while !bytes.is_empty() {
        let count = control
            .step(reader.read(bytes))
            .await?
            .map_err(|error| TransferIoError::LocalIo(error.kind()))?;
        if count == 0 {
            return Err(TransferRecordError::Length);
        }
        bytes = &mut bytes[count..];
    }
    Ok(())
}

/// Fail-closed private record errors, without raw payload bytes or path diagnostics.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum TransferRecordError {
    /// Local file I/O, cancellation, or the per-read idle deadline failed.
    #[error("transfer record read failed: {0}")]
    Io(#[from] TransferIoError),
    /// An incomplete, empty, or incorrectly sized complete envelope.
    #[error("transfer record length mismatch")]
    Length,
    /// The envelope is not a transfer-state file.
    #[error("invalid transfer record magic")]
    Magic,
    /// No forward-compatible guessing is permitted for private state versions.
    #[error("unsupported transfer record version")]
    Version,
    /// The declared length exceeds the independent 8 KiB bound.
    #[error("transfer record payload exceeds 8 KiB")]
    TooLarge,
    /// Header or payload bytes disagree with the stored checksum.
    #[error("transfer record checksum mismatch")]
    Checksum,
    /// Malformed Postcard, unsupported variants, or invalid bounded domain values.
    #[error("invalid transfer record payload")]
    Decode,
    /// Extra bytes follow a valid value inside the checksummed payload.
    #[error("trailing transfer record payload")]
    TrailingPayload,
    /// Serialization failed within the fixed record bound.
    #[error("transfer record encoding failed")]
    Encode,
    /// A manifest was supplied where a monotonic marker is required.
    #[error("transfer record is not a marker")]
    NotMarker,
    /// A marker belongs to a different immutable manifest.
    #[error("transfer marker does not match manifest")]
    ManifestMismatch,
    /// Acceptance/completion/rejection is attributed to the sender rather than receiver.
    #[error("transfer marker has invalid sender or receiver role")]
    InvalidRole,
}

#[cfg(test)]
mod tests;
