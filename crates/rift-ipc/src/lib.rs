//! Stable, bounded messages for local Rift daemon control.
//!
//! IPC protocol v1 is independent from the Rift network protocol. Payloads are UTF-8
//! JSON preceded by a four-byte big-endian length. This crate owns no socket, named-pipe,
//! trust-store, session, or Iroh behavior.

use std::{fmt, io, str::Utf8Error};

use rift_core::{DeviceId, TrustState};
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use thiserror::Error;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

/// IPC protocol version implemented by these messages.
pub const IPC_PROTOCOL_VERSION: u16 = 1;

/// Runtime descriptor version implemented by these messages.
pub const RUNTIME_DESCRIPTOR_VERSION: u16 = 1;

/// Maximum JSON payload bytes accepted in one local IPC frame.
pub const MAX_IPC_FRAME_LEN: usize = 256 * 1024;

/// Maximum peer entries permitted in one IPC page.
pub const MAX_PEER_PAGE_SIZE: u16 = 128;

/// A daemon-local pending pairing identifier. It resets on daemon restart.
#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(transparent)]
pub struct PairingAttemptId(pub u64);

/// A daemon-local authorized session identifier. It resets on daemon restart.
#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(transparent)]
pub struct SessionId(pub u64);

/// Messages sent from an authenticated local client to the daemon.
#[derive(Clone, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "type", rename_all = "snake_case", deny_unknown_fields)]
pub enum ClientMessage {
    /// The mandatory first frame on every connection.
    Authenticate {
        /// Independent local IPC protocol version.
        version: u16,
        /// Fresh per-runtime 32-byte token encoded as 64 lowercase hex characters.
        token: String,
    },
    /// One client-selected request identifier and operation.
    Request {
        /// Client-selected response correlation identifier.
        id: u64,
        /// Bounded runtime-management operation.
        request: Request,
    },
}

impl fmt::Debug for ClientMessage {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Authenticate { version, .. } => formatter
                .debug_struct("Authenticate")
                .field("version", version)
                .field("token", &"<redacted>")
                .finish(),
            Self::Request { id, request } => formatter
                .debug_struct("Request")
                .field("id", id)
                .field("request", request)
                .finish(),
        }
    }
}

/// Runtime-management operations available in Foundation M4.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "type", rename_all = "snake_case", deny_unknown_fields)]
pub enum Request {
    /// Returns bounded daemon identity and lifecycle information.
    GetStatus {},
    /// Returns one bounded page of durable peer decisions.
    ListPeers {
        /// Exclusive deterministic `DeviceId` cursor.
        after: Option<DeviceId>,
        /// Requested page size, capped by the daemon.
        limit: u16,
    },
    /// Lists the bounded in-memory authorized-session registry.
    ListSessions {},
    /// Lists the bounded in-memory pending-pairing registry.
    ListPendingPairings {},
    /// Supplies the only local decision that can complete network pairing.
    ConfirmPairing {
        /// Runtime-local pairing handle.
        attempt_id: PairingAttemptId,
        /// Human decision after comparing the displayed SAS.
        accepted: bool,
    },
    /// Durably revokes a peer and invalidates live authorization.
    RevokePeer {
        /// Authenticated cryptographic identity to revoke.
        device_id: DeviceId,
    },
    /// Durably removes a peer decision and invalidates live authorization.
    ForgetPeer {
        /// Authenticated cryptographic identity to forget.
        device_id: DeviceId,
    },
    /// Closes one active authorized session without changing trust.
    DisconnectSession {
        /// Runtime-local session handle.
        session_id: SessionId,
    },
}

/// Messages sent by the daemon after local authentication succeeds.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "type", rename_all = "snake_case", deny_unknown_fields)]
pub enum ServerMessage {
    /// Confirms that the bearer token and version were accepted.
    Authenticated {
        /// Negotiated local IPC version.
        version: u16,
    },
    /// Successful response correlated by request ID.
    Response {
        /// Original client-selected request identifier.
        id: u64,
        /// Typed bounded operation result.
        result: Response,
    },
    /// Failed response correlated by request ID.
    Error {
        /// Original client-selected request identifier.
        id: u64,
        /// Stable error category and bounded explanation.
        error: ErrorResponse,
    },
    /// Unsolicited bounded runtime event.
    Event {
        /// Runtime state change.
        event: Event,
    },
}

/// Successful operation result variants.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "type", rename_all = "snake_case", deny_unknown_fields)]
pub enum Response {
    /// Result of [`Request::GetStatus`].
    Status {
        /// Current bounded status.
        status: Status,
    },
    /// Result of [`Request::ListPeers`].
    Peers {
        /// Deterministically ordered bounded page.
        page: PeerPage,
    },
    /// Result of [`Request::ListSessions`].
    Sessions {
        /// At most the configured active-session bound.
        sessions: Vec<SessionInfo>,
    },
    /// Result of [`Request::ListPendingPairings`].
    PendingPairings {
        /// At most the configured pending-pairing bound.
        pairings: Vec<PendingPairingInfo>,
    },
    /// Pairing reached a terminal local result.
    PairingResolved {
        /// Runtime-local pairing handle.
        attempt_id: PairingAttemptId,
        /// Whether pairing produced an authorized session.
        accepted: bool,
        /// New session when both peers accepted and durable trust committed.
        session_id: Option<SessionId>,
    },
    /// Durable revocation and live invalidation completed.
    PeerRevoked {
        /// Revoked identity.
        device_id: DeviceId,
    },
    /// Durable forget and live invalidation completed.
    PeerForgotten {
        /// Forgotten identity.
        device_id: DeviceId,
    },
    /// The requested session was closed.
    SessionDisconnected {
        /// Closed runtime-local session handle.
        session_id: SessionId,
    },
}

/// Stable local lifecycle states exposed by status.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RuntimeState {
    /// Startup has not published readiness.
    Starting,
    /// Endpoint and IPC are ready.
    Running,
    /// New work is rejected while owned work closes.
    ShuttingDown,
    /// Cleanup and task joins completed.
    Stopped,
    /// A fatal runtime failure initiated shutdown.
    Failed,
}

/// Bounded daemon status returned to authenticated clients.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Status {
    /// Daemon crate version.
    pub daemon_version: String,
    /// Persistent public device identity.
    pub device_id: DeviceId,
    /// Configured local display name.
    pub device_name: String,
    /// Configured local platform display value.
    pub platform: String,
    /// Current explicit lifecycle state.
    pub state: RuntimeState,
    /// Current authorized-session count.
    pub active_sessions: u32,
    /// Current pending-pairing count.
    pub pending_pairings: u32,
    /// Whether this daemon advertises pairing v1.
    pub pairing_enabled: bool,
}

/// One bounded durable trust decision for local presentation.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PeerInfo {
    /// Durable identity key.
    pub device_id: DeviceId,
    /// Current local trust decision.
    pub state: TrustState,
    /// Captured display name for trusted peers only.
    pub device_name: Option<String>,
    /// Captured platform value for trusted peers only.
    pub platform: Option<String>,
}

/// One deterministic, bounded peer page.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PeerPage {
    /// Current page entries.
    pub entries: Vec<PeerInfo>,
    /// Exclusive cursor for another page, or `None` at the end.
    pub next_cursor: Option<DeviceId>,
}

/// Public metadata for one active authorized session.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SessionInfo {
    /// Runtime-local session identifier.
    pub session_id: SessionId,
    /// Authenticated durable peer identity.
    pub device_id: DeviceId,
    /// Captured trusted display name.
    pub device_name: String,
    /// Captured trusted platform value.
    pub platform: String,
}

/// Public metadata for one pairing awaiting or resolving local confirmation.
#[derive(Clone, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PendingPairingInfo {
    /// Runtime-local pairing identifier.
    pub attempt_id: PairingAttemptId,
    /// Authenticated peer identity.
    pub device_id: DeviceId,
    /// Peer-controlled bounded display name.
    pub device_name: String,
    /// Peer-controlled bounded platform value.
    pub platform: String,
    /// Exactly six decimal SAS characters.
    pub verification_code: String,
    /// Saturating time remaining for local confirmation.
    pub timeout_remaining_ms: u64,
}

impl fmt::Debug for PendingPairingInfo {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PendingPairingInfo")
            .field("attempt_id", &self.attempt_id)
            .field("device_id", &self.device_id)
            .field("device_name", &self.device_name)
            .field("platform", &self.platform)
            .field("verification_code", &"<redacted>")
            .field("timeout_remaining_ms", &self.timeout_remaining_ms)
            .finish()
    }
}

/// Terminal pairing outcomes emitted asynchronously.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PairingOutcome {
    /// Both sides accepted, trust committed, and a session opened.
    Accepted,
    /// At least one human rejected the comparison.
    Rejected,
    /// The local confirmation deadline elapsed.
    Expired,
    /// Revocation, forget, or shutdown cancelled the attempt.
    Cancelled,
    /// Transport, protocol, or persistence failed.
    Failed,
}

/// Reasons an authorized runtime session left the registry.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SessionCloseReason {
    /// The underlying disposable connection ended.
    ConnectionClosed,
    /// An authenticated local client requested disconnection.
    Disconnected,
    /// Durable revocation invalidated authorization.
    Revoked,
    /// Durable forget removed authorization.
    Forgotten,
    /// Runtime shutdown closed owned work.
    Shutdown,
}

/// Bounded asynchronous daemon events.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "type", rename_all = "snake_case", deny_unknown_fields)]
pub enum Event {
    /// A pairing code is ready for local comparison.
    PairingPending {
        /// Bounded presentation data.
        pairing: PendingPairingInfo,
    },
    /// A pairing attempt reached a terminal outcome.
    PairingResolved {
        /// Runtime-local pairing identifier.
        attempt_id: PairingAttemptId,
        /// Authenticated peer identity.
        device_id: DeviceId,
        /// Terminal outcome.
        outcome: PairingOutcome,
    },
    /// An authorized session entered the registry.
    SessionOpened {
        /// Bounded session metadata.
        session: SessionInfo,
    },
    /// An authorized session left the registry.
    SessionClosed {
        /// Runtime-local session identifier.
        session_id: SessionId,
        /// Authenticated peer identity.
        device_id: DeviceId,
        /// Why the session ended.
        reason: SessionCloseReason,
    },
    /// Durable local trust changed.
    TrustChanged {
        /// Affected identity.
        device_id: DeviceId,
        /// New decision, or `None` after forget.
        state: Option<TrustState>,
    },
    /// The daemon stopped accepting new operations.
    DaemonShuttingDown,
}

/// Stable operation-error categories for local clients.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ErrorCode {
    /// The request values violate a bounded contract.
    InvalidRequest,
    /// A runtime-local pairing ID is absent or no longer confirmable.
    PairingNotFound,
    /// A runtime-local session ID is absent.
    SessionNotFound,
    /// The peer is not currently trusted for an authenticated dial.
    PeerNotTrusted,
    /// The peer is already trusted and does not need pairing.
    PeerAlreadyTrusted,
    /// A configured runtime resource limit was reached.
    CapacityExceeded,
    /// Durable trust persistence failed.
    PersistenceFailed,
    /// Network bootstrap, admission, or pairing failed.
    ConnectionFailed,
    /// The daemon is no longer accepting operations.
    ShuttingDown,
    /// An internal owned task failed.
    Internal,
}

/// One bounded failed response.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ErrorResponse {
    /// Stable machine-readable category.
    pub code: ErrorCode,
    /// Human-readable bounded explanation.
    pub message: String,
}

impl ErrorResponse {
    /// Creates an operation error from a stable category and explanation.
    pub fn new(code: ErrorCode, message: impl Into<String>) -> Self {
        Self {
            code,
            message: message.into(),
        }
    }
}

/// Local transport types published in `runtime.json`.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum LocalTransport {
    /// Unix-domain socket beneath the private data directory.
    Unix,
    /// Per-runtime Windows named pipe.
    NamedPipe,
}

/// Runtime-local IPC endpoint descriptor.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct LocalEndpointDescriptor {
    /// Platform-local transport implementation.
    pub transport: LocalTransport,
    /// Unix socket path or Windows named-pipe name.
    pub address: String,
}

/// Atomically published local discovery descriptor.
#[derive(Clone, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RuntimeDescriptor {
    /// Descriptor schema version, independent from IPC framing version.
    pub descriptor_version: u16,
    /// Owning daemon process ID.
    pub pid: u32,
    /// Fresh non-security runtime identifier.
    pub runtime_id: String,
    /// Platform-local endpoint.
    pub ipc: LocalEndpointDescriptor,
    /// Fresh per-launch bearer capability encoded as lowercase hex.
    pub auth_token: String,
}

impl fmt::Debug for RuntimeDescriptor {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RuntimeDescriptor")
            .field("descriptor_version", &self.descriptor_version)
            .field("pid", &self.pid)
            .field("runtime_id", &self.runtime_id)
            .field("ipc", &self.ipc)
            .field("auth_token", &"<redacted>")
            .finish()
    }
}

/// Bounded frame encoding and decoding failures.
#[derive(Debug, Error)]
pub enum FrameError {
    /// Reading or writing the local byte stream failed.
    #[error("IPC {operation} failed: {source}")]
    Io {
        /// Bounded stream operation.
        operation: &'static str,
        #[source]
        source: io::Error,
    },
    /// EOF arrived before the complete four-byte prefix.
    #[error("IPC frame prefix is truncated: received {actual} of 4 bytes")]
    TruncatedPrefix {
        /// Prefix bytes received before EOF.
        actual: usize,
    },
    /// The declared frame exceeds the allocation limit.
    #[error("IPC frame declares {actual} bytes; maximum is {maximum}")]
    FrameTooLarge {
        /// Untrusted declared length.
        actual: usize,
        /// Configured hard limit.
        maximum: usize,
    },
    /// EOF arrived before the complete bounded payload.
    #[error("IPC frame payload is truncated: received {actual} of {expected} bytes")]
    TruncatedPayload {
        /// Payload bytes received before EOF.
        actual: usize,
        /// Declared bounded payload length.
        expected: usize,
    },
    /// JSON payload bytes are not UTF-8.
    #[error("IPC payload is not UTF-8: {0}")]
    InvalidUtf8(#[source] Utf8Error),
    /// UTF-8 payload does not match the requested strict JSON schema.
    #[error("IPC payload is invalid JSON: {0}")]
    InvalidJson(#[source] serde_json::Error),
    /// A local value could not be serialized as JSON.
    #[error("unable to encode IPC JSON: {0}")]
    Encode(#[source] serde_json::Error),
}

/// Reads and deserializes one bounded IPC frame.
pub async fn read_json_frame<R, T>(reader: &mut R) -> Result<T, FrameError>
where
    R: AsyncRead + Unpin,
    T: DeserializeOwned,
{
    read_json_frame_with_limit(reader, MAX_IPC_FRAME_LEN).await
}

/// Serializes and writes one bounded IPC frame.
pub async fn write_json_frame<W, T>(writer: &mut W, value: &T) -> Result<(), FrameError>
where
    W: AsyncWrite + Unpin,
    T: Serialize + ?Sized,
{
    let frame = encode_json_frame(value)?;
    writer
        .write_all(&frame)
        .await
        .map_err(|source| io_error("write", source))?;
    writer
        .flush()
        .await
        .map_err(|source| io_error("flush", source))
}

/// Serializes one value into its complete bounded length-prefixed frame.
pub fn encode_json_frame<T>(value: &T) -> Result<Vec<u8>, FrameError>
where
    T: Serialize + ?Sized,
{
    encode_json_frame_with_limit(value, MAX_IPC_FRAME_LEN)
}

async fn read_json_frame_with_limit<R, T>(reader: &mut R, limit: usize) -> Result<T, FrameError>
where
    R: AsyncRead + Unpin,
    T: DeserializeOwned,
{
    let mut prefix = [0_u8; size_of::<u32>()];
    let prefix_read = read_until_eof(reader, &mut prefix, "read prefix").await?;
    if prefix_read != prefix.len() {
        return Err(FrameError::TruncatedPrefix {
            actual: prefix_read,
        });
    }
    let declared = usize::try_from(u32::from_be_bytes(prefix)).unwrap_or(usize::MAX);
    if declared > limit {
        return Err(FrameError::FrameTooLarge {
            actual: declared,
            maximum: limit,
        });
    }

    let mut payload = vec![0_u8; declared];
    let payload_read = read_until_eof(reader, &mut payload, "read payload").await?;
    if payload_read != declared {
        return Err(FrameError::TruncatedPayload {
            actual: payload_read,
            expected: declared,
        });
    }
    let payload = std::str::from_utf8(&payload).map_err(FrameError::InvalidUtf8)?;
    serde_json::from_str(payload).map_err(FrameError::InvalidJson)
}

fn encode_json_frame_with_limit<T>(value: &T, limit: usize) -> Result<Vec<u8>, FrameError>
where
    T: Serialize + ?Sized,
{
    let payload = serde_json::to_vec(value).map_err(FrameError::Encode)?;
    if payload.len() > limit {
        return Err(FrameError::FrameTooLarge {
            actual: payload.len(),
            maximum: limit,
        });
    }
    let length = u32::try_from(payload.len()).map_err(|_| FrameError::FrameTooLarge {
        actual: payload.len(),
        maximum: limit,
    })?;
    let mut frame = Vec::with_capacity(size_of::<u32>() + payload.len());
    frame.extend_from_slice(&length.to_be_bytes());
    frame.extend_from_slice(&payload);
    Ok(frame)
}

async fn read_until_eof<R>(
    reader: &mut R,
    bytes: &mut [u8],
    operation: &'static str,
) -> Result<usize, FrameError>
where
    R: AsyncRead + Unpin,
{
    let mut read = 0;
    while read < bytes.len() {
        match reader.read(&mut bytes[read..]).await {
            Ok(0) => break,
            Ok(count) => read += count,
            Err(source) => return Err(io_error(operation, source)),
        }
    }
    Ok(read)
}

fn io_error(operation: &'static str, source: io::Error) -> FrameError {
    FrameError::Io { operation, source }
}

#[cfg(test)]
mod tests {
    use std::io::Cursor;

    use super::*;

    fn device(byte: u8) -> DeviceId {
        DeviceId::from_bytes([byte; 32])
    }

    #[tokio::test]
    async fn async_framing_round_trips_requests() -> Result<(), Box<dyn std::error::Error>> {
        let message = ClientMessage::Request {
            id: 42,
            request: Request::ListPeers {
                after: Some(device(1)),
                limit: 64,
            },
        };
        let (mut client, mut server) = tokio::io::duplex(4096);
        let write = write_json_frame(&mut client, &message);
        let read = read_json_frame::<_, ClientMessage>(&mut server);
        let (write, read) = tokio::join!(write, read);
        write?;
        assert_eq!(read?, message);
        Ok(())
    }

    #[tokio::test]
    async fn oversized_prefix_is_rejected_before_payload_read() {
        let declared = u32::try_from(MAX_IPC_FRAME_LEN + 1).unwrap_or(u32::MAX);
        let mut bytes = declared.to_be_bytes().to_vec();
        bytes.extend_from_slice(b"payload must remain unread");
        let mut reader = Cursor::new(bytes);
        let result = read_json_frame::<_, ClientMessage>(&mut reader).await;
        assert!(matches!(
            result,
            Err(FrameError::FrameTooLarge {
                actual,
                maximum: MAX_IPC_FRAME_LEN
            }) if actual == MAX_IPC_FRAME_LEN + 1
        ));
        assert_eq!(reader.position(), 4);
    }

    #[tokio::test]
    async fn truncated_invalid_utf8_and_malformed_json_are_distinct() {
        let mut prefix = Cursor::new(vec![0_u8; 3]);
        assert!(matches!(
            read_json_frame::<_, ClientMessage>(&mut prefix).await,
            Err(FrameError::TruncatedPrefix { actual: 3 })
        ));

        let mut truncated = Cursor::new([3_u32.to_be_bytes().as_slice(), b"{}"].concat());
        assert!(matches!(
            read_json_frame::<_, ClientMessage>(&mut truncated).await,
            Err(FrameError::TruncatedPayload {
                actual: 2,
                expected: 3
            })
        ));

        let mut invalid_utf8 = Cursor::new([1_u32.to_be_bytes().as_slice(), &[0xff]].concat());
        assert!(matches!(
            read_json_frame::<_, ClientMessage>(&mut invalid_utf8).await,
            Err(FrameError::InvalidUtf8(_))
        ));

        let mut malformed = Cursor::new([1_u32.to_be_bytes().as_slice(), b"{"].concat());
        assert!(matches!(
            read_json_frame::<_, ClientMessage>(&mut malformed).await,
            Err(FrameError::InvalidJson(_))
        ));
    }

    #[test]
    fn schemas_reject_unknown_fields_and_message_types() {
        let unknown_field = r#"{"type":"authenticate","version":1,"token":"00","extra":1}"#;
        assert!(serde_json::from_str::<ClientMessage>(unknown_field).is_err());
        assert!(serde_json::from_str::<ClientMessage>(r#"{"type":"trust_peer"}"#).is_err());
        assert!(serde_json::from_str::<Request>(r#"{"type":"get_status","extra":1}"#).is_err());
    }

    #[test]
    fn encoding_checks_limit_and_prefix_before_returning_bytes()
    -> Result<(), Box<dyn std::error::Error>> {
        let message = ClientMessage::Authenticate {
            version: IPC_PROTOCOL_VERSION,
            token: "a".repeat(64),
        };
        let payload = serde_json::to_vec(&message)?;
        let frame = encode_json_frame_with_limit(&message, payload.len())?;
        assert_eq!(&frame[..4], &u32::try_from(payload.len())?.to_be_bytes());
        assert_eq!(&frame[4..], payload);
        assert!(matches!(
            encode_json_frame_with_limit(&message, payload.len() - 1),
            Err(FrameError::FrameTooLarge { .. })
        ));
        Ok(())
    }

    #[test]
    fn debug_redacts_auth_token_pairing_code_and_descriptor_token() {
        let token = "ab".repeat(32);
        let authentication = ClientMessage::Authenticate {
            version: IPC_PROTOCOL_VERSION,
            token: token.clone(),
        };
        assert!(!format!("{authentication:?}").contains(&token));

        let pairing = PendingPairingInfo {
            attempt_id: PairingAttemptId(7),
            device_id: device(2),
            device_name: "peer".to_owned(),
            platform: "test".to_owned(),
            verification_code: "123456".to_owned(),
            timeout_remaining_ms: 1000,
        };
        assert!(!format!("{pairing:?}").contains("123456"));

        let descriptor = RuntimeDescriptor {
            descriptor_version: RUNTIME_DESCRIPTOR_VERSION,
            pid: 42,
            runtime_id: "runtime".to_owned(),
            ipc: LocalEndpointDescriptor {
                transport: LocalTransport::Unix,
                address: "/tmp/rift.sock".to_owned(),
            },
            auth_token: token.clone(),
        };
        assert!(!format!("{descriptor:?}").contains(&token));
    }

    #[derive(Deserialize)]
    struct VectorDocument {
        ipc_protocol_version: u16,
        vectors: Vec<ConformanceVector>,
    }

    #[derive(Deserialize)]
    struct ConformanceVector {
        name: String,
        direction: String,
        semantic: serde_json::Value,
        payload_utf8: String,
        payload_hex: String,
        frame_hex: String,
    }

    #[test]
    fn documented_vectors_pin_semantic_json_payload_and_complete_frame()
    -> Result<(), Box<dyn std::error::Error>> {
        let document: VectorDocument =
            serde_json::from_str(include_str!("../../../docs/ipc/v1-vectors.json"))?;
        assert_eq!(document.ipc_protocol_version, IPC_PROTOCOL_VERSION);
        let expected = [
            "authenticate",
            "get_status_request",
            "get_status_response",
            "list_peers_request",
            "confirm_pairing_request",
            "revoke_peer_request",
            "forget_peer_request",
            "pairing_pending_event",
            "session_opened_event",
        ]
        .into_iter()
        .collect::<std::collections::BTreeSet<_>>();
        let actual = document
            .vectors
            .iter()
            .map(|vector| vector.name.as_str())
            .collect::<std::collections::BTreeSet<_>>();
        assert_eq!(actual, expected);

        for vector in document.vectors {
            let payload = hex::decode(&vector.payload_hex)?;
            let frame = hex::decode(&vector.frame_hex)?;
            assert_eq!(payload, vector.payload_utf8.as_bytes(), "{}", vector.name);
            assert_eq!(
                serde_json::from_slice::<serde_json::Value>(&payload)?,
                vector.semantic,
                "{}",
                vector.name
            );
            assert_eq!(&frame[..4], &u32::try_from(payload.len())?.to_be_bytes());
            assert_eq!(&frame[4..], payload, "{}", vector.name);

            let encoded = match vector.direction.as_str() {
                "client_to_daemon" => {
                    let message: ClientMessage = serde_json::from_slice(&payload)?;
                    serde_json::to_vec(&message)?
                }
                "daemon_to_client" => {
                    let message: ServerMessage = serde_json::from_slice(&payload)?;
                    serde_json::to_vec(&message)?
                }
                direction => return Err(format!("unknown vector direction {direction}").into()),
            };
            assert_eq!(encoded, payload, "{}", vector.name);
        }
        Ok(())
    }
}
