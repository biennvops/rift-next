//! Rift production protocol v1.
//!
//! This crate owns the versioned wire contract, bounded control framing, and
//! handshake invariants. It deliberately has no knowledge of Iroh or any other
//! transport implementation.

use std::{fmt, io, time::Duration};

use rift_core::DeviceId;
use serde::{
    Deserialize, Deserializer, Serialize,
    de::{self, DeserializeOwned, SeqAccess, Visitor},
};
use thiserror::Error;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tracing::debug;

/// The production Rift protocol version.
pub const PROTOCOL_VERSION: u16 = 1;

/// The one canonical ALPN for production Rift protocol v1.
pub const ALPN: &[u8] = b"rift/1";

/// The maximum encoded control payload, excluding the four-byte frame prefix.
pub const MAX_CONTROL_FRAME_LEN: usize = 1024 * 1024;

/// The size of the big-endian frame length prefix.
pub const FRAME_LENGTH_PREFIX_LEN: usize = 4;

/// The maximum UTF-8 byte length of a device name in [`Hello`].
pub const MAX_DEVICE_NAME_LEN: usize = 128;

/// The maximum UTF-8 byte length of a platform identifier in [`Hello`].
pub const MAX_PLATFORM_LEN: usize = 64;

/// The maximum number of capabilities in [`Hello`].
pub const MAX_CAPABILITIES: usize = 64;

/// A forward-compatible capability identifier.
///
/// Unknown values are valid wire values and are preserved in a decoded `Hello`.
/// Rift v1 does not act on unknown capabilities. The known blob-transfer slot is
/// intentionally not advertised by the production bootstrap default because the
/// production blob-transfer plane does not exist yet.
#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(transparent)]
pub struct Capability(u16);

impl Capability {
    /// The reserved capability identifier for future production blob transfer.
    pub const BLOB_TRANSFER_V1: Self = Self(1);

    /// Constructs a capability identifier, retaining unknown values for forward
    /// compatibility.
    pub const fn new(value: u16) -> Self {
        Self(value)
    }

    /// Returns the numeric capability identifier.
    pub const fn value(self) -> u16 {
        self.0
    }

    /// Returns whether this is a capability known by Rift v1.
    pub const fn is_known(self) -> bool {
        self.0 == Self::BLOB_TRANSFER_V1.0
    }
}

/// The metadata supplied by the local application for the v1 `Hello` message.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct HelloMetadata {
    /// A human-readable device name, bounded by [`MAX_DEVICE_NAME_LEN`].
    pub device_name: String,
    /// A stable platform identifier, bounded by [`MAX_PLATFORM_LEN`].
    pub platform: String,
    /// Capability identifiers, bounded by [`MAX_CAPABILITIES`].
    pub capabilities: Vec<Capability>,
}

impl HelloMetadata {
    /// Validates and constructs local Hello metadata.
    pub fn new(
        device_name: impl Into<String>,
        platform: impl Into<String>,
        capabilities: Vec<Capability>,
    ) -> Result<Self, HandshakeError> {
        let metadata = Self {
            device_name: device_name.into(),
            platform: platform.into(),
            capabilities,
        };
        validate_metadata(
            &metadata.device_name,
            &metadata.platform,
            &metadata.capabilities,
        )?;
        Ok(metadata)
    }
}

/// The production v1 Hello payload.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Hello {
    /// The protocol version selected by this peer.
    pub protocol_version: u16,
    /// The public cryptographic identity claimed by this peer.
    pub device_id: DeviceId,
    /// The peer's human-readable device name.
    #[serde(deserialize_with = "deserialize_device_name")]
    pub device_name: String,
    /// The peer's platform identifier.
    #[serde(deserialize_with = "deserialize_platform")]
    pub platform: String,
    /// The peer's capability identifiers.
    #[serde(deserialize_with = "deserialize_capabilities")]
    pub capabilities: Vec<Capability>,
}

impl Hello {
    /// Constructs a v1 Hello from a transport-authenticated local identity and
    /// validated metadata.
    pub fn new(device_id: DeviceId, metadata: HelloMetadata) -> Result<Self, HandshakeError> {
        let hello = Self {
            protocol_version: PROTOCOL_VERSION,
            device_id,
            device_name: metadata.device_name,
            platform: metadata.platform,
            capabilities: metadata.capabilities,
        };
        validate_hello_metadata(&hello)?;
        Ok(hello)
    }

    /// Returns the metadata portion of this Hello.
    pub fn metadata(&self) -> HelloMetadata {
        HelloMetadata {
            device_name: self.device_name.clone(),
            platform: self.platform.clone(),
            capabilities: self.capabilities.clone(),
        }
    }
}

fn deserialize_device_name<'de, D>(deserializer: D) -> Result<String, D::Error>
where
    D: Deserializer<'de>,
{
    deserializer.deserialize_str(BoundedStringVisitor::<MAX_DEVICE_NAME_LEN>)
}

fn deserialize_platform<'de, D>(deserializer: D) -> Result<String, D::Error>
where
    D: Deserializer<'de>,
{
    deserializer.deserialize_str(BoundedStringVisitor::<MAX_PLATFORM_LEN>)
}

struct BoundedStringVisitor<const MAXIMUM: usize>;

impl<'de, const MAXIMUM: usize> Visitor<'de> for BoundedStringVisitor<MAXIMUM> {
    type Value = String;

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "a UTF-8 string of at most {MAXIMUM} bytes")
    }

    fn visit_str<E>(self, value: &str) -> Result<Self::Value, E>
    where
        E: de::Error,
    {
        if value.len() > MAXIMUM {
            return Err(E::invalid_length(value.len(), &self));
        }
        Ok(value.to_owned())
    }
}

fn deserialize_capabilities<'de, D>(deserializer: D) -> Result<Vec<Capability>, D::Error>
where
    D: Deserializer<'de>,
{
    deserializer.deserialize_seq(BoundedCapabilitiesVisitor)
}

struct BoundedCapabilitiesVisitor;

impl<'de> Visitor<'de> for BoundedCapabilitiesVisitor {
    type Value = Vec<Capability>;

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "a sequence of at most {MAX_CAPABILITIES} capabilities"
        )
    }

    fn visit_seq<A>(self, mut sequence: A) -> Result<Self::Value, A::Error>
    where
        A: SeqAccess<'de>,
    {
        let capacity = match sequence.size_hint() {
            Some(length) if length > MAX_CAPABILITIES => {
                return Err(de::Error::invalid_length(length, &self));
            }
            Some(length) => length,
            None => 0,
        };

        let mut capabilities = Vec::with_capacity(capacity);
        while let Some(capability) = sequence.next_element()? {
            if capabilities.len() == MAX_CAPABILITIES {
                return Err(de::Error::invalid_length(MAX_CAPABILITIES + 1, &self));
            }
            capabilities.push(capability);
        }
        Ok(capabilities)
    }
}

/// The minimal production control message set for v1.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub enum ControlMessage {
    /// The symmetric session bootstrap message.
    Hello(Hello),
    /// A one-shot control-channel ping.
    Ping { nonce: u64 },
    /// The response to a one-shot control-channel ping.
    Pong { nonce: u64 },
}

impl ControlMessage {
    /// Returns the message kind without exposing its payload in an error.
    pub const fn kind(&self) -> MessageKind {
        match self {
            Self::Hello(_) => MessageKind::Hello,
            Self::Ping { .. } => MessageKind::Ping,
            Self::Pong { .. } => MessageKind::Pong,
        }
    }
}

/// A payload-free control message kind used in typed sequencing errors.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MessageKind {
    /// A Hello message.
    Hello,
    /// A Ping message.
    Ping,
    /// A Pong message.
    Pong,
}

impl fmt::Display for MessageKind {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let name = match self {
            Self::Hello => "Hello",
            Self::Ping => "Ping",
            Self::Pong => "Pong",
        };
        formatter.write_str(name)
    }
}

/// Errors produced by bounded length-prefixed control framing.
#[derive(Debug, Error)]
pub enum FrameError {
    /// Postcard could not encode a payload.
    #[error("unable to encode control frame: {0}")]
    Encode(#[source] postcard::Error),
    /// Postcard could not decode a payload.
    #[error("unable to decode control frame: {0}")]
    Decode(#[source] postcard::Error),
    /// The four-byte length prefix ended before four bytes were received.
    #[error("control frame length prefix is truncated: {0}")]
    TruncatedLengthPrefix(#[source] io::Error),
    /// The declared payload ended before the declared number of bytes arrived.
    #[error("control frame payload is truncated: {0}")]
    TruncatedPayload(#[source] io::Error),
    /// The declared payload exceeds the protocol maximum.
    #[error("control frame length {actual} exceeds maximum {maximum}")]
    FrameTooLarge { actual: usize, maximum: usize },
    /// The complete in-memory frame does not contain exactly the declared payload.
    #[error("control frame length {declared} does not match payload length {actual}")]
    PayloadLengthMismatch { declared: usize, actual: usize },
    /// The complete payload contained bytes after the decoded Postcard value.
    #[error("control frame contains {remaining} trailing payload bytes")]
    TrailingPayload { remaining: usize },
    /// The stream rejected a frame write.
    #[error("unable to write control frame: {0}")]
    Write(#[source] io::Error),
}

/// Errors produced while validating and exchanging the v1 Hello message.
#[derive(Debug, Error)]
pub enum HandshakeError {
    /// Framing or Postcard failed while exchanging Hello.
    #[error("control framing failed: {0}")]
    Frame(#[from] FrameError),
    /// The Hello exchange exceeded its explicit deadline.
    #[error("Hello exchange timed out")]
    HandshakeTimeout,
    /// The peer selected a protocol version this implementation does not support.
    #[error("unsupported protocol version {0}; supported version is {PROTOCOL_VERSION}")]
    UnsupportedProtocolVersion(u16),
    /// The peer's Hello identity does not match the authenticated transport identity.
    #[error("authenticated peer identity {authenticated} does not match Hello identity {hello}")]
    IdentityMismatch {
        /// The identity authenticated by the transport.
        authenticated: DeviceId,
        /// The identity claimed by the Hello payload.
        hello: DeviceId,
    },
    /// A Hello metadata field exceeds its semantic bound.
    #[error("invalid Hello metadata in {field}: {actual} UTF-8 bytes exceeds maximum {maximum}")]
    InvalidMetadata {
        /// The metadata field that exceeded its limit.
        field: MetadataField,
        /// The supplied UTF-8 byte length.
        actual: usize,
        /// The permitted UTF-8 byte length.
        maximum: usize,
    },
    /// A Hello advertises too many capabilities.
    #[error("Hello advertises {actual} capabilities; maximum is {maximum}")]
    TooManyCapabilities { actual: usize, maximum: usize },
    /// The first or otherwise expected message was not received.
    #[error("expected {expected} control message, received {received}")]
    UnexpectedMessage {
        /// The expected message kind.
        expected: MessageKind,
        /// The received message kind.
        received: MessageKind,
    },
}

/// The Hello metadata field named by [`HandshakeError::InvalidMetadata`].
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MetadataField {
    /// The device name field.
    DeviceName,
    /// The platform field.
    Platform,
}

impl fmt::Display for MetadataField {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let name = match self {
            Self::DeviceName => "device_name",
            Self::Platform => "platform",
        };
        formatter.write_str(name)
    }
}

/// Errors produced by post-handshake control messages.
#[derive(Debug, Error)]
pub enum ControlError {
    /// Framing or Postcard failed while using the control stream.
    #[error("control framing failed: {0}")]
    Frame(#[from] FrameError),
    /// The control stream received a message of the wrong kind.
    #[error("expected {expected} control message, received {received}")]
    UnexpectedMessage {
        /// The expected message kind.
        expected: MessageKind,
        /// The received message kind.
        received: MessageKind,
    },
    /// The received Pong did not answer the requested nonce.
    #[error("Pong nonce {actual} does not match Ping nonce {expected}")]
    NonceMismatch { expected: u64, actual: u64 },
}

/// A generic bidirectional control stream.
///
/// The protocol only requires Tokio's asynchronous I/O traits; concrete QUIC
/// stream types remain in the transport crate.
pub struct ControlChannel<S, R> {
    /// The stream used for outbound control frames.
    pub send: S,
    /// The stream used for inbound control frames.
    pub recv: R,
}

impl<S, R> ControlChannel<S, R> {
    /// Creates a control channel from its independently owned stream halves.
    pub const fn new(send: S, recv: R) -> Self {
        Self { send, recv }
    }
}

/// Encodes a value as a four-byte big-endian length-prefixed Postcard frame.
pub fn encode_frame<T: Serialize>(value: &T) -> Result<Vec<u8>, FrameError> {
    let payload = postcard::to_stdvec(value).map_err(FrameError::Encode)?;
    ensure_frame_size(payload.len())?;

    let length = u32::try_from(payload.len()).map_err(|_| FrameError::FrameTooLarge {
        actual: payload.len(),
        maximum: MAX_CONTROL_FRAME_LEN,
    })?;
    let mut frame = Vec::with_capacity(FRAME_LENGTH_PREFIX_LEN + payload.len());
    frame.extend_from_slice(&length.to_be_bytes());
    frame.extend_from_slice(&payload);
    Ok(frame)
}

/// Decodes a complete in-memory four-byte big-endian length-prefixed frame.
pub fn decode_frame<T: DeserializeOwned>(frame: &[u8]) -> Result<T, FrameError> {
    if frame.len() < FRAME_LENGTH_PREFIX_LEN {
        return Err(FrameError::TruncatedLengthPrefix(unexpected_eof(
            "control frame length prefix",
        )));
    }

    let declared = declared_length(&frame[..FRAME_LENGTH_PREFIX_LEN]);
    ensure_frame_size(declared)?;
    let payload = &frame[FRAME_LENGTH_PREFIX_LEN..];
    if declared != payload.len() {
        return Err(FrameError::PayloadLengthMismatch {
            declared,
            actual: payload.len(),
        });
    }
    decode_payload(payload)
}

/// Encodes a production control message as a complete frame.
pub fn encode_message(message: &ControlMessage) -> Result<Vec<u8>, FrameError> {
    encode_frame(message)
}

/// Decodes a complete production control message frame.
pub fn decode_message(frame: &[u8]) -> Result<ControlMessage, FrameError> {
    decode_frame(frame)
}

/// Writes one bounded frame to an asynchronous writer.
pub async fn write_value<W, T>(writer: &mut W, value: &T) -> Result<(), FrameError>
where
    W: AsyncWrite + Unpin,
    T: Serialize,
{
    let frame = encode_frame(value)?;
    writer
        .write_all(&frame[..FRAME_LENGTH_PREFIX_LEN])
        .await
        .map_err(FrameError::Write)?;
    writer
        .write_all(&frame[FRAME_LENGTH_PREFIX_LEN..])
        .await
        .map_err(FrameError::Write)
}

/// Reads one bounded frame from an asynchronous reader.
pub async fn read_value<R, T>(reader: &mut R) -> Result<T, FrameError>
where
    R: AsyncRead + Unpin,
    T: DeserializeOwned,
{
    let mut length_bytes = [0_u8; FRAME_LENGTH_PREFIX_LEN];
    reader
        .read_exact(&mut length_bytes)
        .await
        .map_err(FrameError::TruncatedLengthPrefix)?;
    let declared = declared_length(&length_bytes);
    ensure_frame_size(declared)?;

    let mut payload = vec![0_u8; declared];
    reader
        .read_exact(&mut payload)
        .await
        .map_err(FrameError::TruncatedPayload)?;
    decode_payload(&payload)
}

/// Writes one production control message.
pub async fn write_message<W>(writer: &mut W, message: &ControlMessage) -> Result<(), FrameError>
where
    W: AsyncWrite + Unpin,
{
    write_value(writer, message).await
}

/// Reads one production control message.
pub async fn read_message<R>(reader: &mut R) -> Result<ControlMessage, FrameError>
where
    R: AsyncRead + Unpin,
{
    read_value(reader).await
}

/// Exchanges symmetric Hello messages and validates the received identity.
pub async fn exchange_hello<S, R>(
    channel: &mut ControlChannel<S, R>,
    local_device_id: DeviceId,
    local_metadata: &HelloMetadata,
    authenticated_remote_id: DeviceId,
) -> Result<Hello, HandshakeError>
where
    S: AsyncWrite + Unpin,
    R: AsyncRead + Unpin,
{
    let local = Hello::new(local_device_id, local_metadata.clone())?;
    debug!(
        local_device_id = %local.device_id,
        protocol_version = local.protocol_version,
        "sending Rift Hello"
    );
    write_message(&mut channel.send, &ControlMessage::Hello(local)).await?;

    let received = read_message(&mut channel.recv).await?;
    let peer = match received {
        ControlMessage::Hello(peer) => peer,
        received => {
            return Err(HandshakeError::UnexpectedMessage {
                expected: MessageKind::Hello,
                received: received.kind(),
            });
        }
    };
    validate_hello(&peer, authenticated_remote_id)?;
    debug!(
        remote_device_id = %peer.device_id,
        protocol_version = peer.protocol_version,
        "received and validated Rift Hello"
    );
    Ok(peer)
}

/// Exchanges Hello messages with an explicit deadline.
pub async fn exchange_hello_with_timeout<S, R>(
    channel: &mut ControlChannel<S, R>,
    local_device_id: DeviceId,
    local_metadata: &HelloMetadata,
    authenticated_remote_id: DeviceId,
    timeout: Duration,
) -> Result<Hello, HandshakeError>
where
    S: AsyncWrite + Unpin,
    R: AsyncRead + Unpin,
{
    tokio::time::timeout(
        timeout,
        exchange_hello(
            channel,
            local_device_id,
            local_metadata,
            authenticated_remote_id,
        ),
    )
    .await
    .map_err(|_| HandshakeError::HandshakeTimeout)?
}

/// Sends a Ping and waits for its matching Pong.
pub async fn ping<S, R>(channel: &mut ControlChannel<S, R>, nonce: u64) -> Result<(), ControlError>
where
    S: AsyncWrite + Unpin,
    R: AsyncRead + Unpin,
{
    write_message(&mut channel.send, &ControlMessage::Ping { nonce }).await?;
    let received = read_message(&mut channel.recv).await?;
    match received {
        ControlMessage::Pong { nonce: actual } if actual == nonce => Ok(()),
        ControlMessage::Pong { nonce: actual } => Err(ControlError::NonceMismatch {
            expected: nonce,
            actual,
        }),
        received => Err(ControlError::UnexpectedMessage {
            expected: MessageKind::Pong,
            received: received.kind(),
        }),
    }
}

/// Sends a Pong in response to the next Ping.
pub async fn respond_to_ping<S, R>(channel: &mut ControlChannel<S, R>) -> Result<u64, ControlError>
where
    S: AsyncWrite + Unpin,
    R: AsyncRead + Unpin,
{
    let received = read_message(&mut channel.recv).await?;
    let ControlMessage::Ping { nonce } = received else {
        return Err(ControlError::UnexpectedMessage {
            expected: MessageKind::Ping,
            received: received.kind(),
        });
    };
    write_message(&mut channel.send, &ControlMessage::Pong { nonce }).await?;
    Ok(nonce)
}

/// Validates the version, metadata bounds, and transport-authenticated identity
/// in a peer Hello.
pub fn validate_hello(
    hello: &Hello,
    authenticated_remote_id: DeviceId,
) -> Result<(), HandshakeError> {
    if hello.protocol_version != PROTOCOL_VERSION {
        return Err(HandshakeError::UnsupportedProtocolVersion(
            hello.protocol_version,
        ));
    }
    validate_hello_metadata(hello)?;
    if hello.device_id != authenticated_remote_id {
        return Err(HandshakeError::IdentityMismatch {
            authenticated: authenticated_remote_id,
            hello: hello.device_id,
        });
    }
    Ok(())
}

/// Validates only the semantic metadata bounds of a Hello.
pub fn validate_hello_metadata(hello: &Hello) -> Result<(), HandshakeError> {
    validate_metadata(&hello.device_name, &hello.platform, &hello.capabilities)
}

fn validate_metadata(
    device_name: &str,
    platform: &str,
    capabilities: &[Capability],
) -> Result<(), HandshakeError> {
    let device_name_len = device_name.len();
    if device_name_len > MAX_DEVICE_NAME_LEN {
        return Err(HandshakeError::InvalidMetadata {
            field: MetadataField::DeviceName,
            actual: device_name_len,
            maximum: MAX_DEVICE_NAME_LEN,
        });
    }
    let platform_len = platform.len();
    if platform_len > MAX_PLATFORM_LEN {
        return Err(HandshakeError::InvalidMetadata {
            field: MetadataField::Platform,
            actual: platform_len,
            maximum: MAX_PLATFORM_LEN,
        });
    }
    if capabilities.len() > MAX_CAPABILITIES {
        return Err(HandshakeError::TooManyCapabilities {
            actual: capabilities.len(),
            maximum: MAX_CAPABILITIES,
        });
    }
    Ok(())
}

fn decode_payload<T: DeserializeOwned>(payload: &[u8]) -> Result<T, FrameError> {
    let (value, remaining) = postcard::take_from_bytes(payload).map_err(FrameError::Decode)?;
    if remaining.is_empty() {
        Ok(value)
    } else {
        Err(FrameError::TrailingPayload {
            remaining: remaining.len(),
        })
    }
}

fn ensure_frame_size(length: usize) -> Result<(), FrameError> {
    if length > MAX_CONTROL_FRAME_LEN {
        return Err(FrameError::FrameTooLarge {
            actual: length,
            maximum: MAX_CONTROL_FRAME_LEN,
        });
    }
    Ok(())
}

fn declared_length(prefix: &[u8]) -> usize {
    usize::try_from(u32::from_be_bytes([
        prefix[0], prefix[1], prefix[2], prefix[3],
    ]))
    .unwrap_or(usize::MAX)
}

fn unexpected_eof(operation: &'static str) -> io::Error {
    io::Error::new(
        io::ErrorKind::UnexpectedEof,
        format!("{operation} ended before the required bytes arrived"),
    )
}

#[cfg(test)]
mod tests {
    use std::{
        io::Cursor,
        pin::Pin,
        task::{Context, Poll},
    };

    use super::*;
    use rift_core::DEVICE_ID_LEN;
    use serde::Deserialize;
    use tokio::io::{AsyncWrite, AsyncWriteExt, duplex, split};

    fn device_id(byte: u8) -> DeviceId {
        DeviceId::from_bytes([byte; DEVICE_ID_LEN])
    }

    fn metadata() -> HelloMetadata {
        HelloMetadata {
            device_name: "Mötley 🦀".to_owned(),
            platform: "macOS-arm64".to_owned(),
            capabilities: vec![Capability::new(99), Capability::BLOB_TRANSFER_V1],
        }
    }

    fn hello() -> Hello {
        let metadata = metadata();
        Hello {
            protocol_version: PROTOCOL_VERSION,
            device_id: device_id(7),
            device_name: metadata.device_name,
            platform: metadata.platform,
            capabilities: metadata.capabilities,
        }
    }

    #[derive(Serialize)]
    enum WireControlMessage<'a> {
        Hello(WireHello<'a>),
    }

    #[derive(Serialize)]
    struct WireHello<'a> {
        protocol_version: u16,
        device_id: DeviceId,
        device_name: &'a str,
        platform: &'a str,
        capabilities: &'a [Capability],
    }

    fn wire_hello_frame(
        device_name: &str,
        platform: &str,
        capabilities: &[Capability],
    ) -> Result<Vec<u8>, FrameError> {
        encode_frame(&WireControlMessage::Hello(WireHello {
            protocol_version: PROTOCOL_VERSION,
            device_id: device_id(7),
            device_name,
            platform,
            capabilities,
        }))
    }

    #[derive(Deserialize)]
    struct ConformanceFile {
        protocol_version: u16,
        alpn_hex: String,
        vectors: Vec<ConformanceVector>,
    }

    #[derive(Deserialize)]
    struct ConformanceVector {
        name: String,
        message: VectorMessage,
        postcard_payload_hex: String,
        frame_hex: String,
    }

    #[derive(Deserialize)]
    #[serde(tag = "type", rename_all = "snake_case")]
    enum VectorMessage {
        Hello {
            protocol_version: u16,
            device_id_hex: String,
            device_name: String,
            platform: String,
            capabilities: Vec<u16>,
        },
        Ping {
            nonce: u64,
        },
        Pong {
            nonce: u64,
        },
    }

    fn vector_message(
        message: VectorMessage,
    ) -> Result<ControlMessage, Box<dyn std::error::Error + Send + Sync>> {
        let message = match message {
            VectorMessage::Hello {
                protocol_version,
                device_id_hex,
                device_name,
                platform,
                capabilities,
            } => {
                let device_id = DeviceId::from_slice(&hex::decode(device_id_hex)?)?;
                let metadata = HelloMetadata::new(
                    device_name,
                    platform,
                    capabilities.into_iter().map(Capability::new).collect(),
                )?;
                ControlMessage::Hello(Hello {
                    protocol_version,
                    device_id,
                    device_name: metadata.device_name,
                    platform: metadata.platform,
                    capabilities: metadata.capabilities,
                })
            }
            VectorMessage::Ping { nonce } => ControlMessage::Ping { nonce },
            VectorMessage::Pong { nonce } => ControlMessage::Pong { nonce },
        };
        Ok(message)
    }

    #[test]
    fn conformance_vectors_match_postcard_payloads_and_complete_frames()
    -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let vectors: ConformanceFile =
            serde_json::from_str(include_str!("../../../docs/protocol/v1-vectors.json"))?;
        assert_eq!(vectors.protocol_version, PROTOCOL_VERSION);
        assert_eq!(vectors.alpn_hex, hex::encode(ALPN));

        for vector in vectors.vectors {
            let message = vector_message(vector.message)?;
            let payload = postcard::to_stdvec(&message)?;
            assert_eq!(
                hex::encode(&payload),
                vector.postcard_payload_hex,
                "{} payload",
                vector.name
            );
            let frame = encode_message(&message)?;
            assert_eq!(
                hex::encode(&frame),
                vector.frame_hex,
                "{} frame",
                vector.name
            );
            assert_eq!(decode_message(&frame)?, message, "{} decode", vector.name);
        }
        Ok(())
    }

    #[test]
    fn all_v1_messages_round_trip_through_framing() -> Result<(), FrameError> {
        for message in [
            ControlMessage::Hello(hello()),
            ControlMessage::Ping { nonce: 7 },
            ControlMessage::Pong { nonce: 7 },
        ] {
            let encoded = encode_message(&message)?;
            assert_eq!(decode_message(&encoded)?, message);
        }
        Ok(())
    }

    #[tokio::test]
    async fn async_framing_reads_exactly_one_message() -> Result<(), FrameError> {
        let (mut writer, mut reader) = duplex(4096);
        let message = ControlMessage::Ping { nonce: 42 };
        write_message(&mut writer, &message).await?;
        write_message(&mut writer, &ControlMessage::Pong { nonce: 43 }).await?;

        assert_eq!(read_message(&mut reader).await?, message);
        assert_eq!(
            read_message(&mut reader).await?,
            ControlMessage::Pong { nonce: 43 }
        );
        Ok(())
    }

    struct FailingWriter;

    impl AsyncWrite for FailingWriter {
        fn poll_write(
            self: Pin<&mut Self>,
            _context: &mut Context<'_>,
            _buffer: &[u8],
        ) -> Poll<Result<usize, io::Error>> {
            Poll::Ready(Err(io::Error::other("test writer failure")))
        }

        fn poll_flush(
            self: Pin<&mut Self>,
            _context: &mut Context<'_>,
        ) -> Poll<Result<(), io::Error>> {
            Poll::Ready(Ok(()))
        }

        fn poll_shutdown(
            self: Pin<&mut Self>,
            _context: &mut Context<'_>,
        ) -> Poll<Result<(), io::Error>> {
            Poll::Ready(Ok(()))
        }
    }

    struct FailingSerialize;

    impl Serialize for FailingSerialize {
        fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
        where
            S: serde::Serializer,
        {
            serializer.serialize_seq(None).and_then(|_| {
                Err(<S::Error as serde::ser::Error>::custom(
                    "test serialization failure",
                ))
            })
        }
    }

    #[tokio::test]
    async fn encoding_and_writing_failures_are_typed() {
        assert!(matches!(
            encode_frame(&FailingSerialize),
            Err(FrameError::Encode(_))
        ));

        let mut writer = FailingWriter;
        let write_result = write_message(&mut writer, &ControlMessage::Ping { nonce: 1 }).await;
        assert!(matches!(write_result, Err(FrameError::Write(_))));
    }

    #[test]
    fn frame_prefix_is_big_endian_and_payload_is_exact() -> Result<(), FrameError> {
        let frame = encode_message(&ControlMessage::Ping { nonce: 7 })?;
        let payload =
            postcard::to_stdvec(&ControlMessage::Ping { nonce: 7 }).map_err(FrameError::Encode)?;
        assert_eq!(
            &frame[..FRAME_LENGTH_PREFIX_LEN],
            u32::try_from(payload.len())
                .map_err(|_| FrameError::FrameTooLarge {
                    actual: payload.len(),
                    maximum: MAX_CONTROL_FRAME_LEN,
                })?
                .to_be_bytes()
        );
        assert_eq!(&frame[FRAME_LENGTH_PREFIX_LEN..], payload);
        Ok(())
    }

    #[test]
    fn exactly_at_the_frame_limit_is_accepted() -> Result<(), FrameError> {
        let value = vec![0_u8; MAX_CONTROL_FRAME_LEN - 3];
        let frame = encode_frame(&value)?;
        assert_eq!(frame.len(), FRAME_LENGTH_PREFIX_LEN + MAX_CONTROL_FRAME_LEN);
        assert_eq!(decode_frame::<Vec<u8>>(&frame)?, value);
        Ok(())
    }

    #[test]
    fn one_byte_over_the_frame_limit_is_rejected() {
        let value = vec![0_u8; MAX_CONTROL_FRAME_LEN - 2];
        assert!(matches!(
            encode_frame(&value),
            Err(FrameError::FrameTooLarge { actual, maximum })
                if actual == MAX_CONTROL_FRAME_LEN + 1 && maximum == MAX_CONTROL_FRAME_LEN
        ));
    }

    #[tokio::test]
    async fn oversized_stream_frame_is_rejected_before_payload_allocation() {
        let (mut writer, mut reader) = duplex(32);
        let write_result = writer
            .write_all(&(MAX_CONTROL_FRAME_LEN as u32 + 1).to_be_bytes())
            .await;
        assert!(write_result.is_ok());
        let result = read_message(&mut reader).await;
        assert!(matches!(
            result,
            Err(FrameError::FrameTooLarge { actual, maximum })
                if actual == MAX_CONTROL_FRAME_LEN + 1 && maximum == MAX_CONTROL_FRAME_LEN
        ));
    }

    #[tokio::test]
    async fn truncated_prefix_and_payload_are_distinct() {
        let mut prefix = &b"\x00\x00\x00"[..];
        assert!(matches!(
            read_message(&mut prefix).await,
            Err(FrameError::TruncatedLengthPrefix(_))
        ));

        let mut payload = Cursor::new([0_u8, 0, 0, 3, 1, 2]);
        assert!(matches!(
            read_message(&mut payload).await,
            Err(FrameError::TruncatedPayload(_))
        ));
    }

    #[test]
    fn malformed_postcard_and_in_memory_length_mismatch_are_rejected() {
        assert!(matches!(
            decode_message(&[0, 0, 0, 1, 0xff]),
            Err(FrameError::Decode(_))
        ));
        assert!(matches!(
            decode_message(&[0, 0, 0, 0]),
            Err(FrameError::Decode(_))
        ));
        assert!(matches!(
            decode_message(&[0, 0, 0, 2, 0]),
            Err(FrameError::PayloadLengthMismatch {
                declared: 2,
                actual: 1
            })
        ));
        assert!(matches!(
            decode_message(&[]),
            Err(FrameError::TruncatedLengthPrefix(_))
        ));
    }

    #[test]
    fn in_memory_frame_with_trailing_postcard_bytes_is_rejected() {
        let frame = [0, 0, 0, 3, 1, 42, 0xff];

        assert!(matches!(
            decode_message(&frame),
            Err(FrameError::TrailingPayload { remaining: 1 })
        ));
    }

    #[tokio::test]
    async fn streamed_frame_with_trailing_postcard_bytes_is_rejected() {
        let mut frame = Cursor::new([0, 0, 0, 3, 1, 42, 0xff]);

        assert!(matches!(
            read_message(&mut frame).await,
            Err(FrameError::TrailingPayload { remaining: 1 })
        ));
    }

    #[tokio::test]
    async fn oversized_hello_metadata_is_rejected_from_wire_bytes() -> Result<(), FrameError> {
        for frame in [
            wire_hello_frame(&"x".repeat(MAX_DEVICE_NAME_LEN + 1), "", &[]),
            wire_hello_frame("", &"x".repeat(MAX_PLATFORM_LEN + 1), &[]),
            wire_hello_frame("", "", &[Capability::new(1); MAX_CAPABILITIES + 1]),
        ] {
            let mut frame = Cursor::new(frame?);
            assert!(matches!(
                read_message(&mut frame).await,
                Err(FrameError::Decode(_))
            ));
        }
        Ok(())
    }

    #[test]
    fn hello_metadata_and_identity_validation_are_explicit() {
        let authenticated = device_id(2);
        let mut peer = hello();
        peer.device_id = device_id(3);
        assert!(matches!(
            validate_hello(&peer, authenticated),
            Err(HandshakeError::IdentityMismatch { .. })
        ));

        peer.device_id = authenticated;
        peer.protocol_version = PROTOCOL_VERSION + 1;
        assert!(matches!(
            validate_hello(&peer, authenticated),
            Err(HandshakeError::UnsupportedProtocolVersion(_))
        ));

        peer.protocol_version = PROTOCOL_VERSION;
        peer.device_name = "x".repeat(MAX_DEVICE_NAME_LEN + 1);
        assert!(matches!(
            validate_hello(&peer, authenticated),
            Err(HandshakeError::InvalidMetadata {
                field: MetadataField::DeviceName,
                ..
            })
        ));

        peer.device_name = "valid".to_owned();
        peer.platform = "x".repeat(MAX_PLATFORM_LEN + 1);
        assert!(matches!(
            validate_hello(&peer, authenticated),
            Err(HandshakeError::InvalidMetadata {
                field: MetadataField::Platform,
                ..
            })
        ));

        peer.platform = "valid".to_owned();
        peer.capabilities = vec![Capability::new(2); MAX_CAPABILITIES + 1];
        assert!(matches!(
            validate_hello(&peer, authenticated),
            Err(HandshakeError::TooManyCapabilities { .. })
        ));
    }

    #[test]
    fn unknown_capabilities_are_preserved_without_being_advertised_by_default() {
        let unknown = Capability::new(u16::MAX);
        assert!(!unknown.is_known());
        assert_eq!(unknown.value(), u16::MAX);
        assert!(HelloMetadata::new("device", "platform", vec![unknown]).is_ok());
        assert!(
            HelloMetadata::new("device", "platform", vec![Capability::BLOB_TRANSFER_V1]).is_ok()
        );
        assert!(HelloMetadata::new("device", "platform", Vec::new()).is_ok());
    }

    #[tokio::test]
    async fn symmetric_hello_exchange_and_ping_pong_work()
    -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let (local, remote) = duplex(4096);
        let (local_recv, local_send) = split(local);
        let (remote_recv, remote_send) = split(remote);
        let mut local_channel = ControlChannel::new(local_send, local_recv);
        let mut remote_channel = ControlChannel::new(remote_send, remote_recv);

        let remote_task = tokio::spawn(async move {
            let remote_metadata = HelloMetadata::new("remote", "linux", Vec::new())?;
            let peer = exchange_hello(
                &mut remote_channel,
                device_id(2),
                &remote_metadata,
                device_id(1),
            )
            .await?;
            respond_to_ping(&mut remote_channel).await?;
            Ok::<Hello, Box<dyn std::error::Error + Send + Sync>>(peer)
        });

        let peer = exchange_hello(
            &mut local_channel,
            device_id(1),
            &HelloMetadata::new("local", "macos", Vec::new())?,
            device_id(2),
        )
        .await?;
        ping(&mut local_channel, 55).await?;
        let remote_peer = remote_task.await??;

        assert_eq!(peer.device_id, device_id(2));
        assert_eq!(remote_peer.device_id, device_id(1));
        Ok(())
    }

    #[tokio::test]
    async fn post_handshake_sequence_errors_are_typed()
    -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let (local, remote) = duplex(4096);
        let (local_recv, local_send) = split(local);
        let (mut remote_recv, mut remote_send) = split(remote);
        let mut local_channel = ControlChannel::new(local_send, local_recv);
        let responder = tokio::spawn(async move {
            let _ = read_message(&mut remote_recv).await?;
            write_message(&mut remote_send, &ControlMessage::Pong { nonce: 2 }).await?;
            Ok::<(), FrameError>(())
        });
        let result = ping(&mut local_channel, 1).await;
        assert!(matches!(
            result,
            Err(ControlError::NonceMismatch {
                expected: 1,
                actual: 2
            })
        ));
        responder.await??;

        let (local, mut remote) = duplex(4096);
        let (local_recv, local_send) = split(local);
        let mut local_channel = ControlChannel::new(local_send, local_recv);
        write_message(&mut remote, &ControlMessage::Pong { nonce: 3 }).await?;
        let result = respond_to_ping(&mut local_channel).await;
        assert!(matches!(
            result,
            Err(ControlError::UnexpectedMessage {
                expected: MessageKind::Ping,
                received: MessageKind::Pong
            })
        ));
        Ok(())
    }

    #[tokio::test]
    async fn wrong_first_message_is_rejected()
    -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let (local, remote) = duplex(4096);
        let (local_recv, local_send) = split(local);
        let (mut remote_recv, mut remote_send) = split(remote);
        let mut local_channel = ControlChannel::new(local_send, local_recv);
        let remote_task = tokio::spawn(async move {
            let _ = read_message(&mut remote_recv).await?;
            write_message(&mut remote_send, &ControlMessage::Ping { nonce: 9 }).await?;
            Ok::<(), FrameError>(())
        });

        let result = exchange_hello(
            &mut local_channel,
            device_id(1),
            &HelloMetadata::new("local", "test", Vec::new())?,
            device_id(2),
        )
        .await;
        assert!(matches!(
            result,
            Err(HandshakeError::UnexpectedMessage {
                expected: MessageKind::Hello,
                received: MessageKind::Ping
            })
        ));
        remote_task.await??;
        Ok(())
    }

    #[tokio::test]
    async fn hello_timeout_is_typed() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let (local, _remote) = duplex(4096);
        let (local_recv, local_send) = split(local);
        let mut local_channel = ControlChannel::new(local_send, local_recv);
        let result = exchange_hello_with_timeout(
            &mut local_channel,
            device_id(1),
            &HelloMetadata::new("local", "test", Vec::new())?,
            device_id(2),
            Duration::from_millis(1),
        )
        .await;
        assert!(matches!(result, Err(HandshakeError::HandshakeTimeout)));
        Ok(())
    }
}
