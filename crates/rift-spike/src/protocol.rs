//! Versioned control-plane messages and length-delimited stream framing.

use std::fmt;

use iroh::endpoint::{RecvStream, SendStream};
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use thiserror::Error;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tracing::debug;

pub const PROTOCOL_VERSION: u16 = 1;
pub const MAX_FRAME_LEN: usize = 1024 * 1024;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum Capability {
    BinaryBlobStream,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum ControlMessage {
    Hello {
        protocol_version: u16,
        node_id: [u8; 32],
    },
    DeviceMetadata {
        device_name: String,
        platform: String,
    },
    Capabilities {
        capabilities: Vec<Capability>,
    },
    TransferAck {
        byte_len: u64,
        blake3: [u8; 32],
    },
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LocalHandshake {
    pub node_id: [u8; 32],
    pub device_name: String,
    pub platform: String,
    pub capabilities: Vec<Capability>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PeerHandshake {
    pub node_id: [u8; 32],
    pub device_name: String,
    pub platform: String,
    pub capabilities: Vec<Capability>,
}

pub struct ControlChannel {
    pub send: SendStream,
    pub recv: RecvStream,
}

#[derive(Debug, Error)]
pub enum FrameError {
    #[error("unable to encode frame: {0}")]
    Encode(#[source] postcard::Error),
    #[error("unable to decode frame: {0}")]
    Decode(#[source] postcard::Error),
    #[error("frame length {actual} exceeds maximum {maximum}")]
    TooLarge { actual: usize, maximum: usize },
    #[error("frame length prefix is truncated: {0}")]
    LengthPrefix(#[source] std::io::Error),
    #[error("frame payload is truncated: {0}")]
    Payload(#[source] std::io::Error),
    #[error("frame length {declared} does not match payload length {actual}")]
    LengthMismatch { declared: usize, actual: usize },
}

#[derive(Debug, Error)]
pub enum HandshakeError {
    #[error("control framing failed: {0}")]
    Frame(#[from] FrameError),
    #[error("control stream could not be finished: {0}")]
    Finish(String),
    #[error("unsupported protocol version {0}; supported version is {PROTOCOL_VERSION}")]
    UnsupportedVersion(u16),
    #[error(
        "authenticated peer identity does not match Hello node ID: TLS={authenticated}, Hello={hello}"
    )]
    IdentityMismatch {
        authenticated: String,
        hello: String,
    },
    #[error("expected {expected} control message, received {received:?}")]
    UnexpectedMessage {
        expected: &'static str,
        received: ControlMessage,
    },
}

pub fn encode_frame<T: Serialize>(value: &T) -> Result<Vec<u8>, FrameError> {
    let payload = postcard::to_stdvec(value).map_err(FrameError::Encode)?;
    if payload.len() > MAX_FRAME_LEN {
        return Err(FrameError::TooLarge {
            actual: payload.len(),
            maximum: MAX_FRAME_LEN,
        });
    }

    let length = u32::try_from(payload.len()).map_err(|_| FrameError::TooLarge {
        actual: payload.len(),
        maximum: MAX_FRAME_LEN,
    })?;
    let mut frame = Vec::with_capacity(4 + payload.len());
    frame.extend_from_slice(&length.to_be_bytes());
    frame.extend_from_slice(&payload);
    Ok(frame)
}

pub fn decode_frame<T: DeserializeOwned>(frame: &[u8]) -> Result<T, FrameError> {
    if frame.len() < 4 {
        return Err(FrameError::LengthMismatch {
            declared: 4,
            actual: frame.len(),
        });
    }
    let declared = u32::from_be_bytes([frame[0], frame[1], frame[2], frame[3]]) as usize;
    if declared > MAX_FRAME_LEN {
        return Err(FrameError::TooLarge {
            actual: declared,
            maximum: MAX_FRAME_LEN,
        });
    }
    let payload = &frame[4..];
    if declared != payload.len() {
        return Err(FrameError::LengthMismatch {
            declared,
            actual: payload.len(),
        });
    }
    postcard::from_bytes(payload).map_err(FrameError::Decode)
}

pub fn encode_message(message: &ControlMessage) -> Result<Vec<u8>, FrameError> {
    encode_frame(message)
}

pub fn decode_message(frame: &[u8]) -> Result<ControlMessage, FrameError> {
    decode_frame(frame)
}

pub async fn write_value<W, T>(writer: &mut W, value: &T) -> Result<(), FrameError>
where
    W: AsyncWrite + Unpin,
    T: Serialize,
{
    let frame = encode_frame(value)?;
    writer.write_all(&frame).await.map_err(FrameError::Payload)
}

pub async fn read_value<R, T>(reader: &mut R) -> Result<T, FrameError>
where
    R: AsyncRead + Unpin,
    T: DeserializeOwned,
{
    let mut length_bytes = [0; 4];
    reader
        .read_exact(&mut length_bytes)
        .await
        .map_err(FrameError::LengthPrefix)?;
    let declared = u32::from_be_bytes(length_bytes) as usize;
    if declared > MAX_FRAME_LEN {
        return Err(FrameError::TooLarge {
            actual: declared,
            maximum: MAX_FRAME_LEN,
        });
    }

    let mut payload = vec![0; declared];
    reader
        .read_exact(&mut payload)
        .await
        .map_err(FrameError::Payload)?;
    postcard::from_bytes(&payload).map_err(FrameError::Decode)
}

pub async fn exchange_handshake(
    channel: &mut ControlChannel,
    local: &LocalHandshake,
    authenticated_remote_id: [u8; 32],
) -> Result<PeerHandshake, HandshakeError> {
    let hello = ControlMessage::Hello {
        protocol_version: PROTOCOL_VERSION,
        node_id: local.node_id,
    };
    debug!(message = ?hello, "control message sent");
    write_value(&mut channel.send, &hello).await?;

    let peer_hello: ControlMessage = read_value(&mut channel.recv).await?;
    debug!(message = ?peer_hello, "control message received");
    let (peer_version, peer_node_id) = match peer_hello {
        ControlMessage::Hello {
            protocol_version,
            node_id,
        } => (protocol_version, node_id),
        received => {
            return Err(HandshakeError::UnexpectedMessage {
                expected: "Hello",
                received,
            });
        }
    };
    validate_hello(peer_version, peer_node_id, authenticated_remote_id)?;

    let metadata = ControlMessage::DeviceMetadata {
        device_name: local.device_name.clone(),
        platform: local.platform.clone(),
    };
    debug!(message = ?metadata, "control message sent");
    write_value(&mut channel.send, &metadata).await?;

    let capabilities = ControlMessage::Capabilities {
        capabilities: local.capabilities.clone(),
    };
    debug!(message = ?capabilities, "control message sent");
    write_value(&mut channel.send, &capabilities).await?;

    let peer_metadata: ControlMessage = read_value(&mut channel.recv).await?;
    debug!(message = ?peer_metadata, "control message received");
    let (device_name, platform) = match peer_metadata {
        ControlMessage::DeviceMetadata {
            device_name,
            platform,
        } => (device_name, platform),
        received => {
            return Err(HandshakeError::UnexpectedMessage {
                expected: "DeviceMetadata",
                received,
            });
        }
    };

    let peer_capabilities: ControlMessage = read_value(&mut channel.recv).await?;
    debug!(message = ?peer_capabilities, "control message received");
    let capabilities = match peer_capabilities {
        ControlMessage::Capabilities { capabilities } => capabilities,
        received => {
            return Err(HandshakeError::UnexpectedMessage {
                expected: "Capabilities",
                received,
            });
        }
    };

    Ok(PeerHandshake {
        node_id: peer_node_id,
        device_name,
        platform,
        capabilities,
    })
}

pub fn validate_hello(
    protocol_version: u16,
    hello_node_id: [u8; 32],
    authenticated_remote_id: [u8; 32],
) -> Result<(), HandshakeError> {
    if protocol_version != PROTOCOL_VERSION {
        return Err(HandshakeError::UnsupportedVersion(protocol_version));
    }
    if hello_node_id != authenticated_remote_id {
        return Err(HandshakeError::IdentityMismatch {
            authenticated: hex::encode(authenticated_remote_id),
            hello: hex::encode(hello_node_id),
        });
    }
    Ok(())
}

impl fmt::Debug for ControlChannel {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ControlChannel")
            .finish_non_exhaustive()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::duplex;

    fn sample_message() -> ControlMessage {
        ControlMessage::Capabilities {
            capabilities: vec![Capability::BinaryBlobStream],
        }
    }

    #[test]
    fn control_messages_round_trip_through_a_length_prefixed_frame() -> Result<(), FrameError> {
        let message = sample_message();
        let encoded = encode_message(&message)?;
        assert_eq!(decode_message(&encoded)?, message);
        Ok(())
    }

    #[tokio::test]
    async fn async_framing_round_trips_without_buffering_the_stream() -> Result<(), FrameError> {
        let (mut writer, mut reader) = duplex(1024);
        let message = sample_message();
        let write_task = tokio::spawn(async move { write_value(&mut writer, &message).await });
        let received: ControlMessage = read_value(&mut reader).await?;
        write_task
            .await
            .map_err(|error| FrameError::Payload(std::io::Error::other(error.to_string())))??;
        assert_eq!(received, sample_message());
        Ok(())
    }

    #[test]
    fn malformed_frames_are_rejected() {
        assert!(decode_message(&[]).is_err());
        assert!(decode_message(&[0, 0, 0, 3, 1]).is_err());
        assert!(decode_message(&[0, 0, 0, 0, 1]).is_err());
        let oversized = (MAX_FRAME_LEN as u32 + 1).to_be_bytes();
        assert!(decode_message(&oversized).is_err());
    }

    #[test]
    fn unsupported_protocol_versions_are_explicit() {
        let id = [7; 32];
        assert!(matches!(
            validate_hello(PROTOCOL_VERSION + 1, id, id),
            Err(HandshakeError::UnsupportedVersion(_))
        ));
    }

    #[test]
    fn hello_identity_mismatch_is_explicit() {
        assert!(matches!(
            validate_hello(PROTOCOL_VERSION, [1; 32], [2; 32]),
            Err(HandshakeError::IdentityMismatch { .. })
        ));
    }
}
