use rift_core::DeviceId;
use rift_ipc::{
    ClientMessage, Event, PairingAttemptId, PendingPairingInfo, Request, Response, RuntimeState,
    ServerMessage, SessionId, SessionInfo, Status, encode_json_frame,
};
use serde::Serialize;
use serde_json::{Value, json};

fn vector<T: Serialize>(
    name: &str,
    direction: &str,
    message: &T,
) -> Result<Value, Box<dyn std::error::Error>> {
    let payload = serde_json::to_string(message)?;
    let frame = encode_json_frame(message)?;
    Ok(json!({
        "name": name,
        "direction": direction,
        "semantic": serde_json::to_value(message)?,
        "payload_utf8": payload,
        "payload_hex": hex::encode(payload.as_bytes()),
        "frame_hex": hex::encode(frame),
    }))
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let one = DeviceId::from_bytes([1; 32]);
    let two = DeviceId::from_bytes([2; 32]);
    let vectors = vec![
        vector(
            "authenticate",
            "client_to_daemon",
            &ClientMessage::Authenticate {
                version: 1,
                token: "00".repeat(32),
            },
        )?,
        vector(
            "get_status_request",
            "client_to_daemon",
            &ClientMessage::Request {
                id: 1,
                request: Request::GetStatus {},
            },
        )?,
        vector(
            "get_status_response",
            "daemon_to_client",
            &ServerMessage::Response {
                id: 1,
                result: Response::Status {
                    status: Status {
                        daemon_version: "0.1.0".to_owned(),
                        device_id: one,
                        device_name: "Node A".to_owned(),
                        platform: "test".to_owned(),
                        state: RuntimeState::Running,
                        active_sessions: 1,
                        pending_pairings: 0,
                        pairing_enabled: true,
                    },
                },
            },
        )?,
        vector(
            "list_peers_request",
            "client_to_daemon",
            &ClientMessage::Request {
                id: 2,
                request: Request::ListPeers {
                    after: None,
                    limit: 128,
                },
            },
        )?,
        vector(
            "confirm_pairing_request",
            "client_to_daemon",
            &ClientMessage::Request {
                id: 3,
                request: Request::ConfirmPairing {
                    attempt_id: PairingAttemptId(7),
                    accepted: true,
                },
            },
        )?,
        vector(
            "revoke_peer_request",
            "client_to_daemon",
            &ClientMessage::Request {
                id: 4,
                request: Request::RevokePeer { device_id: two },
            },
        )?,
        vector(
            "forget_peer_request",
            "client_to_daemon",
            &ClientMessage::Request {
                id: 5,
                request: Request::ForgetPeer { device_id: two },
            },
        )?,
        vector(
            "pairing_pending_event",
            "daemon_to_client",
            &ServerMessage::Event {
                event: Event::PairingPending {
                    pairing: PendingPairingInfo {
                        attempt_id: PairingAttemptId(7),
                        device_id: two,
                        device_name: "Node B".to_owned(),
                        platform: "test".to_owned(),
                        verification_code: "042731".to_owned(),
                        timeout_remaining_ms: 60_000,
                    },
                },
            },
        )?,
        vector(
            "session_opened_event",
            "daemon_to_client",
            &ServerMessage::Event {
                event: Event::SessionOpened {
                    session: SessionInfo {
                        session_id: SessionId(9),
                        device_id: two,
                        device_name: "Node B".to_owned(),
                        platform: "test".to_owned(),
                    },
                },
            },
        )?,
    ];
    let document = json!({
        "ipc_protocol_version": 1,
        "frame": "u32 big-endian payload length followed by exact UTF-8 JSON bytes",
        "vectors": vectors,
    });
    let output = serde_json::to_string_pretty(&document)? + "\n";
    let path =
        std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../docs/ipc/v1-vectors.json");
    std::fs::write(&path, output)?;
    println!("wrote {}", path.display());
    Ok(())
}
