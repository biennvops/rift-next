use std::time::Instant;

use rift_core::DeviceId;
use rift_ipc::{ClientMessage, Request, encode_json_frame};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let iterations = std::env::args()
        .nth(1)
        .as_deref()
        .unwrap_or("100")
        .parse::<usize>()?;
    if iterations == 0 {
        return Err("iterations must be greater than zero".into());
    }

    let message = ClientMessage::Request {
        id: 42,
        request: Request::ListPeers {
            after: Some(DeviceId::from_bytes([7; 32])),
            limit: 128,
        },
    };
    let frame = encode_json_frame(&message)?;
    let payload = &frame[4..];
    let start = Instant::now();
    for _ in 0..iterations {
        let encoded = encode_json_frame(&message)?;
        let decoded: ClientMessage = serde_json::from_slice(&encoded[4..])?;
        if decoded != message {
            return Err("IPC benchmark round trip changed the message".into());
        }
    }
    let elapsed = start.elapsed().as_secs_f64();

    println!(
        "production.ipc_json.encode_decode.ops_per_second={:.2}",
        iterations as f64 / elapsed
    );
    println!("production.ipc_json.frame_bytes={}", frame.len());
    println!("production.ipc_json.payload_bytes={}", payload.len());
    println!("production.ipc_json.iterations={iterations}");
    Ok(())
}
