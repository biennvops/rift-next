use std::{env, error::Error, hint::black_box, time::Instant};

use rift_core::DeviceId;
use rift_protocol::{
    ControlMessage, Hello, HelloMetadata, PAIRING_ID_LEN, PAIRING_NONCE_LEN, PairingTranscript,
    decode_message, encode_message,
};

fn main() -> Result<(), Box<dyn Error + Send + Sync>> {
    let iterations = env::args()
        .nth(1)
        .and_then(|value| value.parse::<u64>().ok())
        .unwrap_or(1_000);
    if iterations == 0 {
        return Err("benchmark iterations must be greater than zero".into());
    }

    let hello = Hello::new(
        DeviceId::from_bytes([0x42; 32]),
        HelloMetadata::new("benchmark-device", "benchmark-platform", Vec::new())?,
    )?;
    let hello_frame = encode_message(&ControlMessage::Hello(hello.clone()))?;
    let hello_start = Instant::now();
    let mut hello_bytes = 0_usize;
    for _ in 0..iterations {
        let frame = encode_message(&ControlMessage::Hello(hello.clone()))?;
        hello_bytes = hello_bytes.saturating_add(frame.len());
        let decoded = decode_message(&frame)?;
        black_box(decoded);
    }
    let hello_seconds = hello_start.elapsed().as_secs_f64().max(f64::EPSILON);

    let ping_start = Instant::now();
    for nonce in 0..iterations {
        for message in [
            ControlMessage::Ping { nonce },
            ControlMessage::Pong { nonce },
        ] {
            let frame = encode_message(&message)?;
            let decoded = decode_message(&frame)?;
            black_box(decoded);
        }
    }
    let ping_seconds = ping_start.elapsed().as_secs_f64().max(f64::EPSILON);
    let ping_pong_operations = iterations.saturating_mul(2);

    let pairing_transcript = PairingTranscript::new(
        DeviceId::from_bytes([0x11; 32]),
        DeviceId::from_bytes([0x22; 32]),
        [0x33; PAIRING_ID_LEN],
        [0x44; PAIRING_NONCE_LEN],
        [0x55; PAIRING_NONCE_LEN],
    );
    let pairing_start = Instant::now();
    for _ in 0..iterations {
        black_box(pairing_transcript.code());
    }
    let pairing_seconds = pairing_start.elapsed().as_secs_f64().max(f64::EPSILON);

    println!(
        "production.protocol_v1.hello_encode_decode.ops_per_second={:.2}",
        iterations as f64 / hello_seconds
    );
    println!(
        "production.protocol_v1.ping_pong_encode_decode.ops_per_second={:.2}",
        ping_pong_operations as f64 / ping_seconds
    );
    println!(
        "production.protocol_v1.pairing_code.ops_per_second={:.2}",
        iterations as f64 / pairing_seconds
    );
    println!(
        "production.protocol_v1.hello_frame_bytes={}",
        hello_frame.len()
    );
    println!("production.protocol_v1.iterations={iterations}");
    println!("production.protocol_v1.hello_bytes_processed={hello_bytes}");
    Ok(())
}
