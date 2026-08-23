use std::{env, error::Error, hint::black_box, time::Instant};

use rift_core::{DEVICE_ID_LEN, DeviceId, TrustedPeer};
use rift_trust::TrustStore;
use tempfile::TempDir;

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error + Send + Sync>> {
    let records = env::args()
        .nth(1)
        .and_then(|value| value.parse::<usize>().ok())
        .unwrap_or(1_000);
    let lookups = env::args()
        .nth(2)
        .and_then(|value| value.parse::<usize>().ok())
        .unwrap_or(records);
    if records == 0 || lookups == 0 {
        return Err("benchmark record and lookup counts must be greater than zero".into());
    }
    if records > u16::MAX as usize {
        return Err("benchmark record count must fit in a u16 identity suffix".into());
    }

    let directory = TempDir::new()?;
    let path = directory.path().join("trust.journal");
    let store = TrustStore::open(&path).await?;
    for index in 0..records {
        let device_id = benchmark_device_id(index)?;
        if index % 2 == 0 {
            store
                .trust(TrustedPeer {
                    device_id,
                    device_name: format!("benchmark-peer-{index}"),
                    platform: "benchmark".to_owned(),
                })
                .await?;
        } else {
            store.revoke(device_id).await?;
        }
    }
    let file_size = tokio::fs::metadata(&path).await?.len();
    drop(store);

    let replay_start = Instant::now();
    let store = TrustStore::open(&path).await?;
    let replay_seconds = replay_start.elapsed().as_secs_f64().max(f64::EPSILON);
    if store.list().await.len() != records {
        return Err("replayed trust entry count did not match the benchmark input".into());
    }

    let lookup_start = Instant::now();
    for index in 0..lookups {
        let state = store.state(benchmark_device_id(index % records)?).await;
        black_box(state);
    }
    let lookup_seconds = lookup_start.elapsed().as_secs_f64().max(f64::EPSILON);

    println!("production.trust_journal.records={records}");
    println!("production.trust_journal.file_bytes={file_size}");
    println!("production.trust_journal.replay_seconds={replay_seconds:.6}");
    println!(
        "production.trust_journal.lookup.ops_per_second={:.2}",
        lookups as f64 / lookup_seconds
    );
    println!("production.trust_journal.lookups={lookups}");
    Ok(())
}

fn benchmark_device_id(index: usize) -> Result<DeviceId, Box<dyn Error + Send + Sync>> {
    let suffix = u16::try_from(index)?;
    let mut bytes = [0_u8; DEVICE_ID_LEN];
    bytes[DEVICE_ID_LEN - 2..].copy_from_slice(&suffix.to_be_bytes());
    Ok(DeviceId::from_bytes(bytes))
}
