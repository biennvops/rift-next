use std::time::Instant;

use rift_identity::IdentityStore;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let iterations = std::env::args()
        .nth(1)
        .as_deref()
        .unwrap_or("100")
        .parse::<usize>()?;
    if iterations == 0 {
        return Err("iterations must be greater than zero".into());
    }

    let directory = tempfile::tempdir()?;
    let path = directory.path().join("identity.key");
    let cold_start = Instant::now();
    let identity = IdentityStore::load_or_create(&path)?;
    let cold_seconds = cold_start.elapsed().as_secs_f64();
    let expected = identity.device_id();

    let warm_start = Instant::now();
    for _ in 0..iterations {
        let loaded = IdentityStore::load_or_create(&path)?;
        if loaded.device_id() != expected {
            return Err("persistent identity changed during benchmark".into());
        }
    }
    let warm_seconds = warm_start.elapsed().as_secs_f64();

    println!("production.identity.cold_create_seconds={cold_seconds:.6}");
    println!(
        "production.identity.warm_load_seconds={:.6}",
        warm_seconds / iterations as f64
    );
    println!("production.identity.iterations={iterations}");
    println!("production.identity.file_bytes={}", path.metadata()?.len());
    Ok(())
}
