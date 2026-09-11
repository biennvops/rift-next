# Performance and regression testing

Rift separates deterministic structural gates from environment-sensitive measurements.

## Deterministic pull-request gates

Normal tests must protect properties that should not vary with runner speed:

- maximum control-frame and metadata sizes;
- bounded externally influenced queues and concurrency;
- fixed-size streaming buffers where designed;
- rejection before untrusted sizes control allocation;
- no payload-sized buffering in streaming paths;
- partial-transfer staging and cleanup;
- malformed-size and excess-stream rejection.

These tests run in `cargo xtask verify` and may fail a pull request.

## Measurement benchmarks

The production protocol benchmark measures v1 Hello encode/decode throughput, Ping/Pong
encode/decode throughput, pairing transcript/code derivation, and encoded Hello frame
size. The production trust benchmark measures bounded journal open/replay, lookup
throughput, and journal size for mixed trusted/revoked records. Foundation M4 adds
persistent identity create/load, local IPC JSON encode/decode and frame size, cold/warm
daemon startup, IPC `GetStatus` round trip, and startup with a populated trust journal.
Prototype 0's benchmark separately measures its Postcard control encode/decode throughput,
localhost Iroh transfer throughput/latency, and application streaming-buffer size. Build
and run all small direct-only smoke scenarios with:

```bash
cargo xtask benchmark-smoke
```

Capture a comparable production protocol baseline with explicit parameters, for example:

```bash
cargo run --locked --release -p rift-protocol --example protocol-benchmark -- 100000
```

Capture the 1,000-record trust-journal measurement with explicit lookup count:

```bash
cargo run --locked --release -p rift-trust \
  --example trust-benchmark -- 1000 100000
```

Capture M4 identity, IPC, and resident-runtime measurements with explicit parameters:

```bash
cargo run --locked --release -p rift-identity \
  --example identity-benchmark -- 100000
cargo run --locked --release -p rift-ipc \
  --example ipc-benchmark -- 100000
cargo run --locked --release -p rift-daemon \
  --example daemon-benchmark -- 1000 1000
```

The daemon benchmark uses direct-only local endpoints and measures first startup, warm
restart, Rust control-plane `GetStatus`, and startup after the requested number of trust
mutations. It starts no public relay infrastructure.

Capture the Prototype 0 baseline with explicit parameters, for example:

```bash
cargo run --locked --release -p rift-spike -- bench \
  --bytes 8388608 \
  --protocol-iterations 100000
```

Shared hosted-runner wall-clock results are noisy and are not hard PR gates. Compare measurements on the same representative machine and investigate material changes; do not tune a pass/fail threshold from one hosted run.

Each saved benchmark record must include:

- Git commit;
- `rustc --version --verbose` output or exact Rust version;
- Iroh version;
- OS and version;
- CPU model and architecture;
- build profile;
- benchmark parameters;
- complete result;
- relevant power, load, and network conditions.

Store milestone baselines in the milestone report. Performance-sensitive pull requests should include before/after records using the same command and environment. For memory work, add an OS-level RSS measurement and retain assertions about fixed buffers and bounded allocation.

## M5 connectivity measurements

`cargo xtask benchmark-smoke` also runs two explicitly ignored measurement tests:

```bash
cargo test --locked -p rift-daemon --lib connectivity_benchmark -- --ignored --nocapture
cargo test --locked -p rift-transport-iroh --lib device_id_conversion_benchmark -- --ignored --nocapture
```

These exercise the actual private production scheduler and DeviceId conversion without
exposing benchmark-only production APIs or duplicating the implementation in an example.
Scheduler initialization inserts 1,000 prebuilt synthetic DeviceIds into the bounded
policy map; it excludes key generation, disk replay, and network startup. Backoff uses
100,000 deterministic injected samples, including saturated attempts. DeviceId conversion
validates a fixed valid public key 10,000 times. These are measurements, not throughput
thresholds; the normal tests separately assert policy/resource properties.

The existing IPC benchmark now also measures a bounded PeerConnectivityChanged event
encode/decode round trip and its frame size. It uses the same iteration argument as the
M4 ListPeers JSON baseline. Report old/new metrics separately: M5-only paths have no M4
implementation against which to claim a speedup. Keep power/load/compiler/profile and
all benchmark parameters with the result. No new benchmark dependency is required.

## M6 streaming-engine checkpoint measurements

Until the daemon transfer runtime exists, `benchmark-smoke` additionally runs an
**engine-only**, non-QUIC measurement:

```bash
cargo test --locked -p rift-transfer --lib streaming_benchmark -- --ignored --nocapture
cargo test --locked --release -p rift-transfer --lib streaming_benchmark -- --ignored --nocapture
```

It creates an 8 MiB zero-filled source with a fixed 64 KiB buffer, measures a separate
whole-source prehash, then sends through a bounded 64 KiB Tokio duplex stream into a
real temporary file at offsets 0 and 4 MiB. It reports separate prefix-rehash and
sync times. `attempt_with_revalidation_seconds` includes the sender's mandatory
whole-source revalidation, prefix rehashing on both sides, suffix I/O, and integrity
verification. It is deliberately **not** labeled payload-only throughput, a daemon
transfer benchmark, atomic-publication time, or a Prototype 0 comparison. Normal tests
also run a synthetic 64 MiB stream that records every I/O buffer request size.

The planned matched production-vs-Prototype 0 and durable-resume measurements remain
required when the runtime exists. Do not substitute this engine-only fixture for
those end-to-end measurements. No timing thresholds are enforced.
