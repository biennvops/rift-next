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

The production protocol benchmark measures v1 Hello encode/decode throughput, Ping/Pong encode/decode throughput, and encoded Hello frame size. Prototype 0's benchmark separately measures its Postcard control encode/decode throughput, localhost Iroh transfer throughput/latency, and application streaming-buffer size. Build and run both small smoke scenarios with:

```bash
cargo xtask benchmark-smoke
```

Capture a comparable production protocol baseline with explicit parameters, for example:

```bash
cargo run --locked --release -p rift-protocol --example protocol-benchmark -- 100000
```

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
