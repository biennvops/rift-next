# Foundation Milestone 5 report

## Status: baseline only — implementation not started

Foundation M5 is not complete. This report records the starting evidence requested by
`PLAN.md`; it is not an implementation handoff or a claim of M5 security properties.

## Starting revision and environment

- Base: `f43cce58fa47a7b6202f6b0d205883bfc9947584`.
- Fetched origin and fast-forward checked `main`; it already matched the expected base.
- Working branch: `feat/foundation-m5-reachability-reconnect`.
- Iroh: exactly `=1.0.3`, unchanged.
- Actual compiler on PATH: Homebrew Rust `1.98.0 (88d9e12ae 2026-08-18)`,
  host `aarch64-apple-darwin`, LLVM `22.1.8`.
- Repository rustup override: `1.91.0-aarch64-apple-darwin`. The baseline commands
  used the Homebrew compiler, not this override.
- Host: macOS `26.6.2` (`25G83`), Apple M1, arm64.
- Benchmark profile: dev/debug; power and competing system load were not controlled.
- Network benchmark: local direct connections; no public N0 lookup was validated.

## Baseline validation

- `cargo xtask verify`: PASS. Dependency auditing emitted warnings, including a
  yanked transitive `chacha20 0.10.1`; no dependencies or lockfile were changed.
- `cargo xtask coverage`: BLOCKED before tests: `cargo llvm-cov` could not find
  `llvm-tools-preview`. No baseline coverage percentage was obtained.
- `cargo xtask benchmark-smoke`: PASS.
- No hosted CI results have been observed for this branch.

Coverage tooling installation requires approval under the global engineering rules.
Resolve the compiler/tooling mismatch and collect coverage before continuing the baseline.

## Baseline benchmark results

Command: `cargo xtask benchmark-smoke`. Protocol, identity, and IPC iterations: 100;
trust records/lookups: 10/100; daemon IPC iterations/trust records: 10/100;
Prototype 0 transfer bytes/protocol iterations: 65536/100.

These are historical, non-gating measurements at the base revision, not M5 results.

```text
production.protocol_v1.hello_encode_decode.ops_per_second=121261.21
production.protocol_v1.ping_pong_encode_decode.ops_per_second=1664364.30
production.protocol_v1.pairing_code.ops_per_second=91341.55
production.protocol_v1.hello_frame_bytes=75
production.protocol_v1.iterations=100
production.protocol_v1.hello_bytes_processed=7500
production.trust_journal.records=10
production.trust_journal.file_bytes=835
production.trust_journal.replay_seconds=0.000132
production.trust_journal.lookup.ops_per_second=1343020.99
production.trust_journal.lookups=100
production.identity.cold_create_seconds=0.011188
production.identity.warm_load_seconds=0.000120
production.identity.iterations=100
production.identity.file_bytes=74
production.ipc_json.encode_decode.ops_per_second=40273.18
production.ipc_json.frame_bytes=148
production.ipc_json.payload_bytes=144
production.ipc_json.iterations=100
production.daemon.cold_start_seconds=0.121210
production.daemon.warm_restart_seconds=0.014654
production.daemon.ipc_get_status_round_trip_seconds=0.000128
production.daemon.ipc_get_status_iterations=10
production.daemon.trust_replay_records=100
production.daemon.trust_replay_start_seconds=0.048970
protocol.encode_decode.ops_per_second=21700.80
transfer.localhost.mib_per_second=21.14
transfer.localhost.seconds=0.002957
transfer.localhost.bytes=65536
transfer.streaming_buffer_bytes=65536
```

## Remaining work

All M5 implementation and acceptance checks remain outstanding, including transport
lookup, purpose-gated admission, canonical sessions, owned bounded reconnect, IPC
extensions, regression tests, conformance vectors, ADRs, documentation, coverage,
and before/after performance comparison. Existing M4 behavior remains unchanged.
