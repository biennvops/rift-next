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

## Initial Homebrew baseline validation

- `cargo xtask verify`: PASS. Dependency auditing emitted warnings, including a
  yanked transitive `chacha20 0.10.1`; no dependencies or lockfile were changed.
- `cargo xtask coverage`: BLOCKED before tests: `cargo llvm-cov` could not find
  `llvm-tools-preview`. No baseline coverage percentage was obtained.
- `cargo xtask benchmark-smoke`: PASS.
- No hosted CI results have been observed for this branch.

The initial blocker was resolved after approval by installing `llvm-tools-preview`
for the existing Rust 1.91.0 toolchain. Neither the Rust pin nor CI configuration
needed to change. No implementation or dependency changes were needed.

## Canonical pinned-toolchain baseline

All three commands passed using Rust `1.91.0 (f8297e351 2025-10-28)`, Cargo
`1.91.0 (ea2d97820 2025-10-10)`, LLVM `21.1.2`, on the same host. These results
supersede the Homebrew measurements for subsequent same-toolchain comparisons.

To ensure nested commands use the pinned compiler rather than Homebrew:

```bash
export PATH="$(dirname "$(rustup which --toolchain 1.91.0 cargo)"):$PATH"
cargo xtask verify
cargo xtask coverage
cargo xtask benchmark-smoke
```

`rustup run 1.91.0 cargo xtask coverage` alone did not resolve the nested tool
selection on this host. Explicitly selecting the toolchain binary directory did.

- `cargo xtask verify`: PASS.
- `cargo xtask coverage`: PASS, **80.23%** workspace line coverage; unchanged 60% floor.
- `cargo xtask benchmark-smoke`: PASS.
- Baseline code is still the starting M4 revision; only this report has changed.

| Production package | Line coverage |
| --- | ---: |
| `rift-core` | 92.47% |
| `rift-protocol` | 93.55% |
| `rift-transport-iroh` | 85.58% |
| `rift-trust` | 93.87% |
| `rift-session` | 90.80% |
| `rift-identity` | 87.29% |
| `rift-ipc` | 95.44% |
| `rift-daemon` | 77.82% |

Daemon coverage aggregates its binary, library, IPC server, and local runtime files
(1,228 covered / 1,578 total lines). Baseline coverage is observed evidence, not a
claim that M5 behavior is implemented.

## Initial Homebrew benchmark results

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

## Pinned-toolchain benchmark results

Same smoke command, parameters, dev/debug profile, and host as above; power and
competing load were not controlled. No public N0 service was validated. Measurements
were collected at documentation commit `a0ca353`, with implementation unchanged
from base `f43cce58fa47a7b6202f6b0d205883bfc9947584`.

```text
production.protocol_v1.hello_encode_decode.ops_per_second=293650.40
production.protocol_v1.ping_pong_encode_decode.ops_per_second=1823021.11
production.protocol_v1.pairing_code.ops_per_second=109359.42
production.protocol_v1.hello_frame_bytes=75
production.protocol_v1.iterations=100
production.protocol_v1.hello_bytes_processed=7500
production.trust_journal.records=10
production.trust_journal.file_bytes=835
production.trust_journal.replay_seconds=0.000139
production.trust_journal.lookup.ops_per_second=1177634.37
production.trust_journal.lookups=100
production.identity.cold_create_seconds=0.010248
production.identity.warm_load_seconds=0.000130
production.identity.iterations=100
production.identity.file_bytes=74
production.ipc_json.encode_decode.ops_per_second=41760.91
production.ipc_json.frame_bytes=148
production.ipc_json.payload_bytes=144
production.ipc_json.iterations=100
production.daemon.cold_start_seconds=0.138698
production.daemon.warm_restart_seconds=0.019378
production.daemon.ipc_get_status_round_trip_seconds=0.000158
production.daemon.ipc_get_status_iterations=10
production.daemon.trust_replay_records=100
production.daemon.trust_replay_start_seconds=0.042924
protocol.encode_decode.ops_per_second=21029.94
transfer.localhost.mib_per_second=15.85
transfer.localhost.seconds=0.003943
transfer.localhost.bytes=65536
transfer.streaming_buffer_bytes=65536
```

## Remaining work

All M5 implementation and acceptance checks remain outstanding, including transport
lookup, purpose-gated admission, canonical sessions, owned bounded reconnect, IPC
extensions, regression tests, conformance vectors, ADRs, documentation, coverage,
and before/after performance comparison. Existing M4 behavior remains unchanged.
