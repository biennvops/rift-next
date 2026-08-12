# Foundation Milestone 2 report

## Handoff identity

- Base SHA: `f8d6bc0cb973a1263c3f42bdc80ff79e8a91ae6b`
- Branch: `feat/foundation-m2-protocol-bootstrap`
- Implementation/test handoff SHA covered by this report refresh:
  `164ae184132f0bc8f00a7b67ed97a3783934a810`
- Previous reviewed report head: `74ffbeab1837c07928a4e8c030796efa3c2e25e4`
- Post-report safety commits included in this refresh:
  - `f39eafd`: strict Postcard payload consumption;
  - `2713d72`: bounded Hello wire deserialization; and
  - `164ae18`: disposable control-connection poisoning.
- Prototype 0 status: unchanged; no files under `crates/rift-spike/` were modified.
- Rust: `1.97.1` (Homebrew), host `aarch64-apple-darwin`, LLVM `22.1.8`
- Host: macOS `26.6`, Apple M1, arm64
- Iroh: `1.0.3`
- Postcard: `1.1.3`

The three safety commits changed four files relative to the previous reviewed report
head—`rift-protocol` implementation, `rift-transport-iroh` implementation and integration
tests, and the protocol specification—with 331 insertions and 31 deletions. The refreshed
report is a documentation-only follow-up to the implementation/test head above. The local
and hosted results below were observed at that exact SHA.

## Production protocol v1 contract

- Protocol version: `1`
- ALPN: `rift/1` (`rift_protocol::ALPN`, defined once)
- Frame: four-byte big-endian payload length followed by exactly one Postcard value that
  consumes the complete payload
- Maximum control payload: `1,048,576` bytes
- Device name bound: `128` UTF-8 bytes
- Platform bound: `64` UTF-8 bytes
- Capability count bound: `64`
- Messages: `Hello`, `Ping`, `Pong`
- Default advertised capabilities: empty
- Reserved known capability: numeric `1`, `BLOB_TRANSFER_V1`; not advertised by M2
  production bootstrap
- Conformance vectors: [`docs/protocol/v1-vectors.json`](protocol/v1-vectors.json)
- Protocol specification: [`docs/protocol/v1.md`](protocol/v1.md)
- ADR: [`docs/adr/0006-production-protocol-v1-bootstrap.md`](adr/0006-production-protocol-v1-bootstrap.md)

`DeviceId` is a 32-byte, transport-independent public identity owned by `rift-core`.
The production transport derives it from the Iroh endpoint public key. The production
bootstrap constructs local Hello from the endpoint-owned identity, validates the peer's
version and metadata, and rejects any Hello identity that differs from the Iroh-
authenticated remote endpoint ID. The result is authenticated, not paired or
authorized.

## Workspace dependency edges

The production graph is now:

```text
rift-protocol       -> rift-core
rift-transport-iroh -> rift-core
rift-transport-iroh -> rift-protocol
```

`rift-transport-iroh` directly pins Iroh to `=1.0.3` and has no direct `iroh-relay`
dependency. Internal production path dependencies are pinned to `=0.1.0` to satisfy
the supply-chain wildcard policy. No generic transport trait was introduced.

## Production API and lifecycle

`rift-transport-iroh::RiftEndpoint` now:

- binds from a caller-supplied Iroh `SecretKey`;
- configures only the production ALPN and selected relay mode;
- supports direct loopback mode without external infrastructure;
- bounds connect, accept, control-stream, Hello, and post-handshake control operations;
- exposes authenticated connect/accept and control-stream open/accept operations;
- composes outbound and inbound Hello bootstrap into `BootstrappedConnection`; and
- provides explicit connection and endpoint close operations.

Failed stream establishment and failed Hello bootstrap close the disposable QUIC
connection. A post-bootstrap control timeout, framing failure, or sequencing failure
discards the control stream, closes the connection, and permanently poisons that
connection wrapper; a later control call fails without touching the stream. The endpoint
identity remains usable for a fresh connection. No reconnect task, retry loop, background
heartbeat, persistent key store, trust store, or authorization policy was added.

## Tests added

### `rift-core`

- fixed-size DeviceId construction and byte round trip;
- equality, ordering, hashing, and canonical lowercase hexadecimal formatting; and
- malformed byte-slice rejection.

### `rift-protocol`

- Hello, Ping, and Pong round trips;
- exact conformance-vector payload/frame equality;
- Unicode and empty/non-empty capability vectors;
- four-byte big-endian framing;
- exactly-at-limit and one-byte-over-limit frame behavior;
- rejection before payload allocation for oversized stream declarations;
- zero-length, malformed Postcard, in-memory length mismatch, truncated prefix, and
  truncated payload behavior;
- strict rejection of trailing Postcard payload bytes for both in-memory and streamed
  frame decoding;
- typed encode and write failures;
- metadata and capability bounds, including wire-level rejection during deserialization
  before allocating owned over-limit strings or growing capability storage past its bound;
- unsupported version, identity mismatch, wrong first message, and Hello timeout; and
- Ping/Pong nonce and sequencing failures.

### `rift-transport-iroh`

- supplied SecretKey to DeviceId derivation;
- loopback/direct configuration and endpoint close behavior;
- explicit timeout configuration validation;
- production two-endpoint direct bootstrap;
- authenticated remote identity checks in both directions;
- peer metadata and capability exposure;
- post-bootstrap Ping/Pong;
- identity spoof rejection;
- unsupported-version rejection without downgrade;
- oversized-frame rejection;
- truncated Hello rejection;
- silent-peer control-stream deadline;
- unexpected first message rejection;
- successful recovery after a failed bootstrap using the same endpoint identities;
- partial-Pong timeout poisoning and deterministic rejection of connection reuse; and
- sequencing-error poisoning and deterministic rejection of connection reuse.

The production protocol unit suite contains 19 tests. The production transport
integration test contains 11 tests, in addition to 4 transport unit tests. It uses only
production crates and deterministic loopback networking; it does not contact public
relay infrastructure or import Prototype 0.

## Validation evidence

The clean M1 base passed the baseline `cargo xtask verify` and benchmark smoke before
implementation. All commands below were rerun against
`164ae184132f0bc8f00a7b67ed97a3783934a810`. This Homebrew Rust installation does not
provide rustup's `llvm-tools-preview` component, so coverage used the
repository-documented Homebrew LLVM paths.

Refreshed validation commands and results:

```text
cargo xtask verify                                      PASS
cargo test --locked -p rift-transport-iroh \
  --test session_bootstrap                              PASS (11 tests)
cargo xtask benchmark-smoke                             PASS
LLVM_COV=/opt/homebrew/opt/llvm/bin/llvm-cov \
LLVM_PROFDATA=/opt/homebrew/opt/llvm/bin/llvm-profdata \
cargo xtask coverage                                   PASS
cargo llvm-cov --locked --package rift-core \
  --summary-only                                       PASS
cargo llvm-cov --locked --package rift-protocol \
  --summary-only                                       PASS
cargo llvm-cov --locked --package rift-transport-iroh \
  --summary-only                                       PASS
```

The transport integration test was run separately and again through the complete
firewall. `cargo xtask verify` passed after all three safety commits, including format,
strict Clippy, all workspace tests/features, warning-denied docs, architecture checks,
and supply-chain checks.

Both same-SHA GitHub Actions executions initially failed before any job step ran; GitHub
recorded empty step lists for all ten failed jobs. Every failed job was rerun. Attempt 2
of both the
[`pull_request` run](https://github.com/biennvops/rift-next/actions/runs/31580150822) and
the [`push` run](https://github.com/biennvops/rift-next/actions/runs/31580145973) passed
all five jobs: Linux quality firewall, Linux coverage floor and LCOV upload, production
crates on macOS, production crates on advisory Windows, and benchmark smoke.

## Coverage

Refreshed workspace coverage remains above the unchanged 60.0% line floor:

| Scope | Previous report | At `164ae184` | Change |
| --- | ---: | ---: | ---: |
| `rift-core` | 90.28% | 90.28% | 0.00 pp |
| `rift-protocol` | 91.99% | 91.92% | -0.07 pp |
| `rift-transport-iroh` | 87.16% | 86.48% | -0.68 pp |
| Workspace total | 72.48% | 73.02% | +0.54 pp |

The package-specific figures were measured with `cargo llvm-cov --package` using the
same explicit LLVM tool paths. The workspace LCOV output is at
`target/llvm-cov/lcov.info` in the local validation workspace. These are point-in-time
measurements for the stated implementation head, not permanent or final percentages.

## Production protocol benchmark

Command:

```bash
cargo run --locked --release -p rift-protocol \
  --example protocol-benchmark -- 1000000
```

Seven paired release-mode samples compared the previous reviewed report head
`74ffbeab1837c07928a4e8c030796efa3c2e25e4` with the implementation/test head
`164ae184132f0bc8f00a7b67ed97a3783934a810`. The two locked trees were built with the
same compiler and release profile, then their binaries were run alternately on the Apple
M1 host above. Values are operations per second:

| Sample | `74ffbea` Hello | `164ae184` Hello | `74ffbea` Ping/Pong | `164ae184` Ping/Pong |
| ---: | ---: | ---: | ---: | ---: |
| 1 | 2,742,827.37 | 3,007,475.83 | 19,688,850.60 | 18,187,495.00 |
| 2 | 2,980,439.00 | 3,012,062.55 | 19,769,438.92 | 18,456,015.85 |
| 3 | 2,945,484.24 | 3,077,232.77 | 20,045,193.49 | 18,543,593.75 |
| 4 | 2,949,325.42 | 2,991,752.49 | 19,640,786.32 | 18,383,669.54 |
| 5 | 2,881,557.54 | 3,023,580.90 | 19,894,344.52 | 18,335,489.08 |
| 6 | 2,925,166.20 | 3,004,166.02 | 19,720,721.84 | 18,432,684.33 |
| 7 | 2,984,107.38 | 3,074,137.44 | 20,141,079.80 | 18,570,827.90 |
| Median | 2,945,484.24 | 3,012,062.55 | 19,769,438.92 | 18,432,684.33 |

The current median changed by +2.26% for Hello encode/decode and -6.76% for Ping/Pong
encode/decode. Both heads encoded the Hello frame as 75 bytes. Each sample used
1,000,000 iterations and processed 75,000,000 encoded Hello bytes. The current decoder
now performs the mandatory complete-payload-consumption check on both measured paths;
the comparison records its result without turning noisy wall-clock throughput into a
pass/fail threshold.

The host was connected to AC power with the battery at 80%; setup-time load averages
were approximately 2.6. The production protocol benchmark performs no network I/O. The
previous report's single 100,000-iteration measurement is superseded by this paired
comparison and is not treated as a final result. The smoke command still runs the same
production path with 100 iterations and the existing Prototype 0 benchmark with its
small localhost transfer.

## Security properties preserved

- Transport authentication is not treated as authorization.
- Hello identity is cryptographically bound to the authenticated Iroh endpoint ID.
- Production transport has no plaintext fallback or insecure relay TLS option.
- Frame payloads must decode to exactly one Postcard value with no trailing bytes.
- Frame, metadata, and capability inputs are bounded before proportional allocation or
  acceptance; Hello string lengths and capability counts are enforced during wire
  deserialization.
- Unsupported versions fail explicitly; no downgrade is attempted.
- SecretKey bytes are not stored in `DeviceId`, endpoint Debug output, tracing fields,
  or library errors.
- Failed bootstrap state is closed and disposable; a fresh connection can use the same
  endpoint identity.
- Failed post-bootstrap control state is closed, poisoned, and unavailable for reuse.

## Platform and CI status

The production path and complete validation firewall were run locally on macOS 26.6,
arm64, Apple M1. At `164ae184`, hosted Linux, macOS, and advisory Windows CI all passed
in both rerun workflow executions linked above. Linux ran the canonical firewall and
coverage upload, macOS and Windows ran the production crates, and benchmark smoke passed.

## Intentionally deferred to Foundation M3 and later

- pairing UX;
- authorization and trust persistence;
- revocation;
- multi-version negotiation beyond v1;
- durable peer records and address discovery/rendezvous;
- reconnect loops, backoff, state replay, and offline delivery;
- blob/file transfer, transfer IDs, resumability, idempotency, and cancellation;
- daemon lifecycle and local IPC;
- BLE;
- folder sync, notifications, clipboard, and media;
- FFI, mobile APIs, and native UI;
- production relay-server implementation; and
- persistent key storage or OS keychain integration.
