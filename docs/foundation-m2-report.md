# Foundation Milestone 2 report

## Handoff identity

- Base SHA: `f8d6bc0cb973a1263c3f42bdc80ff79e8a91ae6b`
- Branch: `feat/foundation-m2-protocol-bootstrap`
- Implementation/test handoff SHA before this report-only documentation commit:
  `93e9b68f8d08acd291a13302c8e478a709031ec1`
- Prototype 0 status: unchanged; no files under `crates/rift-spike/` were modified.
- Rust: `1.97.1` (Homebrew), host `aarch64-apple-darwin`, LLVM `22.1.8`
- Host: macOS `26.6`, Apple M1, arm64
- Iroh: `1.0.3`
- Postcard: `1.1.3`

The final branch also contains this report and the corresponding README update as a
documentation-only handoff commit. No hosted CI result is claimed here; only the local
results below were observed.

## Production protocol v1 contract

- Protocol version: `1`
- ALPN: `rift/1` (`rift_protocol::ALPN`, defined once)
- Frame: four-byte big-endian payload length followed by Postcard payload
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
connection. No reconnect task, retry loop, background heartbeat, persistent key store,
trust store, or authorization policy was added.

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
- typed encode and write failures;
- metadata and capability bounds;
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
- unexpected first message rejection; and
- successful recovery after a failed bootstrap using the same endpoint identities.

The final production transport integration test contains 9 tests, in addition to 4
transport unit tests. It uses only production crates and deterministic loopback
networking; it does not contact public relay infrastructure or import Prototype 0.

## Validation evidence

The clean M1 base passed the baseline `cargo xtask verify` and benchmark smoke before
implementation. The initial bare local coverage attempt was blocked because this
Homebrew Rust installation does not provide rustup's `llvm-tools-preview` component.
The repository-documented Homebrew LLVM paths were available and produced the final
coverage report.

Final validation commands and results:

```text
cargo xtask verify                                      PASS
cargo test --locked -p rift-transport-iroh --test session_bootstrap PASS
cargo xtask benchmark-smoke                             PASS
LLVM_COV=/opt/homebrew/opt/llvm/bin/llvm-cov \
LLVM_PROFDATA=/opt/homebrew/opt/llvm/bin/llvm-profdata \
cargo xtask coverage                                   PASS
cargo deny --locked check                              PASS
```

The final transport integration test was run repeatedly during implementation and
passed on the final run. `cargo xtask verify` passed after the final code/test changes,
including format, strict Clippy, all workspace tests/features, warning-denied docs,
architecture checks, and supply-chain checks.

## Coverage

Final workspace coverage was above the unchanged 60.0% line floor:

| Scope | Line coverage |
| --- | ---: |
| `rift-core` | 90.28% |
| `rift-protocol` | 91.99% |
| `rift-transport-iroh` | 87.16% |
| Workspace total | 72.48% |

The package-specific figures were measured with `cargo llvm-cov --package` using the
same explicit LLVM tool paths. The workspace LCOV output is at
`target/llvm-cov/lcov.info` in the local validation workspace.

## Production protocol benchmark

Command:

```bash
cargo run --locked --release -p rift-protocol \
  --example protocol-benchmark -- 100000
```

Local release-mode result on the Apple M1 host above:

| Measurement | Result |
| --- | ---: |
| Hello encode/decode | 2,810,992.39 ops/s |
| Ping/Pong encode/decode | 20,161,459.01 ops/s |
| Encoded Hello frame | 75 bytes |
| Iterations | 100,000 |

The benchmark is a measurement baseline, not a hosted CI throughput threshold. The
smoke command runs the same production path with 100 iterations and also runs the
existing Prototype 0 benchmark with its small localhost transfer.

## Security properties preserved

- Transport authentication is not treated as authorization.
- Hello identity is cryptographically bound to the authenticated Iroh endpoint ID.
- Production transport has no plaintext fallback or insecure relay TLS option.
- Frame, metadata, and capability inputs are bounded before proportional allocation or
  acceptance.
- Unsupported versions fail explicitly; no downgrade is attempted.
- SecretKey bytes are not stored in `DeviceId`, endpoint Debug output, tracing fields,
  or library errors.
- Failed bootstrap state is closed and disposable; a fresh connection can use the same
  endpoint identity.

## Platform and CI status

The production path and complete validation firewall were run locally on macOS 26.6,
arm64, Apple M1. Hosted Linux, macOS, and Windows CI were not independently triggered
or observed during this handoff, so no hosted CI success is claimed. The existing M1
CI policy remains in place; cross-platform execution is the next external validation
step.

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
