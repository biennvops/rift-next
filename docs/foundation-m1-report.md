# Foundation Milestone 1 report

Evidence refreshed 2026-08-09.

## Revisions and toolchain

- Base commit: `af2e423ead6b5f67e533a2a4033195f0b15b80d8`
- Final implementation commit: `65d40d48eb7e8916b131b1f49e12c1ead606a7c4`
- Final report commit: the commit containing this file (the branch tip at handoff; a Git commit cannot embed its own SHA)
- Pinned project/CI Rust: `1.91.0`
- Local validation Rust: `rustc 1.97.1 (8bab26f4f 2026-07-14)`, LLVM `22.1.8`, Homebrew installation
- Iroh: exactly `1.0.3`
- cargo-deny: exactly `0.20.2`
- cargo-llvm-cov: exactly `0.8.7`

The repository was fetched and rebased against `origin/main` before work. `main` was current at the base SHA, and the initial tree was clean.

## Workspace established

```text
crates/rift-core             platform-independent domain ownership; no APIs invented
crates/rift-protocol         production wire/protocol ownership; no spike port
crates/rift-transport-iroh   concrete Iroh boundary; no insecure relay/server API
crates/rift-spike            unchanged non-production Prototype 0 behavior/evidence
xtask                        canonical validation and architecture policy
```

`cargo xtask architecture` reads Cargo's resolved `resolve.nodes` package-ID graph with all workspace features enabled and enforces forbidden transitive dependencies from core/protocol, forbids a direct production `iroh-relay` dependency, and verifies exact `=1.0.3` Iroh requirements from manifest declarations. Its tests prove that forbidden direct/transitive dependencies, loose pins, duplicate package names/versions, and optional Iroh dependencies resolved under all features are rejected. No generic transport trait or placeholder domain/protocol API was added. The `cargo xtask` alias and nested Cargo invocations use `--locked` so validation cannot repair a stale lockfile before the checks run; the architecture metadata query also uses `--all-features` so non-default optional edges are validated.

## Validation evidence

The untouched base passed:

```bash
cargo fmt --check
cargo clippy --all-targets --all-features -- -D warnings
cargo test --all
```

That run passed 27 Prototype 0 tests: 24 unit tests, the direct networking integration test, the relay-only integration test, and the live direct-to-relay recovery integration test.

The implementation checkpoint passed the complete canonical firewall:

```bash
cargo xtask verify
```

This executed, in fail-fast order:

```bash
cargo fmt --all --check
cargo clippy --locked --workspace --all-targets --all-features -- -D warnings
cargo test --locked --workspace --all-features
RUSTDOCFLAGS="-D warnings" cargo doc --locked --workspace --all-features --no-deps
cargo metadata --format-version 1 --locked --all-features  # architecture policy
cargo deny --locked check
```

The workspace suite passed 37 tests: the original 27, the wildcard IPv4 proxy regression test, and nine xtask policy/failure-propagation tests. The live direct-to-relay test also passed in eight consecutive focused local runs after synchronizing both peers on an open relay path before cutting direct UDP. Warning-denied documentation and all supply-chain checks passed. Production crates also passed an independent package-scoped test/doc-test run:

```bash
cargo test --all-features \
  -p rift-core \
  -p rift-protocol \
  -p rift-transport-iroh
```

The benchmark path passed:

```bash
cargo xtask benchmark-smoke
```

## CI firewall

The workflow defines:

- `quality-linux` (required): installs pinned cargo-deny and runs `cargo xtask verify`, including all Prototype 0 direct/relay/recovery tests;
- `coverage-linux` (required): installs pinned cargo-llvm-cov, enforces the line floor, and uploads LCOV;
- `macos-smoke` (required): tests all production foundation crates;
- `windows-smoke` (advisory via `continue-on-error`): exposes production-crate status without becoming a roadmap veto;
- `benchmark-smoke`: runs the deterministic benchmark smoke path without a noisy throughput threshold.

These hosted jobs were configured but not claimed as executed locally. Linux/Windows results will be established by CI.

## Dependency and supply-chain policy

`cargo deny check` passed advisories, licenses, bans, and sources. The policy permits crates.io only, denies unknown registries/Git sources and wildcard requirements, and uses a reviewed permissive license set plus narrow exceptions for the actual MPL-2.0, CDLA-Permissive-2.0, and Unlicense transitive crates.

Two unmaintained advisories remain visible as scoped exceptions because the exact Iroh/Postcard graph has no safe compatible upgrade:

- `RUSTSEC-2023-0089`: `atomic-polyfill` through Postcard/heapless;
- `RUSTSEC-2024-0436`: `paste` through Iroh netwatch/netlink dependencies.

Duplicate-version checking remains enabled as warnings. The observed duplicate names are transitive graph convergence in Iroh and platform support: `core-foundation`, `cpufeatures`, `crypto-common`, `getrandom`, `hashbrown`, `jni`, `jni-sys`, `spin`, `syn`, `thiserror`, `thiserror-impl`, `windows-sys`, `windows-targets`, and associated Windows target crates. Foundation M1 does not loosen the Iroh pin or churn that validated graph merely to collapse these versions.

## Coverage baseline

The measured command on this machine was:

```bash
LLVM_COV=/opt/homebrew/opt/llvm/bin/llvm-cov \
LLVM_PROFDATA=/opt/homebrew/opt/llvm/bin/llvm-profdata \
cargo xtask coverage
```

It ran all 37 tests and generated `target/llvm-cov/lcov.info`.

| Scope | Line coverage |
| --- | ---: |
| Entire meaningful workspace | 65.34% |
| Spike identity | 94.09% |
| Spike protocol | 84.82% |
| Spike transfer | 93.27% |
| Spike network | 80.27% |
| xtask | 69.37% |

The enforced non-regression floor remains 60.0%, established from the original measured 61.05% baseline with modest cross-platform instrumentation tolerance. The refreshed result is 65.34%; neither percentage is a quality target or a substitute for targeted failure/state-machine tests.

The first bare `cargo xtask coverage` attempt failed before tests because Homebrew Rust does not provide the rustup-managed `llvm-tools-preview` component. The matching Homebrew LLVM 22 tools succeeded when specified explicitly. CI installs `llvm-tools-preview`, so its canonical command remains bare.

## Foundation M1 performance baseline

Benchmark measurement commit: `c4393cf146b0233299dd2ecb9b30901834188278`

Environment:

- Rust `1.97.1`, LLVM `22.1.8`;
- Iroh `1.0.3`;
- macOS Darwin `25.6.0`;
- MacBook Air `MacBookAir10,1`, Apple M1 arm64, 8 cores, 16 GB RAM;
- Cargo release profile with debug information;
- localhost direct Iroh path;
- 8,388,608-byte payload and 100,000 protocol iterations.

Command:

```bash
cargo run --locked --release -p rift-spike -- bench \
  --bytes 8388608 \
  --protocol-iterations 100000
```

| Measurement | Result |
| --- | ---: |
| Control encode/decode | 5,108,121.83 ops/s |
| Localhost Iroh transfer | 141.57 MiB/s |
| Transfer time | 0.056510 s |
| Payload | 8,388,608 bytes |
| Streaming buffer | 65,536 bytes |

These values are historical comparison data, not pass/fail promises. Hosted runner timing is intentionally not gated.

## Platform limitations

- The local Homebrew toolchain was Rust 1.97.1 rather than the repository-pinned Rust 1.91.0. CI explicitly installs 1.91.0.
- Bare local coverage required explicit Homebrew LLVM tool paths as described above.
- Local macOS production tests passed. Linux and advisory Windows job results await CI.
- No public-relay topology test was added; the deterministic local relay and live migration tests remain the regression evidence.

## Intentionally deferred

No user-facing Rift functionality was added. Pairing, trust persistence/database, revocation, durable peer records, discovery/rendezvous, offline mailbox, reconnect replay, transfer IDs, resumability, idempotency, cancellation protocol, daemon lifecycle, local IPC, desktop/mobile APIs, BLE, folder sync, notifications, clipboard, FFI, and native UI integration remain future milestones as listed in `docs/architecture/deferred.md`.
