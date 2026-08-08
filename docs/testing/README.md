# Testing and validation

The canonical local command is:

```bash
cargo xtask verify
```

It fails immediately and runs the same mandatory commands as Linux CI:

```bash
cargo fmt --all --check
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo test --workspace --all-features
RUSTDOCFLAGS="-D warnings" cargo doc --workspace --all-features --no-deps
cargo xtask architecture
cargo deny check
```

Install the pinned supply-chain tool when needed:

```bash
cargo install --locked cargo-deny --version 0.20.2
```

Individual commands can be run while diagnosing a failure, but they do not replace the complete firewall.

## Test expectations

Unit tests belong beside pure behavior. Integration tests cover real crate and transport boundaries. Bug fixes include a regression test when reproducible. Protocol work covers malformed, oversized, truncated, unsupported, and contradictory input. Cancellation, corruption, cleanup, deadline, and resource-bound paths require assertions about the failure outcome, not line execution alone.

Prototype 0 direct, relay-only, and live direct-to-relay tests remain part of the Linux workspace suite. Production crates are additionally tested on macOS and advisory Windows CI.

## Coverage

Install the pinned tool and generate the repository report with:

```bash
cargo install --locked cargo-llvm-cov --version 0.8.7
cargo xtask coverage
```

The command writes `target/llvm-cov/lcov.info` and enforces the measured Foundation M1 line floor. CI uploads that file. Updating the floor requires an explicit reviewed change and updated Foundation report; percentage alone never replaces targeted tests.
