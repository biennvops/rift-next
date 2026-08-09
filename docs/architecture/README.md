# Rift vNext architecture

Foundation Milestone 1 turns the Prototype 0 evidence into production ownership boundaries. It deliberately introduces no user-facing Rift functionality.

## Workspace ownership

```text
future application/daemon crates
        |
        +--> rift-core
        +--> rift-protocol
        +--> rift-transport-iroh

rift-core             platform-independent domain logic
rift-protocol         wire representation and protocol invariants
rift-transport-iroh   concrete Iroh endpoint integration
rift-spike            non-production Prototype 0 evidence
xtask                  repository validation and developer automation
```

`rift-core` must not depend on a transport, Iroh, OS APIs, UI/FFI code, or daemon process management. `rift-protocol` must not depend on Iroh, filesystems, OS behavior, application trust policy, or daemon lifecycle. `rift-transport-iroh` owns Iroh-specific endpoint operations and types, but not pairing, authorization, business logic, relay-server implementation, or insecure TLS modes.

The production crates are intentionally minimal. APIs enter them only with a real caller and tests. Prototype code moves incrementally when a production milestone requires it; Foundation M1 does not mechanically promote the spike into production.

`cargo xtask architecture` evaluates Cargo's resolved package-ID graph from `cargo metadata.resolve.nodes` and fails when core/protocol can reach Iroh or the Iroh transport crate, when production transport directly acquires `iroh-relay`, or when the validated Iroh dependencies are no longer exactly `1.0.3`. Manifest dependency requirements are kept separately for exact-pin checks; inactive optional dependencies and unrelated duplicate package versions do not become reachable edges.

## Engineering policy

- `unsafe` is forbidden workspace-wide. A future exception requires an ADR and an explicit lint-policy change.
- Library API errors are typed, normally with `thiserror`; `anyhow` belongs at executable/application boundaries.
- `todo!`, `unimplemented!`, `dbg!`, `unwrap`, `expect`, and explicit panic control flow are denied. A narrow test or proven internal-invariant allowance must explain itself.
- Results must not be silently ignored.
- Externally influenced queues, frames, lengths, counts, allocations, and concurrency are bounded.
- Externally supplied sizes are validated before allocation.
- Asynchronous work has an owner, shutdown path, and cleanup behavior.
- Network and I/O operations have explicit cancellation/deadline semantics when introduced.

See [security invariants](security.md), [deferred decisions](deferred.md), and the decisions in `docs/adr/`.
