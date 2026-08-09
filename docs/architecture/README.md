# Rift vNext architecture

Foundation Milestone 1 turns the Prototype 0 evidence into production ownership boundaries. It deliberately introduces no user-facing Rift functionality.

## Workspace ownership

```text
future application/daemon crates
        |
        +--> rift-transport-iroh --> rift-protocol --> rift-core
        |             |
        |             +-----------------------------> rift-core
        +--> rift-protocol
        +--> rift-core

rift-core             platform-independent domain logic and DeviceId
rift-protocol         production v1 wire representation and invariants
rift-transport-iroh   concrete authenticated Iroh endpoint integration
rift-spike            non-production Prototype 0 evidence
xtask                 repository validation and developer automation
```

The production dependency direction is intentionally explicit:

```text
rift-protocol       -> rift-core
rift-transport-iroh -> rift-core
rift-transport-iroh -> rift-protocol
```

`rift-core` must not depend on a transport, Iroh, OS APIs, UI/FFI code, or daemon process management. `rift-protocol` may depend on `rift-core` for transport-independent identity types, but must not depend on Iroh, filesystems, OS behavior, application trust policy, or daemon lifecycle. `rift-transport-iroh` owns Iroh-specific endpoint operations and types and composes the production protocol, but not pairing, authorization, business logic, relay-server implementation, or insecure TLS modes.

The production crates are intentionally minimal. APIs enter them only with a real caller and tests. Foundation M2 promotes the first real vertical slice—`DeviceId`, protocol v1 framing/bootstrap, and the concrete Iroh session wrapper—without mechanically promoting the spike. Prototype code moves incrementally when a production milestone requires it.

`cargo xtask architecture` evaluates Cargo's resolved package-ID graph from `cargo metadata.resolve.nodes`, requires the three direct production edges shown above, and fails when core/protocol can reach Iroh or the Iroh transport crate, when production transport directly acquires `iroh-relay`, or when the validated Iroh dependencies are no longer exactly `1.0.3`. Manifest dependency requirements are kept separately for exact-pin checks; inactive optional dependencies and unrelated duplicate package versions do not become reachable edges.

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
