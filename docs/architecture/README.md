# Rift vNext architecture

Foundation Milestone 3 establishes the first application authorization boundary above
authenticated Iroh transport. Prototype 0 remains architectural evidence and independent
regression coverage.

## Workspace ownership

```text
future application/daemon crates
        |
        +--> rift-session ---------> rift-trust ---------> rift-core
        |       |
        |       +--> rift-transport-iroh --> rift-protocol --> rift-core
        |       |              |                 |
        |       |              +---------------->+
        |       +---------------------> rift-protocol
        |       +---------------------> rift-core
        |
        +--> production feature crates (future, authorized connections only)

rift-core             platform-independent identity and trust domain types
rift-protocol         production v1 wire representation and pairing transcript
rift-transport-iroh   concrete authenticated Iroh endpoint integration
rift-trust            durable identity-keyed trust/revocation journal
rift-session          admission, pairing state machine, authorized boundary
rift-spike            non-production Prototype 0 evidence
xtask                 repository validation and developer automation
```

The permitted production dependency direction is:

```text
rift-protocol       -> rift-core
rift-transport-iroh -> rift-core, rift-protocol
rift-trust          -> rift-core
rift-session        -> rift-core, rift-protocol, rift-transport-iroh, rift-trust
```

`rift-core` has no transport, filesystem, OS, UI/FFI, or daemon dependency.
`rift-protocol` owns bounded framing, fixed pairing messages, canonical transcript/SAS
derivation, and capability identifiers; it has no Iroh, filesystem, or trust-policy
dependency. `rift-transport-iroh` owns authenticated endpoint/stream operations and
poison-on-error behavior but no trust lookup or pairing sequence policy. `rift-trust` owns
only durable local trust/revocation decisions and has no protocol, transport, address, or
daemon dependency. `rift-session` is the composition layer where authenticated Hello,
local trust, and pairing policy meet.

The admission boundary is:

```text
BootstrappedConnection (authenticated)
        |
        +-- Trusted --> AuthorizedConnection
        +-- Unknown --> PairableConnection (pairing operations only)
        +-- Revoked --> close and reject
```

Application features become reachable only through `AuthorizedConnection`. A display
name, platform string, network address, or remote acceptance message never creates
application authorization. Only `DeviceId` keys durable trust, and unknown-to-trusted
requires explicit local confirmation followed by durable persistence.

The production crates remain narrow and concrete. No generic transport trait, daemon,
connection registry, address book, feature ACL matrix, or persistent secret-key store is
introduced. APIs enter them only with a production caller and tests.

`cargo xtask architecture` evaluates Cargo's resolved package-ID graph, requires every
permitted direct edge above, rejects forbidden reverse/cross-layer reachability, rejects
production `iroh-relay`, and keeps Iroh exactly pinned to `1.0.3`. Manifest requirements
and resolved graph edges are checked independently; inactive optional dependencies do not
silently become acceptable under all-feature validation.

## Engineering policy

- `unsafe` is forbidden workspace-wide. A future exception requires an ADR and explicit
  lint-policy change.
- Library API errors are typed; `anyhow` belongs at executable/application boundaries.
- `todo!`, `unimplemented!`, `dbg!`, unwrap/expect, and panic control flow are denied.
- Results are not silently ignored.
- Externally influenced frames, lengths, counts, allocations, queues, and concurrency are
  bounded before resource acquisition.
- Asynchronous work has an owner, deadline, shutdown path, and cleanup behavior.
- Pairing and control errors poison/close disposable connections; retries never hide
  sequencing failures.
- Durable trust is synced before it becomes visible or authorizes a connection.

See [security invariants](security.md), [deferred decisions](deferred.md), and the accepted
decisions in `docs/adr/`.
