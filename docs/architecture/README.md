# Rift vNext architecture

Foundation Milestone 5 adds purpose-gated known-peer reachability and managed reconnect
to the M4 resident owner. Prototype 0 remains independent architectural evidence.

## Workspace ownership

```text
Native UI / CLI / future platform client
                    |
          authenticated local IPC
                    v
              rift-daemon
        (sole mutable-state owner)
          /      |       |       \
         v       v       v        v
rift-identity rift-ipc rift-session rift-transport-iroh
     |                    |          |       |
     v                    v          v       v
rift-core           rift-trust   rift-protocol
                         |             |
                         +----> rift-core
```

Crate responsibilities are:

```text
rift-core             platform-independent identity and trust domain types
rift-protocol         bounded production network v1 and pairing transcript
rift-transfer         transport-independent fixed-buffer hashing and payload mechanics
rift-transport-iroh   authenticated Iroh endpoint/control integration
rift-trust            durable identity-keyed trust/revocation journal
rift-session          pairing state machine and authorization boundary
rift-identity         persistent production Iroh SecretKey envelope
rift-ipc              bounded transport-independent local JSON contract
rift-daemon           resident composition, registries, tasks, IPC transport, riftd
rift-spike            non-production Prototype 0 evidence
xtask                 validation, architecture policy, and benchmarks
```

The permitted internal production dependency direction is:

```text
rift-protocol       -> rift-core
rift-transfer       -> rift-core, rift-protocol
rift-transport-iroh -> rift-core, rift-protocol
rift-trust          -> rift-core
rift-session        -> rift-core, rift-protocol, rift-transport-iroh, rift-trust
rift-identity       -> rift-core
rift-ipc            -> rift-core
rift-daemon         -> rift-core, rift-identity, rift-ipc, rift-session,
                       rift-transport-iroh, rift-trust
```

The M6 transfer mechanics are a foundation only: no daemon/runtime integration or
durable store is implemented yet. `rift-transfer` has no dependency or transitive
reachability to Iroh, transport, session, trust, identity, IPC, daemon, or Prototype 0.
Other lower production crates cannot reach upward into transfer. Its generic Tokio
I/O functions spawn no work and confer no authorization, acceptance, or publication.

`rift-identity` and `rift-transport-iroh` are the only production crates with a direct Iroh
dependency, exactly pinned to `=1.0.3`. `rift-identity` owns storage only; endpoint creation
stays in transport. `rift-ipc` has no Iroh, network protocol, transport, trust store,
session, identity-store, or daemon dependency. No lower crate reaches upward into
`rift-daemon`, and daemon behavior never enters `rift-core`.

`cargo xtask architecture` evaluates Cargo's resolved package-ID graph, requires every
owned direct edge, rejects forbidden reverse/cross-layer reachability, rejects direct
production `iroh-relay`, and independently validates exact Iroh manifest requirements.

## Process and durable-state boundary

Exactly one `riftd` process owns one explicit data directory:

```text
runtime.lock (OS-held exclusive lock)
identity.key (persistent Iroh SecretKey)
trust.journal (durable authorization)
runtime.json / local IPC endpoint
```

Local clients own presentation and communicate through authenticated IPC. They do not open
or mutate identity/trust/runtime files. The singleton daemon is the cross-process
coordination mechanism; `TrustStore` remains a one-process journal.

Persistent state is deliberately small:

- the exact local Iroh key/`DeviceId`; and
- peer trust/revocation mutations.

Active connections/sessions, pending pairings, runtime/session/attempt IDs, bearer token,
Iroh endpoint addresses, socket/pipe, and task state are recreated every launch.

## Network admission and live ownership

The M5 purpose gate precedes application admission:

```text
BootstrappedConnection (Iroh + identity-bound Hello authenticated)
        |
        +-- explicit AuthorizedSession + Trusted --> canonical AuthorizedConnection
        +-- explicit Pairing + Unknown --> bounded PairableConnection
        +-- every other combination --> coarse rejection and close
```

Application functionality is reachable only through `AuthorizedConnection`. Display name,
platform, address, remote acceptance, and IPC fields never identify or authorize a peer.
Only `DeviceId` keys durable trust. Unknown-to-trusted requires attended M3 commit/reveal
pairing, both positive decisions, authenticated local confirmation, and durable persistence.
There is no direct `TrustPeer` operation.

A minimal opaque connection handle propagates close/liveness from Iroh through bootstrap
and session wrappers; raw Iroh connection objects are not exposed. The daemon tracks every
active session and pending confirmation. Durable revoke/forget closes matching live
sessions and pairings before returning. Natural disconnect removes only runtime session
state and does not revoke trust.

The daemon advertises `PAIRING_V1`, not `BLOB_TRANSFER_V1`. It persists no addresses.
`rift-transport-iroh` owns explicit Disabled/N0 lookup and transient MemoryLookup hints;
relay selection remains independent. One daemon scheduler manages bounded trusted-peer
retry state and outbound work. Lower DeviceId prefers outbound and higher prefers inbound,
so cross-dials converge on one canonical session. Intent rejection never falls back to
pairing. DisconnectSession suspends local automatic outbound until ConnectPeer, without
rejecting inbound trusted sessions. Reconnect establishes a fresh Hello, purpose gate, and
SessionId; **feature state replay remains deferred**. See ADRs 0012–0013.

## Local control boundary

IPC protocol v1 is separate from Rift network protocol v1:

```text
Unix socket (Linux/macOS) or named pipe (Windows)
4-byte big-endian bounded length + UTF-8 JSON
fresh 32-byte per-launch bearer token
client request IDs + bounded async events
```

Frames are capped at 256 KiB before allocation; peer pages are capped at 128; clients,
outstanding requests, request work, and outgoing queues are bounded. The private atomic
runtime descriptor is local discovery only. IPC never binds TCP or any network interface
and never carries raw Iroh addresses, connections, secret keys, pairing nonces/commitments,
or network protocol frames.

See [daemon runtime](../daemon/runtime.md), [IPC v1](../ipc/v1.md), and ADRs 0009–0011.

## Engineering policy

- `unsafe` is forbidden workspace-wide. A future exception requires an ADR and explicit
  lint-policy change.
- Library API errors are typed; `anyhow` belongs at executable/application boundaries.
- `todo!`, `unimplemented!`, `dbg!`, unwrap/expect, and panic control flow are denied.
- Results are not silently ignored.
- Externally influenced frames, lengths, counts, allocations, queues, and concurrency are
  bounded before resource acquisition.
- Asynchronous work has an owner, deadline, shutdown path, cleanup behavior, and joined
  task result.
- Pairing and control errors poison/close disposable connections; retries never hide
  sequencing failures.
- Durable trust is synced before it becomes visible or authorizes a connection.
- Corrupt/missing persistent identity never triggers silent replacement.
- Local control never bypasses the pairing-only trust transition.

See [security invariants](security.md), [deferred decisions](deferred.md), and accepted
[architecture decisions](../adr/).
