# ADR 0009: Resident daemon owns mutable Rift state

Status: Accepted

## Context

M1–M3 established bounded protocol, authenticated transport, durable trust, pairing, and
an authorized connection boundary. `TrustStore` still assumed one process, active sessions
had no resident owner, local applications had no safe control plane, and revocation could
only affect fresh admission.

Making every UI or CLI process open the identity and trust files would require a
cross-process database/coordination design and would allow presentation clients to bypass
the pairing-only trust transition.

## Decision

Exactly one foreground `riftd` process exclusively owns one explicit Rift data directory.
It holds an OS-managed exclusive lock on `runtime.lock` for its lifetime; the existence of
the file is not ownership. A second process receives a typed `AlreadyRunning` failure, and
the OS releases ownership after normal exit or crash.

The daemon is the sole mutable owner of persistent device identity, trust journal, Iroh
endpoint, admission manager, active authorized sessions, pending pairings, local IPC, and
all child tasks. Other local applications own presentation and use authenticated IPC. They
must not directly open or mutate `identity.key`, `trust.journal`, `runtime.lock`, or runtime
state.

The runtime has explicit `Starting`, `Running`, `ShuttingDown`, `Stopped`, and `Failed`
states. One supervisor owns bounded incoming bootstrap work, IPC clients, pending-pairing
tasks, and session tasks through tracked join handles and a shared shutdown signal. It does
not detach asynchronous work.

Pending pairing and active session IDs are daemon-local monotonic `u64` values that reset
on restart. Their registries are bounded and are not persisted. A small cloneable
disposable-connection handle exposes only close/liveness behavior; raw Iroh connections do
not leave the transport/session boundary.

Durable revoke or forget commits before live authorization changes. On success the daemon
cancels matching pending pairings and closes every matching active session before returning
to local control. Pending pairing trust commits are fenced by a per-peer in-memory generation,
so a pairing that was already resolving cannot recreate Trusted after a successful forget. Session
loss removes only runtime state; it does not mutate durable trust.

## Consequences

The trust journal remains a single-process store rather than becoming a cross-process
database. Local clients cannot directly create trusted state: pairing confirmation still
consumes an M3 `PendingPairing`, requires both peers' positive decisions, and persists trust
before an authorized session opens.

The initial default bounds are 32 in-flight network bootstrap tasks, 64 active sessions,
4 sessions per peer, 8 pending pairings, and 8 local IPC clients. Hard validation caps
configuration above finite implementation maxima. Capacity rejection closes the new
connection and does not evict unrelated sessions.

Shutdown first removes published readiness, stops accepting work, emits shutdown state,
closes endpoint/connections, cancels pairings and sessions, signals IPC/tasks, joins every
owned task under a deadline, removes runtime artifacts, and releases the OS lock. A clean
restart can immediately reacquire the same directory and recovers identity/trust only.

## Deferred

Service-manager integration, daemonization/forking, final platform data-directory defaults,
durable peer addresses, discovery, automatic reconnect, session replay, synchronization
features, and remote administration remain deferred.
