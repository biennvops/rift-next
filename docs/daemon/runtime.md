# Rift daemon runtime

Foundation M4's `riftd` is a foreground resident process. Exactly one process owns one
explicit data directory; it composes persistent identity, durable trust, the production
Iroh endpoint, pairing/admission, active sessions, pending confirmations, and authenticated
local control. It implements no synchronization or feature data plane.

The library (`rift-daemon`) is the testable owner. The `riftd` executable only parses real
startup options, configures tracing, installs Ctrl-C/SIGTERM handling where supported, and
drives the library runtime.

## Data directory and singleton ownership

```text
<data-dir>/
    identity.key       fixed persistent Iroh key envelope
    trust.journal      bounded durable trust/revocation journal
    runtime.lock       OS-lock target; existence does not mean running
    runtime.json       private active-runtime descriptor
    ipc.sock           Unix only; Windows uses a named pipe
```

An OS-held exclusive lock on `runtime.lock` is acquired before identity/trust/runtime
mutation and retained through cleanup. A second daemon receives `DaemonError::AlreadyRunning`
without removing or replacing the first daemon's identity, journal, socket, or descriptor.
The operating system releases the lock if the process exits or crashes. `runtime.lock`
therefore remains as an ordinary file after shutdown and is safely reused.

Unix modes are:

```text
data directory  0700
identity.key    0600
runtime.json    0600
ipc.sock        0600
runtime.lock    0600
```

Windows initially relies on the user/custom directory ACL. The per-launch IPC token adds a
second local capability boundary. The identity secret is checksummed but not encrypted at
rest; see ADR 0010.

## Startup order

`Daemon::start` performs deterministic initialization:

1. validate every duration/count against nonzero hard bounds and validate Hello metadata;
2. create/harden/verify the explicit data directory;
3. acquire the OS lock;
4. remove stale `runtime.json` and Unix socket while lock ownership is proven;
5. enforce the identity/trust presence policy and load/create `identity.key`;
6. open and fully recover/validate `trust.journal`;
7. create the M3 `SessionManager`;
8. bind `RiftEndpoint` with the persisted key and pairing-only Hello capability;
9. generate fresh runtime ID and 32-byte IPC token;
10. bind Unix socket or Windows named pipe;
11. atomically publish private `runtime.json`;
12. return a ready `Daemon` and cloneable `DaemonHandle`.

`run_until_shutdown` then seeds the bounded incoming bootstrap workers and serves IPC. The
listener and Iroh endpoint are already bound before readiness is published, so queued local
or network work cannot observe partially initialized policy state.

If `trust.journal` exists while `identity.key` is absent, startup fails and creates no new
identity. If identity exists without trust, it is retained and a warning accompanies a new
empty journal.

## Runtime descriptor and IPC

A descriptor resembles:

```json
{
  "descriptor_version": 1,
  "pid": 1234,
  "runtime_id": "fresh-32-lowercase-hex-characters",
  "ipc": {
    "transport": "unix",
    "address": "/private/data/dir/ipc.sock"
  },
  "auth_token": "fresh-64-lowercase-hex-characters"
}
```

Windows publishes `"transport":"named_pipe"` and a `\\.\pipe\rift-...` address.
`runtime.json` is local client discovery only. It is never peer discovery and its token is
never returned by `GetStatus`.

See [IPC v1](../ipc/v1.md) and its
[exact vectors](../ipc/v1-vectors.json). Each client must authenticate before any other
frame, has at most 16 outstanding requests, and uses a 64-entry bounded outgoing queue.
The daemon accepts at most the configured local-client count. Slow, malformed, or
unauthenticated clients close independently.

## Concurrency and registries

Default limits are:

| Resource | Default | Hard configuration maximum |
| --- | ---: | ---: |
| Incoming bootstrap/setup tasks | 32 | 256 |
| Active authorized sessions | 64 | 1,024 |
| Active sessions per `DeviceId` | 4 | 16 |
| Pending pairing confirmations | 8 | 64 |
| Local IPC clients | 8 | 64 |

Each unknown inbound connection acquires a pending-pairing permit before responder pairing.
Each pending task owns the M3 `PendingPairing`, confirmation deadline, bounded command
receiver, and permit. The registry stores only bounded presentation metadata, an opaque
close handle, and daemon-local ID. Expiry, connection loss, cancellation, rejection,
protocol/persistence failure, or success removes the record and releases the permit.

Each authorized connection is owned by one tracked session task. The registry stores its
trusted metadata and opaque close handle. Global and per-peer bounds reject and close a new
connection without evicting unrelated sessions. Natural connection loss removes the
session and emits an event; durable trust remains unchanged. M4 has no reconnect loop and
persists no `EndpointAddr`.

All daemon tasks are in an owned `JoinSet`; the IPC client task owns its nested writer
`JoinSet`. No production `tokio::spawn` handle is dropped. A watch channel supplies shared
shutdown state.

## Pairing, revoke, and forget

The daemon advertises `PAIRING_V1`, never `BLOB_TRANSFER_V1`. Unknown connections can only
enter the M3 commit/reveal pairing state machine. Authenticated IPC exposes the six-digit
SAS and a daemon-local attempt ID, never network pairing ID, nonce, or commitment.

`ConfirmPairing` consumes the live M3 `PendingPairing`. It is the only local request capable
of Unknown → Trusted and still requires both peers' positive decisions plus durable trust
commit before a session opens.

Revoke ordering is:

```text
durably append/sync Revoked
    -> remove and close matching pending pairings
    -> remove and close matching active sessions
    -> emit bounded events
    -> return success
```

Forget uses the same live invalidation after durably removing the decision. Fresh admission
then treats the peer as unknown/pairable. The trust journal remains authoritative in a
confirm/revoke race: revoke-before-trust makes `TrustStore::trust` fail, while
trust-before-revoke is overwritten by the later durable revoke; session registration
rechecks durable trust before accepting the result.

## Shutdown

A handle request, Ctrl-C, or SIGTERM begins bounded graceful shutdown:

1. set `ShuttingDown` and remove `runtime.json`;
2. emit `DaemonShuttingDown` and stop accepting new control/network work;
3. close the Iroh endpoint;
4. close/cancel every pending pairing and active session;
5. notify IPC and all child tasks;
6. flush the shutdown event to authenticated IPC clients;
7. join all owned tasks under `shutdown_timeout` (default 10 seconds);
8. abort and report the remaining count if the deadline expires;
9. remove Unix socket/runtime artifacts;
10. release the OS lock and enter `Stopped`.

A completed shutdown leaves identity and trust untouched. Restart from the same directory
recovers the same `DeviceId` and trust decisions but creates fresh runtime IDs, session and
pairing IDs, endpoint addresses, IPC token, socket/pipe, and task registries.

## Running

```bash
cargo run -p rift-daemon --bin riftd -- \
  --data-dir /path/to/rift \
  --device-name "MacBook" \
  --relay disabled
```

`--relay` accepts `disabled`, `default`, or `staging`. Use `--log` or `RUST_LOG` for tracing.
There is no daemonize/fork mode, config-file framework, platform default data path, service
installer, discovery, reconnect, or feature/synchronization command in M4.
