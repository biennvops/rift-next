# Rift daemon runtime

Foundation M5's `riftd` is a foreground resident process. Exactly one process owns one
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
7. load trusted connectivity candidates in bounded pages (hard cap 4,096), and create the
   purpose-aware `SessionManager`;
8. bind `RiftEndpoint` with the persisted key and pairing-only Hello capability;
9. generate fresh runtime ID and 32-byte IPC token;
10. bind Unix socket or Windows named pipe;
11. atomically publish private `runtime.json`;
12. return a ready `Daemon` and cloneable `DaemonHandle`.

`run_until_shutdown` then seeds bounded incoming workers, runs the earliest-deadline
reconnect scheduler, and serves IPC. The
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
| Active authorized sessions | 64 | 128 |
| Canonical sessions per `DeviceId` | 1 | 1 (not configurable) |
| Shared outbound setup tasks | 8 | 64 |
| Managed trusted peers | 4096 | 4096 |
| Coalesced waiters per outbound peer | 16 | 16 |
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

Forget uses the same live invalidation after durably removing the decision. A pending pairing
captures a per-peer in-memory trust generation before it waits for confirmation. Forget advances
that generation while holding the trust-store mutation lock, so a pre-existing pairing can either
commit before the forget (and then be durably removed) or fail its stale-generation check; it
cannot recreate Trusted after ForgetPeer returns. Fresh admission then treats the peer as
unknown/pairable. The trust journal remains authoritative in a confirm/revoke race:
revoke-before-trust makes `TrustStore::trust` fail, while trust-before-revoke is overwritten by the
later durable revoke; session registration rechecks durable trust before accepting the result.

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

## M5 known-peer reachability configuration

`riftd --address-lookup disabled` is the default. `--address-lookup n0` explicitly
opts into Number 0's reachability publication and DNS/Pkarr resolution. This is
independent from `--relay`; enabling lookup does not enable relays. Daemon readiness
never waits for DNS, Pkarr publication, or relay availability. Public infrastructure
behavior is not a required test dependency.

The concrete transport accepts DeviceId-only dials and bounded transient address
hints through Iroh MemoryLookup. Hints are not trust and disappear at endpoint
restart. With lookup disabled and no hint, identity-only dialing returns Unresolved
without retrying. No address journal or raw-address IPC operation is added. See
[ADR 0012](../adr/0012-known-peer-reachability.md).


## M5 canonical sessions and reconnect supervision

The session layer first exchanges explicit intent: Trusted + AuthorizedSession and
Unknown + Pairing are the only admitted combinations. Intent rejection cannot open a
pairing prompt. Final registry insertion rechecks trust and the forget generation
captured before the gate. See [ADR 0013](../adr/0013-managed-peer-connectivity.md).

The lower DeviceId prefers outbound; the higher prefers inbound. Either direction is
accepted when alone. A preferred candidate replaces nonpreferred, while same-direction
or nonpreferred duplicates keep the older healthy canonical session. Replacements emit
SessionClosed/Superseded followed by SessionOpened. Joined results for displaced IDs
cannot remove the replacement or schedule retries. Already-closed candidates never
replace healthy sessions.

One bounded BTreeMap holds trusted connectivity state, with at most one deadline per
peer. The supervisor uses one earliest-deadline timer; no permanent task/channel/timer
is created per peer. Connecting includes Iroh lookup as well as connection establishment.
Each manual/automatic outbound setup consumes the shared bound until its result is
joined, including cancelled tasks. Concurrent Session requests coalesce with at most
16 waiting replies. Excess manual requests fail CapacityExceeded, not queued retries.

Automatic starts are spaced by at least 100 ms. Equal-jitter backoff is 50–100% of a
1-second initial exponential ceiling, doubling to 60 seconds. A connected interval of
at least 30 seconds resets history on loss; short flaps retain it. Canonical replacement
preserves the stability clock. RNG failure uses the upper jitter bound. Pure injected-
time/sample tests cover these decisions without wall-clock sleeps.

Network/lookup failure and capacity pressure retry. Invalid identity, protocol or
invariant failure, lost trust, and coarse remote purpose rejection do not. Disabled
lookup without a hint settles Unresolved with no timer. A new explicit runtime hint
wakes Unresolved state. Successful pairing registers Connected; startup with durable
trust and available lookup schedules fresh authorization without pairing.

DisconnectSession suspends local automatic outbound until ConnectPeer, leaves trust
unchanged, and does not reject inbound trusted connections. Inbound sessions preserve
that suspension for their next loss. ConnectPeer bypasses backoff but not capacity and
returns an existing healthy canonical session when available.

Revoke/forget persist before cancelling work and removing connectivity. Shutdown closes
the command receiver, clears timers, cancels outbound work, closes the endpoint and
registries, and joins every task. Connection loss alone never changes durable trust.
A Rust-only capability-minimal session handle supports forced-loss tests; IPC cannot
access it. Iroh path migration is not a session loss or reconnect trigger.

Connectivity transitions emit deduplicated events and structured debug logs containing
DeviceId, state, attempt, retry delay, and stable failure category. Countdown changes
alone do not generate ticks. Raw transport errors and addresses are not connectivity
DTO fields. The Status schema remains unchanged.
