# Foundation Milestone 4 report

## Handoff identity

- M4 base SHA: `19213ca2e907d98321cf00498c22700b8985c2f6`
- M4 implementation/documentation handoff SHA:
  `cc1f1738a9c9f37cceeee154c50a49f943358fd4`
- Branch: `feat/foundation-m4-daemon-runtime`
- Reconstructed M3 baseline report:
  [`foundation-m3-report.md`](foundation-m3-report.md), added in
  `29858bc87ab7d86eed201c49ed33436b70c2348c`
- M3 implementation head: `4561f949186cab10328f6d59264dcac9377a24d1`
- M3 merge/base: `19213ca2e907d98321cf00498c22700b8985c2f6`
- Report status: this report is an evidence-only commit after the named M4 handoff; no
  implementation behavior changed after final validation at `cc1f173`.

Local evidence was collected on 2026-08-23 using:

- Rust `1.97.1 (8bab26f4f 2026-07-14)`, LLVM `22.1.8` for macOS validation/coverage;
- pinned Rust `1.91.0` for the advisory Windows cross-target check;
- Iroh exactly `=1.0.3`;
- macOS 26.6 (25G72), Apple M1, arm64; and
- `x86_64-pc-windows-gnu` as the Windows compile target.

## Result

M4 establishes `riftd`, the first production resident Rift process. Exactly one daemon
owns one data directory, persistent Iroh identity, durable trust journal, endpoint,
admission manager, bounded pending pairings, bounded authorized sessions, local IPC, and
all child tasks. It runs in the foreground and contains no synchronization or feature data
plane.

The workspace now contains:

```text
rift-core
rift-protocol       -> rift-core
rift-transport-iroh -> rift-core, rift-protocol
rift-trust          -> rift-core
rift-session        -> rift-core, rift-protocol, rift-transport-iroh, rift-trust
rift-identity       -> rift-core, iroh
rift-ipc            -> rift-core
rift-daemon         -> rift-core, rift-identity, rift-ipc, rift-session,
                       rift-transport-iroh, rift-trust
rift-spike
xtask
```

`cargo xtask architecture` requires those direct internal edges, rejects reverse/upward
reachability, rejects direct production `iroh-relay`, and validates both production Iroh
owners' exact `=1.0.3` manifest requirements. `rift-daemon` is the top-level composition
crate; no lower crate depends on it.

## Persistent identity

`rift-identity` owns one fixed 74-byte binary envelope:

```text
8 bytes   magic "RIFTIDEN"
2 bytes   format version 1 (u16 big-endian)
32 bytes  exact Iroh SecretKey bytes
32 bytes  BLAKE3 checksum of the preceding 42 bytes
```

First creation generates the key, creates a unique same-directory no-clobber temporary
file, writes and flushes the complete envelope, syncs data, applies/verifies private mode,
atomically promotes the complete inode with a hard link without replacing an existing
winner, removes the temporary link, syncs the Unix parent directory, then reopens and
validates the final identity.

Existing truncation, trailing bytes, wrong magic, unsupported version, checksum mismatch,
non-regular file, or unsafe Unix permissions fails closed. It never regenerates malformed
identity. `StoredIdentity` Debug contains public `DeviceId` and path only; key bytes are not
JSON, log, error, or Debug data.

Daemon startup while holding the singleton lock enforces:

```text
identity absent + trust absent  -> create both
identity present + trust absent -> preserve identity, create empty trust, warn
identity absent + trust present -> IdentityMissingWithExistingState
```

Unix protection is data directory `0700` and identity `0600`. Windows uses the explicit
user/custom directory ACL baseline. The key is not encrypted at rest; keychain and
hardware-backed storage remain deferred.

## Singleton lock and data layout

The daemon uses stable `std::fs::File::try_lock` to hold an OS-managed exclusive lock on
`runtime.lock` for its complete lifetime. It does not use a permanent `create_new` sentinel
and adds no locking dependency. A second daemon receives typed `AlreadyRunning` before
runtime artifacts or durable files are changed. The OS releases ownership on process/file
handle loss; `runtime.lock` itself remains and is reused.

```text
<data-dir>/
    identity.key
    trust.journal
    runtime.lock
    runtime.json
    ipc.sock       # Unix only
```

`runtime.json`, socket/pipe, bearer token, runtime/session/pairing IDs, endpoint addresses,
connections, registries, and tasks are transient. Active sessions and pairing attempts are
never persisted.

Unix modes tested by the lifecycle integration test are:

```text
data directory 0700
identity.key   0600
runtime.lock   0600
runtime.json   0600
ipc.sock       0600
```

A stale descriptor/socket is removed only after lock acquisition. A second process cannot
damage a live descriptor or socket, and clean shutdown removes transient artifacts before
releasing the lock.

## Local IPC v1

IPC version `1` is independent from Rift network protocol v1. Every frame is:

```text
4-byte unsigned big-endian payload length
UTF-8 JSON payload (maximum 262,144 bytes)
```

The prefix is checked before payload allocation. Strict schemas reject truncated input,
invalid UTF-8/JSON, unknown message types, and unknown fields. Exact semantic JSON, payload
bytes, and complete frame bytes are committed in
[`ipc/v1-vectors.json`](ipc/v1-vectors.json) and verified by tests for:

- Authenticate;
- GetStatus request/response;
- ListPeers;
- ConfirmPairing;
- RevokePeer;
- ForgetPeer;
- PairingPending event; and
- SessionOpened event.

Linux/macOS use `tokio::net::UnixListener`; overlong paths return a typed error before bind.
Windows uses `tokio::net::windows::named_pipe` with one unique pipe name per runtime. There
is no TCP or network-interface fallback.

Every launch obtains a fresh OS-CSPRNG 32-byte bearer token. `runtime.json` atomically
publishes descriptor version, PID, fresh runtime ID, local transport/address, and token.
The first frame must authenticate with version `1` and exactly 64 lowercase hex token
characters. Comparison checks every candidate byte without exposing a matching prefix.
Wrong token/version, missing auth, oversized auth, malformed JSON, and the real five-second
authentication deadline close only that client. No command/status/event is sent first.

M4 requests are GetStatus, bounded ListPeers, ListSessions, ListPendingPairings,
ConfirmPairing, RevokePeer, ForgetPeer, and DisconnectSession. There is no `TrustPeer` and
no IPC `EndpointAddr`. Peer pages are capped at 128. Each client has at most 16 outstanding
requests and a 64-message outgoing queue; lag disconnects the client. Required pairing,
session, trust, and shutdown events are bounded, and shutdown events are flushed before
an authenticated socket closes.

## Runtime ownership and bounds

Default and hard configuration bounds are:

| Resource | Default | Hard maximum |
| --- | ---: | ---: |
| Incoming bootstrap/setup tasks | 32 | 256 |
| Active authorized sessions | 64 | 128 |
| Sessions per `DeviceId` | 4 | 16 |
| Pending pairing confirmations | 8 | 64 |
| Local IPC clients | 8 | 64 |

All counts and relevant deadlines must be nonzero. Capacity rejection closes the new
connection and does not evict unrelated sessions. The active-session hard maximum is 128
so its unpaginated listing remains below 256 KiB; a worst-case escaped-metadata test also
pins peer-page and pending-pairing responses below the frame bound. A pending-pairing
semaphore is acquired before responder/initiator setup and remains owned by its task until
success, rejection, expiry, cancellation, connection loss, or failure.

One supervisor `JoinSet` owns incoming, outbound, pairing, session, and IPC client tasks;
each IPC client owns its nested writer `JoinSet`. Production code drops no spawned task
handle. A watch channel provides explicit shutdown state. The transport/session layers
propagate only an opaque cloneable close/liveness handle, not a raw Iroh connection.

Daemon-local `PairingAttemptId` and `SessionId` are monotonic `u64` values reset each
runtime. Pending entries expose authenticated identity, bounded display metadata, SAS, and
remaining deadline only; nonces, commitments, and the network pairing ID remain private.

## Startup and shutdown order

Startup is:

1. validate metadata, durations, and hard bounds;
2. create/harden/verify the explicit data directory;
3. acquire the OS lock;
4. remove stale transient artifacts;
5. enforce identity/trust presence policy and load/create identity;
6. open/recover the trust journal;
7. create `SessionManager`;
8. bind `RiftEndpoint` using the persisted key;
9. generate runtime ID and IPC token;
10. bind Unix socket or Windows named pipe;
11. atomically publish private `runtime.json`;
12. return ready and begin tracked accept/IPC work in `run_until_shutdown`.

Shutdown is:

1. enter `ShuttingDown` and remove the ready descriptor;
2. emit `DaemonShuttingDown` and stop accepting new operations;
3. close the Iroh endpoint;
4. close/cancel all pending pairings and active sessions;
5. notify IPC and child tasks;
6. flush the shutdown event to authenticated IPC clients;
7. join every task under the configured deadline;
8. abort/report remaining tasks if the deadline expires;
9. remove socket/runtime artifacts;
10. release the lock and enter `Stopped`.

The binary handles Ctrl-C and Unix SIGTERM and does not fork/daemonize. The integration
suite verifies artifact removal, task completion, lock release, and immediate restart.

## Pairing, sessions, revocation, and forget

The daemon advertises `PAIRING_V1` and never `BLOB_TRANSFER_V1`. Both local clients observe
the same M3 commit/reveal SAS. `ConfirmPairing` is the only IPC transition capable of
Unknown → Trusted and consumes the live M3 `PendingPairing`; no direct test/store trust
mutation substitutes for pairing in the vertical scenario.

Successful pairing commits both journals, opens bounded authorized sessions, emits events,
and survives restart. A manual Rust-level dial after restart admits both sides directly
without a pairing event. Natural connection closure removes only runtime session state.
There is no persisted address or reconnect loop.

Revoke and forget first durably mutate the journal, then cancel matching pairings, close
matching sessions, emit events, and return. Session registration rechecks durable trust.
The confirmation/revoke race test permits either operation ordering but requires the final
journal state to be Revoked and no authorized session/pending pairing to survive.

Forget returns the peer to unknown, closes current sessions, makes authenticated dial
pairing-only, and permits a fresh attended pairing after both peers forget. Active global
and per-peer overflow rejects a new session while preserving the existing one.

## Integration-test inventory

`crates/rift-daemon/tests/runtime.rs` covers:

- identity bytes and `DeviceId` surviving restart;
- OS lock A/B/release/C behavior and second-process non-damage;
- runtime descriptor/socket removal and restart;
- Unix data/identity/descriptor/socket permission modes;
- trust-without-identity startup refusal;
- corrupt identity startup refusal without replacement; and
- typed overlong Unix socket paths without descriptor publication.

`crates/rift-daemon/tests/ipc.rs` covers:

- descriptor/token authentication and status;
- wrong token and wrong IPC version;
- non-authenticate first message;
- oversized frame before payload read;
- malformed JSON;
- real authentication timeout;
- malformed-client isolation with daemon health checks; and
- shutdown-event flush followed by IPC close.

`crates/rift-daemon/tests/pairing.rs` covers:

- full two-daemon pairing driven by Rust address seam and confirmed through two IPC clients;
- matching SAS, durable peers, sessions, and SessionOpened events;
- forget, immediate session invalidation, pairable fresh dial, and re-pairing;
- restart with stable identities/trust and direct authorized reconnect without pairing;
- live durable revoke, session close, and blocked fresh admission;
- pairing-confirmation/revoke race final invariant;
- pending expiry and slot release;
- pending capacity; and
- global/per-peer active-session bounds without eviction.

Lower-crate tests additionally cover every identity corruption class, identity permissions
and concurrent first creation, IPC exact vectors/framing failures, trust pagination,
disposable connection liveness, M3 pairing failures, and journal persistence/replay bounds.

## Coverage

Final coverage at handoff SHA `cc1f173` passed the unchanged 60% workspace line floor:

| Package | Line coverage |
| --- | ---: |
| `rift-core` | 92.47% |
| `rift-protocol` | 94.24% |
| `rift-transport-iroh` | 86.77% |
| `rift-trust` | 93.50% |
| `rift-session` | 90.92% |
| `rift-identity` | 87.25% |
| `rift-ipc` | 95.77% |
| `rift-daemon` | 76.79% |
| **Workspace** | **80.45%** |

The `rift-daemon` aggregate includes the thin foreground binary at 0% under library-driven
coverage; its library is 79.81%, local runtime artifact code 83.41%, and IPC server 71.33%.
Security-sensitive identity/IPC failure paths have targeted tests in addition to their
aggregate percentages.

## Performance measurements

These are historical, non-gating debug-profile measurements on the host above. Shared
runner timing is not a performance promise.

Final `cargo xtask benchmark-smoke` (100 protocol/identity/IPC iterations, 10 journal
records, 100 lookups, 10 daemon IPC requests, 100 daemon replay records) reported:

| Measurement | Result |
| --- | ---: |
| Hello encode/decode | 119,940.03 ops/s |
| Ping/Pong encode/decode | 1,622,165.27 ops/s |
| Pairing-code derivation | 183,865.78 ops/s |
| Trust replay (10 records / 835 bytes) | 0.000155 s |
| Trust lookup | 1,256,549.77 ops/s |
| Identity cold create | 0.016334 s |
| Identity warm load | 0.000128 s |
| Identity file | 74 bytes |
| IPC JSON encode/decode | 38,420.28 ops/s |
| IPC benchmark frame/payload | 148 / 144 bytes |
| Daemon cold start | 0.115711 s |
| Daemon warm restart | 0.018737 s |
| Authenticated IPC GetStatus round trip | 0.000124 s |
| Daemon startup with 100 trust mutations | 0.054972 s |

The explicit 1,000-record daemon command:

```bash
cargo run --locked --quiet -p rift-daemon \
  --example daemon-benchmark -- 100 1000
```

reported cold start `0.122194 s`, warm restart `0.017790 s`, real framed/authenticated IPC
GetStatus round trip `0.000076 s`, and startup with 1,000 trust mutations `0.060919 s`.
No public relay was started by any M4 benchmark.

## Validation and platform status

Final handoff validation:

```text
cargo xtask verify                                      PASS
cargo xtask coverage                                    PASS (80.45% lines)
cargo xtask benchmark-smoke                             PASS
cargo test --locked -p rift-identity                    PASS
cargo test --locked -p rift-ipc                         PASS
cargo test --locked -p rift-daemon                      PASS
cargo test --locked -p rift-session                     PASS
cargo test --locked -p rift-trust                       PASS
cargo xtask architecture                                PASS
```

The first firewall attempt at the final benchmark stage exposed a nondeterministic test
fixture: replacing a random token's final nibble with `0` could leave it unchanged. Commit
`fbd68e1` changed the fixture to deterministically alter the first nibble; the unchanged
runtime comparison then passed the focused test and complete firewall. No retry, timeout,
or production behavior masked the failure.

Pinned Windows advisory compile evidence:

```text
RUSTC=<rustup 1.91 rustc> rustup run 1.91.0 cargo check --locked \
  -p rift-identity -p rift-ipc -p rift-daemon \
  --all-targets --all-features --target x86_64-pc-windows-gnu   PASS
```

This compiles named-pipe production code and cfg-specific integration tests. Actual named
pipe execution was not possible on the macOS host and remains evidence expected from the
advisory Windows CI job. macOS executed the full workspace firewall and real Unix IPC
suite locally.

No GitHub Actions run exists for this unpushed M4 branch at report time. The CI workflow
has been extended so macOS and advisory Windows production smoke include `rift-identity`,
`rift-ipc`, and `rift-daemon`; claiming a hosted result before push would be fabrication.
PR #3's historical M3 CI result remains documented only in the reconstructed M3 report.

## Known limitations and deferred work

- Identity confidentiality is private-filesystem/user-account based, not encrypted or
  keychain/hardware backed.
- Windows named-pipe behavior is cross-compiled locally but awaits hosted/runtime evidence.
- `riftd` runs in the foreground with explicit data directory; no service manager,
  autostart, daemonization, or final platform path is selected.
- The runtime persists no peer address and implements no discovery, reconnect, backoff, or
  session replay.
- There is no native UI/CLI client package yet; IPC protocol/vectors are the client seam.
- There is no transfer, file sync, clipboard, notification, media, BLE, FFI, feature ACL,
  remote administration, or production relay-server feature.
- Identity rotation/recovery, trust backup/compaction, simultaneous pairing, and
  asymmetric-final-commit UX remain deferred.

The central M4 invariant is now implemented: one durable process safely owns the M1–M3
network/trust primitives and exposes bounded authenticated local control without allowing
clients to bypass pairing or durable authorization.
