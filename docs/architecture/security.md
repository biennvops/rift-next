# Security invariants

These are project-level invariants. Future implementation, tests, and review must preserve
them.

1. Network discovery does not imply trust.
2. Authentication does not imply authorization. Iroh authenticates endpoint identity;
   Rift applies local admission after authenticated Hello.
3. Secret device identity material never leaves the owning device.
4. Rift has no plaintext network fallback.
5. Development-only insecure relay TLS never enters a production API.
6. Untrusted lengths and counts are bounded before allocation or resource acquisition.
7. Partial binary transfers never become completed outputs.
8. Cancellation and error paths clean temporary resources and owned work.
9. Sensitive key material, pairing nonces, and SAS values do not appear in normal logs.
10. Protocol failures fail explicitly; implementations do not silently downgrade or
    retry sequencing errors.
11. Production `Hello.device_id` equals the Iroh-authenticated remote endpoint ID.
12. `BootstrappedConnection` is authenticated only; only `AuthorizedConnection` denotes
    application authorization.
13. Durable trust is keyed solely by `DeviceId`; names, platforms, and addresses are not
    identity or authorization keys.
14. No network message directly creates trust. Unknown-to-trusted requires an explicit
    local confirmation API call and positive decisions from both peers.
15. Unknown peers are isolated to bounded pairing behavior. Revoked peers are rejected
    and cannot pair again until an explicit local `forget`.
16. Pairing uses fresh OS-CSPRNG session material, role-ordered authenticated identities,
    commit/reveal so both nonces are fixed before disclosure, explicit deadlines, and a
    canonical transcript.
17. Trust persistence completes before authorization becomes visible. A persistence
    failure never returns `AuthorizedConnection`, and a failed mutation cannot become
    visible after journal reopen.
18. Trust-journal corruption fails closed; only an incomplete final record envelope is
    recoverable, through the last fully validated record.
19. Trust storage contains no secret identity key, endpoint address, relay URL, or
    transient pairing state.
20. Exactly one daemon holds the OS lock and exclusively owns one Rift data directory;
    lock-file existence alone never proves ownership.
21. Missing or corrupt persistent identity fails startup and never silently creates a
    replacement identity for existing trust state.
22. Foundation M4 identity confidentiality relies on the private OS user/filesystem
    boundary; the Iroh secret key is checksummed but not encrypted at rest.
23. Local applications mutate trust/session state only through authenticated IPC; they do
    not directly open daemon-owned identity, trust, lock, or runtime files.
24. Every IPC connection proves possession of a fresh per-launch 32-byte capability before
    receiving commands, status, responses, or events; token comparisons reveal no prefix.
25. IPC has no operation that directly creates trusted state. Only confirmation of a live
    M3 `PendingPairing` can cause Unknown → Trusted.
26. IPC uses only Unix sockets or Windows named pipes, never a TCP/network fallback. Frames,
    clients, requests, peer pages, and outgoing queues are bounded.
27. Verification codes leave the daemon only through authenticated local IPC. Secret key
    bytes, pairing nonces/commitments, network pairing IDs, and raw Iroh objects do not.
28. Durable revoke/forget completes before the daemon invalidates matching pending pairings
    and active sessions or reports success. A pending pairing captures a per-peer in-memory
    generation; a successful forget advances it under the trust-store mutation lock, so an
    older pairing cannot subsequently commit Trusted.
29. The resident supervisor owns, cancels, and joins every network, pairing, session, and
    IPC task under a bounded shutdown deadline.

30. Known-identity reachability never implies trust. N0 publication/lookup is explicit and
    independent from relay routing; no address, relay URL, or EndpointAddr becomes durable
    trust state or enters IPC.
31. Every application connection requests exactly one purpose after Hello. Only Trusted +
    AuthorizedSession and Unknown + Pairing are accepted. Remote rejection is coarse and
    never automatically routes into pairing, including asymmetric forget/revocation.
32. One canonical authorized session exists per DeviceId. Both peers prefer lower→higher;
    superseded results cannot create retry loops while the canonical session is healthy.
33. Only durable Trusted identities enter managed reconnect. A single bounded scheduler,
    shared bounded outbound registry, rate spacing, and capped jittered backoff prevent
    unbounded per-peer task/timer creation and tight retry loops. No-route and policy
    rejection leave no automatic retry deadline.
34. Cancellation retains outbound capacity until the task is joined. Unique runtime tokens
    and the forget generation prevent delayed results from restoring stale authorization
    after revoke, forget, replacement, or shutdown. Final pending/session registration
    rechecks current durable eligibility and the admission generation.
35. Local DisconnectSession suspends automatic outbound without mutating trust or banning
    inbound trusted sessions. Only explicit ConnectPeer clears suspension in this runtime.
36. Authorized control streams reject duplicate intent/results and premature pairing;
    every started frame is deadline-bound, while idle connections can remain healthy.
    Cancelling bootstrap closes the disposable connection; path migration is not loss.

A change affecting an invariant needs targeted failure-path coverage. Aggregate coverage
and green CI do not by themselves prove that an invariant holds.

## M6 streaming foundation checkpoint

The new protocol codecs and transfer mechanics do not enable application admission.
Blob capability remains unadvertised until the daemon runtime and durable recovery
exist. Transfer messages are rejected by pairing-only conversion; existing authorized
sessions still reject unsolicited transfer traffic rather than dispatching it.

The transfer engine never chooses paths, opens network streams, spawns workers,
publishes outputs, or records Completed. Hashing, sends, and receives request at most
64 KiB per payload I/O. Per-operation cancellation/idle checks and cooperative budget
consumption prevent an always-ready synthetic source from monopolizing the worker.
Source revalidation and receive-prefix rehashing bind each successful attempt to the
whole immutable digest. Stream reset, short clean FIN, extra bytes, local I/O failure,
and hash mismatch remain distinct results.

Engine success is not durable completion. Its caller must still own authorization,
acceptance, worker capacity/generation, shutdown/reset, joined work, partial-file
flush/sync, and cleanup or atomic publication. Those runtime responsibilities and
related race/recovery tests are not implemented by this checkpoint.

Source preparation now validates the already-open handle as a regular file and checks
configured size before hashing. Core's `SourcePath` bounds local paths to 4096 UTF-8
bytes, rejects NUL/nonabsolute/non-UTF-8 input, and always redacts Debug. Its Serde
representation is intentionally local-only for authenticated IPC/private manifests;
it is not a field of any network message. Native absolute-path syntax is evaluated
on the local platform, with no filesystem access or lossy path conversion.

The preparation helper does not open paths. The runtime must acquire a read-only
handle under owned, bounded preparation work and ensure it corresponds to the supplied
path. Checking a path's type before opening is not sufficient to prevent replacement
with a special file; the future platform-specific opener still needs that failure-path
coverage. Successful preparation is not authorization, a stable source snapshot,
or permission to offer before persisting immutable metadata.

Logical transfer sequencing now rejects preacceptance data, wrong transfer IDs, impossible
ranges, second simultaneous data attempts, conflicting immutable metadata, premature
local completion/acknowledgement, wrong-role operations, and stale-generation results.
Worker terminal failures must supply their generation just like successful verification.
Terminal replay is monotonic and cannot turn a cancelled transfer into a completed one.
These are deterministic in-memory state tests, not proof of durable acceptance, atomic
publication, trust-race fencing, or cancellation/join behavior in a daemon runtime.
