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
    and active sessions or reports success. Session registration rechecks durable trust.
29. The resident supervisor owns, cancels, and joins every network, pairing, session, and
    IPC task under a bounded shutdown deadline.

A change affecting an invariant needs targeted failure-path coverage. Aggregate coverage
and green CI do not by themselves prove that an invariant holds.
