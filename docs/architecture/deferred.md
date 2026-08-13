# Deferred decisions

Foundation Milestone 3 decides the initial application admission boundary:

- authenticated transport and Hello do not imply application authorization;
- `DeviceId` is the sole trust key;
- local trust states are unknown (absence), trusted, and sticky revoked;
- unknown peers can access only fixed, bounded pairing protocol v1;
- pairing uses fresh session material, a six-digit human comparison code, explicit local
  confirmation, both positive decisions, deadlines, and typed state ordering;
- trust/revoke/forget mutations persist in a bounded checksummed append-only journal;
- trust persistence completes before authorization is returned; and
- trusted peers reconnect through `AuthorizedConnection`, while revoked peers are
  rejected on new admission.

These decisions introduce no general feature permissions or daemon lifecycle. The
following remain future product architecture decisions:

- actual desktop/mobile pairing UI, QR scanning, and SAS presentation;
- persistent local Iroh `SecretKey` storage and OS keychain integration;
- device replacement, trust backup/recovery, and asymmetric final-commit reconciliation
  UX;
- simultaneous-pairing resolution;
- multi-version negotiation and compatibility beyond pre-release protocol v1;
- durable peer addresses, discovery, DNS/rendezvous, and relay deployment;
- reconnect policy, backoff, session replay, and state replay;
- daemon lifecycle and local IPC;
- a global active-connection registry and active-session revocation;
- trust-journal compaction and cross-process writer coordination;
- offline mailbox/delivery;
- transfer IDs, blob/file transfer, resumability, idempotency, and cancellation protocol;
- per-capability authorization or feature ACLs;
- BLE, folder synchronization, notifications, clipboard, and media;
- FFI, desktop/mobile APIs, and native UI integration; and
- production relay-server implementation.

Existing Prototype 0 mechanisms remain evidence about transport behavior, not accidental
product decisions. Every connection remains disposable. Revocation affects fresh
admission immediately; closing already-authorized live sessions is deferred until a
resident owner exists.
