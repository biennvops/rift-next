# Deferred decisions

Foundation Milestones 1–4 now decide:

- authenticated Iroh transport and identity-bound Hello do not imply application
  authorization;
- `DeviceId` is the sole durable trust key;
- unknown peers are pairing-only, trusted peers receive `AuthorizedConnection`, and sticky
  revoked peers are rejected until explicit forget;
- attended pairing uses fresh OS-CSPRNG material, nonce commit/reveal, canonical six-digit
  SAS, both positive decisions, explicit local confirmation, deadlines, and durable trust;
- trust/revoke/forget mutations persist in a bounded checksummed journal and failed commits
  cannot become visible after reopen;
- one persistent production Iroh `SecretKey` preserves the local `DeviceId`, with atomic
  creation, fixed version/checksum, private filesystem modes, and fail-closed corruption;
- exactly one resident foreground daemon exclusively owns one data directory, endpoint,
  identity, trust journal, task tree, pending pairings, and active sessions;
- authenticated bounded local JSON IPC uses Unix sockets or Windows named pipes and cannot
  directly create trust;
- live revoke/forget cancels matching pending pairing and active authorization after the
  durable mutation; and
- graceful shutdown removes readiness, closes all runtime resources, joins owned work, and
  releases the OS lock for restart.

The following remain future product/architecture decisions:

- OS keychain, credential manager, keystore, hardware-backed or encrypted identity storage;
- identity rotation, device replacement/recovery UX, identity/trust backup, and migration;
- service-manager/autostart installation (`systemd`, `launchd`, Windows Service, login item)
  and daemonization/forking;
- final platform data-directory locations and packaging policy;
- durable peer addresses and address-book schema;
- peer discovery, mDNS, DNS, QR address exchange, and rendezvous;
- reconnect policy, backoff, session replay, and state replay;
- simultaneous-pairing resolution and asymmetric final-commit reconciliation UX;
- multi-version network or local IPC negotiation beyond pre-release v1;
- remote administration and TCP/WebSocket IPC;
- trust-journal compaction and backup (cross-process writer coordination is no longer a
  requirement because the daemon is the sole writer);
- offline mailbox/delivery;
- transfer IDs, blob/file transfer, resumability, idempotency, and cancellation protocol;
- per-capability authorization or feature ACLs;
- clipboard, notifications, media, folder synchronization, and BLE;
- FFI, Swift/Kotlin/native client libraries, desktop/mobile UI, and system tray; and
- production relay-server deployment.

Prototype 0 mechanisms remain evidence about transport behavior, not accidental production
features. Connections remain disposable. M4 tracks and invalidates live sessions but does
not imply reconnect, replay, durable addressing, or synchronization semantics.
