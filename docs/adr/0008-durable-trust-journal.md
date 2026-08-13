# ADR 0008: Durable trust journal

Status: Accepted

## Context

Application authorization must survive connection and process replacement, and pairing
must not return an authorized connection before local trust is durable. Foundation M3
needs a small store for identity-keyed trust/revocation decisions, not a general database,
address book, or daemon lifecycle framework.

## Decision

`rift-trust` owns a versioned append-only journal and depends only on `rift-core` among
Rift production crates. The fixed header contains the eight-byte ASCII magic `RIFTTRST`
and a two-byte big-endian format version (`1`). Each record contains:

```text
four-byte big-endian Postcard payload length
Postcard TrustMutation payload
32-byte BLAKE3 checksum of exactly the payload bytes
```

The mutation set is `Trust { TrustedPeer }`, `Revoke { DeviceId }`, and
`Forget { DeviceId }`. Replay applies mutations in order and the last valid mutation for
each `DeviceId` wins. Unknown is represented by absence, never a stored enum value.

Record payloads are bounded to 1,024 bytes, the complete journal to 16 MiB, replay to
100,000 records, and display metadata to the protocol Hello bounds. Declared lengths are
checked before proportional allocation. The complete store size is checked before a
bounded read.

A mutation is serialized, appended as a complete checksummed record, flushed, and synced
to durable storage before the in-memory map changes or the call returns success. Mutations
are serialized under one store-instance lock. A persistence failure leaves the mutation
invisible and poisons that instance against further writes.

A physically incomplete final record envelope is treated as an interrupted append: replay
stops at the last completely validated record, truncates the tail, and syncs recovery.
Any complete record with a bad checksum, invalid/trailing Postcard bytes, or invalid peer
metadata fails the entire open. Corruption is never skipped and no partially replayed peer
set is exposed.

The journal contains only public `DeviceId` values, bounded display metadata, and local
trust decisions. It contains no Iroh `SecretKey`, nonce/pairing state, endpoint address,
relay URL, discovery metadata, permissions, or transport path.

One running Rift process owns one trust-store path in Foundation M3.

## Consequences

The journal supplies deterministic recovery and fail-closed authorization without a new
database dependency or encryption scheme. BLAKE3 checksums detect truncation, torn writes,
corruption, and wrong record format; they do not defend against an attacker who can
arbitrarily rewrite the user's local disk.

A newly created store syncs its header before opening successfully. Trusted metadata may
be updated by a later trust mutation, but a revoked identity cannot transition directly
back to trusted: explicit `forget` is required first.

## Deferred

Journal compaction, cross-process locking/writer coordination, backups, authenticated or
encrypted local storage, active-session notification, and daemon ownership are deferred
until a real lifecycle requirement exists.
