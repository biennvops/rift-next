# ADR 0010: Persistent production device identity

Status: Accepted

## Context

ADR 0002 defines one Iroh `SecretKey` as the Rift device's cryptographic identity. M2 and
M3 required a caller-supplied key but did not own production persistence. A resident daemon
must preserve the same authenticated `DeviceId` across process and connection replacement
without silently changing identity after corruption or operator error.

## Decision

`rift-identity` exclusively owns a fixed Foundation M4 identity envelope:

```text
8 bytes   magic "RIFTIDEN"
2 bytes   unsigned big-endian format version 1
32 bytes  exact Iroh SecretKey bytes
32 bytes  BLAKE3 checksum of all preceding bytes
```

The complete file is exactly 74 bytes. The crate derives the public `DeviceId` from the
Iroh key and implements redacted `Debug`; secret bytes are never serialized as JSON or
included in logs/errors.

First creation generates an Iroh key, creates a uniquely named same-directory temporary
file with no-clobber semantics, writes and flushes the complete envelope, syncs it, applies
and verifies private permissions, atomically promotes the fully written inode without
overwriting an existing winner, removes the temporary link, syncs the parent directory on
Unix, and reopens/validates the final file before returning.

Existing identity is validated before secret bytes are accepted. Truncation, trailing
bytes, wrong magic, unsupported version, checksum mismatch, non-regular paths, and unsafe
Unix permissions fail startup. Existing malformed identity is never regenerated or
repaired automatically.

Daemon startup applies this state rule while holding the singleton lock:

- no identity and no trust journal: create identity, then an empty trust journal;
- identity present and trust journal absent: preserve identity, create empty trust, warn;
- trust journal present and identity absent: fail with
  `IdentityMissingWithExistingState`.

On Unix the daemon data directory is mode `0700` and `identity.key` is `0600`. On Windows,
M4 relies on the user-profile/custom-directory ACL inherited by the explicitly selected
data directory. Foundation M4 protects identity with the OS user/filesystem boundary; it
does not encrypt the secret key at rest.

## Consequences

The exact Iroh identity survives daemon restart, while ordinary corruption and accidental
file deletion cannot cause silent identity replacement. `rift-identity` depends only on
`rift-core`, exact Iroh `=1.0.3`, and checksum/runtime utilities; it owns no endpoint,
trust policy, daemon lifecycle, UI, or rotation behavior.

The checksum detects malformed/torn storage but is not authentication against an attacker
who can arbitrarily rewrite the user's private filesystem.

## Deferred

OS keychain/credential-manager/keystore integration, hardware-backed storage, encryption at
rest, key rotation, replacement/recovery UX, backup, and migration between storage backends
remain deferred.
