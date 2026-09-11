# ADR 0015: Bounded private transfer records

Status: Accepted (record encoding implemented; filesystem store and recovery pending)

## Context

M6 transfers survive disposable sessions and require durable explicit acceptance and
terminal replay. A source path must survive outgoing restart without crossing the
network. Neither the trust journal nor ephemeral SessionId owns feature progress.
The daemon remains the sole writer under its data-directory lock (ADR 0009).

## Decision

`rift-transfer` owns the private record format and depends downward on core/protocol,
using existing workspace Serde, Postcard, and BLAKE3. The format is separate from network
protocol v1 and does not alter network or IPC vectors.

Each complete file has exactly this envelope:

```text
8 bytes     ASCII RIFTXFER
2 bytes     big-endian version 1
4 bytes     big-endian Postcard payload length (1..8192)
N bytes     exactly one Postcard TransferRecord
32 bytes    BLAKE3 of header and payload, excluding the checksum itself
```

The complete file maximum is 8238 bytes. Check magic, version, declared length, exact
file size, and checksum before deserializing any owned values. Reject truncation,
trailing bytes, invalid domain values, unsupported variants, and checksum failure;
never skip or repair corruption by silently dropping an active transfer. Unlike the
append-only trust journal, an incomplete immutable record is not a recoverable tail.
A filesystem reader must bound input before allocation, not read an arbitrary file
and rely on this in-memory codec to enforce the file-read bound afterward.

Postcard record indices and field order are:

- `0 Manifest`: TransferId, DeviceId, TransferMetadata, ManifestSource.
- `1 Accepted`: 32-byte manifest digest.
- `2 Terminal`: 32-byte manifest digest, TransferTerminalStatus, TerminalOrigin.

`ManifestSource` is `0 Outgoing(SourcePath)` or `1 Incoming`. This makes an incoming
source path or a missing outgoing path unrepresentable. Core validates the local path
as absolute native UTF-8, 1..4096 bytes without NUL, and redacts Debug. This is private
local serialization, not a remote filename or a filesystem opening authorization.
Metadata retains the protocol's validated portable filename and 1 TiB size ceiling.
The manifest contains no secret keys, IPC tokens, endpoint addresses, session IDs,
attempt generations, hash implementation state, or serialized byte-progress counters.

Markers bind to the BLAKE3 digest of the complete encoded manifest including its
checksum. Binding all immutable fields detects accidental cross-record substitution,
including a changed source path. `TerminalOrigin` is `0 Local` or `1 Peer`: local
terminal state requires Terminal replay, whereas peer state requires acknowledgement
and settlement. Only the receiver can accept, complete, or reject; either side may
cancel or fail. Marker validation checks binding and these role constraints. It does
not prove that acceptance was synced or output was atomically published.

The forthcoming store must create immutable `manifest`, `accepted`, and `terminal`
files under private transfer-ID state directories with no-overwrite atomic persistence.
It must match record kind to filename and manifest ID to directory, validate marker
bindings and semantic combinations, reconcile actual partial/final files, enforce
record counts, and reconcile current durable trust before readiness or network replay.
Acceptance must be durable before Accept or partial-file creation. Completed requires
verified content, flush/sync, atomic publication, directory sync, and persisted terminal
state before the terminal message. Recovery and storage tests must prove each boundary;
the codec and logical state machine do not satisfy those requirements alone.

## Consequences

An independent 8 KiB bound avoids using the much larger IPC/control frame limits for
private state. Encoding uses bounded scratch storage; decoding validates borrowed bytes
before allocating bounded fields. Errors expose no supplied source paths or raw payload.
Checksums detect accidental corruption, not malicious local disk modification, and
provide neither encryption nor authenticity. Unix private permissions and the existing
Windows explicit data-directory ACL model remain mandatory for the future store.

No filesystem operations, atomic creation, permission changes, durable markers, startup
recovery, or daemon transfer capability are implemented by this format checkpoint.
