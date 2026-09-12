# ADR 0014: Production single-file blob transfer

Status: Accepted (wire contract and streaming mechanics implemented; runtime integration pending)

## Context

The first production user capability needs attended single-file delivery between
trusted devices. Prototype 0 proved independent QUIC payload streams and bounded
streaming; its implementation is not imported into production. A QUIC connection
cannot be the identity or owner of a durable logical transfer (ADRs 0003–0004).

## Decision

`rift-core::TransferId` is a stable 16-byte domain identifier. The daemon will generate
it from the OS CSPRNG and own logical transfers keyed by peer identity and transfer ID.
Runtime SessionId remains separate. A transfer carries immutable portable filename,
exact byte length, and BLAKE3 digest, never a source path or filesystem metadata.

Protocol v1 appends Offer, Accept, Terminal, and TerminalAck at indices 10–13 without
changing prior discriminants or vectors. A terminal result is replayable and acknowledged.
The receiver explicitly accepts locally and persists acceptance before advertising a
resume offset. Trust alone does not grant permission to write file payloads.

Each attempt uses a separate unidirectional QUIC stream with a bounded typed header
(BlobV1 index 0, transfer ID, offset, remaining length), raw bytes, and clean FIN. The
header maximum is 256 bytes. Control remains on its existing bounded bidirectional
stream with one session reader/writer owner; file bytes never become control payloads.

Streaming and hashing use fixed 64 KiB buffers. Completion requires exact length and
whole-file BLAKE3 verification, followed by local durability and atomic publication.
The hard file limit is 1 TiB; runtime policy is stricter by default. Portable filenames
are validated 1–255-byte components and never control receiver directories. Final
outputs stay under the daemon's private transfer-ID directory; no arbitrary destination
or metadata-preserving filesystem behavior is introduced.

Only authorized sessions may expose the production data plane. Blob capability 1 is
advertised only after successful runtime initialization; outbound transfers require
remote support and unsolicited transfer traffic without support is a protocol violation.
At this checkpoint no runtime advertises the capability or starts payload streams.

## Consequences

`rift-protocol` owns wire validation and codecs, transport owns concrete QUIC streams,
and the daemon composes authorization and bounded feature work. The transfer engine
must remain independent of Iroh, session, trust, IPC, and daemon crates. Codec coverage
includes malformed, oversized, truncated, trailing, and unsupported input, exact vectors,
and contextual offset/length checks. Runtime tests must separately prove authorization,
acceptance, durability, cancellation, and bounded owned workers.

No folders, batch transactions, synchronization, compression, delta/chunk hashing,
arbitrary Save As, or generic plugin framework is part of this decision. ADR 0015
defines the private manifest/marker encoding; filesystem persistence and resumption
recovery remain pending.
