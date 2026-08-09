# ADR 0003: Separate control and binary data planes

Status: Accepted

## Context

Prototype 0 validated bounded Postcard control framing alongside independent QUIC streams for streamed blob data. A stalled binary stream did not block control traffic or another transfer.

## Decision

Rift uses structured, versioned, length-bounded control messages and independent QUIC streams for bulk binary transfer. It does not place all application traffic into one giant multiplexed byte stream. Untrusted lengths are checked before allocation, and bulk payloads use fixed-size streaming buffers with receiver-side length/hash verification.

## Consequences

Control codecs and their invariants belong in `rift-protocol`; Iroh stream operations belong in `rift-transport-iroh`; domain transfer policy belongs outside both. Tests must protect malformed-size rejection, buffering bounds, independent-stream behavior, and partial-output cleanup.

## Deferred

The production message set, protocol negotiation, transfer IDs, cancellation messages, resumability, idempotency, and durable transfer state remain future decisions.
