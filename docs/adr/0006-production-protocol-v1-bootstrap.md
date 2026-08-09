# ADR 0006: Production protocol v1 bootstrap

Status: Accepted

## Context

Prototype 0 validated authenticated Iroh QUIC, bounded Postcard framing, and explicit
identity matching. It remains an independent experiment with its own ALPN and message
set. Production Rift needs a small, stable control contract that can be reproduced by
future native implementations without importing Iroh types into the protocol crate.

## Decision

Rift production protocol version 1 uses:

- ALPN `rift/1`;
- a four-byte big-endian length prefix followed by a bounded Postcard payload;
- a one-megabyte maximum control payload;
- a symmetric `Hello` exchange containing protocol version, public `DeviceId`, bounded
  device metadata, and bounded capability identifiers;
- explicit binding between `Hello.device_id` and the Iroh-authenticated remote endpoint
  identity;
- an empty default capability advertisement, with a reserved blob-transfer slot that is
  not advertised until production blob transfer exists; and
- `Ping`/`Pong` as a one-shot post-bootstrap control primitive.

A successful bootstrap produces an authenticated—not authorized—peer. Every connection
is disposable, and failed bootstrap closes/discards its temporary connection state.

## Consequences

The encoded representation is a compatibility contract. Postcard dependency or schema
changes that alter encoded bytes require deliberate review and updated machine-readable
conformance vectors. Framing, semantic bounds, and protocol validation belong in
`rift-protocol`; Iroh endpoint and QUIC stream operations belong in
`rift-transport-iroh`.

## Deferred

The following remain outside this decision and milestone:

- pairing and authorization;
- trust persistence and revocation;
- discovery, rendezvous, and durable peer addresses;
- reconnect policy, state replay, and offline delivery;
- transfer IDs, blob transfer, resumability, idempotency, and cancellation protocol;
- daemon lifecycle and local IPC;
- BLE, folder sync, notifications, clipboard, FFI, and native UI.
