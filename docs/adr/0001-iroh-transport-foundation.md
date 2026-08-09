# ADR 0001: Iroh is the Rift vNext transport foundation

Status: Accepted

## Context

Prototype 0 validated authenticated direct QUIC connectivity, relay-only connectivity, live direct-to-relay path migration, persistent endpoint identity, independent streams, and reconnect using Iroh.

## Decision

Rift vNext uses Iroh as its concrete networking foundation. QUIC/TLS authenticates the remote Iroh endpoint identity before Rift protocol handling. Rift still owns pairing, trust, and application authorization; successful transport authentication is not authorization.

Iroh remains exactly pinned to `1.0.3` during Foundation M1 and will be periodically revalidated before upgrades. No generic `Transport` trait is introduced without a real caller or test seam.

## Consequences

Iroh-specific operations stay in `rift-transport-iroh`. Production APIs provide no plaintext or insecure TLS mode. The non-production spike may retain its explicit local self-signed relay infrastructure.

## Deferred

Relay deployment, address discovery/rendezvous, trust persistence, pairing, reconnect replay, and upgrade cadence details remain future decisions.
