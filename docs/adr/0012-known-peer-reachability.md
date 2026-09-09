# ADR 0012: Known-peer reachability through Iroh address lookup

Status: Accepted

## Context

M4 persists DeviceId and trust, but dialing requires a transient Iroh EndpointAddr.
IP paths and relay URLs change independently of identity and authorization.

## Decision

DeviceId remains the durable peer key. The concrete `rift-transport-iroh` boundary
converts it to a validated Iroh EndpointId and resolves current reachability at dial
time. No lower domain, protocol, trust, or IPC crate acquires an Iroh dependency.

External lookup defaults to Disabled. Explicit N0 configuration composes Iroh 1.0.3's
PkarrPublisher, PkarrResolver, and DnsAddressLookup with the existing Minimal builder.
It does not change the independently selected relay mode or wait for WAN readiness. A native MemoryLookup may also be injected
through the Rust configuration for hermetic by-ID resolution, including daemon restart
tests. That local fixture owns its contents/lifetime; the CLI exposes only Disabled/N0.
Enabling N0 publishes/resolves reachability through Number 0 infrastructure; it is
not browsable device discovery and never implies trust.

Every endpoint owns an Iroh MemoryLookup for ephemeral out-of-band hints. Explicit
address dials populate it. Latest snapshots replace previous paths, bounded to 4,096
peers and 32 paths per peer. Removal withdraws the application hint, not an existing
QUIC connection or Iroh's internal path cache. With external lookup disabled and no
hint, a fresh DeviceId-only dial returns typed Unresolved before contacting Iroh.

Rift does not persist EndpointAddr, IP addresses, or relay URLs. Tests use local
endpoints and memory hints, not public DNS, Pkarr, or relays.

## Consequences

Lookup-enabled nodes can attempt fresh resolution after restart by DeviceId alone.
Lookup-disabled nodes need a new out-of-band hint after restart. Future private or
LAN lookup can live below the same identity/trust/IPC boundary. The daemon, not
transport, owns retry and session policy; this ADR does not authorize automatic
pairing or application-state replay.

## Rejected

A Rift-specific durable IP/relay address journal. Revisit durable hints only if a
private/offline requirement provides evidence that transient lookup is insufficient.
