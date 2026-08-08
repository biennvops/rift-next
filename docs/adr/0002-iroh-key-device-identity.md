# ADR 0002: The Iroh key is the cryptographic device identity

Status: Accepted

## Context

Prototype 0 demonstrated stable endpoint identity by persisting one Iroh `SecretKey`. The Iroh public key is the endpoint ID authenticated by QUIC/TLS.

## Decision

A Rift vNext device uses one persistent Iroh `SecretKey` as its cryptographic identity. Rift will not recreate the capstone identity/certificate stack, and vNext has no migration requirement from that model. Display fingerprints are deterministic presentation data for comparison, not a second identity or protocol identifier.

## Consequences

Secret key material remains on the owning device and must not be logged. Storage must preserve confidentiality, integrity expectations, atomic creation, and corruption handling appropriate to each platform. Peer authorization is a separate Rift policy applied to the authenticated endpoint ID.

## Deferred

Platform key storage, backup/recovery, pairing UX, trust records, revocation, and device replacement remain future decisions.
