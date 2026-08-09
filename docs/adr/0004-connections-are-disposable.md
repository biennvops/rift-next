# ADR 0004: Connections are disposable

Status: Accepted

## Context

Prototype 0 observed useful live Iroh migration from a failed direct path to relay and also proved that a persistent identity can establish a fresh authenticated connection after close. A new connection still requires application handshake and state restoration.

## Decision

Rift treats every QUIC connection as replaceable. Live Iroh path migration is valuable, but it is not application session durability. Future session/state replay is owned by Rift. Iroh path events are diagnostics and transport observations, not application state.

## Consequences

Application state must not rely on a connection object living forever. Connection loss, cancellation, task ownership, cleanup, and replay boundaries need explicit tests and deadlines. Retry loops must not hide nondeterminism or substitute for a state model.

## Deferred

Reconnect policy, backoff, durable peer addressing, session replay, transfer resumption, idempotency, and offline delivery remain future decisions.
