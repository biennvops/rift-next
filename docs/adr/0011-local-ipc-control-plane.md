# ADR 0011: Authenticated local IPC control plane

Status: Accepted

## Context

A resident daemon needs a stable local contract for future native UI, CLI, and platform
clients. Reusing Rust/Postcard network messages would couple local Swift/Kotlin clients to
Rift's QUIC protocol and could expose transport objects. TCP localhost would create an
unnecessary network administration surface.

## Decision

`rift-ipc` owns transport-independent local control DTOs and framing. IPC protocol version
`1` is independent from Rift network protocol v1. Every message is a four-byte unsigned
big-endian payload length followed by exact UTF-8 JSON. Payloads are capped at 256 KiB; the
length is rejected before proportional allocation, and strict schemas reject malformed
UTF-8/JSON, unknown message types, and unknown fields.

Linux and macOS use a private Unix-domain socket beneath the daemon directory with mode
`0600`. Windows uses a unique per-runtime local named pipe. There is no TCP, LAN, or remote
fallback.

After complete daemon initialization, `runtime.json` is atomically published at mode
`0600` on Unix. Descriptor version `1` contains the PID, a fresh runtime ID, local
transport/address, and a fresh random 32-byte bearer token encoded as 64 lowercase hex
characters. The token comes from the OS CSPRNG on every launch and is never persisted to a
later runtime, logged, or exposed through `Debug`.

The first client frame must authenticate with token and IPC version. Before success the
daemon sends no status, command result, or event. Wrong token/version, missing auth,
authentication timeout, oversized input, malformed JSON, and schema failures close only
that client without revealing a matching token prefix.

Authenticated requests use client-selected `u64` IDs so responses can coexist with events.
M4 exposes status, paginated peer listing, session listing, pending-pairing listing,
pairing confirmation, revoke, forget, and session disconnect. It intentionally exposes no
`TrustPeer` and no raw Iroh `EndpointAddr`.

Required bounded events are pairing pending/resolved, session opened/closed, trust changed,
and daemon shutting down. Every client has bounded outstanding requests and an outgoing
queue; lag disconnects only that client. Peer pages are capped at 128 entries.

## Consequences

Future native clients can implement one small JSON contract without embedding Rust or
Postcard. Exact semantic/payload/frame vectors live in `docs/ipc/v1-vectors.json` and are
verified by Rust tests.

Possession of the private runtime descriptor token is an additional local capability
boundary, not a substitute for OS user/filesystem isolation. Verification codes can leave
the daemon only on an authenticated connection; nonces, commitments, secret keys, raw
network frames, and connection/address objects never enter this contract.

## Deferred

Remote administration, TCP/WebSocket IPC, durable peer address/discovery DTOs, native
bindings, multi-version negotiation beyond pre-release IPC v1, and platform-specific
client libraries remain deferred.
