# ADR 0007: Pairing and durable trust authorization model

Status: Accepted

## Context

Iroh QUIC and protocol v1 Hello bind a connection to a cryptographic `DeviceId`, but
authentication does not decide whether that peer may use Rift application features.
Foundation M3 needs the first application security boundary without introducing a daemon,
feature ACL matrix, discovery database, or pairing UI.

## Decision

`DeviceId` is the only durable trust key. Peer names and platform strings are bounded,
peer-controlled display metadata captured from the authenticated Hello after pairing; they
never identify a peer.

Local trust has three semantic states:

- absent record: unknown, authenticated but pairing-only;
- trusted: authorized; and
- revoked: rejected and not pairable.

Revocation is sticky. Only an explicit local `forget` mutation removes either a trust or
revocation decision and makes the identity unknown again. Forgetting does not trust the
peer.

Pairing protocol v1 uses explicit initiator and responder roles, a fresh 16-byte
initiator pairing ID, fresh 32-byte nonces from both peers, and role-bound BLAKE3
commitments to those nonces. Each implementation generates its nonce before receiving any
peer nonce. The peers exchange commitments before either reveals its nonce, verify each
reveal against the prior commitment, and only then derive the SAS from an ephemeral
canonical transcript containing the role-ordered identities and all three random values.
A commitment binds the protocol version, role, identities, pairing ID, and nonce under a
distinct domain. This prevents either peer—especially a responder that acts after
receiving the request—from adaptively searching nonce candidates after learning the other
nonce. BLAKE3 over the SAS transcript produces a six-digit, zero-padded decimal short
authentication string (SAS) for human comparison. Pairing attempts and nonce material are
not persisted.

Receiving network messages can advance a pairing transcript but can never directly
create trust. Both remote acceptance and an explicit local confirmation API call are
required. The application can inspect authenticated peer identity, bounded display
metadata, and the SAS before supplying its local decision. A rejection or timeout creates
no trust or revocation record and invalidates the disposable connection.

After both decisions are positive, each side durably commits local trust before sending
`PairingComplete`. Authorization is returned only after the peer completion arrives.
This is not a distributed transaction: a persistence failure, crash, or network loss near
final completion can leave one side trusted while the other remains unknown. That state
fails safely because an unknown side still refuses authorization and no side can
impersonate a different authenticated `DeviceId`.

## Consequences

Unknown peers receive a session wrapper exposing only pairing behavior. Trusted peers
receive an `AuthorizedConnection`; revoked peers are closed and rejected. A fresh
connection after successful pairing can be authorized from durable local state without
repeating pairing.

The six-digit SAS has limited entropy and is strictly an attended human comparison value,
not a password, reusable credential, or replacement for Iroh authentication. Pairing has
explicit phase deadlines and typed sequencing errors; no retry loop or simultaneous-
pairing resolution is introduced. A commitment mismatch fails before local confirmation
or trust persistence.

Revocation affects every new admission immediately. Foundation M3 has no resident daemon
or global live-connection registry, so it does not retroactively close already-authorized
connections.

## Deferred

Pairing UI and QR presentation, active-session revocation, per-feature authorization,
device replacement UX, reconciliation UX for asymmetric final commits, persistent local
secret-key storage, discovery/address persistence, reconnect policy, and simultaneous
pairing resolution remain deferred.
