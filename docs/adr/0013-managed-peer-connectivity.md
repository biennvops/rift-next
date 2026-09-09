# ADR 0013: Purpose-gated managed peer sessions

Status: Accepted

## Context

M4's local trust-only admission implicitly routed unknown identities into pairing.
Automatic reconnect would therefore prompt an asymmetric-forget peer to pair again.
Competing cross-dials also require a single application session, not a per-peer list
from which future features might accidentally process state twice.

## Decision

Hello is followed by one dialer ConnectionIntent and one coarse accepted/rejected
ConnectionIntentResult. Trusted + AuthorizedSession and Unknown + Pairing are the
only accepted combinations. All other combinations reject; Session never falls back
to Pairing. The remote does not learn a trust-database reason. Session policy remains
in rift-session; wire bounds remain in protocol/transport.

The daemon owns at most one canonical authorized session per DeviceId. The lower
DeviceId prefers outbound; the higher prefers inbound, so both select lower→higher.
With no current session, either direction is usable. Preferred replaces nonpreferred;
otherwise the current session wins, including same-direction duplicates. Superseded
close results cannot schedule retries while the canonical session is healthy. The
misleading M4 max_sessions_per_peer configuration is removed, not preserved as an
application option. The global active-session bound remains 64/default, 128/hard.

One daemon-owned scheduler stores up to 4,096 trusted-peer records. Each has at most
one optional deadline; the supervisor polls one earliest-deadline timer. No permanent
task or channel is created per trusted peer. States are Disconnected, Connecting
(including Iroh lookup), Connected, Backoff, Suspended, Unresolved, and Blocked.

Startup reads trusted candidates in bounded journal pages. Successful pairing and
natural canonical loss feed the same policy. No-route with external lookup disabled
settles Unresolved with no timer. New runtime hints wake Unresolved peers. External
lookup failure and temporary network loss retry; remote purpose rejection, protocol
incompatibility, invalid identity, and local invariants do not.

Retry delay uses equal jitter: half to all of an exponential 1-second initial ceiling,
doubling to a 60-second ceiling. Samples come from the OS RNG; RNG failure uses the
upper bound rather than hot-looping. Short flaps preserve attempt history. A session
lasting at least 30 seconds resets history when lost; canonical replacement preserves
that stability clock. Automatic starts are spaced by at least 100 milliseconds.

Manual and automatic setup share max_outbound_connects (8/default, 64/hard). Session
dials coalesce by peer, retaining at most 16 waiting replies per active dial. Excess
manual requests receive CapacityExceeded, never an unbounded pending queue. Each
setup has a unique runtime token and cancellation watch. Cancelled work continues
occupying capacity until its joined result is consumed, preventing cancellation churn
from bypassing bounds. A 1,024-task overall ceiling includes unjoined results, with
one slot reserved during registry insertion for incoming-worker replacement.
Replacement/invalidation cannot register a stale result.

DisconnectSession suspends local automatic outbound until ConnectPeer. Inbound
trusted sessions remain allowed and do not clear that suspension. ConnectPeer resumes
local outbound and bypasses backoff, subject to capacity, or returns the canonical
session. Revoke/forget persist first, cancel matching work, remove connectivity, and
invalidate sessions/pairings. Final session registration rechecks durable Trusted and
the forget generation captured before purpose admission. Pairing keeps that same
fence through durable commit; setup completed after invalidation cannot publish a
stale pending pairing.

The admitted control owner reads Ping or fails closed on unexpected control messages,
including duplicate intent/results. Idle sessions have no artificial application idle
timeout; a started frame still has the bounded control deadline. Iroh path migration
is not session loss. Reconnect establishes a new Hello, gate, and runtime SessionId;
it does not replay application state.

## Consequences

IPC v1 adds identity-only BeginPairing, ConnectPeer, paginated ListPeerConnectivity,
and deduplicated connectivity events without changing Status or old exact vectors.
Diagnostics contain stable categories, not raw transport addresses/errors. Reachability
and connectivity remain runtime-only. More than 4,096 trusted peers fails startup
explicitly rather than silently omitting candidates or allocating unbounded policy.

Security and cancellation tests must cover asymmetric forget, stale completions,
simultaneous cross-dial convergence, manual suspension, and bounded scheduling.

## Deferred

Feature state replay, transfer resumption/idempotency, browsable discovery, private
resolver services, QR/UI flows, and asymmetric pairing-final-commit reconciliation UX.
