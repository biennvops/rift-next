# Foundation Milestone 5 report

## Status: implemented and locally verified

M5 implements known-peer reachability, explicit connection purpose, canonical sessions,
managed reconnect, and additive identity-only IPC. The final code revision is `9d6e314`;
this report and the final documentation reconciliation follow it. Hosted CI and public
N0 behavior have **not** been observed, and are not claimed as validated here.

Base: `f43cce58fa47a7b6202f6b0d205883bfc9947584`. Branch:
`feat/foundation-m5-reachability-reconnect`. Logical implementation commits:

- `51cd78d`: native Iroh lookup, identity-only transport, ephemeral bounded hints, CLI.
- `1b95276`: explicit purpose framing/admission and asymmetric-trust regression.
- `766497d`: canonical session ownership, scheduler, IPC, lifecycle tests, ADRs.
- `505d73a`: managed-peer capacity before positive trust confirmation.
- `db6b178`: deterministic policy/conversion measurements and connectivity JSON benchmark.
- `0a26f9e`: total owned-work ceiling, including unjoined task results.
- `9d6e314`: stable transport failure categories during pairing setup.

No dependencies, manifests, Cargo.lock, Rust pin, CI infrastructure, or durable file
formats changed. Iroh remains exactly `=1.0.3`. The supplied untracked `PLAN.md` is
unchanged and intentionally not committed.

## Architecture and implemented behavior

### Reachability, not browsable discovery

`rift-transport-iroh` owns native Iroh lookup and validates DeviceId public-key bytes.
External lookup defaults Disabled. `riftd --address-lookup n0` explicitly composes
PkarrPublisher/PkarrResolver/DnsAddressLookup with Minimal, independently from relay
selection. Startup does not wait for DNS, publication, or relay readiness. Native
MemoryLookup can be injected through Rust configuration for hermetic lookup/restart tests.

Every endpoint also owns bounded ephemeral hints: 4,096 peers, 32 paths per peer.
Explicit-address dials replace the stored path snapshot; hints disappear on endpoint
restart. Removing a hint removes application routing input, not an existing QUIC path
cache. Disabled + no hint returns typed Unresolved before dialing. No addresses, relay
URLs, or EndpointAddr are persisted or added to IPC. ADR 0012 records this decision.

### Explicit purpose before authorization

Network v1 appends ConnectionIntent (**discriminant 8**) and ConnectionIntentResult
(**9**). Purpose discriminants are AuthorizedSession (**0**) and Pairing (**1**).
Accepted is one boolean; rejection contains no remote trust-state reason. Existing
message discriminants 0–7 and all ten prior network vectors are unchanged. Four exact
intent/result payload/frame vectors are appended.

| Durable local state | AuthorizedSession | Pairing |
| --- | --- | --- |
| Trusted | authorized | reject |
| Unknown | reject | pairing-only |
| Revoked | reject | reject |

Both directions enforce the table in `rift-session`. There is no public trust-only
admission bypass and no Session→Pairing fallback. The existing attended commit/reveal
SAS protocol, both positive decisions, explicit local confirmation, and durable sync
remain mandatory. Invalid ordering, malformed bytes, timeout, unexpected intent/result,
and duplicate operations poison/close the disposable connection.

Intent I/O uses the configured Hello/control deadline (10 seconds by default). On
rejection the acceptor gives the dialer at most that interval to receive the coarse
result and close, avoiding immediate QUIC close discarding the response. Bootstrap
cancellation and wrapper drop close the disposable connection. The admitted control
owner services Ping and rejects unexpected frames, including duplicate intent/results;
idle sessions have no artificial application idle timeout, but started frames do.

### Canonical sessions and managed reconnect

The lower DeviceId prefers outbound, higher prefers inbound. Either direction is
usable alone. Preferred replaces nonpreferred; otherwise the older healthy canonical
session wins, including same-direction duplicates. Closed candidates cannot replace
healthy sessions. Superseded task results cannot remove the replacement or arm retries.
M4's misleading public max_sessions_per_peer option is removed.

One supervisor owns a bounded BTreeMap and a single earliest-deadline timer. Each peer
has at most one optional deadline, not a permanent task/channel/timer. Startup reads
trusted candidates in bounded journal pages. Successful pairing registers Connected;
natural canonical loss feeds reconnect. Iroh path migration is not loss.

| Bound/timing | Implemented value |
| --- | --- |
| Managed trusted peers | 4,096 hard cap; startup fails explicitly above capacity |
| Shared manual/automatic outbound setup | 8 default / 64 hard |
| Coalesced Session callers | 16 waiting replies per active peer dial |
| Total owned tasks, including unjoined results | 1,024 hard ceiling |
| Automatic start spacing | at least 100 ms |
| Initial exponential delay ceiling | 1 second |
| Maximum delay ceiling | 60 seconds |
| Jitter | equal jitter, 50–100% of ceiling, OS sample |
| Stable interval before history reset on loss | 30 seconds |
| Active canonical sessions | 64 default / 128 hard; one per DeviceId |
| Incoming setup workers | 32 default / 256 hard |
| Pending confirmations | 8 default / 64 hard |
| IPC clients | 8 default / 64 hard |

Short flaps retain retry history; canonical replacement preserves the stability clock.
RNG failure uses the upper jitter bound, not an immediate retry. Network/lookup failure
and capacity pressure retry. No route becomes Unresolved with no deadline; policy,
protocol, identity, and invariant failures become Blocked without automatic retries.
Connecting includes Iroh resolution; no artificial separate Resolving state is exposed.

ConnectPeer clears local suspension and bypasses backoff subject to capacity, coalesces
with current Session work, or returns the canonical SessionId. Excess manual work fails
CapacityExceeded rather than entering an unbounded queue. DisconnectSession preserves
trust and suspends local automatic outbound until ConnectPeer; incoming trusted sessions
remain allowed and do not clear that suspension.

Unique outbound tokens, cancellation watches, and the admission-time forget generation
fence stale work. Cancelled setup occupies capacity until its result is joined. Durable
revoke/forget happens before cancelling live work/removing connectivity. Final pending
and session registration recheck eligibility and generation. Positive confirmation also
checks managed-peer capacity, reserving slots for resolving confirmations before trust
commit. Shutdown clears timers, rejects new commands, cancels work, closes resources,
and joins every owned task under the existing deadline. ADR 0013 records these choices.

### IPC and diagnostics

IPC remains strict version 1; Status and all nine old exact vectors remain unchanged.
New requests: BeginPairing, ConnectPeer, ListPeerConnectivity. New results:
PairingStarted, PeerConnected, PeerConnectivity. New event: PeerConnectivityChanged;
SessionClosed adds Superseded. Nine new exact IPC vectors cover these additions and
coarse purpose rejection.

Connectivity pages are DeviceId-ordered with exclusive cursors, capped at 128; zero
limit is rejected. Entries contain only identity, state, optional session/delay, retry
attempt, and a stable bounded failure category. No raw Iroh address/error appears in
these DTOs; pairing setup transport errors are also sanitized. Events are deduplicated
by state/session/attempt/failure rather than emitted on countdown ticks. Structured
transition logs contain identity and bounded policy fields; retries do not spam WARN.

## Regression and resource-bound evidence

The canonical validation firewall executes **195 passing tests**, zero failures, and
two intentionally ignored measurement tests; benchmark-smoke runs those measurements.
Existing failure tests were retained and purpose-sensitive tests updated to exercise
the new mandatory gate rather than preserving a bypass.

Key new checks include:

- Identity-only Hello through memory hints; missing route; hint removal and restart;
  identity-authoritative lookup; invalid public bytes; hint peer/path hard bounds.
- Complete inbound and outbound trust/purpose tables; old vectors unchanged; malformed
  purpose/result payloads; premature control/pairing; wrong result; timeout/poisoned
  reuse; duplicate intent after acceptance rejected by the authorized control owner.
- Two real local daemons pair, lose a whole connection through a capability-minimal
  Rust test seam, then create fresh SessionIds automatically without manual dialing
  or another pairing attempt.
- Asymmetric forget produces a coarse remote Session rejection, Blocked/no deadline,
  no PairingPending, no trust mutation, and no hot retry loop.
- Two-daemon restart with injected native MemoryLookup reconnects by durable DeviceId,
  without importing per-runtime application hints into the restarted endpoint.
- Eight injected-registration-order cross-dial rounds exercise nonpreferred alone,
  preferred replacement, both duplicate classes, and joined superseded-result handling.
- Disconnect/suspension and identity-only ConnectPeer resume; inbound trusted session
  permitted while local outbound remains suspended, including subsequent loss.
- Coalesced callers, shared outbound capacity, cancelled work retaining capacity until
  joined, buffered late authorization after revoke/forget/shutdown, forget→retrust
  generation fencing, and final global session-capacity rejection without eviction.
- 4,096-peer synthetic policy bound, 1,000 deterministic spaced starts, exact injected
  jitter/cap/backoff/stability/manual-bypass checks, and no stale timer queue after clear.
- Total 1,024-owned-task bound, shutdown joins, confirmation rejected before trust at
  managed-peer capacity, bounded connectivity pagination/JSON, event deduplication, and
  explicit CLI lookup selection independent from relays.

## Final local validation and coverage

At `9d6e314`, using pinned Rust 1.91.0 on the host recorded below:

| Command/check | Result |
| --- | --- |
| `cargo xtask verify` | PASS: fmt, clippy all targets/features, tests, rustdoc warnings, architecture, dependency audit |
| `cargo xtask coverage` | PASS: **81.66%** workspace lines; unchanged 60% floor |
| `cargo xtask benchmark-smoke` | PASS, including both ignored measurement tests |
| `git diff --check` | PASS |
| Old network and IPC vector objects compared against base | unchanged; only additions |
| Hosted CI / cross-platform hosted execution | not observed |
| Public N0 DNS/Pkarr/relay validation | not performed; not required by hermetic tests |

| Package | Pinned M4 baseline | Final M5 line coverage |
| --- | ---: | ---: |
| rift-core | 92.47% | 92.47% |
| rift-protocol | 93.55% | 93.21% |
| rift-transport-iroh | 85.58% | 86.29% |
| rift-trust | 93.87% | 93.87% |
| rift-session | 90.80% | 90.38% |
| rift-identity | 87.29% | 87.29% |
| rift-ipc | 95.44% | 96.04% |
| rift-daemon, aggregated | 77.82% | 83.59% |

Final workspace report: 10,397 total / 1,907 missed lines. Daemon aggregation: 2,877
lines / 472 missed. Scheduler file coverage is 84.16% because its 35 measurement-test
lines are intentionally skipped by normal tests; its other 186 reported lines are
covered. Coverage is evidence, not a substitute for failure-path assertions.

Local logs: `/tmp/rift-m5-final-verify.log`, `/tmp/rift-m5-final-coverage.log`,
`/tmp/rift-m5-final-benchmark.log`. LCOV: `target/llvm-cov/lcov.info`.

## Performance comparison and M5 measurements

Final smoke run: `9d6e314`, Rust 1.91.0 / Iroh 1.0.3, macOS 26.6.2 (25G83), Apple M1
arm64, dev/debug, local direct network only; power and competing load uncontrolled.
Parameters match the pinned baseline below. New fixtures use 1,000 scheduler entries,
100,000 backoff samples, 10,000 valid public-key conversions, and 100 connectivity JSON
round trips. Complete final metrics:

```text
production.connectivity.scheduler_peers=1000
production.connectivity.scheduler_init_seconds=0.001594
production.connectivity.backoff_iterations=100000
production.connectivity.backoff.ops_per_second=44824616.96
production.transport.device_id_conversion_iterations=10000
production.transport.device_id_conversion.ops_per_second=66887.26
production.protocol_v1.hello_encode_decode.ops_per_second=319957.00
production.protocol_v1.ping_pong_encode_decode.ops_per_second=1781070.78
production.protocol_v1.pairing_code.ops_per_second=113255.54
production.protocol_v1.hello_frame_bytes=75
production.protocol_v1.iterations=100
production.protocol_v1.hello_bytes_processed=7500
production.trust_journal.records=10
production.trust_journal.file_bytes=835
production.trust_journal.replay_seconds=0.000135
production.trust_journal.lookup.ops_per_second=1193445.60
production.trust_journal.lookups=100
production.identity.cold_create_seconds=0.012920
production.identity.warm_load_seconds=0.000124
production.identity.iterations=100
production.identity.file_bytes=74
production.ipc_json.encode_decode.ops_per_second=22592.70
production.ipc_json.frame_bytes=148
production.ipc_json.payload_bytes=144
production.ipc_json.iterations=100
production.ipc_connectivity.encode_decode.ops_per_second=54569.01
production.ipc_connectivity.frame_bytes=258
production.ipc_connectivity.iterations=100
production.daemon.cold_start_seconds=0.155251
production.daemon.warm_restart_seconds=0.017319
production.daemon.ipc_get_status_round_trip_seconds=0.000172
production.daemon.ipc_get_status_iterations=10
production.daemon.trust_replay_records=100
production.daemon.trust_replay_start_seconds=0.052949
protocol.encode_decode.ops_per_second=18841.12
transfer.localhost.mib_per_second=15.27
transfer.localhost.seconds=0.004092
transfer.localhost.bytes=65536
transfer.streaming_buffer_bytes=65536
```

Hello frame (75 bytes), IPC ListPeers frame (148), identity file (74), trust journal
fixture (835), and transfer streaming buffer (65,536) remain unchanged. Small startup
measurements moved from 0.138698→0.155251 s cold, 0.019378→0.017319 s warm, and
0.042924→0.052949 s for 100-record replay. These are single dev/debug smoke observations,
not performance guarantees or evidence sufficient to tune a regression threshold.

The 100-iteration IPC observation was substantially below baseline, so it was investigated
with **100,000 iterations** on the same machine/profile/toolchain. A read-only git archive
of base `f43cce58` and M5 `db6b178` ran the same existing IPC example command:

```text
baseline: production.ipc_json.encode_decode.ops_per_second=83271.27
M5:       production.ipc_json.encode_decode.ops_per_second=82893.57
both:     frame_bytes=148, payload_bytes=144, iterations=100000
M5:       production.ipc_connectivity.encode_decode.ops_per_second=57045.02
M5:       connectivity frame_bytes=258, iterations=100000
```

The sustained existing-path difference is **−0.45%**, not the large drop suggested by
the tiny cold smoke sample. Logs: `/tmp/rift-m5-ipc-baseline-long.log` and
`/tmp/rift-m5-ipc-after-long.log`. Later commits do not change IPC framing/DTOs or this
benchmark. No M4 implementation exists for the new scheduler/conversion measurements;
no speedup is claimed for those paths.

An isolated `/usr/bin/time -l` run of the built daemon test binary with
`--ignored --nocapture connectivity_benchmark` at final code recorded:

- scheduler initialization 0.006353 s; backoff 36,366,942.45 ops/s;
- maximum process RSS **9,338,880 bytes**; peak memory footprint 3,048,512 bytes;
- one passing measurement test; no network tasks, Cargo build, or journal replay.

This is whole test-process memory, not an allocator-level per-peer claim. The full
smoke invocation peaked at 1,036,566,528 bytes **including compiler/linker processes**;
that number is not daemon runtime RSS. The separate measurement's timing difference
also illustrates why wall-clock results are not hard PR gates. Structural bounds are
asserted independently. See `docs/performance/README.md` for reproduction.

## Limitations and M6 handoff

- Known-ID lookup is not browsable discovery. N0 is explicit and public infrastructure
  operation was not exercised; release deployment should observe it separately.
- Disabled lookup needs new runtime hints after restart. Injected MemoryLookup is a
  local Rust fixture/service input whose contents/lifetime are caller-owned; it is not
  an address journal, IPC address field, or generic discovery framework.
- Existing M3 asymmetric final-commit persistence remains nontransactional; a failure
  after local trust commit can leave asymmetric trust. Session reconnect fails closed
  rather than repairing trust or opening a pairing prompt automatically.
- More than 4,096 managed trusted peers is rejected explicitly, not silently truncated.
  No private/offline durable-address schema is introduced.
- No feature state replay, transfer resumption/idempotency, clipboard/file sync, browsing,
  mDNS UI, QR flow, custom resolver service, native UI/FFI, remote IPC, service install,
  keychain integration, protocol v2, or development-insecure TLS production API was added.
- Hosted CI, Windows/Linux execution, release-profile performance, and public N0 service
  observations remain unobserved here. Existing CI/toolchain configuration is unchanged.

## Historical baseline evidence

The following sections record the pre-implementation baseline. Statements about unchanged
M4 implementation in this historical subsection describe that earlier checkpoint only.

### Starting revision and environment

- Base: `f43cce58fa47a7b6202f6b0d205883bfc9947584`.
- Fetched origin and fast-forward checked `main`; it already matched the expected base.
- Working branch: `feat/foundation-m5-reachability-reconnect`.
- Iroh: exactly `=1.0.3`, unchanged.
- Actual compiler on PATH: Homebrew Rust `1.98.0 (88d9e12ae 2026-08-18)`,
  host `aarch64-apple-darwin`, LLVM `22.1.8`.
- Repository rustup override: `1.91.0-aarch64-apple-darwin`. The baseline commands
  used the Homebrew compiler, not this override.
- Host: macOS `26.6.2` (`25G83`), Apple M1, arm64.
- Benchmark profile: dev/debug; power and competing system load were not controlled.
- Network benchmark: local direct connections; no public N0 lookup was validated.

### Initial Homebrew baseline validation

- `cargo xtask verify`: PASS. Dependency auditing emitted warnings, including a
  yanked transitive `chacha20 0.10.1`; no dependencies or lockfile were changed.
- `cargo xtask coverage`: BLOCKED before tests: `cargo llvm-cov` could not find
  `llvm-tools-preview`. No baseline coverage percentage was obtained.
- `cargo xtask benchmark-smoke`: PASS.
- No hosted CI results have been observed for this branch.

The initial blocker was resolved after approval by installing `llvm-tools-preview`
for the existing Rust 1.91.0 toolchain. Neither the Rust pin nor CI configuration
needed to change. No implementation or dependency changes were needed.

### Canonical pinned-toolchain baseline

All three commands passed using Rust `1.91.0 (f8297e351 2025-10-28)`, Cargo
`1.91.0 (ea2d97820 2025-10-10)`, LLVM `21.1.2`, on the same host. These results
supersede the Homebrew measurements for subsequent same-toolchain comparisons.

To ensure nested commands use the pinned compiler rather than Homebrew:

```bash
export PATH="$(dirname "$(rustup which --toolchain 1.91.0 cargo)"):$PATH"
cargo xtask verify
cargo xtask coverage
cargo xtask benchmark-smoke
```

`rustup run 1.91.0 cargo xtask coverage` alone did not resolve the nested tool
selection on this host. Explicitly selecting the toolchain binary directory did.

- `cargo xtask verify`: PASS.
- `cargo xtask coverage`: PASS, **80.23%** workspace line coverage; unchanged 60% floor.
- `cargo xtask benchmark-smoke`: PASS.
- Baseline code is still the starting M4 revision; only this report has changed.

| Production package | Line coverage |
| --- | ---: |
| `rift-core` | 92.47% |
| `rift-protocol` | 93.55% |
| `rift-transport-iroh` | 85.58% |
| `rift-trust` | 93.87% |
| `rift-session` | 90.80% |
| `rift-identity` | 87.29% |
| `rift-ipc` | 95.44% |
| `rift-daemon` | 77.82% |

Daemon coverage aggregates its binary, library, IPC server, and local runtime files
(1,228 covered / 1,578 total lines). Baseline coverage is observed evidence, not a
claim that M5 behavior is implemented.

### Initial Homebrew benchmark results

Command: `cargo xtask benchmark-smoke`. Protocol, identity, and IPC iterations: 100;
trust records/lookups: 10/100; daemon IPC iterations/trust records: 10/100;
Prototype 0 transfer bytes/protocol iterations: 65536/100.

These are historical, non-gating measurements at the base revision, not M5 results.

```text
production.protocol_v1.hello_encode_decode.ops_per_second=121261.21
production.protocol_v1.ping_pong_encode_decode.ops_per_second=1664364.30
production.protocol_v1.pairing_code.ops_per_second=91341.55
production.protocol_v1.hello_frame_bytes=75
production.protocol_v1.iterations=100
production.protocol_v1.hello_bytes_processed=7500
production.trust_journal.records=10
production.trust_journal.file_bytes=835
production.trust_journal.replay_seconds=0.000132
production.trust_journal.lookup.ops_per_second=1343020.99
production.trust_journal.lookups=100
production.identity.cold_create_seconds=0.011188
production.identity.warm_load_seconds=0.000120
production.identity.iterations=100
production.identity.file_bytes=74
production.ipc_json.encode_decode.ops_per_second=40273.18
production.ipc_json.frame_bytes=148
production.ipc_json.payload_bytes=144
production.ipc_json.iterations=100
production.daemon.cold_start_seconds=0.121210
production.daemon.warm_restart_seconds=0.014654
production.daemon.ipc_get_status_round_trip_seconds=0.000128
production.daemon.ipc_get_status_iterations=10
production.daemon.trust_replay_records=100
production.daemon.trust_replay_start_seconds=0.048970
protocol.encode_decode.ops_per_second=21700.80
transfer.localhost.mib_per_second=21.14
transfer.localhost.seconds=0.002957
transfer.localhost.bytes=65536
transfer.streaming_buffer_bytes=65536
```

### Pinned-toolchain benchmark results

Same smoke command, parameters, dev/debug profile, and host as above; power and
competing load were not controlled. No public N0 service was validated. Measurements
were collected at documentation commit `a0ca353`, with implementation unchanged
from base `f43cce58fa47a7b6202f6b0d205883bfc9947584`.

```text
production.protocol_v1.hello_encode_decode.ops_per_second=293650.40
production.protocol_v1.ping_pong_encode_decode.ops_per_second=1823021.11
production.protocol_v1.pairing_code.ops_per_second=109359.42
production.protocol_v1.hello_frame_bytes=75
production.protocol_v1.iterations=100
production.protocol_v1.hello_bytes_processed=7500
production.trust_journal.records=10
production.trust_journal.file_bytes=835
production.trust_journal.replay_seconds=0.000139
production.trust_journal.lookup.ops_per_second=1177634.37
production.trust_journal.lookups=100
production.identity.cold_create_seconds=0.010248
production.identity.warm_load_seconds=0.000130
production.identity.iterations=100
production.identity.file_bytes=74
production.ipc_json.encode_decode.ops_per_second=41760.91
production.ipc_json.frame_bytes=148
production.ipc_json.payload_bytes=144
production.ipc_json.iterations=100
production.daemon.cold_start_seconds=0.138698
production.daemon.warm_restart_seconds=0.019378
production.daemon.ipc_get_status_round_trip_seconds=0.000158
production.daemon.ipc_get_status_iterations=10
production.daemon.trust_replay_records=100
production.daemon.trust_replay_start_seconds=0.042924
protocol.encode_decode.ops_per_second=21029.94
transfer.localhost.mib_per_second=15.85
transfer.localhost.seconds=0.003943
transfer.localhost.bytes=65536
transfer.streaming_buffer_bytes=65536
```
