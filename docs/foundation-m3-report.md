# Foundation Milestone 3 post-merge handoff reconstruction

This report is a post-merge reconstruction prepared during Foundation M4 because PR #3
did not contain its required milestone report. Measurements below were collected from the
merged M3 source on 2026-08-23; they are not presented as original August 13–22 pre-merge
results.

> measured on merged M3 baseline during M4 handoff reconstruction

## Handoff identity

- M3 base SHA: `833118b7bdc12df40cf6d0d3c4fa2720ed7c5ff0`
- PR #3 implementation head: `4561f949186cab10328f6d59264dcac9377a24d1`
- Merge SHA and reconstructed baseline: `19213ca2e907d98321cf00498c22700b8985c2f6`
- Branch: `feat/foundation-m3-pairing-trust`
- Pull request: [#3](https://github.com/biennvops/rift-next/pull/3), merged
  2026-08-23T16:50:15Z
- Prototype 0 status: retained as independent architecture evidence and regression coverage.
- Rust used for reconstruction: `rustc 1.97.1 (8bab26f4f 2026-07-14)`, LLVM `22.1.8`
- Host: macOS 26.6 (25G72), Apple M1, arm64
- Foundation dependencies: Iroh `=1.0.3`, Postcard `1.1.3`, BLAKE3 `1.8.6`, and
  getrandom `=0.4.3`

## M3 workspace and authorization boundary

M3 added `rift-trust` and `rift-session` with this production dependency direction:

```text
rift-protocol       -> rift-core
rift-transport-iroh -> rift-core, rift-protocol
rift-trust          -> rift-core
rift-session        -> rift-core, rift-protocol, rift-transport-iroh, rift-trust
```

`cargo xtask architecture` checks these direct edges, rejects reverse and cross-layer
reachability, rejects production `iroh-relay`, and requires the exact Iroh `=1.0.3` pin.

The application admission boundary is:

```text
BootstrappedConnection (authenticated)
        |
        +-- Trusted --> AuthorizedConnection
        +-- Unknown --> PairableConnection
        +-- Revoked --> reject and close
```

Only a durable decision keyed by the Iroh-authenticated `DeviceId` authorizes a peer.
Display metadata, addresses, and remote protocol messages do not create trust.

## Pairing protocol decisions

Pairing extends network protocol v1 without changing M2's Hello, Ping, or Pong encodings.
The bounded message sequence is:

```text
PairingRequest(pairing_id, initiator commitment)
PairingResponse(pairing_id, responder commitment)
PairingReveal(pairing_id, initiator nonce)
PairingReveal(pairing_id, responder nonce)
PairingDecision(pairing_id, accepted) in both directions
PairingComplete(pairing_id) in both directions
```

Each attempt uses a fresh 16-byte pairing ID and fresh 32-byte nonces from the OS CSPRNG.
Both roles generate their nonce before learning the peer nonce. Role-, identity-, and
attempt-bound BLAKE3 commitments are exchanged before either nonce is revealed. This
commit/reveal ordering prevents a responder from adaptively grinding its nonce after
learning the initiator nonce.

After both reveals verify, each side derives the same six-digit, zero-padded SAS from a
canonical role-ordered transcript containing the protocol domain/version, both
authenticated `DeviceId` values, pairing ID, and both nonces. The SAS is an attended human
comparison value, not a reusable credential. Both remote acceptance and explicit local
confirmation are required. Each side syncs its local trust mutation before exchanging
`PairingComplete` and returning `AuthorizedConnection`.

## Durable trust journal

`rift-trust` owns this versioned append-only format:

```text
header:
  magic             "RIFTTRST" (8 bytes)
  format version    u16 big-endian, value 1

record:
  payload length    u32 big-endian, maximum 1,024
  payload           Postcard TrustMutation
  checksum          32-byte BLAKE3(payload)
```

The journal is bounded to 16 MiB and 100,000 records. Mutations are `Trust`, `Revoke`, and
`Forget`; unknown is absence. Revocation is sticky both during live mutation and replay:
`Revoke -> Trust` without an intervening `Forget` is semantic corruption and fails open.
Complete corrupt records fail closed. Only a physically incomplete final envelope is
truncated back to the last validated record.

Before a mutation becomes visible, the store appends, flushes, and calls `sync_data`.
The pre-append length is retained. Any write, flush, or sync failure poisons the instance
and durably truncates/syncs back to that length; rollback failure quarantines the store.
Thus a mutation reported as failed cannot become visible after reopen.

## Security fixes included before merge

PR #3's final head includes three review-driven security corrections after the original
implementation handoff draft:

- `54f6488`: failed journal commits are durably rolled back at write, flush, and sync
  boundaries, with reopen regression tests;
- `9f7a954`: pairing changed to nonce commit/reveal, with an adversarial responder test and
  updated protocol vectors/ADR; and
- the final trust implementation validates sticky revocation during journal replay, with
  a checksummed `Revoke -> Trust` corruption test.

The final merge therefore reflects the security invariants documented in ADRs 0007 and
0008, not the earlier pre-review protocol/journal behavior.

## Reconstructed validation evidence

The following commands were run from source at merge SHA `19213ca2` before the M4 branch
was created:

```text
cargo xtask verify          FAIL: Prototype 0 relay path-event test ended before fallback
cargo xtask coverage        PASS (with Homebrew LLVM_COV/LLVM_PROFDATA paths)
cargo xtask benchmark-smoke PASS
```

`cargo xtask verify` passed formatting, Clippy, and every M1–M3 production test reached.
It then failed in the retained `rift-spike` test
`direct_path_outage_falls_back_to_relay_on_live_connection`: the connection path event
stream ended before relay selection. The independent coverage run subsequently passed the
same relay test. This is recorded as observed baseline behavior; no timeout, retry, or M3
source change was made during reconstruction.

### Reconstructed coverage

> measured on merged M3 baseline during M4 handoff reconstruction

`cargo llvm-cov --workspace --all-features` reported:

| Package | Line coverage | Function coverage |
| --- | ---: | ---: |
| `rift-core` | 92.47% | 85.71% |
| `rift-protocol` | 94.24% | 89.29% |
| `rift-transport-iroh` | 86.91% | 89.83% |
| `rift-trust` | 93.03% | 80.39% |
| `rift-session` | 89.68% | 92.86% |
| **Workspace** | **79.91%** | **79.71%** |

The enforced global line floor remained 60%.

### Reconstructed benchmark smoke

> measured on merged M3 baseline during M4 handoff reconstruction

These are tiny unoptimized smoke parameters (`100` protocol iterations, `10` trust
records, `100` lookups, and a 65,536-byte Prototype 0 transfer), not release performance
claims:

| Measurement | Result |
| --- | ---: |
| Production Hello encode/decode | 137,606.66 ops/s |
| Production Ping/Pong encode/decode | 1,498,127.34 ops/s |
| Pairing-code derivation | 179,506.14 ops/s |
| Encoded Hello frame | 75 bytes |
| Trust journal replay (10 records / 835 bytes) | 0.000166 s |
| Trust lookup | 1,353,637.90 ops/s |
| Prototype control encode/decode | 19,998.50 ops/s |
| Prototype localhost transfer | 17.04 MiB/s (0.003668 s) |

## Observed PR #3 CI result

GitHub reports PR #3's final head `4561f949…` as successful. Both recorded workflow runs
completed successfully for the Linux quality firewall, Linux coverage floor, macOS
production-crate smoke, advisory Windows production-crate smoke, and benchmark smoke.
This is historical M3 CI evidence only; it says nothing about the M4 branch.

## Deferred to Foundation M4

M3 deliberately left these ownership problems for a resident process:

- persistent production Iroh `SecretKey` storage;
- one-daemon/single-writer data-directory ownership;
- endpoint, task, pending-pairing, and active-session registries;
- authenticated local IPC and local pairing confirmation;
- immediate revocation/forget invalidation of live sessions; and
- explicit startup, readiness, graceful shutdown, and restart behavior.

Discovery, durable addresses, reconnect, synchronization/features, native UI/FFI,
platform keychains, service installation, and production relay deployment remained beyond
M4 as well.
