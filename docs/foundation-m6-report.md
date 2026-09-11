# Foundation Milestone 6 report

## Status: partial foundation checkpoint — M6 is not complete

Base: `b02a77a1c5d671716566809c06373647a200b898`.
Branch: `feat/foundation-m6-file-transfer`.

Implementation commits at this checkpoint:

- `edd46d3`: stable transport-independent transfer identifiers in `rift-core`.
- `c3194b1`: portable filename validation and immutable metadata in `rift-protocol`.

There is no final M6 implementation or merge candidate yet. The supplied untracked
`PLAN.md` and `REVIEW.md` remain untouched. Dependency and CI changes specified by the
plan were explicitly approved, but only existing Postcard/serde_json workspace
packages were added as core test dependencies so far. No dependency versions changed.

## Implemented scope

`TransferId` is a transparent 16-byte domain type with value-based equality, ordering,
hashing, Serde, byte constructors/accessors, and canonical lowercase hexadecimal
Display/strict parsing. It does not use runtime SessionId or generate randomness.
OS-CSPRNG generation and deterministic collision handling remain daemon work.

`TransferFileName` checks 1–255 UTF-8 bytes before owned allocation and rejects path
separators, ASCII controls, Windows-invalid characters, trailing dots/spaces, and
case-insensitive reserved device basenames with extensions. Windows superscript
COM/LPT digit forms are also rejected. Other Unicode remains unnormalized.

`TransferMetadata` has validated filename, exact length, and raw 32-byte BLAKE3 digest.
Its private fields and validated deserialization enforce the 1 TiB hard limit; zero
length is valid. The type carries no local path or filesystem metadata. Actual
hashing and daemon size policy are not implemented yet.

Production dependency direction remains unchanged: core owns domain identity;
protocol depends on core. No lower crate gains transport or daemon dependencies.
No control discriminants, network/IPC vectors, authorization APIs, filesystem
writes, or capability advertisement changed. Blob support remains unadvertised.

## Verification observed

Pinned validation toolchain: Rust `1.91.0 (f8297e351 2025-10-28)`.
Nested commands selected it with:

```sh
export PATH="$(dirname "$(rustup which --toolchain 1.91.0 cargo)"):$PATH"
```

| Check | Result |
| --- | --- |
| Baseline `cargo xtask verify` | PASS |
| Baseline `cargo xtask coverage` | PASS, 81.87% workspace lines |
| Baseline `cargo xtask benchmark-smoke` | PASS |
| `cargo test --locked -p rift-protocol` | PASS, 29 tests |
| Core unit tests | PASS, 10 tests |
| `cargo xtask verify` after each implementation slice | PASS |
| Checkpoint `cargo xtask coverage` | PASS, 82.33% workspace lines; unchanged floor |
| Checkpoint `cargo xtask benchmark-smoke` | PASS, existing paths only |
| `git diff --check` | PASS |
| Hosted CI / Windows execution | Not run |

New TransferId file line coverage is 100%; new protocol metadata file is 97.69%.
Coverage does not establish correctness of unimplemented runtime behavior.
Dependency auditing reports the pre-existing yanked `chacha20 0.10.1` warning.

Tests cover raw and text round trips, byte ordering/hash deduplication, malformed
hex/lengths, exact raw Postcard ID encoding, JSON serialization, invalid array
lengths, portable-name boundaries, forbidden components/control bytes, zero/maximum
length, over-limit metadata from wire bytes, invalid UTF-8, and every truncated
metadata prefix. Existing conformance tests remain green.

Local logs:

- `/tmp/rift-m6-baseline-verify.log`
- `/tmp/rift-m6-baseline-coverage.log`
- `/tmp/rift-m6-baseline-benchmark.log`
- `/tmp/rift-m6-core-verify.log`
- `/tmp/rift-m6-metadata-verify.log`
- `/tmp/rift-m6-foundation-coverage.log`
- `/tmp/rift-m6-foundation-benchmark.log`

No production transfer throughput or resume benchmark exists yet. Existing smoke
success is rot-detection evidence only, not an M6 performance claim.

## Outstanding plan execution

All remaining M6 requirements still apply, notably:

1. Append transfer control messages, bounded typed data headers, exact vectors and
   malformed-input tests without changing existing vector objects.
2. Add the transport-independent `rift-transfer` crate, fixed-buffer streaming,
   explicit state machine, durable store, acceptance/terminal markers, recovery,
   source integrity, and cancellation/failure-path tests.
3. Expose data streams only through authorized sessions; preserve the sole control
   owner and capability gating.
4. Integrate bounded daemon registry, preparations, workers, session commands/events,
   generation fences, reconnect/restart replay, revoke/forget, and joined shutdown.
5. Add validated/redacted local source paths and paginated transfer IPC operations,
   DTOs, throttled progress, and exact conformance vectors.
6. Exercise the mandatory two-daemon vertical, rejection, cancellation, resume,
   supersession, restart, integrity, capacity, and authorization-race scenarios.
7. Update architecture policy, ADRs 0014–0015, storage/runtime/security/deferred docs,
   CI platform smoke lists, production/resume benchmarks, and complete the final
   evidence report with actual measurements and observed CI results.

Do not enable `BLOB_TRANSFER_V1` based on this checkpoint: there is no transfer runtime.
