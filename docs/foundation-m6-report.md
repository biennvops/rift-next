# Foundation Milestone 6 report

## Status: partial private-record checkpoint — M6 is not complete

Base: `b02a77a1c5d671716566809c06373647a200b898`.
Branch: `feat/foundation-m6-file-transfer`.

Implementation commits at this checkpoint:

- `edd46d3`: stable transport-independent transfer identifiers in `rift-core`.
- `c3194b1`: portable filename validation and immutable metadata in `rift-protocol`.
- `3ae000a`: transfer control messages, bounded data header, exact vectors, ADR 0014.
- `5e8f991`: cancellable fixed-buffer engine, architecture policy, and platform smoke lists.
- `15a63fa`: bounded redacted local source paths and regular-handle metadata preparation.
- `a009bf0`: explicit logical transfer sequencing and checked attempt generations.
- `d60b6e4`: bounded checksummed manifests/markers and ADR 0015.
- `4880a88`: bounded cancellable reads from already-open state-file handles.

There is no final M6 implementation or merge candidate yet. The supplied untracked
`PLAN.md` and `REVIEW.md` remain untouched. Dependency and CI changes specified by the
plan were explicitly approved. The new `rift-transfer` workspace member uses existing
workspace dependencies and enables Tokio test-util only for its tests. Core adds
existing Postcard/serde_json test dependencies. The macOS and advisory Windows production
smoke lists include transfer; Linux already uses the whole-workspace firewall.
No dependency versions or Iroh pin changed. Hosted CI has not been observed.

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
hashing and already-open regular-file preparation are implemented in the engine.
The daemon's safe read-only source opener and configured policy wiring remain pending.

Protocol appends discriminants 10–13: Offer, Accept, Terminal, TerminalAck. Terminal
outcomes and failures are coarse typed enums. Twelve control and two data-header vectors
were added; an immutable M5 fixture protects every pre-existing vector object. Data
headers have their own 256-byte bound, fixed receive buffer, exact-consumption decoder,
and range checks; file payloads never enter control frames. Protocol/runtime sequencing
requirements are documented. Codecs and the in-memory logical state machine are
implemented, but no live session yet dispatches transfer control messages.

The new engine revalidates the full source before writing stream bytes, hashes again
while sending, rehashes receiver staging prefixes, requires exact suffix length and
clean EOF, checks whole-file BLAKE3, and flushes successful receive output. Per-operation
watch cancellation and progress-idle deadlines preserve slow-but-progressing transfers.
Partial writes reset deadlines, and intermediate progress is throttled by
`max(1 MiB, ceil(total / 100))`. There is no total transfer deadline or spawned task.

Payload loops allocate constant 64 KiB buffers on the heap, not on nested async stacks.
A composed duplex benchmark exposed a stack overflow in the initial stack-buffer
implementation; normal tests now bound future size and execute joined file/duplex
transfers. A failing always-ready-reader cancellation test additionally led to explicit
Tokio cooperative-budget consumption. No timeouts or tests were weakened.

`rift-core::SourcePath` is a local-only 4096-byte-bounded UTF-8 absolute native path.
It rejects NUL, relative paths, and non-UTF-8 native paths. Debug is always redacted;
there is no Display implementation. Validated Serde is intended only for authenticated
local IPC/private manifests, never a network field. Path validation performs no I/O,
canonicalization, or lossy conversion. Core ownership lets IPC and transfer share the
same value without introducing a forbidden cross-layer dependency.

`prepare_source` validates portable basename and configured size limit, checks the
actual opened handle is regular before hashing, computes immutable whole-file metadata,
and rechecks length afterward. It never opens or modifies a source, generates an ID,
or persists an offer. Its caller must supply a matching read-only handle under bounded
owned preparation work. This deliberately does not claim to solve special-file or
path-replacement races in the future runtime opener.

`LogicalTransfer` tracks immutable peer/ID/metadata, direction, and explicit state.
Incoming permission requires an acceptance-persisted transition; outgoing Accept requires
an Offer. Repeated offers produce pending/accepted/terminal replay decisions without
creating another record. A data attempt checks the ID, exact range, accepted offset,
and exclusive state. Verification precedes incoming completion; terminal acknowledgement
is illegal before terminal state. Repeated terminal traffic cannot resurrect a settled
or cancelled transfer. Checked attempt counters cannot wrap; pause invalidates old
verification, publication, and worker-failure results. The daemon must still fence by
canonical SessionId, cancel/join workers, and reconcile actual durable partial length.
Methods named `*_persisted` are logical transitions after caller-owned persistence,
not a store implementation or evidence of crash-safe behavior.

`rift-transfer` depends only on core/protocol plus standard workspace utility crates.
Architecture tests reject upward/transport/Prototype 0 reachability, including transitive
helper edges, and require both direct core/protocol edges. No lower crate gains an
upward transfer dependency. There is no daemon integration, IPC change, authorized data
API, final output publication, or capability advertisement. Blob support stays disabled.

## Initial foundation verification (historical)

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

## Wire/streaming checkpoint verification (historical)

Implementation SHA: `5e8f9912be805e98fd13cc945f584807e7ff4611` (not a final M6 SHA).
Same pinned Rust 1.91.0 toolchain, Apple M1 arm64, macOS 26.6.2 (25G83).
Iroh remains exactly `=1.0.3`; the transfer engine does not depend on it.

| Check | Result |
| --- | --- |
| `cargo xtask verify` | PASS after wire change and final engine change |
| `cargo test --locked -p rift-protocol` | PASS: 40 tests |
| `cargo test --locked -p rift-transfer` | PASS: 20 tests, one ignored measurement |
| `cargo test --locked -p xtask` | PASS: 17 architecture/tool tests |
| `cargo xtask coverage` | PASS: **83.25%** workspace lines, unchanged 60% floor |
| `cargo xtask benchmark-smoke` | PASS, including engine-only fixture |
| Release engine-only benchmark | PASS |
| `git diff --check` | PASS |
| Hosted CI and other platform execution | Not observed |

Final coverage: 11,579 workspace lines / 1,940 missed. Package aggregation from the
canonical report (includes only files reported by llvm-cov):

| Package | Line coverage |
| --- | ---: |
| rift-core | 96.37% |
| rift-protocol | 94.91% |
| rift-transfer | 94.09% |
| rift-transport-iroh | 86.29% |
| rift-trust | 93.87% |
| rift-session | 90.38% |
| rift-identity | 87.29% |
| rift-ipc | 96.04% |
| rift-daemon | 84.21% |
| rift-spike | 63.54% |

Engine tests cover empty, tiny, buffer-boundary, multibuffer, zero/full/nonzero resume
ranges, real-file prefix rehash, source changes before/after preflight, clean truncation,
extra bytes, integrity mismatch, stream reset, local read/seek/write/flush failure,
write-zero, invalid partial lengths, cancellation while blocked, owner loss, cooperative
cancellation, paused-time idle/FIN deadlines, and slow continuous progress. A cancelled
in-memory partial is resumed without resending its prefix. A 64 MiB synthetic transfer
records and bounds every read/write request without allocating a 64 MiB payload.
These are engine tests, **not daemon restart, trust-race, or durable acceptance tests**.

Codec tests cover all new variants, exact discriminants and vectors, pairing exclusion,
every truncated control/header prefix, trailing input, invalid metadata, oversized
headers before payload reads, unsupported enums, range overflow, and write failure.
Existing network/IPC conformance tests remain green; the IPC vectors are untouched.

Current logs:

- `/tmp/rift-m6-wire-verify.log`
- `/tmp/rift-m6-streaming-final-verify.log`
- `/tmp/rift-m6-streaming-final-coverage.log`
- `/tmp/rift-m6-streaming-benchmark.log`
- `/tmp/rift-m6-streaming-environment.log`
- `/tmp/rift-m6-engine-release-benchmark.log`
- `/tmp/rift-m6-engine-release-memory.log`
- `/tmp/rift-m6-wire-release-before.log`
- `/tmp/rift-m6-wire-release-after.log`

## Checkpoint measurements (not production transfer completion evidence)

Host: Apple M1 arm64, macOS 26.6.2 (25G83), Rust 1.91.0 / LLVM 21.1.2.
Power/load uncontrolled. Engine uses only temporary local files and a 64 KiB Tokio
duplex stream, not Iroh or public networking. Release uses optimized + debuginfo.
There is no old production engine for a speedup comparison.

At `5e8f991`, `cargo test --locked --release -p rift-transfer --lib
streaming_benchmark -- --ignored --nocapture` produced:

```text
production.transfer_engine.prehash_seconds=0.006461
production.transfer_engine.offset_0.prefix_rehash_seconds=0.000042
production.transfer_engine.offset_0.attempt_with_revalidation_seconds=0.019649
production.transfer_engine.offset_0.sync_seconds=0.013456
production.transfer_engine.offset_4194304.prefix_rehash_seconds=0.002985
production.transfer_engine.offset_4194304.attempt_with_revalidation_seconds=0.018358
production.transfer_engine.offset_4194304.sync_seconds=0.012472
production.transfer_engine.bytes=8388608
production.transfer_engine.buffer_bytes=65536
```

`attempt_with_revalidation_seconds` includes full sender preflight, resumed-prefix
rehashing, suffix streaming, and integrity verification. It is not payload-only
throughput or atomic durable publication. For the same fixture, dev/debug smoke gave:

```text
production.transfer_engine.prehash_seconds=0.108263
production.transfer_engine.offset_0.prefix_rehash_seconds=0.000064
production.transfer_engine.offset_0.attempt_with_revalidation_seconds=0.321050
production.transfer_engine.offset_0.sync_seconds=0.015138
production.transfer_engine.offset_4194304.prefix_rehash_seconds=0.063459
production.transfer_engine.offset_4194304.attempt_with_revalidation_seconds=0.319405
production.transfer_engine.offset_4194304.sync_seconds=0.012836
production.transfer_engine.bytes=8388608
production.transfer_engine.buffer_bytes=65536
```

An isolated `/usr/bin/time -l` invocation of the already-built release engine test
binary recorded **2,998,272 bytes maximum RSS**, excluding Cargo/compiler processes.
Its complete engine results (timing differs from the separate release run):

```text
production.transfer_engine.prehash_seconds=0.006608
production.transfer_engine.offset_0.prefix_rehash_seconds=0.000030
production.transfer_engine.offset_0.attempt_with_revalidation_seconds=0.019331
production.transfer_engine.offset_0.sync_seconds=0.012852
production.transfer_engine.offset_4194304.prefix_rehash_seconds=0.003020
production.transfer_engine.offset_4194304.attempt_with_revalidation_seconds=0.018081
production.transfer_engine.offset_4194304.sync_seconds=0.012331
production.transfer_engine.bytes=8388608
production.transfer_engine.buffer_bytes=65536
```

This is whole test-process RSS, not a per-worker heap measurement or a daemon memory
claim. Fixed buffer requests and small future sizes are independently tested.

### Matched existing-protocol comparison

The unchanged existing protocol benchmark ran at **100,000 iterations**, release,
same host/compiler and Iroh pin, at the pre-wire checkpoint `f834bd4` and `5e8f991`.
The baseline was a read-only git archive in a fresh `/tmp` directory; the working
branch was not reset. Both ran `cargo run --locked --release -p rift-protocol
--example protocol-benchmark -- 100000`.

| Metric | Before (`f834bd4`) | After (`5e8f991`) |
| --- | ---: | ---: |
| Hello encode/decode ops/s | 2,814,549.32 | 2,889,999.43 |
| Ping/Pong encode/decode ops/s | 17,171,803.90 | 18,537,399.20 |
| Pairing-code ops/s | 3,744,500.17 | 3,825,335.19 |
| Hello frame bytes | 75 | 75 |
| Iterations | 100,000 | 100,000 |
| Hello bytes processed | 7,500,000 | 7,500,000 |

No observed existing-path regression in these samples; no speedup or threshold is
claimed from one uncontrolled run. Required 8/64/256 MiB production-vs-Prototype 0 and
256 MiB durable-resume measurements are still outstanding until the runtime exists.

## Source/sequencing checkpoint verification (historical)

Implementation SHA: `a009bf0ed13fc8c72c42c3d8fab4396a4a108b04` (not final M6).
Pinned Rust 1.91.0; same local host as the prior checkpoint. No dependency, CI,
network vector, IPC vector, capability-advertisement, or platform policy changes in
these two implementation commits.

| Check | Result |
| --- | --- |
| `cargo xtask verify` after source and state changes | PASS |
| Core unit tests | PASS: 13 |
| Transfer unit tests | PASS: 38, plus one ignored measurement |
| `cargo xtask coverage` | PASS: **83.80%** workspace lines, unchanged floor |
| `cargo xtask benchmark-smoke` | PASS; still engine-only, not daemon transfer |
| `git diff --check` | PASS |
| Hosted CI / Windows execution | Not observed |

Final canonical coverage reports 12,097 lines / 1,960 missed. SourcePath file: 95.35%;
source preparation: 97.57%; logical state machine: 99.55%; transfer package aggregate:
97.01%. Coverage fluctuates slightly in unchanged runtime files between executions;
it is not evidence of unimplemented durability or authorization properties.

Path tests exercise exact byte bounds, Unicode byte counts, absolute/native syntax,
NUL, non-UTF-8 Unix paths, unchanged local serialization, truncated Postcard, invalid
wire values, and redacted diagnostics. A Windows-only drive-relative/root-relative
regression test is present but not executed on this host.

Preparation tests cover empty, tiny, buffer-boundary, exact-limit and oversized files;
invalid configured limits; directories and `/dev/null` on Unix; portable-name rejection;
read failures; pre-I/O cancellation; unchanged source contents; and source mutation
between preparation and sending. Limits and invalid names are checked without moving
the file cursor into the hashing loop.

State-machine tests cover happy-path sequencing, pending/accepted/terminal duplicate
offers, immutable metadata conflicts, wrong roles, premature acceptance/data/completion/
acknowledgement, invalid ranges/IDs, second simultaneous attempts, nonzero resume,
terminal replay/settlement, cancellation, late worker verification/publication/failure,
and generation exhaustion without wraparound. They are deterministic and perform no
network or disk I/O; durable marker ordering remains a required store/runtime test.

Logs:

- `/tmp/rift-m6-source-final-verify.log`
- `/tmp/rift-m6-source-coverage.log`
- `/tmp/rift-m6-state-verify.log`
- `/tmp/rift-m6-state-coverage.log`
- `/tmp/rift-m6-state-benchmark.log`

## Private-record checkpoint verification

Implementation SHA: `4880a88d37e72ba38011da8ec90320343f103184` (not final M6).
Same pinned Rust 1.91.0 and local host as above; no hosted CI or Windows execution.
Transfer now uses the existing workspace Postcard and Serde dependencies; the lockfile
only adds those two dependency edges, without any version changes.

ADR 0015 defines a private `RIFTXFER` envelope: version 1, big-endian payload length,
strict Postcard payload of at most 8192 bytes, and BLAKE3 over header plus payload.
Complete files are at most 8238 bytes. Manifest fields are ID, peer, metadata, and a
role enum that contains a redacted source path only for outgoing transfers. Accepted
and terminal markers bind the complete immutable manifest digest. Terminal origin
records whether recovery should replay a local terminal decision or acknowledge a
peer outcome. Binding and role checks are not evidence of durable acceptance or
publication; no filesystem store or logical recovery constructor exists yet.

The already-open record reader checks its 14-byte header before body allocation or
reads, consumes no more than one extra EOF-probe byte, and applies per-partial-read
cancellation/idle control. It does not open paths, enforce file type/permissions,
enumerate directories, mutate files, or grant trust/recovery authorization.

| Check | Result |
| --- | --- |
| `cargo xtask verify` after codec and bounded-reader changes | PASS |
| Record unit tests | PASS: 11 |
| Transfer unit tests | PASS: 49, plus one ignored benchmark |
| `cargo xtask coverage` | PASS: **83.92%**, unchanged floor |
| Record implementation line coverage | **98.13%** |
| `git diff --check` | PASS |
| Hosted CI / Windows execution | Not observed |

Coverage: 12,204 workspace lines / 1,963 missed. These changes add no payload streaming
or hashing algorithm changes; existing performance comparisons above remain historical,
not measurements of a durable production transfer runtime.

Tests cover all record/status/origin variants, independent marker discriminant bytes,
maximum valid manifest fields, every truncated prefix and single-byte corruption
position, oversized declarations, exact-bound/trailing payloads, unsupported versions
and enums, domain-validation bypass attempts, source redaction, every manifest binding
field, and wrong-role markers. Reader tests cover real file round trips, read errors,
pre-body oversized rejection, bounded trailing-byte probes, truncation/corruption,
header/body/EOF stalls, pre-cancellation/owner loss, blocked cancellation, and slow
partial progress that legitimately outlasts the idle deadline. An initial reader
verification caught a missing public re-export; it was fixed without suppressing lint.

Logs:

- `/tmp/rift-m6-record-verify.log`
- `/tmp/rift-m6-record-coverage.log`
- `/tmp/rift-m6-record-reader-verify.log`
- `/tmp/rift-m6-record-reader-coverage.log`

## Outstanding plan execution

All remaining M6 requirements still apply, notably:

1. Implement the bounded durable store, accepted/terminal markers, recovery into the
   logical state machine, safe runtime source opening, source identity generation/
   collision handling, and storage failure-path tests.
2. Expose data streams only through authorized sessions; preserve the sole control
   owner and capability gating. The protocol codecs alone do not implement this API.
3. Integrate the bounded daemon registry, preparation/data workers, commands/events,
   generation fences, reconnect/restart replay, revoke/forget, and joined shutdown.
4. Wire the validated/redacted source path into authenticated SendFile IPC and add
   paginated transfer operations, DTOs, progress events, and exact conformance vectors.
5. Exercise mandatory two-daemon authenticated IPC transfer, rejection, cancellation,
   resume, supersession, restart, integrity, capacity, and authorization-race scenarios.
6. Extend ADR 0015 with implemented storage/runtime/recovery guarantees; complete the
   daemon dependency edges, production/resume benchmarks, hosted CI evidence, and final
   report.

Do not enable `BLOB_TRANSFER_V1` based on this checkpoint: there is no daemon transfer
runtime, durable acceptance/recovery, or end-to-end authorized payload integration yet.
