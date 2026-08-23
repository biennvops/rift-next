# Rift vNext agent instructions

Rift vNext is production code. Prototype 0 is retained as architectural evidence and regression coverage, not as an invitation to add more experiments.

## Required workflow

Before modifying code:

1. Read the relevant documents in `docs/architecture/` and `docs/adr/`.
2. Inspect the existing tests, especially failure and resource-bound coverage near the code.
3. Confirm which crate owns the change and its permitted dependency direction.
4. Make the smallest coherent change that satisfies the requirement.

Before declaring work complete, run:

```bash
cargo xtask verify
```

Run coverage and benchmark comparison as required by the change. Individual commands remain useful for diagnosis, but `cargo xtask verify` is the canonical validation firewall.

## Runtime ownership

- Exactly one `riftd` process owns one Rift data directory through the OS-held lock.
- Local UI/CLI clients use authenticated IPC and never directly mutate `identity.key`,
  `trust.journal`, `runtime.lock`, or runtime state.
- `rift-daemon` is the top-level composition crate. Identity, IPC, session, trust,
  transport, protocol, and core crates must not depend upward on it.
- Daemon work belongs to its supervisor/registries and must have bounded input,
  cancellation, cleanup, and a joined task result.
- No IPC operation may bypass M3 pairing to create trusted state.

## Every pull request

- New functionality requires meaningful tests.
- Bug fixes require a regression test when the failure is reasonably reproducible.
- Protocol parsers and codecs require malformed, oversized, truncated, and unsupported-version input coverage as applicable.
- Performance-sensitive changes require comparison with a recorded benchmark using the process in `docs/performance/README.md`.
- Changes to protocol behavior require corresponding tests and documentation.
- Security and resource-bound changes must test the relevant failure path, not merely execute it.

Do not:

- weaken or delete tests to make a change pass;
- broaden timeouts to hide races;
- add retries to hide nondeterminism;
- remove frame, queue, allocation, concurrency, or streaming bounds;
- bypass typed errors with panics in production paths;
- ignore a `Result`;
- detach asynchronous work without explicit ownership and cleanup;
- duplicate functionality across crates;
- perform unrelated refactors;
- silently change an ADR-backed architecture decision;
- add a generic transport framework without a real caller or test seam;
- expose development-only insecure relay TLS through production APIs.

Green CI is necessary, but it does not by itself prove that behavior, security, cancellation, cleanup, or architecture is correct. Review the complete diff and reason about those properties explicitly.
