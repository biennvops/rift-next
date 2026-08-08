# ADR 0005: Validation is a foundation boundary

Status: Accepted

## Context

Rift vNext will be implemented by humans and coding agents across multiple milestones. Architecture documentation without executable checks drifts, while separate local and CI command sets create inconsistent truth.

## Decision

`cargo xtask verify` is the canonical validation firewall. It runs formatting, strict Clippy, all workspace tests/features, warning-denied documentation, executable dependency policy, and supply-chain policy in deterministic fail-fast order. CI invokes the same command. Coverage has a measured non-regression floor. Deterministic resource/performance properties gate pull requests; noisy throughput measurements do not.

New behavior requires tests, and benchmark-sensitive work requires comparison with recorded evidence. Tests, checks, timeouts, and bounds may not be weakened to make a change merge.

## Consequences

Validation tooling is production infrastructure and has its own tests. Linux runs the complete gate including Prototype 0 networking. macOS gates production crates. Windows status remains visible and advisory. Green CI is necessary but does not replace review and reasoning.

## Deferred

Hosted benchmark history, coverage-service integration, additional platforms/topologies, fuzzing, and changed thresholds remain explicit future policy changes.
