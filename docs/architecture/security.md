# Security invariants

These are project-level invariants. Future implementation, tests, and review must preserve them.

1. Network discovery does not imply trust.
2. Authentication does not imply authorization. Iroh authenticates endpoint identity; Rift decides pairing and application access.
3. Secret device identity material never leaves the owning device.
4. Rift has no plaintext network fallback.
5. Development-only insecure relay TLS must never become a production option accidentally.
6. Untrusted lengths and counts are bounded before allocation or resource acquisition.
7. Partial binary transfers never become completed outputs.
8. Cancellation and error paths clean temporary resources and owned work.
9. Sensitive key material never appears in normal logs.
10. Protocol failures fail explicitly; implementations do not silently downgrade behavior.

A change affecting an invariant needs targeted failure-path coverage. Aggregate coverage is not evidence that the invariant holds.
