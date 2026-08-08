//! Rift's concrete production integration boundary with Iroh.
//!
//! Foundation Milestone 1 pins the validated Iroh dependency and establishes crate
//! ownership without adding a speculative transport abstraction. Endpoint operations
//! and Iroh-specific types belong here when production callers need them. Application
//! pairing/trust policy, relay-server implementation, and insecure TLS modes do not.
