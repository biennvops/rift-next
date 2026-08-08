# Deferred decisions

Foundation Milestone 1 creates places and validation for future work; it does not decide or implement the following product architecture:

- pairing UX;
- application trust database and authorization rules;
- revocation;
- durable peer records;
- address discovery and rendezvous strategy;
- offline mailbox;
- reconnect state replay;
- transfer IDs;
- transfer resumability and idempotency;
- cancellation protocol;
- daemon lifecycle;
- local IPC;
- desktop and mobile APIs;
- BLE;
- folder synchronization;
- notifications;
- clipboard behavior;
- FFI and native UI integration.

These require explicit future milestones and, where architectural, ADRs. Existing Prototype 0 mechanisms are evidence about transport behavior, not accidental decisions for these product concerns.
