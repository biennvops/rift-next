# Deferred decisions

Foundation Milestone 2 decides the initial production control boundary only:

- production control framing is a four-byte big-endian bounded Postcard frame;
- protocol v1 uses ALPN `rift/1` and an explicit symmetric Hello bootstrap;
- the initial control set is Hello, Ping, and Pong; and
- Hello carries bounded metadata and a forward-compatible capability slot.

These decisions do not authorize peers or create durable session state. The following
remain future product architecture decisions:

- multi-version negotiation and compatibility beyond protocol v1;
- pairing UX;
- application trust database and authorization rules;
- revocation;
- durable peer records;
- address discovery and rendezvous strategy;
- offline mailbox;
- reconnect policy and reconnect state replay;
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
- FFI and native UI integration;
- blob/file transfer and its production capabilities;
- session replay, state replay, and durable transfer state.

Existing Prototype 0 mechanisms are evidence about transport behavior, not accidental
decisions for these product concerns. A successful v1 bootstrap remains authenticated,
not paired or authorized, and every connection remains disposable.
