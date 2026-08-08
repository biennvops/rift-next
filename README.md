# Rift vNext — Prototype 0: Iroh/QUIC networking spike

This is a deliberately small architecture-validation prototype. It is not the Rift daemon, does not preserve the existing Rift protocol, and has no UI, mobile, FFI, database, sync semantics, or migration layer.

The prototype uses Iroh `1.0.3` directly. Iroh provides the authenticated QUIC endpoint, public-key identity, direct/relay path management, and stream primitives. The spike adds only the Rift-shaped control framing and blob transfer needed to test the proposed split.

## Build and quality gates

Rust `1.91` or newer is required by Iroh `1.0.3`.

```bash
cargo fmt --check
cargo clippy --all-targets --all-features -- -D warnings
cargo test --all
```

GitHub Actions runs these same three commands for every push and pull request. The repository pins Rust `1.91.0` in `rust-toolchain.toml`, and the Iroh dependencies are exact `1.0.3` requirements.

The workspace contains the main executable and a local relay helper:

```text
crates/rift-spike/src/main.rs
crates/rift-spike/src/bin/rift-relay.rs
crates/rift-spike/src/identity.rs
crates/rift-spike/src/network.rs
crates/rift-spike/src/protocol.rs
crates/rift-spike/src/transfer.rs
crates/rift-spike/tests/networking.rs
crates/rift-spike/tests/relay.rs
```

## Running two nodes directly

`run` creates a persistent node that accepts connections. It prints a full JSON peer descriptor. Copy the entire value after `Peer address:` or `Peer address (after relay discovery):`; the descriptor contains the authenticated node ID and the direct/relay addresses known at that moment.

Start a receiver:

```bash
cargo run -p rift-spike -- run \
  --data-dir /tmp/rift-b \
  --relay-mode disabled \
  --device-name "Node B"
```

Startup includes:

```text
Node ID: <64-character Iroh endpoint ID>
Fingerprint: blake3:<32-hex-character manual fingerprint>
Peer address: {"node_id":"...","addresses":["ip:..."]}
```

Create a test payload and send it from a second persistent identity:

```bash
head -c 1048576 /dev/urandom > /tmp/rift-payload.bin

cargo run -p rift-spike -- send \
  --data-dir /tmp/rift-a \
  --relay-mode disabled \
  '<paste Node B peer descriptor here>' \
  /tmp/rift-payload.bin
```

The sender uses the identity in `/tmp/rift-a`, so the sender and receiver have independent persistent identities. `send` is intentionally a short-lived experiment process; `run` is the resident accepting node. The receiver writes verified files to `/tmp/rift-b/received` by default. Override that with `--receive-dir`.

On the same machine the printed descriptor includes loopback addresses derived from Iroh's bound sockets. That is useful for local experiments where the host has interface addresses that are not reachable from the current network namespace. On a LAN, the other advertised IP address should be used if loopback is not appropriate.

Use `--log` or `RUST_LOG` to increase diagnostics:

```bash
RUST_LOG='rift_spike=debug,iroh=debug' \
cargo run -p rift-spike -- send \
  --data-dir /tmp/rift-a \
  --relay-mode disabled \
  '<peer descriptor>' \
  /tmp/rift-payload.bin
```

## Local relay-only experiment

The workspace includes a small local self-signed relay server backed by Iroh's relay server implementation. In one terminal:

```bash
cargo run -p rift-spike --bin rift-relay
```

It prints a URL such as `https://127.0.0.1:54321/`. In two more terminals, use that URL for both nodes:

```bash
cargo run -p rift-spike -- run \
  --data-dir /tmp/rift-relay-b \
  --relay-mode disabled \
  --relay-url 'https://127.0.0.1:54321/' \
  --insecure-relay-tls \
  --relay-only \
  --device-name "Relay Node B"
```

Wait for `Peer address (after relay discovery):`, then transfer through the relay:

```bash
cargo run -p rift-spike -- send \
  --data-dir /tmp/rift-relay-a \
  --relay-mode disabled \
  --relay-url 'https://127.0.0.1:54321/' \
  --insecure-relay-tls \
  --relay-only \
  '<paste the relay-only peer descriptor here>' \
  /tmp/rift-payload.bin
```

`--relay-only` removes Iroh's direct IP transports. The logs should show `path_kind="relay"`, and the transfer should still complete with a verified BLAKE3 hash. The local relay helper uses a self-signed certificate; `--insecure-relay-tls` explicitly enables its development-only trust mode. A custom `--relay-url` without that flag keeps normal certificate verification, so production relay URLs cannot silently disable TLS verification.

For an external relay experiment, omit `--relay-url` and use Iroh's configured relay set:

```bash
cargo run -p rift-spike -- run \
  --data-dir /tmp/rift-public-b \
  --relay-mode default \
  --relay-only
```

The default mode uses n0's public relays. It requires DNS and outbound access to the relay infrastructure. A relay-only node cannot be dialed until `Iroh endpoint is online via relay` has appeared and its updated peer descriptor contains a `relay:` address. `staging` selects Iroh's staging relay set.

## Reconnect-after-close experiment

Start a direct receiver as above, copy its descriptor, and run:

```bash
cargo run -p rift-spike -- reconnect-after-close \
  --data-dir /tmp/rift-reconnect-a \
  --relay-mode disabled \
  --attempts 4 \
  --drop-after-ms 1000 \
  --retry-delay-ms 1000 \
  '<peer descriptor>'
```

This experiment establishes and handshakes once, deliberately closes the connection, waits, and establishes/handshakes again. It logs `reconnect attempt`, `connection restored`, and `connection lost`. It proves repeated connections with one persistent identity; it does not simulate a network failure or provide session resumption. The application must decide what state to replay after a new QUIC connection.

## Live direct-path fault-injection experiment

This experiment requires a peer descriptor containing both a direct IP address and a relay address. The receiver must be running with relay support and a non-relay-only configuration. For the local self-signed relay setup, start the receiver as in the relay-only example but omit `--relay-only`, then run:

```bash
cargo run -p rift-spike -- fault-inject \
  --data-dir /tmp/rift-fault-a \
  --relay-mode disabled \
  --relay-url 'https://127.0.0.1:54321/' \
  --insecure-relay-tls \
  --fault-after-ms 1000 \
  --recovery-timeout-secs 30 \
  '<direct-plus-relay peer descriptor>'
```

`fault-inject` puts a local UDP forwarder in front of the peer's direct address, establishes the live connection through that direct path, then stops forwarding packets underneath the connection and notifies Iroh of a network change. It requires the selected path to move to the relay, sends a framed `Ping { nonce }` over the existing control stream, and requires the receiver's matching `Pong { nonce }` before reporting success. Iroh may advertise additional direct candidates during connection establishment; if one of those uncontrolled paths is selected, the command fails rather than claiming that the proxy caused a complete outage. The integration test uses a constrained local topology for deterministic packet-loss/path-loss evidence; interface changes, arbitrary NAT changes, and public-relay outages remain separate topology cases.

## Architecture implemented

```text
persistent Iroh SecretKey
        ↓
Iroh Endpoint (ALPN: rift-next-spike/0)
        ↓ authenticated EndpointId / QUIC connection
        ├── one client-opened bidirectional control stream
        │     ├── Hello
        │     ├── DeviceMetadata
        │     ├── Capabilities
        │     └── TransferAck
        └── one unidirectional stream per blob transfer
              ├── framed TransferMetadata
              └── streamed arbitrary bytes
```

### Identity

`identity.key` is created beneath the requested data directory. It contains an application storage envelope around Iroh's 32-byte `SecretKey`: a magic/version prefix, the secret bytes, and a BLAKE3 checksum. The envelope detects truncation, wrong format, and ordinary corruption; it does not introduce a second key or certificate system.

The node ID is Iroh's public key rendered in its normal compact hexadecimal form. The displayed fingerprint is the first 16 bytes of `BLAKE3(node_id_bytes)`, rendered as 32 hex characters. It is deterministic and convenient for manual comparison, but is intentionally not a protocol-stable identity representation. First creation writes a fully-synced uniquely-created temporary file and atomically elects one winner for `identity.key`; concurrent starters that lose the election reload the winner's identity.

### Control plane

Control messages use Serde with Postcard encoding. Every value is prefixed by a four-byte big-endian payload length, with a one-megabyte maximum frame size. The control stream is structured and versioned; it is not an unframed socket.

The handshake sends and validates:

- `Hello { protocol_version, node_id }`
- `DeviceMetadata { device_name, platform }`
- `Capabilities { capabilities }`

The application compares the `Hello.node_id` to the endpoint ID already authenticated by Iroh's TLS/QUIC handshake. A mismatch is rejected. A transfer acknowledgement stays on the control stream, while the payload itself stays on its own QUIC stream.

### Blob/data plane

The sender hashes the file once to create metadata, then streams it in 64 KiB chunks while calculating a second hash. The receiver reads the metadata, writes into a temporary file, hashes while reading, checks the byte count and BLAKE3 digest, then atomically promotes the temporary file with a hard link and removes the staging path. A failed or truncated transfer does not become a completed output file.

This is deliberately a two-pass sender because the receiver needs the expected content hash before bytes arrive. Each receive uses a uniquely-created staging path, and promotion refuses an already-existing destination instead of overwriting it. The receiver never buffers the complete payload in memory.

## Tests and benchmark

Unit tests cover identity creation/reload/corruption, fingerprint stability, frame round trips and malformed frames, unsupported versions, metadata, unsafe names, hash/length failures, and truncated payloads.

`tests/networking.rs` launches two direct Iroh endpoints and verifies authenticated Hello/metadata/capabilities, a separate binary stream, receiver-side length/hash verification, and the acknowledgement. `tests/relay.rs` starts a local self-signed Iroh relay, verifies a relay-only authenticated control connection including Ping/Pong framing, and runs a second direct-plus-relay scenario whose local UDP forwarder is cut under a live connection; the test observes relay selection and post-outage control delivery. Both integration scenarios wrap the complete setup, handshake, stream, transfer, channel, and cleanup sequence in an outer deadline, with shorter stage deadlines for diagnostics.

The explicit benchmark command is intentionally environment-dependent and has no pass/fail throughput threshold:

```bash
cargo run -p rift-spike -- bench \
  --bytes 16777216 \
  --protocol-iterations 100000
```

It measures Postcard control encode/decode operations and a localhost Iroh transfer, waits for the receiver acknowledgement, and prints the fixed streaming buffer size. For larger memory experiments, run it with an OS-level RSS tool such as `/usr/bin/time -l`; the transfer implementation has a fixed 64 KiB application buffer and does not allocate a vector proportional to the payload.

Initial local baseline captured on 2026-08-08 with an 8 MiB transfer and 100,000 protocol iterations:

| Measurement | Result |
| --- | ---: |
| Control encode/decode | 962,806 ops/s |
| Localhost Iroh transfer | 33.42 MiB/s |
| Transfer time | 0.239393 s |
| Payload | 8,388,608 bytes |
| Streaming buffer | 65,536 bytes |

The numbers are a comparison seed, not a performance promise. Repeat the command on the target CI/development machines before using it as a regression signal.

## Findings from the experiments

### What Iroh provides

- A persistent `SecretKey` can be injected into an endpoint; its public key is the endpoint ID used for addressing and peer authentication.
- QUIC/TLS authenticates the intended endpoint ID before the application handshake. Iroh does not decide whether an authenticated peer is trusted by the Rift application; that policy remains ours.
- `EndpointAddr` carries an endpoint ID plus relay and/or direct transport addresses. An endpoint ID by itself requires a configured address lookup service; this spike copies the current address as a JSON descriptor for repeatable experiments.
- The endpoint can establish direct UDP QUIC paths and relay paths behind the same connection API. `Endpoint::paths()` and `Connection::path_events()` expose selected/opened/closed path information.
- QUIC streams are independent ordered byte streams on one connection. A control stream and blob streams do not require a single socket-like application channel.
- Relay forwarding carries encrypted Iroh traffic. The relay is a transport rendezvous/forwarder, not a Rift protocol endpoint.
- Iroh can keep a connection alive while path state changes, but application-level reconnection and state replay are not supplied by this spike or implied by a new `connect` call.

### What was observed

- Direct local CLI transfer succeeded after including loopback in the copied local descriptor. The selected path was logged as `direct`.
- A local relay-only transfer succeeded with no IP transport on either endpoint. The selected path was logged as `relay`, and the receiver verified the same length/hash as the sender.
- The `reconnect-after-close` command established two separate authenticated connections using the same persisted sender identity. Each new connection required a new control handshake; this remains deliberately distinct from a transport outage.
- The live fault-injection scenario started with direct and relay addresses available, routed the direct candidate through a local UDP forwarder, cut that forwarder underneath the live QUIC connection, and observed Iroh select the relay. A post-outage probe stream completed, proving useful connectivity survived this local direct-path loss.
- Ordinary direct-plus-relay local runs selected a direct path immediately and emitted path events for additional candidates. Interface changes, arbitrary packet-loss patterns, NAT/path changes, and public-relay outages remain topology matrix items beyond the deterministic local fault injector.
- The current environment could not resolve/reach n0's public relay hostnames. Iroh timed out its online wait and reported no address lookup information. This is an environment/infrastructure result, not evidence that public relay fallback is broken; the local relay tests provide deterministic transport and fallback validation.
- `Endpoint::online()` is useful for waiting until a relay address appears, but it can wait for external infrastructure. The CLI bounds it and continues for ordinary direct mode.
- Dropping an endpoint without `Endpoint::close()` produces an Iroh diagnostic and aborts ungracefully. The normal CLI paths explicitly close endpoints; abrupt process termination during manual experiments will still produce that warning.

## Limitations and recommendations before the real foundation

1. Keep Iroh's endpoint ID as the cryptographic peer identity, but define a real pairing/trust policy before allowing arbitrary authenticated peers. The spike currently proves identity possession and manual fingerprint comparison only.
2. Keep the control/data split. Add transfer IDs, resumability/idempotency rules, explicit cancellation, authorization, and durable application state only when the next milestone needs them.
3. Treat a QUIC connection as disposable at the application layer even though this spike now demonstrates one live direct-to-relay path migration. Build reconnect and session replay at the Rift layer; use Iroh path events for diagnostics, not as a substitute for application state machines.
4. Choose the production address lookup/discovery model deliberately. A copied `EndpointAddr` JSON is ideal for this spike but is not an offline pairing/mailbox protocol.
5. Make relay certificate trust a real configuration decision. The local helper's insecure self-signed mode requires `--insecure-relay-tls`; production relay URLs use normal CA verification or explicit pinned-root handling.
6. Pin and periodically revalidate the Iroh API/version in the next milestone. The spike uses exact Iroh and Iroh Relay `1.0.3` requirements and intentionally keeps its networking module thin so API changes remain visible.
7. Keep protocol and localhost transfer baselines in the regression suite, but collect networking numbers on representative machines and network topologies before imposing thresholds.
