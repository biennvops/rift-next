//! Production Rift networking over authenticated Iroh QUIC.
//!
//! This crate owns endpoint configuration, Iroh connection and stream operations,
//! transport-authenticated identity conversion, and composition with the production
//! protocol bootstrap. It contains no pairing, authorization, trust persistence,
//! reconnect loop, or insecure relay TLS mode.

use std::{
    collections::BTreeSet,
    fmt,
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
    sync::{Arc, Mutex},
    time::Duration,
};

pub use iroh::address_lookup::memory::MemoryLookup;
use iroh::address_lookup::{DnsAddressLookup, PkarrPublisher, PkarrResolver};
use iroh::endpoint::{
    ConnectingError, Connection, ConnectionError, RecvStream, SendStream, presets,
};
use iroh::{Endpoint, RelayMode};
pub use iroh::{EndpointAddr, RelayUrl, SecretKey, TransportAddr};
use rift_core::DeviceId;
use rift_protocol::{
    ConnectionPurpose, ControlChannel, ControlError, ControlMessage, FrameError, HandshakeError,
    Hello, HelloMetadata, MessageKind, PROTOCOL_VERSION, PairingMessage,
    exchange_hello_with_timeout,
};
use thiserror::Error;
use tokio::time;
use tracing::{debug, info, warn};

/// The one production ALPN, re-exported for callers that need to construct a
/// manual protocol conformance peer.
pub use rift_protocol::ALPN;

/// The concrete production bidirectional control stream type.
pub type ControlStream = ControlChannel<SendStream, RecvStream>;

/// Default connection establishment deadline.
pub const DEFAULT_CONNECTION_TIMEOUT: Duration = Duration::from_secs(10);

/// Default Hello exchange deadline.
pub const DEFAULT_HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);

/// Relay configuration exposed by the production endpoint without exposing relay
/// server implementation or TLS override APIs.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum RelayConfiguration {
    /// Do not use Iroh relay transports or relay addressing.
    Disabled,
    /// Use Iroh's production relay map.
    Default,
    /// Use Iroh's staging relay map.
    Staging,
    /// Use the supplied relay URLs.
    Custom(Vec<RelayUrl>),
}

impl RelayConfiguration {
    fn as_iroh_mode(&self) -> RelayMode {
        match self {
            Self::Disabled => RelayMode::Disabled,
            Self::Default => RelayMode::Default,
            Self::Staging => RelayMode::Staging,
            Self::Custom(relays) => RelayMode::custom(relays.iter().cloned()),
        }
    }
}

/// External known-identity reachability, independent from relay routing.
#[derive(Clone, Debug, Default)]
pub enum AddressLookupConfiguration {
    /// Do not publish or resolve through external infrastructure.
    #[default]
    Disabled,
    /// Publish and resolve through Number 0's DNS/Pkarr infrastructure.
    N0,
    /// Injected native in-memory resolver for hermetic known-identity lookup.
    /// Its lifetime/contents are owned by the local caller, not persisted by Rift.
    Memory(MemoryLookup),
}

/// Maximum ephemeral peer hints retained by one endpoint.
pub const MAX_PEER_HINTS: usize = 4096;
/// Maximum paths in one ephemeral peer hint.
pub const MAX_HINT_PATHS: usize = 32;

/// Small production endpoint configuration.
#[derive(Clone, Debug)]
pub struct EndpointConfig {
    /// Explicit external lookup selection; memory hints are always available.
    pub address_lookup: AddressLookupConfiguration,
    /// Relay behavior for the endpoint.
    pub relay: RelayConfiguration,
    /// Optional explicit IP bind address. `None` uses Iroh's normal IP transports.
    pub bind_addr: Option<SocketAddr>,
    /// Deadline for QUIC connection and control-stream establishment.
    pub connection_timeout: Duration,
    /// Deadline for Hello and post-bootstrap control operations.
    pub handshake_timeout: Duration,
}

impl Default for EndpointConfig {
    fn default() -> Self {
        Self {
            address_lookup: AddressLookupConfiguration::Disabled,
            relay: RelayConfiguration::Disabled,
            bind_addr: None,
            connection_timeout: DEFAULT_CONNECTION_TIMEOUT,
            handshake_timeout: DEFAULT_HANDSHAKE_TIMEOUT,
        }
    }
}

impl EndpointConfig {
    /// Returns a deterministic direct-only loopback configuration for local tests
    /// and local callers.
    pub fn direct() -> Self {
        Self {
            bind_addr: Some(SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0)),
            ..Self::default()
        }
    }

    fn validate(&self) -> Result<(), TransportError> {
        if self.connection_timeout.is_zero() {
            return Err(TransportError::InvalidConfiguration(
                "connection_timeout must be greater than zero",
            ));
        }
        if self.handshake_timeout.is_zero() {
            return Err(TransportError::InvalidConfiguration(
                "handshake_timeout must be greater than zero",
            ));
        }
        Ok(())
    }
}

/// Errors from endpoint, connection, stream, and production bootstrap operations.
#[derive(Debug, Error)]
pub enum TransportError {
    /// The peer rejected the requested purpose without disclosing trust state.
    #[error("remote connection purpose rejected")]
    IntentRejected,
    /// Purpose framing failed.
    #[error("connection intent framing failed: {0}")]
    IntentFrame(#[source] FrameError),
    /// A message is not legal during purpose negotiation.
    #[error("expected {expected} during connection intent, received {received}")]
    UnexpectedIntentMessage {
        expected: MessageKind,
        received: MessageKind,
    },
    /// An intent operation was repeated or invoked out of sequence.
    #[error("connection intent operation is out of sequence")]
    IntentSequence,
    /// The public bytes cannot represent an Iroh endpoint identity.
    #[error("invalid peer device identity")]
    InvalidDeviceId,
    /// No configured route source exists for this identity.
    #[error("no reachability source for peer {0}")]
    Unresolved(DeviceId),
    /// The local endpoint cannot dial itself.
    #[error("cannot connect to the local device")]
    SelfConnect,
    /// Ephemeral hint input exceeded a hard resource bound.
    #[error("peer address hint capacity exceeded")]
    HintCapacityExceeded,
    /// An earlier panic invalidated the hint registry.
    #[error("peer address hint registry is poisoned")]
    HintRegistryPoisoned,
    /// The caller supplied an unusable endpoint configuration.
    #[error("invalid endpoint configuration: {0}")]
    InvalidConfiguration(&'static str),
    /// Iroh rejected the explicit bind address.
    #[error("invalid endpoint bind address: {0}")]
    InvalidBindAddress(#[source] iroh::endpoint::InvalidSocketAddr),
    /// Iroh could not bind the endpoint.
    #[error("unable to bind Iroh endpoint: {0}")]
    Bind(#[source] iroh::endpoint::BindError),
    /// The connect deadline elapsed.
    #[error("Iroh connection attempt timed out")]
    ConnectTimeout,
    /// Iroh rejected or failed the connection attempt.
    #[error("unable to connect to Iroh peer: {0}")]
    Connect(#[source] iroh::endpoint::ConnectError),
    /// The accept deadline elapsed before a connection was available or completed.
    #[error("Iroh incoming connection timed out")]
    AcceptTimeout,
    /// The endpoint was closed while waiting for an incoming connection.
    #[error("Iroh endpoint closed while waiting for an incoming connection")]
    EndpointClosed,
    /// Iroh rejected the initial incoming connection acceptance.
    #[error("unable to accept incoming Iroh connection: {0}")]
    AcceptStart(#[source] ConnectionError),
    /// Iroh failed while completing an incoming connection handshake.
    #[error("unable to complete incoming Iroh connection: {0}")]
    Accept(#[source] ConnectingError),
    /// The outgoing control stream could not be opened before its deadline.
    #[error("opening the Rift control stream timed out")]
    ControlStreamOpenTimeout,
    /// The incoming control stream could not be accepted before its deadline.
    #[error("accepting the Rift control stream timed out")]
    ControlStreamAcceptTimeout,
    /// Iroh failed while opening or accepting the control stream.
    #[error("unable to establish the Rift control stream: {0}")]
    ControlStream(#[source] ConnectionError),
    /// The production Hello exchange failed.
    #[error("Rift Hello exchange failed: {0}")]
    Handshake(#[from] HandshakeError),
    /// A post-bootstrap control message failed.
    #[error("Rift control message failed: {0}")]
    Control(#[from] ControlError),
    /// Pairing control framing failed.
    #[error("Rift pairing control framing failed: {0}")]
    PairingFrame(#[source] FrameError),
    /// Pairing-only control received a non-pairing message.
    #[error("pairing-only connection received {received}")]
    UnexpectedPairingMessage { received: MessageKind },
    /// A prior control failure invalidated and closed this disposable connection.
    #[error("Rift control connection is poisoned by a prior failure")]
    ControlConnectionPoisoned,
    /// A post-bootstrap control operation exceeded its deadline.
    #[error("Rift control operation timed out")]
    ControlTimeout,
}

impl TransportError {
    /// Classification only; transport never retries a failed disposable connection.
    pub fn is_retryable(&self) -> bool {
        use iroh::endpoint::{ConnectError, ConnectWithOptsError};
        match self {
            Self::ConnectTimeout
            | Self::AcceptTimeout
            | Self::ControlStreamOpenTimeout
            | Self::ControlStreamAcceptTimeout
            | Self::ControlTimeout => true,
            Self::Connect(ConnectError::Connect {
                source: ConnectWithOptsError::NoAddress { .. },
                ..
            }) => true,
            Self::Connect(ConnectError::Connecting {
                source: ConnectingError::ConnectionError { source, .. },
                ..
            })
            | Self::Connect(ConnectError::Connection { source, .. })
            | Self::ControlStream(source)
            | Self::AcceptStart(source)
            | Self::Accept(ConnectingError::ConnectionError { source, .. }) => {
                retryable_connection_error(source)
            }
            Self::Handshake(HandshakeError::HandshakeTimeout) => true,
            Self::Handshake(HandshakeError::Frame(error))
            | Self::IntentFrame(error)
            | Self::PairingFrame(error)
            | Self::Control(ControlError::Frame(error)) => matches!(
                error,
                FrameError::TruncatedLengthPrefix(_)
                    | FrameError::TruncatedPayload(_)
                    | FrameError::Write(_)
            ),
            _ => false,
        }
    }
}

fn retryable_connection_error(error: &ConnectionError) -> bool {
    matches!(
        error,
        ConnectionError::Reset | ConnectionError::TimedOut | ConnectionError::ApplicationClosed(_)
    )
}

/// An Iroh endpoint configured for the production Rift ALPN.
#[derive(Clone)]
pub struct RiftEndpoint {
    endpoint: Endpoint,
    device_id: DeviceId,
    config: EndpointConfig,
    memory_lookup: MemoryLookup,
    hint_ids: Arc<Mutex<BTreeSet<DeviceId>>>,
}

impl fmt::Debug for RiftEndpoint {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RiftEndpoint")
            .field("device_id", &self.device_id)
            .field("config", &self.config)
            .finish_non_exhaustive()
    }
}

impl RiftEndpoint {
    /// Binds an endpoint from the caller-supplied Iroh secret key.
    ///
    /// The secret key is consumed by Iroh and is never included in this wrapper's
    /// debug output, logs, or errors.
    pub async fn bind(
        secret_key: SecretKey,
        config: EndpointConfig,
    ) -> Result<Self, TransportError> {
        config.validate()?;
        let memory_lookup = MemoryLookup::new();
        let mut builder = Endpoint::builder(presets::Minimal)
            .address_lookup(memory_lookup.clone())
            .secret_key(secret_key)
            .alpns(vec![ALPN.to_vec()])
            .relay_mode(config.relay.as_iroh_mode());
        if matches!(config.address_lookup, AddressLookupConfiguration::N0) {
            builder = builder
                .address_lookup(PkarrPublisher::n0_dns())
                .address_lookup(PkarrResolver::n0_dns())
                .address_lookup(DnsAddressLookup::n0_dns());
        }
        if let AddressLookupConfiguration::Memory(lookup) = &config.address_lookup {
            builder = builder.address_lookup(lookup.clone());
        }
        if let Some(bind_addr) = config.bind_addr {
            builder = builder.clear_ip_transports();
            builder = builder
                .bind_addr(bind_addr)
                .map_err(TransportError::InvalidBindAddress)?;
        }
        let endpoint = builder.bind().await.map_err(TransportError::Bind)?;
        let device_id = device_id_from_endpoint_id(endpoint.id());
        info!(
            local_device_id = %device_id,
            protocol_version = PROTOCOL_VERSION,
            "Rift production endpoint bound"
        );
        Ok(Self {
            endpoint,
            device_id,
            config,
            memory_lookup,
            hint_ids: Arc::new(Mutex::new(BTreeSet::new())),
        })
    }

    /// Returns the public identity owned by this endpoint.
    pub const fn device_id(&self) -> DeviceId {
        self.device_id
    }

    /// Returns the current Iroh endpoint address.
    pub fn addr(&self) -> EndpointAddr {
        self.endpoint.addr()
    }

    /// Returns a direct local address suitable for deterministic loopback tests.
    ///
    /// Iroh may report an unspecified bind address. This helper maps only such
    /// local IP addresses to the matching loopback address and leaves relay/custom
    /// addresses unchanged.
    pub fn local_addr(&self) -> EndpointAddr {
        let address = self.endpoint.addr();
        let endpoint_id = address.id;
        let mut addresses = address
            .addrs
            .into_iter()
            .map(normalize_local_transport_address)
            .collect::<Vec<_>>();
        for socket in self.endpoint.bound_sockets() {
            let address = TransportAddr::Ip(normalize_local_socket(socket));
            if !addresses.iter().any(|candidate| candidate == &address) {
                addresses.push(address);
            }
        }
        EndpointAddr::from_parts(endpoint_id, addresses)
    }

    /// Returns whether the underlying Iroh endpoint has been closed.
    pub fn is_closed(&self) -> bool {
        self.endpoint.is_closed()
    }

    /// Updates an ephemeral route hint, keyed by its embedded authenticated identity.
    /// This is not trust. The latest snapshot replaces old paths to bound stale state.
    pub fn remember_peer_addr(&self, peer: EndpointAddr) -> Result<DeviceId, TransportError> {
        let device_id = device_id_from_endpoint_id(peer.id);
        if device_id == self.device_id {
            return Err(TransportError::SelfConnect);
        }
        if peer.addrs.len() > MAX_HINT_PATHS {
            return Err(TransportError::HintCapacityExceeded);
        }
        if peer.addrs.is_empty() {
            return Ok(device_id);
        }
        let mut ids = self
            .hint_ids
            .lock()
            .map_err(|_| TransportError::HintRegistryPoisoned)?;
        if !ids.contains(&device_id) && ids.len() >= MAX_PEER_HINTS {
            return Err(TransportError::HintCapacityExceeded);
        }
        ids.insert(device_id);
        let _previous = self.memory_lookup.set_endpoint_info(peer);
        Ok(device_id)
    }

    /// Removes an application hint, not trust or an existing Iroh connection/path cache.
    pub fn forget_peer_addr(&self, device_id: DeviceId) -> Result<(), TransportError> {
        let endpoint_id = endpoint_id_from_device_id(device_id)?;
        let mut ids = self
            .hint_ids
            .lock()
            .map_err(|_| TransportError::HintRegistryPoisoned)?;
        ids.remove(&device_id);
        let _previous = self.memory_lookup.remove_endpoint_info(endpoint_id);
        Ok(())
    }

    /// Whether a fresh identity-only dial has an external lookup or ephemeral hint source.
    pub fn has_route_source(&self, device_id: DeviceId) -> Result<bool, TransportError> {
        let endpoint_id = endpoint_id_from_device_id(device_id)?;
        let ids = self
            .hint_ids
            .lock()
            .map_err(|_| TransportError::HintRegistryPoisoned)?;
        let external = match &self.config.address_lookup {
            AddressLookupConfiguration::Disabled => false,
            AddressLookupConfiguration::N0 => true,
            AddressLookupConfiguration::Memory(lookup) => lookup
                .get_endpoint_info(endpoint_id)
                .is_some_and(|info| !info.to_endpoint_addr().addrs.is_empty()),
        };
        Ok(external || ids.contains(&device_id))
    }

    /// Resolves current reachability and authenticates a peer using only its identity.
    pub async fn connect_device(
        &self,
        device_id: DeviceId,
    ) -> Result<AuthenticatedConnection, TransportError> {
        if device_id == self.device_id {
            return Err(TransportError::SelfConnect);
        }
        let endpoint_id = endpoint_id_from_device_id(device_id)?;
        if !self.has_route_source(device_id)? {
            return Err(TransportError::Unresolved(device_id));
        }
        self.dial(EndpointAddr::new(endpoint_id)).await
    }

    /// Identity-only dial followed by the mandatory authenticated Hello exchange.
    pub async fn connect_device_and_bootstrap(
        &self,
        device_id: DeviceId,
        metadata: HelloMetadata,
    ) -> Result<BootstrappedConnection, TransportError> {
        let connection = self.connect_device(device_id).await?;
        self.bootstrap(connection, metadata, ControlDirection::Open)
            .await
    }

    /// Connects to an authenticated Iroh peer using the production ALPN.
    pub async fn connect(
        &self,
        peer: EndpointAddr,
    ) -> Result<AuthenticatedConnection, TransportError> {
        let device_id = self.remember_peer_addr(peer)?;
        self.connect_device(device_id).await
    }

    async fn dial(&self, peer: EndpointAddr) -> Result<AuthenticatedConnection, TransportError> {
        debug!(
            local_device_id = %self.device_id,
            remote_device_id = %device_id_from_endpoint_id(peer.id),
            protocol_version = PROTOCOL_VERSION,
            "connecting Rift production endpoint"
        );
        let connection = time::timeout(
            self.config.connection_timeout,
            self.endpoint.connect(peer, ALPN),
        )
        .await
        .map_err(|_| TransportError::ConnectTimeout)?
        .map_err(TransportError::Connect)?;
        let authenticated =
            AuthenticatedConnection::new(connection, self.config.connection_timeout);
        info!(
            local_device_id = %self.device_id,
            remote_device_id = %authenticated.remote_device_id(),
            protocol_version = PROTOCOL_VERSION,
            "Rift Iroh connection authenticated"
        );
        Ok(authenticated)
    }

    /// Accepts the next authenticated Iroh connection using the production ALPN.
    pub async fn accept(&self) -> Result<AuthenticatedConnection, TransportError> {
        let incoming = time::timeout(self.config.connection_timeout, self.endpoint.accept())
            .await
            .map_err(|_| TransportError::AcceptTimeout)?
            .ok_or(TransportError::EndpointClosed)?;
        let accepting = incoming.accept().map_err(TransportError::AcceptStart)?;
        let connection = time::timeout(self.config.connection_timeout, accepting)
            .await
            .map_err(|_| TransportError::AcceptTimeout)?
            .map_err(TransportError::Accept)?;
        let authenticated =
            AuthenticatedConnection::new(connection, self.config.connection_timeout);
        info!(
            local_device_id = %self.device_id,
            remote_device_id = %authenticated.remote_device_id(),
            protocol_version = PROTOCOL_VERSION,
            "accepted Rift Iroh connection"
        );
        Ok(authenticated)
    }

    /// Connects and bootstraps the outbound production control stream.
    pub async fn connect_and_bootstrap(
        &self,
        peer: EndpointAddr,
        metadata: HelloMetadata,
    ) -> Result<BootstrappedConnection, TransportError> {
        let connection = self.connect(peer).await?;
        self.bootstrap(connection, metadata, ControlDirection::Open)
            .await
    }

    /// Accepts and bootstraps the inbound production control stream.
    pub async fn accept_and_bootstrap(
        &self,
        metadata: HelloMetadata,
    ) -> Result<BootstrappedConnection, TransportError> {
        let connection = self.accept().await?;
        self.bootstrap(connection, metadata, ControlDirection::Accept)
            .await
    }

    /// Gracefully closes the endpoint and waits for Iroh's close/drain operation.
    pub async fn close(&self) {
        self.endpoint.close().await;
    }

    async fn bootstrap(
        &self,
        connection: AuthenticatedConnection,
        metadata: HelloMetadata,
        direction: ControlDirection,
    ) -> Result<BootstrappedConnection, TransportError> {
        let mut close_guard = BootstrapCloseGuard(Some(connection.connection.clone()));
        let remote_device_id = connection.remote_device_id();
        let control_result = match direction {
            ControlDirection::Open => connection.open_control().await,
            ControlDirection::Accept => connection.accept_control().await,
        };
        let mut control = match control_result {
            Ok(control) => control,
            Err(error) => {
                connection.close();
                return Err(error);
            }
        };
        let peer_hello = match exchange_hello_with_timeout(
            &mut control,
            self.device_id,
            &metadata,
            remote_device_id,
            self.config.handshake_timeout,
        )
        .await
        {
            Ok(peer_hello) => peer_hello,
            Err(error) => {
                warn!(
                    local_device_id = %self.device_id,
                    remote_device_id = %remote_device_id,
                    protocol_version = PROTOCOL_VERSION,
                    failure_category = handshake_failure_category(&error),
                    "Rift production bootstrap failed"
                );
                connection.close();
                return Err(TransportError::Handshake(error));
            }
        };
        info!(
            local_device_id = %self.device_id,
            remote_device_id = %remote_device_id,
            protocol_version = peer_hello.protocol_version,
            handshake_outcome = "success",
            "Rift production bootstrap complete"
        );
        close_guard.0 = None;
        Ok(BootstrappedConnection {
            connection: connection.connection,
            control: Some(control),
            local_device_id: self.device_id,
            peer_hello,
            control_timeout: self.config.handshake_timeout,
            intent_phase: IntentPhase::Fresh,
        })
    }
}

struct BootstrapCloseGuard(Option<Connection>);

impl Drop for BootstrapCloseGuard {
    fn drop(&mut self) {
        if let Some(connection) = &self.0 {
            connection.close(0_u32.into(), b"Rift bootstrap cancelled");
        }
    }
}

#[derive(Clone, Copy)]
enum ControlDirection {
    Open,
    Accept,
}

/// An authenticated QUIC connection before the Rift Hello exchange.
#[derive(Clone)]
pub struct AuthenticatedConnection {
    connection: Connection,
    stream_timeout: Duration,
}

impl fmt::Debug for AuthenticatedConnection {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AuthenticatedConnection")
            .field("remote_device_id", &self.remote_device_id())
            .finish_non_exhaustive()
    }
}

impl AuthenticatedConnection {
    fn new(connection: Connection, stream_timeout: Duration) -> Self {
        Self {
            connection,
            stream_timeout,
        }
    }

    /// Returns the public endpoint identity authenticated by Iroh.
    pub fn remote_device_id(&self) -> DeviceId {
        device_id_from_endpoint_id(self.connection.remote_id())
    }

    /// Opens the production bidirectional control stream.
    pub async fn open_control(&self) -> Result<ControlStream, TransportError> {
        let (send, recv) = time::timeout(self.stream_timeout, self.connection.open_bi())
            .await
            .map_err(|_| TransportError::ControlStreamOpenTimeout)?
            .map_err(TransportError::ControlStream)?;
        Ok(ControlChannel::new(send, recv))
    }

    /// Accepts the next incoming production bidirectional control stream.
    pub async fn accept_control(&self) -> Result<ControlStream, TransportError> {
        let (send, recv) = time::timeout(self.stream_timeout, self.connection.accept_bi())
            .await
            .map_err(|_| TransportError::ControlStreamAcceptTimeout)?
            .map_err(TransportError::ControlStream)?;
        Ok(ControlChannel::new(send, recv))
    }

    /// Closes this disposable QUIC connection immediately.
    pub fn close(&self) {
        self.connection
            .close(0_u32.into(), b"Rift connection closed");
    }
}

/// A cloneable, capability-minimal handle for closing or observing one disposable
/// connection without exposing the raw Iroh connection.
#[derive(Clone)]
pub struct DisposableConnectionHandle {
    connection: Connection,
}

impl fmt::Debug for DisposableConnectionHandle {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("DisposableConnectionHandle")
            .field(
                "remote_device_id",
                &device_id_from_endpoint_id(self.connection.remote_id()),
            )
            .finish_non_exhaustive()
    }
}

impl DisposableConnectionHandle {
    /// Immediately closes the disposable connection.
    pub fn close(&self) {
        self.connection
            .close(0_u32.into(), b"Rift connection closed by runtime owner");
    }

    /// Whether the underlying connection has already terminated.
    pub fn is_closed(&self) -> bool {
        self.connection.close_reason().is_some()
    }

    /// Waits until the underlying disposable connection has terminated.
    pub async fn closed(&self) {
        let _closed_reason = self.connection.closed().await;
    }
}

#[derive(Clone, Copy, Eq, PartialEq)]
enum IntentPhase {
    Fresh,
    AwaitingDecision,
    Finished,
}

/// A successfully Hello-bootstrapped, still-disposable Rift connection.
pub struct BootstrappedConnection {
    connection: Connection,
    control: Option<ControlStream>,
    local_device_id: DeviceId,
    peer_hello: Hello,
    control_timeout: Duration,
    intent_phase: IntentPhase,
}

impl Drop for BootstrappedConnection {
    fn drop(&mut self) {
        self.close();
    }
}

impl fmt::Debug for BootstrappedConnection {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("BootstrappedConnection")
            .field("peer_hello", &self.peer_hello)
            .finish_non_exhaustive()
    }
}

impl BootstrappedConnection {
    /// Returns the endpoint-owned local public identity used in Hello.
    pub const fn local_device_id(&self) -> DeviceId {
        self.local_device_id
    }

    /// Returns the validated peer Hello metadata and identity.
    pub const fn peer_hello(&self) -> &Hello {
        &self.peer_hello
    }

    /// Returns the identity authenticated by Iroh and matched by Hello.
    pub const fn remote_device_id(&self) -> DeviceId {
        self.peer_hello.device_id
    }

    /// Returns a minimal cloneable handle for runtime liveness and cancellation.
    pub fn disposable_handle(&self) -> DisposableConnectionHandle {
        DisposableConnectionHandle {
            connection: self.connection.clone(),
        }
    }

    /// Waits until this disposable connection terminates.
    pub async fn closed(&self) {
        let _closed_reason = self.connection.closed().await;
    }

    /// Dialer gate: sends exactly one purpose and requires the matching coarse result.
    pub async fn request_intent(
        &mut self,
        purpose: ConnectionPurpose,
    ) -> Result<(), TransportError> {
        self.require_intent_phase(IntentPhase::Fresh)?;
        self.intent_phase = IntentPhase::Finished;
        self.write_intent(ControlMessage::ConnectionIntent { purpose })
            .await?;
        match self.read_intent().await? {
            ControlMessage::ConnectionIntentResult { accepted: true } => Ok(()),
            ControlMessage::ConnectionIntentResult { accepted: false } => {
                self.poison();
                Err(TransportError::IntentRejected)
            }
            message => {
                self.poison();
                Err(TransportError::UnexpectedIntentMessage {
                    expected: MessageKind::ConnectionIntentResult,
                    received: message.kind(),
                })
            }
        }
    }

    /// Acceptor gate: reads the purpose before the session layer applies trust policy.
    pub async fn receive_intent(&mut self) -> Result<ConnectionPurpose, TransportError> {
        self.require_intent_phase(IntentPhase::Fresh)?;
        self.intent_phase = IntentPhase::AwaitingDecision;
        match self.read_intent().await? {
            ControlMessage::ConnectionIntent { purpose } => Ok(purpose),
            message => {
                self.poison();
                Err(TransportError::UnexpectedIntentMessage {
                    expected: MessageKind::ConnectionIntent,
                    received: message.kind(),
                })
            }
        }
    }

    /// Sends a coarse result. Rejection closes after bounded delivery, not a retry.
    pub async fn send_intent_result(&mut self, accepted: bool) -> Result<(), TransportError> {
        self.require_intent_phase(IntentPhase::AwaitingDecision)?;
        self.intent_phase = IntentPhase::Finished;
        self.write_intent(ControlMessage::ConnectionIntentResult { accepted })
            .await?;
        if !accepted {
            // Immediate QUIC close could discard the result and disguise policy rejection
            // as a retryable network failure. The rejected dialer closes on receipt.
            let _closed = time::timeout(self.control_timeout, self.connection.closed()).await;
            self.poison();
        }
        Ok(())
    }

    fn require_intent_phase(&mut self, phase: IntentPhase) -> Result<(), TransportError> {
        if self.control.is_none() {
            return Err(TransportError::ControlConnectionPoisoned);
        }
        if self.intent_phase != phase {
            self.poison();
            return Err(TransportError::IntentSequence);
        }
        Ok(())
    }

    async fn write_intent(&mut self, message: ControlMessage) -> Result<(), TransportError> {
        let control = self
            .control
            .as_mut()
            .ok_or(TransportError::ControlConnectionPoisoned)?;
        match time::timeout(
            self.control_timeout,
            rift_protocol::write_message(&mut control.send, &message),
        )
        .await
        {
            Ok(Ok(())) => Ok(()),
            Ok(Err(error)) => {
                self.poison();
                Err(TransportError::IntentFrame(error))
            }
            Err(_) => {
                self.poison();
                Err(TransportError::ControlTimeout)
            }
        }
    }

    async fn read_intent(&mut self) -> Result<ControlMessage, TransportError> {
        let control = self
            .control
            .as_mut()
            .ok_or(TransportError::ControlConnectionPoisoned)?;
        match time::timeout(
            self.control_timeout,
            rift_protocol::read_message(&mut control.recv),
        )
        .await
        {
            Ok(Ok(message)) => Ok(message),
            Ok(Err(error)) => {
                self.poison();
                Err(TransportError::IntentFrame(error))
            }
            Err(_) => {
                self.poison();
                Err(TransportError::ControlTimeout)
            }
        }
    }

    /// Monitors the admitted control stream, allowing only Ping/Pong service.
    /// Idle sessions have no application idle timeout, but every started frame does.
    pub async fn serve_authorized_control(&mut self) -> Result<(), TransportError> {
        use tokio::io::AsyncReadExt;
        loop {
            let control = self
                .control
                .as_mut()
                .ok_or(TransportError::ControlConnectionPoisoned)?;
            let mut first = [0; 1];
            if let Err(error) = AsyncReadExt::read_exact(&mut control.recv, &mut first).await {
                self.poison();
                return Err(TransportError::Control(ControlError::Frame(
                    FrameError::TruncatedLengthPrefix(error),
                )));
            }
            let mut frame = first.as_slice().chain(&mut control.recv);
            let received = time::timeout(
                self.control_timeout,
                rift_protocol::read_message(&mut frame),
            )
            .await;
            let result = match received {
                Ok(Ok(ControlMessage::Ping { nonce })) => time::timeout(
                    self.control_timeout,
                    rift_protocol::write_message(
                        &mut control.send,
                        &ControlMessage::Pong { nonce },
                    ),
                )
                .await
                .map_err(|_| TransportError::ControlTimeout)
                .and_then(|result| {
                    result.map_err(|error| TransportError::Control(ControlError::Frame(error)))
                }),
                Ok(Ok(message)) => Err(TransportError::Control(ControlError::UnexpectedMessage {
                    expected: MessageKind::Ping,
                    received: message.kind(),
                })),
                Ok(Err(error)) => Err(TransportError::Control(ControlError::Frame(error))),
                Err(_) => Err(TransportError::ControlTimeout),
            };
            if let Err(error) = result {
                self.poison();
                return Err(error);
            }
        }
    }

    /// Sends a Ping and waits for the matching Pong before the control deadline.
    /// Any failure closes and permanently invalidates this disposable connection.
    pub async fn ping(&mut self, nonce: u64) -> Result<(), TransportError> {
        let control = self
            .control
            .as_mut()
            .ok_or(TransportError::ControlConnectionPoisoned)?;
        let result = time::timeout(self.control_timeout, rift_protocol::ping(control, nonce)).await;
        match result {
            Ok(Ok(())) => Ok(()),
            Ok(Err(error)) => {
                self.poison();
                Err(TransportError::Control(error))
            }
            Err(_) => {
                self.poison();
                Err(TransportError::ControlTimeout)
            }
        }
    }

    /// Waits for one Ping and sends its matching Pong before the control deadline.
    /// Any failure closes and permanently invalidates this disposable connection.
    pub async fn respond_to_ping(&mut self) -> Result<u64, TransportError> {
        let control = self
            .control
            .as_mut()
            .ok_or(TransportError::ControlConnectionPoisoned)?;
        let result = time::timeout(
            self.control_timeout,
            rift_protocol::respond_to_ping(control),
        )
        .await;
        match result {
            Ok(Ok(nonce)) => Ok(nonce),
            Ok(Err(error)) => {
                self.poison();
                Err(TransportError::Control(error))
            }
            Err(_) => {
                self.poison();
                Err(TransportError::ControlTimeout)
            }
        }
    }

    /// Sends one pairing message before the supplied pairing phase deadline.
    /// Any failure poisons this disposable connection.
    pub async fn send_pairing(
        &mut self,
        message: PairingMessage,
        timeout: Duration,
    ) -> Result<(), TransportError> {
        let control = self
            .control
            .as_mut()
            .ok_or(TransportError::ControlConnectionPoisoned)?;
        let message = ControlMessage::from(message);
        let result = time::timeout(
            timeout,
            rift_protocol::write_message(&mut control.send, &message),
        )
        .await;
        match result {
            Ok(Ok(())) => Ok(()),
            Ok(Err(error)) => {
                self.poison();
                Err(TransportError::PairingFrame(error))
            }
            Err(_) => {
                self.poison();
                Err(TransportError::ControlTimeout)
            }
        }
    }

    /// Receives one pairing message before the supplied pairing phase deadline.
    ///
    /// General control messages are rejected and poison the pairing-only connection.
    pub async fn receive_pairing(
        &mut self,
        timeout: Duration,
    ) -> Result<PairingMessage, TransportError> {
        let control = self
            .control
            .as_mut()
            .ok_or(TransportError::ControlConnectionPoisoned)?;
        let result = time::timeout(timeout, rift_protocol::read_message(&mut control.recv)).await;
        match result {
            Ok(Ok(message)) => match message.into_pairing() {
                Ok(pairing) => Ok(pairing),
                Err(received) => {
                    self.poison();
                    Err(TransportError::UnexpectedPairingMessage { received })
                }
            },
            Ok(Err(error)) => {
                self.poison();
                Err(TransportError::PairingFrame(error))
            }
            Err(_) => {
                self.poison();
                Err(TransportError::ControlTimeout)
            }
        }
    }

    /// Closes this disposable QUIC connection immediately.
    pub fn close(&self) {
        self.close_with_reason(b"Rift connection closed");
    }

    fn poison(&mut self) {
        self.control = None;
        self.close_with_reason(b"Rift control connection poisoned");
    }

    fn close_with_reason(&self, reason: &[u8]) {
        self.connection.close(0_u32.into(), reason);
    }
}

fn endpoint_id_from_device_id(device_id: DeviceId) -> Result<iroh::EndpointId, TransportError> {
    iroh::EndpointId::from_bytes(device_id.as_bytes()).map_err(|_| TransportError::InvalidDeviceId)
}

fn device_id_from_endpoint_id(endpoint_id: iroh::EndpointId) -> DeviceId {
    DeviceId::from_bytes(*endpoint_id.as_bytes())
}

fn normalize_local_transport_address(address: TransportAddr) -> TransportAddr {
    match address {
        TransportAddr::Ip(socket) => TransportAddr::Ip(normalize_local_socket(socket)),
        address => address,
    }
}

fn normalize_local_socket(socket: SocketAddr) -> SocketAddr {
    match socket {
        SocketAddr::V4(address) if address.ip().is_unspecified() => {
            SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), address.port())
        }
        SocketAddr::V6(address) if address.ip().is_unspecified() => {
            SocketAddr::new(IpAddr::V6(Ipv6Addr::LOCALHOST), address.port())
        }
        socket => socket,
    }
}

fn handshake_failure_category(error: &HandshakeError) -> &'static str {
    match error {
        HandshakeError::Frame(_) => "frame",
        HandshakeError::HandshakeTimeout => "timeout",
        HandshakeError::UnsupportedProtocolVersion(_) => "unsupported_version",
        HandshakeError::IdentityMismatch { .. } => "identity_mismatch",
        HandshakeError::InvalidMetadata { .. } => "invalid_metadata",
        HandshakeError::TooManyCapabilities { .. } => "too_many_capabilities",
        HandshakeError::UnexpectedMessage { .. } => "unexpected_message",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    #[ignore = "measurement executed by cargo xtask benchmark-smoke"]
    fn device_id_conversion_benchmark() -> Result<(), TransportError> {
        use std::hint::black_box;
        let id = device_id_from_endpoint_id(SecretKey::from_bytes(&[7; 32]).public());
        let iterations = 10_000;
        let start = std::time::Instant::now();
        for _ in 0..iterations {
            black_box(endpoint_id_from_device_id(black_box(id))?);
        }
        let elapsed = start.elapsed();
        println!("production.transport.device_id_conversion_iterations={iterations}");
        println!(
            "production.transport.device_id_conversion.ops_per_second={:.2}",
            f64::from(iterations) / elapsed.as_secs_f64()
        );
        Ok(())
    }

    #[test]
    fn retry_classification_rejects_policy_protocol_and_invariant_failures() {
        for error in [
            TransportError::IntentRejected,
            TransportError::IntentSequence,
            TransportError::InvalidDeviceId,
            TransportError::SelfConnect,
            TransportError::EndpointClosed,
            TransportError::Handshake(HandshakeError::UnsupportedProtocolVersion(2)),
            TransportError::Handshake(HandshakeError::IdentityMismatch {
                authenticated: DeviceId::from_bytes([1; 32]),
                hello: DeviceId::from_bytes([2; 32]),
            }),
            TransportError::IntentFrame(FrameError::FrameTooLarge {
                actual: 999999,
                maximum: 1000,
            }),
            TransportError::ControlStream(ConnectionError::VersionMismatch),
        ] {
            assert!(!error.is_retryable());
        }
        for error in [
            TransportError::ConnectTimeout,
            TransportError::ControlTimeout,
            TransportError::ControlStream(ConnectionError::Reset),
            TransportError::ControlStream(ConnectionError::TimedOut),
            TransportError::Handshake(HandshakeError::HandshakeTimeout),
        ] {
            assert!(error.is_retryable());
        }
    }

    #[test]
    fn device_identity_conversion_validates_public_key_bytes() -> Result<(), TransportError> {
        let public = SecretKey::from_bytes(&[7; 32]).public();
        assert_eq!(
            endpoint_id_from_device_id(device_id_from_endpoint_id(public))?,
            public
        );
        let invalid = (0..=255)
            .map(|byte| DeviceId::from_bytes([byte; 32]))
            .find(|id| {
                matches!(
                    endpoint_id_from_device_id(*id),
                    Err(TransportError::InvalidDeviceId)
                )
            });
        assert!(invalid.is_some());
        Ok(())
    }

    #[tokio::test]
    async fn hint_peer_capacity_rejects_without_eviction_and_updates_at_capacity()
    -> Result<(), TransportError> {
        let endpoint = RiftEndpoint::bind(SecretKey::generate(), EndpointConfig::direct()).await?;
        {
            let mut ids = endpoint
                .hint_ids
                .lock()
                .map_err(|_| TransportError::HintRegistryPoisoned)?;
            for index in 0..MAX_PEER_HINTS {
                let mut bytes = [0; 32];
                bytes[..8].copy_from_slice(&(index as u64).to_le_bytes());
                ids.insert(DeviceId::from_bytes(bytes));
            }
        }
        let other = SecretKey::generate().public();
        let addr = EndpointAddr::from_parts(
            other,
            [TransportAddr::Ip(SocketAddr::from(([127, 0, 0, 1], 1234)))],
        );
        assert!(matches!(
            endpoint.remember_peer_addr(addr.clone()),
            Err(TransportError::HintCapacityExceeded)
        ));
        endpoint.forget_peer_addr(device_id_from_endpoint_id(other))?;
        {
            let mut ids = endpoint
                .hint_ids
                .lock()
                .map_err(|_| TransportError::HintRegistryPoisoned)?;
            ids.pop_first();
        }
        endpoint.remember_peer_addr(addr.clone())?;
        endpoint.remember_peer_addr(addr)?;
        assert!(endpoint.has_route_source(device_id_from_endpoint_id(other))?);
        endpoint.close().await;
        Ok(())
    }

    #[test]
    fn direct_configuration_has_no_relay_or_insecure_tls_setting() {
        let config = EndpointConfig::direct();
        assert_eq!(config.relay, RelayConfiguration::Disabled);
        assert!(matches!(
            config.address_lookup,
            AddressLookupConfiguration::Disabled
        ));
        assert_eq!(
            config.bind_addr,
            Some(SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0))
        );
        assert!(config.connection_timeout > Duration::ZERO);
        assert!(config.handshake_timeout > Duration::ZERO);
    }

    #[tokio::test]
    async fn endpoint_identity_derives_from_the_supplied_secret_key() -> Result<(), TransportError>
    {
        let secret_key = SecretKey::from_bytes(&[7_u8; 32]);
        let expected = DeviceId::from_bytes(*secret_key.public().as_bytes());
        let endpoint = RiftEndpoint::bind(secret_key, EndpointConfig::direct()).await?;
        assert_eq!(endpoint.device_id(), expected);
        assert!(!endpoint.is_closed());
        let debug = format!("{endpoint:?}");
        assert!(debug.contains(&expected.to_string()));
        assert!(!debug.contains("SecretKey"));
        endpoint.close().await;
        assert!(endpoint.is_closed());
        Ok(())
    }

    #[tokio::test]
    async fn zero_deadlines_are_rejected_before_binding() {
        let mut config = EndpointConfig::direct();
        config.connection_timeout = Duration::ZERO;
        let result = RiftEndpoint::bind(SecretKey::generate(), config).await;
        assert!(matches!(
            result,
            Err(TransportError::InvalidConfiguration(
                "connection_timeout must be greater than zero"
            ))
        ));
    }

    #[test]
    fn local_address_normalization_only_changes_unspecified_ip_addresses() {
        let direct = normalize_local_transport_address(TransportAddr::Ip(
            "0.0.0.0:1234"
                .parse()
                .unwrap_or_else(|_| SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 1234)),
        ));
        assert_eq!(
            direct,
            TransportAddr::Ip(
                "127.0.0.1:1234"
                    .parse()
                    .unwrap_or_else(|_| { SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 1234) })
            )
        );
    }
}
