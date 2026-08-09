//! Production Rift networking over authenticated Iroh QUIC.
//!
//! This crate owns endpoint configuration, Iroh connection and stream operations,
//! transport-authenticated identity conversion, and composition with the production
//! protocol bootstrap. It contains no pairing, authorization, trust persistence,
//! reconnect loop, or insecure relay TLS mode.

use std::{
    fmt,
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
    time::Duration,
};

use iroh::endpoint::{
    ConnectingError, Connection, ConnectionError, RecvStream, SendStream, presets,
};
use iroh::{Endpoint, RelayMode};
pub use iroh::{EndpointAddr, RelayUrl, SecretKey, TransportAddr};
use rift_core::DeviceId;
use rift_protocol::{
    ControlChannel, ControlError, HandshakeError, Hello, HelloMetadata, PROTOCOL_VERSION,
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

/// Small production endpoint configuration.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EndpointConfig {
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
    /// A post-bootstrap control operation exceeded its deadline.
    #[error("Rift control operation timed out")]
    ControlTimeout,
}

/// An Iroh endpoint configured for the production Rift ALPN.
#[derive(Clone)]
pub struct RiftEndpoint {
    endpoint: Endpoint,
    device_id: DeviceId,
    config: EndpointConfig,
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
        let mut builder = Endpoint::builder(presets::Minimal)
            .secret_key(secret_key)
            .alpns(vec![ALPN.to_vec()])
            .relay_mode(config.relay.as_iroh_mode());
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

    /// Connects to an authenticated Iroh peer using the production ALPN.
    pub async fn connect(
        &self,
        peer: EndpointAddr,
    ) -> Result<AuthenticatedConnection, TransportError> {
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
        Ok(BootstrappedConnection {
            connection: connection.connection,
            control,
            peer_hello,
            control_timeout: self.config.handshake_timeout,
        })
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

/// A successfully Hello-bootstrapped, still-disposable Rift connection.
pub struct BootstrappedConnection {
    connection: Connection,
    control: ControlStream,
    peer_hello: Hello,
    control_timeout: Duration,
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
    /// Returns the validated peer Hello metadata and identity.
    pub const fn peer_hello(&self) -> &Hello {
        &self.peer_hello
    }

    /// Returns the identity authenticated by Iroh and matched by Hello.
    pub const fn remote_device_id(&self) -> DeviceId {
        self.peer_hello.device_id
    }

    /// Sends a Ping and waits for the matching Pong before the control deadline.
    pub async fn ping(&mut self, nonce: u64) -> Result<(), TransportError> {
        time::timeout(
            self.control_timeout,
            rift_protocol::ping(&mut self.control, nonce),
        )
        .await
        .map_err(|_| TransportError::ControlTimeout)?
        .map_err(TransportError::Control)
    }

    /// Waits for one Ping and sends its matching Pong before the control deadline.
    pub async fn respond_to_ping(&mut self) -> Result<u64, TransportError> {
        time::timeout(
            self.control_timeout,
            rift_protocol::respond_to_ping(&mut self.control),
        )
        .await
        .map_err(|_| TransportError::ControlTimeout)?
        .map_err(TransportError::Control)
    }

    /// Closes this disposable QUIC connection immediately.
    pub fn close(&self) {
        self.connection
            .close(0_u32.into(), b"Rift connection closed");
    }
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
    fn direct_configuration_has_no_relay_or_insecure_tls_setting() {
        let config = EndpointConfig::direct();
        assert_eq!(config.relay, RelayConfiguration::Disabled);
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
        assert!(format!("{endpoint:?}").contains(&expected.to_string()));
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
