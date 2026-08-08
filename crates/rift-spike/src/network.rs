//! Iroh endpoint setup, peer-address exchange, and transport diagnostics.

use std::{
    io,
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
    str::FromStr,
    time::Duration,
};

use anyhow::{Context, Result, bail};
use futures_util::StreamExt;
use iroh::{
    Endpoint, EndpointAddr, EndpointId, RelayMode, RelayUrl, TransportAddr,
    endpoint::{Connection, PathEvent, QuicTransportConfig, presets},
};
use serde::{Deserialize, Serialize};
use tokio::{
    net::UdpSocket,
    sync::oneshot,
    task::JoinHandle,
    time::{self, error::Elapsed},
};
use tracing::{debug, info, warn};

use crate::identity::NodeIdentity;

pub const ALPN: &[u8] = b"rift-next-spike/0";

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RelayModeConfig {
    Disabled,
    Default,
    Staging,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NetworkConfig {
    pub relay_mode: RelayModeConfig,
    pub relay_only: bool,
    pub relay_url: Option<RelayUrl>,
    pub insecure_relay_tls: bool,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct PeerDescriptor {
    pub node_id: String,
    pub addresses: Vec<String>,
}

pub async fn bind_endpoint(identity: &NodeIdentity, config: NetworkConfig) -> Result<Endpoint> {
    bind_endpoint_with_transport(identity, config, None).await
}

pub async fn bind_endpoint_with_transport(
    identity: &NodeIdentity,
    config: NetworkConfig,
    transport_config: Option<QuicTransportConfig>,
) -> Result<Endpoint> {
    if config.insecure_relay_tls && config.relay_url.is_none() {
        bail!("insecure relay TLS requires --relay-url");
    }
    if config.relay_only
        && config.relay_mode == RelayModeConfig::Disabled
        && config.relay_url.is_none()
    {
        bail!("--relay-only requires a relay mode other than disabled or a custom relay URL");
    }

    let relay_mode = if let Some(relay_url) = config.relay_url.clone() {
        RelayMode::custom([relay_url])
    } else {
        match config.relay_mode {
            RelayModeConfig::Disabled => RelayMode::Disabled,
            RelayModeConfig::Default => RelayMode::Default,
            RelayModeConfig::Staging => RelayMode::Staging,
        }
    };
    let mut builder = Endpoint::builder(presets::Minimal)
        .secret_key(identity.secret_key().clone())
        .alpns(vec![ALPN.to_vec()])
        .relay_mode(relay_mode);
    if config.relay_only {
        builder = builder
            .clear_ip_transports()
            .addr_filter(iroh::address_lookup::AddrFilter::relay_only());
    }
    if config.insecure_relay_tls {
        builder = builder.ca_tls_config(iroh_relay::tls::CaTlsConfig::insecure_skip_verify());
    }
    if let Some(transport_config) = transport_config {
        builder = builder.transport_config(transport_config);
    }

    builder.bind().await.context("unable to bind Iroh endpoint")
}

pub async fn wait_for_relay(endpoint: &Endpoint, timeout: Duration) -> bool {
    match time::timeout(timeout, endpoint.online()).await {
        Ok(()) => {
            info!(endpoint_addr = ?endpoint.addr(), "Iroh endpoint is online via relay");
            true
        }
        Err(Elapsed { .. }) => {
            warn!(?timeout, endpoint_addr = ?endpoint.addr(), "relay did not become online before timeout");
            false
        }
    }
}

pub async fn connect(
    endpoint: &Endpoint,
    peer: EndpointAddr,
    timeout: Duration,
) -> Result<Connection> {
    info!(
        local_node_id = %endpoint.id(),
        remote_node_id = %peer.id,
        remote_addresses = ?peer.addrs,
        "connection attempt"
    );
    let connection = time::timeout(timeout, endpoint.connect(peer.clone(), ALPN))
        .await
        .with_context(|| format!("connection to peer {} timed out", peer.id))?
        .with_context(|| format!("unable to connect to peer {}", peer.id))?;
    info!(
        local_node_id = %endpoint.id(),
        remote_node_id = %connection.remote_id(),
        "connection established"
    );
    log_connection_paths(&connection);
    Ok(connection)
}

pub struct UdpFaultInjector {
    address: SocketAddr,
    stop: Option<oneshot::Sender<()>>,
    task: JoinHandle<io::Result<()>>,
}

impl UdpFaultInjector {
    pub async fn start(target: SocketAddr) -> Result<Self> {
        let socket = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).await?;
        let address = socket.local_addr()?;
        let (stop_tx, mut stop_rx) = oneshot::channel();
        let task = tokio::spawn(async move {
            let mut buffer = [0_u8; 65_536];
            let mut client = None;
            loop {
                tokio::select! {
                    _ = &mut stop_rx => break,
                    result = socket.recv_from(&mut buffer) => {
                        let (length, source) = result?;
                        if source == target {
                            if let Some(client) = client {
                                socket.send_to(&buffer[..length], client).await?;
                            }
                        } else {
                            client = Some(source);
                            socket.send_to(&buffer[..length], target).await?;
                        }
                    }
                }
            }
            Ok(())
        });
        Ok(Self {
            address,
            stop: Some(stop_tx),
            task,
        })
    }

    pub fn address(&self) -> SocketAddr {
        self.address
    }

    pub fn cut(mut self) {
        drop(self.stop.take());
        self.task.abort();
    }
}

impl Drop for UdpFaultInjector {
    fn drop(&mut self) {
        self.task.abort();
    }
}

pub async fn wait_for_selected_path(
    connection: &Connection,
    relay: bool,
    timeout: Duration,
) -> Result<()> {
    let mut events = connection.path_events();
    time::timeout(timeout, async {
        loop {
            if connection
                .paths()
                .iter()
                .any(|path| path.is_selected() && path.is_relay() == relay)
            {
                return Ok::<(), anyhow::Error>(());
            }
            events
                .next()
                .await
                .ok_or_else(|| anyhow::anyhow!("connection path events ended"))?;
        }
    })
    .await
    .context("timed out waiting for selected connection path")??;
    Ok(())
}

pub fn local_endpoint_addr(endpoint: &Endpoint) -> EndpointAddr {
    let mut address = endpoint.addr();
    for bound_socket in endpoint.bound_sockets() {
        let loopback = match bound_socket.ip() {
            IpAddr::V4(_) => IpAddr::V4(Ipv4Addr::LOCALHOST),
            IpAddr::V6(_) => IpAddr::V6(Ipv6Addr::LOCALHOST),
        };
        address = address.with_ip_addr(SocketAddr::new(loopback, bound_socket.port()));
    }
    address
}

pub fn local_peer_descriptor(endpoint: &Endpoint) -> Result<String> {
    peer_descriptor(&local_endpoint_addr(endpoint))
}

pub fn peer_descriptor(address: &EndpointAddr) -> Result<String> {
    let descriptor = PeerDescriptor {
        node_id: address.id.to_string(),
        addresses: address.addrs.iter().map(ToString::to_string).collect(),
    };
    serde_json::to_string(&descriptor).context("unable to encode peer descriptor")
}

pub fn first_ip_address(address: &EndpointAddr) -> Result<SocketAddr> {
    address
        .addrs
        .iter()
        .find_map(|address| match address {
            TransportAddr::Ip(address) => Some(*address),
            _ => None,
        })
        .context("peer descriptor does not contain a direct IP address")
}

pub fn peer_with_ip_proxy(address: &EndpointAddr, proxy: SocketAddr) -> Result<EndpointAddr> {
    if !address.addrs.iter().any(TransportAddr::is_ip) {
        bail!("peer descriptor does not contain a direct IP address");
    }
    let addresses = address
        .addrs
        .iter()
        .filter(|address| !address.is_ip())
        .cloned()
        .chain(std::iter::once(TransportAddr::Ip(proxy)));
    Ok(EndpointAddr::from_parts(address.id, addresses))
}

pub fn parse_peer_descriptor(input: &str) -> Result<EndpointAddr> {
    let input = input.trim();
    if input.is_empty() {
        bail!("peer identifier is empty");
    }

    if input.starts_with('{') {
        let descriptor: PeerDescriptor =
            serde_json::from_str(input).context("invalid JSON peer descriptor")?;
        let id = EndpointId::from_str(&descriptor.node_id)
            .with_context(|| format!("invalid peer node ID {:?}", descriptor.node_id))?;
        let mut addresses = Vec::with_capacity(descriptor.addresses.len());
        for address in descriptor.addresses {
            addresses.push(parse_transport_address(&address)?);
        }
        return Ok(EndpointAddr::from_parts(id, addresses));
    }

    let id = EndpointId::from_str(input)
        .with_context(|| format!("invalid peer node ID {input:?}; pass the full JSON peer descriptor when addresses are needed"))?;
    Ok(EndpointAddr::new(id))
}

fn parse_transport_address(input: &str) -> Result<TransportAddr> {
    if let Some(relay) = input.strip_prefix("relay:") {
        return Ok(TransportAddr::Relay(
            RelayUrl::from_str(relay).with_context(|| format!("invalid relay URL {relay:?}"))?,
        ));
    }
    if let Some(ip) = input.strip_prefix("ip:") {
        return Ok(TransportAddr::Ip(SocketAddr::from_str(ip).with_context(
            || format!("invalid direct socket address {ip:?}"),
        )?));
    }
    bail!("unsupported peer transport address {input:?}; expected relay: or ip:")
}

pub fn log_connection_paths(connection: &Connection) {
    let paths = connection.paths();
    if paths.is_empty() {
        warn!(remote_node_id = %connection.remote_id(), "connection has no currently open paths");
        return;
    }
    for path in paths.iter() {
        let kind = if path.is_relay() {
            "relay"
        } else if path.is_ip() {
            "direct"
        } else {
            "custom"
        };
        info!(
            remote_node_id = %connection.remote_id(),
            path_id = ?path.id(),
            selected = path.is_selected(),
            path_kind = kind,
            remote_addr = %path.remote_addr(),
            local_addr = ?path.local_addr(),
            rtt = ?path.rtt(),
            "connection path"
        );
    }
}

pub struct PathDiagnostics {
    task: JoinHandle<()>,
}

impl PathDiagnostics {
    pub fn abort(&self) {
        self.task.abort();
    }
}

impl Drop for PathDiagnostics {
    fn drop(&mut self) {
        self.task.abort();
    }
}

pub fn spawn_path_diagnostics(connection: Connection) -> PathDiagnostics {
    PathDiagnostics {
        task: tokio::spawn(async move {
            let remote_node_id = connection.remote_id();
            let mut events = connection.path_events();
            while let Some(event) = events.next().await {
                match event {
                    PathEvent::Opened {
                        id,
                        remote_addr,
                        local_addr,
                        ..
                    } => {
                        debug!(
                            %remote_node_id,
                            path_id = ?id,
                            path_kind = transport_kind(&remote_addr),
                            remote_addr = %remote_addr,
                            local_addr = ?local_addr,
                            "connection path opened"
                        );
                    }
                    PathEvent::Closed {
                        id,
                        remote_addr,
                        local_addr,
                        last_stats,
                        ..
                    } => {
                        info!(
                            %remote_node_id,
                            path_id = ?id,
                            path_kind = transport_kind(&remote_addr),
                            remote_addr = %remote_addr,
                            local_addr = ?local_addr,
                            stats = ?last_stats,
                            "connection path closed"
                        );
                    }
                    PathEvent::Selected {
                        id,
                        remote_addr,
                        local_addr,
                        ..
                    } => {
                        info!(
                            %remote_node_id,
                            path_id = ?id,
                            path_kind = transport_kind(&remote_addr),
                            remote_addr = %remote_addr,
                            local_addr = ?local_addr,
                            "connection path selected"
                        );
                    }
                    PathEvent::Lagged { missed, .. } => {
                        warn!(%remote_node_id, missed, "connection path diagnostics lagged");
                    }
                    _ => {
                        warn!(%remote_node_id, "unknown connection path event");
                    }
                }
            }
            debug!(%remote_node_id, "connection path diagnostics stopped");
        }),
    }
}

fn transport_kind(address: &TransportAddr) -> &'static str {
    if address.is_relay() {
        "relay"
    } else if address.is_ip() {
        "direct"
    } else {
        "custom"
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use iroh::SecretKey;

    #[test]
    fn peer_descriptor_round_trips_direct_and_relay_addresses() -> Result<()> {
        let id = SecretKey::generate().public();
        let relay = RelayUrl::from_str("https://relay.example.test")?;
        let address = EndpointAddr::new(id)
            .with_relay_url(relay)
            .with_ip_addr("127.0.0.1:12345".parse()?);
        let encoded = peer_descriptor(&address)?;
        let decoded = parse_peer_descriptor(&encoded)?;
        assert_eq!(decoded, address);
        Ok(())
    }

    #[test]
    fn a_node_id_without_addresses_is_a_valid_lookup_target() -> Result<()> {
        let id = SecretKey::generate().public();
        let decoded = parse_peer_descriptor(&id.to_string())?;
        assert_eq!(decoded, EndpointAddr::new(id));
        Ok(())
    }

    #[test]
    fn invalid_peer_identifiers_are_reported() {
        assert!(parse_peer_descriptor("not-a-node-id").is_err());
        assert!(parse_peer_descriptor("{").is_err());
    }
}
