use std::{
    hint::black_box,
    path::{Path, PathBuf},
    process,
    str::FromStr,
    sync::Arc,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

use anyhow::{Context, Result, bail};
use clap::{Args, Parser, Subcommand, ValueEnum};
use iroh::{Endpoint, EndpointAddr, RelayUrl, endpoint::Incoming};
use rift_spike::{
    identity::NodeIdentity,
    network::{self, NetworkConfig, RelayModeConfig},
    protocol::{self, Capability, ControlChannel, ControlMessage, LocalHandshake},
    transfer,
};
use tokio::{
    fs,
    io::AsyncWriteExt,
    signal,
    sync::{mpsc, oneshot},
    task::JoinSet,
    time,
};
use tracing::{debug, info, warn};
use tracing_subscriber::{EnvFilter, fmt, prelude::*};

const CONNECTION_TIMEOUT: Duration = Duration::from_secs(15);
const CONTROL_TIMEOUT: Duration = Duration::from_secs(10);
const TRANSFER_TIMEOUT: Duration = Duration::from_secs(120);
const MAX_CONCURRENT_TRANSFERS: usize = 4;

#[derive(Debug, Parser)]
#[command(
    name = "rift-spike",
    about = "Rift vNext Iroh/QUIC networking prototype"
)]
struct Cli {
    #[arg(long, global = true, default_value = "rift_spike=info,iroh=info")]
    log: String,
    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Start a persistent node and accept control/data connections.
    Run(RunArgs),
    /// Connect, handshake, and stream one file to a running node.
    Send(SendArgs),
    /// Deliberately close and re-establish a control connection.
    ReconnectAfterClose(ReconnectAfterCloseArgs),
    /// Cut a live direct UDP path and observe relay recovery.
    FaultInject(FaultInjectArgs),
    /// Run the explicit protocol and localhost transfer baseline.
    Bench(BenchArgs),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, ValueEnum)]
enum RelayModeArg {
    Disabled,
    Default,
    Staging,
}

#[derive(Args, Clone, Debug)]
struct EndpointArgs {
    #[arg(long, default_value = ".rift-spike")]
    data_dir: PathBuf,
    #[arg(long, value_enum, default_value_t = RelayModeArg::Default)]
    relay_mode: RelayModeArg,
    /// Remove direct UDP transports so the experiment is relay-only.
    #[arg(long)]
    relay_only: bool,
    /// A custom relay URL, intended for the local `rift-relay` experiment.
    #[arg(long)]
    relay_url: Option<String>,
    /// Disable certificate verification for a self-signed local relay only.
    #[arg(long)]
    insecure_relay_tls: bool,
    #[arg(long, default_value = "rift-spike")]
    device_name: String,
    #[arg(long)]
    platform: Option<String>,
    #[arg(long, default_value_t = 15)]
    relay_timeout_secs: u64,
}

impl EndpointArgs {
    fn platform_name(&self) -> String {
        self.platform
            .clone()
            .unwrap_or_else(|| std::env::consts::OS.to_owned())
    }

    fn uses_relay(&self) -> bool {
        self.relay_url.is_some() || self.relay_mode != RelayModeArg::Disabled
    }

    fn network_config(&self) -> Result<NetworkConfig> {
        let relay_url = self
            .relay_url
            .as_deref()
            .map(|value| {
                RelayUrl::from_str(value)
                    .with_context(|| format!("invalid custom relay URL {value:?}"))
            })
            .transpose()?;
        Ok(NetworkConfig {
            relay_mode: match self.relay_mode {
                RelayModeArg::Disabled => RelayModeConfig::Disabled,
                RelayModeArg::Default => RelayModeConfig::Default,
                RelayModeArg::Staging => RelayModeConfig::Staging,
            },
            relay_only: self.relay_only,
            relay_url,
            insecure_relay_tls: self.insecure_relay_tls,
        })
    }
}

#[derive(Args, Debug)]
struct RunArgs {
    #[command(flatten)]
    endpoint: EndpointArgs,
    #[arg(long)]
    receive_dir: Option<PathBuf>,
}

#[derive(Args, Debug)]
struct SendArgs {
    #[command(flatten)]
    endpoint: EndpointArgs,
    /// A node ID or the JSON printed as `Peer address` by `run`.
    peer: String,
    file: PathBuf,
}

#[derive(Args, Debug)]
struct ReconnectAfterCloseArgs {
    #[command(flatten)]
    endpoint: EndpointArgs,
    /// A node ID or the JSON printed as `Peer address` by `run`.
    peer: String,
    #[arg(long, default_value_t = 4)]
    attempts: u32,
    #[arg(long, default_value_t = 1_000)]
    drop_after_ms: u64,
    #[arg(long, default_value_t = 1_000)]
    retry_delay_ms: u64,
}

#[derive(Args, Debug)]
struct FaultInjectArgs {
    #[command(flatten)]
    endpoint: EndpointArgs,
    /// A node ID or the JSON printed as `Peer address` by `run`.
    peer: String,
    #[arg(long, default_value_t = 1_000)]
    fault_after_ms: u64,
    #[arg(long, default_value_t = 30)]
    recovery_timeout_secs: u64,
}

#[derive(Args, Debug)]
struct BenchArgs {
    #[arg(long, default_value_t = 16 * 1024 * 1024)]
    bytes: u64,
    #[arg(long, default_value_t = 100_000)]
    protocol_iterations: u64,
}

struct ServerContext {
    identity: NodeIdentity,
    device_name: String,
    platform: String,
    receive_dir: PathBuf,
}

#[tokio::main]
async fn main() {
    if let Err(error) = run().await {
        eprintln!("error: {error:#}");
        process::exit(1);
    }
}

async fn run() -> Result<()> {
    let cli = Cli::parse();
    init_tracing(&cli.log)?;
    match cli.command {
        Command::Run(args) => run_node(args).await,
        Command::Send(args) => send_file(args).await,
        Command::ReconnectAfterClose(args) => reconnect_after_close(args).await,
        Command::FaultInject(args) => fault_inject(args).await,
        Command::Bench(args) => benchmark(args).await,
    }
}

fn init_tracing(filter: &str) -> Result<()> {
    let filter = EnvFilter::try_new(filter).context("invalid tracing filter")?;
    tracing_subscriber::registry()
        .with(fmt::layer().with_target(true))
        .with(filter)
        .try_init()
        .context("unable to initialize tracing")
}

async fn run_node(args: RunArgs) -> Result<()> {
    let identity = NodeIdentity::load_or_create(&args.endpoint.data_dir)
        .context("unable to load node identity")?;
    let endpoint = network::bind_endpoint(&identity, args.endpoint.network_config()?).await?;
    print_startup(&identity, &endpoint)?;

    if args.endpoint.uses_relay() {
        network::wait_for_relay(
            &endpoint,
            Duration::from_secs(args.endpoint.relay_timeout_secs),
        )
        .await;
        print_updated_peer_address(&endpoint)?;
    }

    let receive_dir = args
        .receive_dir
        .unwrap_or_else(|| args.endpoint.data_dir.join("received"));
    fs::create_dir_all(&receive_dir).await.with_context(|| {
        format!(
            "unable to create receive directory {}",
            receive_dir.display()
        )
    })?;
    let context = Arc::new(ServerContext {
        identity,
        device_name: args.endpoint.device_name.clone(),
        platform: args.endpoint.platform_name(),
        receive_dir,
    });

    info!(local_node_id = %context.identity.node_id(), "node listening for connections");
    let mut connections = JoinSet::new();
    let ctrl_c = signal::ctrl_c();
    tokio::pin!(ctrl_c);

    loop {
        tokio::select! {
            result = &mut ctrl_c => {
                result.context("unable to listen for Ctrl-C")?;
                info!(local_node_id = %context.identity.node_id(), "shutdown requested");
                break;
            }
            incoming = endpoint.accept() => {
                let Some(incoming) = incoming else {
                    break;
                };
                let context = Arc::clone(&context);
                connections.spawn(async move {
                    if let Err(error) = handle_connection(incoming, context).await {
                        warn!(error = ?error, "connection handler failed");
                    }
                });
            }
            result = connections.join_next(), if !connections.is_empty() => {
                if let Some(Err(error)) = result {
                    warn!(error = ?error, "connection task failed to join");
                }
            }
        }
    }

    endpoint.close().await;
    while let Some(result) = connections.join_next().await {
        if let Err(error) = result {
            warn!(error = ?error, "connection task failed during shutdown");
        }
    }
    Ok(())
}

fn print_startup(identity: &NodeIdentity, endpoint: &Endpoint) -> Result<()> {
    println!("Node ID: {}", identity.node_id());
    println!("Fingerprint: {}", identity.fingerprint());
    println!(
        "Peer address: {}",
        network::local_peer_descriptor(endpoint)?
    );
    println!("Identity file: {}", identity.storage_path().display());
    Ok(())
}

fn print_updated_peer_address(endpoint: &Endpoint) -> Result<()> {
    println!(
        "Peer address (after relay discovery): {}",
        network::local_peer_descriptor(endpoint)?
    );
    Ok(())
}

async fn handle_connection(incoming: Incoming, context: Arc<ServerContext>) -> Result<()> {
    let connection = time::timeout(CONNECTION_TIMEOUT, async { incoming.await })
        .await
        .context("incoming connection handshake timed out")?
        .context("incoming connection handshake failed")?;
    let remote_node_id = connection.remote_id();
    info!(
        local_node_id = %context.identity.node_id(),
        remote_node_id = %remote_node_id,
        "authenticated connection accepted"
    );
    network::log_connection_paths(&connection);
    let path_diagnostics = network::spawn_path_diagnostics(connection.clone());

    let (send, recv) = time::timeout(CONTROL_TIMEOUT, connection.accept_bi())
        .await
        .context("timed out waiting for control stream")?
        .context("unable to accept control stream")?;
    info!(
        local_node_id = %context.identity.node_id(),
        remote_node_id = %remote_node_id,
        "control stream created"
    );
    let mut control = ControlChannel { send, recv };
    let peer = time::timeout(
        CONTROL_TIMEOUT,
        protocol::exchange_handshake(
            &mut control,
            &local_handshake(&context),
            *remote_node_id.as_bytes(),
        ),
    )
    .await
    .context("control handshake timed out")?
    .context("control handshake failed")?;
    info!(
        local_node_id = %context.identity.node_id(),
        remote_node_id = %remote_node_id,
        peer_device_name = %peer.device_name,
        peer_platform = %peer.platform,
        peer_capabilities = ?peer.capabilities,
        "control handshake complete"
    );

    let ControlChannel { send, recv } = control;
    let mut control_send = send;
    let (control_tx, mut control_rx) = mpsc::channel(16);
    let control_reader = tokio::spawn(protocol::read_control_messages(recv, control_tx));
    let (transfer_result_tx, mut transfer_result_rx) =
        mpsc::channel::<Result<transfer::TransferResult>>(MAX_CONCURRENT_TRANSFERS);
    let mut transfer_tasks = JoinSet::new();

    loop {
        tokio::select! {
            close_reason = connection.closed() => {
                info!(
                    local_node_id = %context.identity.node_id(),
                    remote_node_id = %remote_node_id,
                    reason = ?close_reason,
                    "connection lost"
                );
                break;
            }
            message = control_rx.recv() => {
                match message {
                    Some(Ok(ControlMessage::Ping { nonce })) => {
                        let pong = ControlMessage::Pong { nonce };
                        debug!(message = ?pong, "control message sent");
                        protocol::write_value(&mut control_send, &pong)
                            .await
                            .context("unable to send ping response")?;
                    }
                    Some(Ok(ControlMessage::Pong { nonce })) => {
                        debug!(nonce, "unexpected pong received on server control stream");
                    }
                    Some(Ok(message)) => {
                        debug!(message = ?message, "unhandled control message received");
                    }
                    Some(Err(error)) => {
                        debug!(error = ?error, "control stream closed");
                        break;
                    }
                    None => {
                        debug!("control reader stopped");
                        break;
                    }
                }
            }
            result = transfer_result_rx.recv() => {
                match result {
                    Some(Ok(result)) => {
                        info!(
                            local_node_id = %context.identity.node_id(),
                            remote_node_id = %remote_node_id,
                            bytes = result.byte_len,
                            blake3 = %hex::encode(result.blake3),
                            output = %result.output_path.display(),
                            "binary transfer verified"
                        );
                        let ack = ControlMessage::TransferAck {
                            byte_len: result.byte_len,
                            blake3: result.blake3,
                        };
                        debug!(message = ?ack, "control message sent");
                        protocol::write_value(&mut control_send, &ack)
                            .await
                            .context("unable to send transfer acknowledgement")?;
                    }
                    Some(Err(error)) => {
                        warn!(
                            local_node_id = %context.identity.node_id(),
                            remote_node_id = %remote_node_id,
                            error = ?error,
                            "binary transfer failed"
                        );
                    }
                    None => {
                        debug!("transfer result channel closed");
                        break;
                    }
                }
            }
            result = transfer_tasks.join_next(), if !transfer_tasks.is_empty() => {
                if let Some(Err(error)) = result {
                    warn!(
                        local_node_id = %context.identity.node_id(),
                        remote_node_id = %remote_node_id,
                        error = ?error,
                        "binary transfer task failed to join"
                    );
                }
            }
            result = connection.accept_uni() => {
                let mut recv = result.context("unable to accept binary stream")?;
                info!(
                    local_node_id = %context.identity.node_id(),
                    remote_node_id = %remote_node_id,
                    "binary stream created"
                );
                if transfer_tasks.len() >= MAX_CONCURRENT_TRANSFERS {
                    warn!(
                        local_node_id = %context.identity.node_id(),
                        remote_node_id = %remote_node_id,
                        maximum = MAX_CONCURRENT_TRANSFERS,
                        "too many concurrent binary transfers"
                    );
                    if let Err(error) = recv.stop(0_u32.into()) {
                        debug!(error = ?error, "unable to stop excess binary stream");
                    }
                    continue;
                }

                let receive_dir = context.receive_dir.clone();
                let transfer_result_tx = transfer_result_tx.clone();
                transfer_tasks.spawn(async move {
                    let result = match time::timeout(
                        TRANSFER_TIMEOUT,
                        transfer::receive_file(&mut recv, &receive_dir),
                    )
                    .await
                    {
                        Ok(result) => result.map_err(anyhow::Error::from),
                        Err(_) => {
                            let _ = recv.stop(0_u32.into());
                            Err(anyhow::anyhow!(
                                "binary transfer timed out after {TRANSFER_TIMEOUT:?}"
                            ))
                        }
                    };
                    let _ = transfer_result_tx.send(result).await;
                });
            }
        }
    }

    transfer_tasks.abort_all();
    control_reader.abort();
    if let Err(error) = control_send.finish() {
        debug!(error = %error, "control stream was already closed");
    }
    path_diagnostics.abort();
    Ok(())
}

fn local_handshake(context: &ServerContext) -> LocalHandshake {
    LocalHandshake {
        node_id: context.identity.node_id_bytes(),
        device_name: context.device_name.clone(),
        platform: context.platform.clone(),
        capabilities: vec![Capability::BinaryBlobStream],
    }
}

async fn send_file(args: SendArgs) -> Result<()> {
    let identity = NodeIdentity::load_or_create(&args.endpoint.data_dir)
        .context("unable to load node identity")?;
    let metadata = transfer::metadata_for_file(&args.file)
        .await
        .with_context(|| format!("unable to inspect transfer file {}", args.file.display()))?;
    let peer = network::parse_peer_descriptor(&args.peer)?;
    let endpoint = network::bind_endpoint(&identity, args.endpoint.network_config()?).await?;
    print_startup(&identity, &endpoint)?;
    if args.endpoint.uses_relay() {
        network::wait_for_relay(
            &endpoint,
            Duration::from_secs(args.endpoint.relay_timeout_secs),
        )
        .await;
        print_updated_peer_address(&endpoint)?;
    }

    let connection = network::connect(&endpoint, peer.clone(), CONNECTION_TIMEOUT).await?;
    let path_diagnostics = network::spawn_path_diagnostics(connection.clone());
    let (send, recv) = time::timeout(CONTROL_TIMEOUT, connection.open_bi())
        .await
        .context("timed out opening control stream")?
        .context("unable to open control stream")?;
    info!(remote_node_id = %connection.remote_id(), "control stream created");
    let mut control = ControlChannel { send, recv };
    let peer_handshake = time::timeout(
        CONTROL_TIMEOUT,
        protocol::exchange_handshake(
            &mut control,
            &LocalHandshake {
                node_id: identity.node_id_bytes(),
                device_name: args.endpoint.device_name.clone(),
                platform: args.endpoint.platform_name(),
                capabilities: vec![Capability::BinaryBlobStream],
            },
            *peer.id.as_bytes(),
        ),
    )
    .await
    .context("control handshake timed out")?
    .context("control handshake failed")?;
    info!(
        remote_node_id = %connection.remote_id(),
        peer_device_name = %peer_handshake.device_name,
        peer_platform = %peer_handshake.platform,
        peer_capabilities = ?peer_handshake.capabilities,
        "control handshake complete"
    );
    if !peer_handshake
        .capabilities
        .contains(&Capability::BinaryBlobStream)
    {
        bail!("peer does not advertise the BinaryBlobStream capability");
    }

    let mut data_stream = time::timeout(CONTROL_TIMEOUT, connection.open_uni())
        .await
        .context("timed out opening binary stream")?
        .context("unable to open binary stream")?;
    info!(
        remote_node_id = %connection.remote_id(),
        file = %args.file.display(),
        expected_bytes = metadata.byte_len,
        expected_blake3 = %hex::encode(metadata.blake3),
        "binary stream created"
    );
    let bytes = time::timeout(
        TRANSFER_TIMEOUT,
        transfer::send_file(&mut data_stream, &args.file, &metadata),
    )
    .await
    .context("binary transfer timed out")??;
    info!(remote_node_id = %connection.remote_id(), bytes, "binary bytes transferred");

    let acknowledgement: ControlMessage =
        time::timeout(CONTROL_TIMEOUT, protocol::read_value(&mut control.recv))
            .await
            .context("timed out waiting for transfer acknowledgement")?
            .context("unable to read transfer acknowledgement")?;
    let ControlMessage::TransferAck { byte_len, blake3 } = acknowledgement else {
        bail!("expected TransferAck, received {acknowledgement:?}");
    };
    if byte_len != metadata.byte_len || blake3 != metadata.blake3 {
        bail!("receiver acknowledgement did not verify the expected length/hash");
    }
    info!(
        remote_node_id = %connection.remote_id(),
        bytes = byte_len,
        blake3 = %hex::encode(blake3),
        "receiver confirmed binary transfer"
    );

    if let Err(error) = control.send.finish() {
        debug!(error = %error, "control stream was already closed");
    }
    connection.close(0_u32.into(), b"transfer complete");
    endpoint.close().await;
    path_diagnostics.abort();
    Ok(())
}

async fn fault_inject(args: FaultInjectArgs) -> Result<()> {
    if args.recovery_timeout_secs == 0 {
        bail!("--recovery-timeout-secs must be greater than zero");
    }
    let identity = NodeIdentity::load_or_create(&args.endpoint.data_dir)
        .context("unable to load node identity")?;
    let peer = network::parse_peer_descriptor(&args.peer)?;
    if peer.relay_urls().next().is_none() {
        bail!("fault injection requires a peer descriptor with a relay address");
    }
    let direct_address = network::first_ip_address(&peer)?;
    let proxy = network::UdpFaultInjector::start(direct_address).await?;
    let fault_peer = network::peer_with_ip_proxy(&peer, proxy.address())?;
    let endpoint = network::bind_endpoint(&identity, args.endpoint.network_config()?).await?;
    print_startup(&identity, &endpoint)?;
    if !args.endpoint.uses_relay()
        || !network::wait_for_relay(
            &endpoint,
            Duration::from_secs(args.endpoint.relay_timeout_secs),
        )
        .await
    {
        bail!("fault injection requires an endpoint that is online via relay");
    }
    print_updated_peer_address(&endpoint)?;

    let (connection, mut control, diagnostics) =
        connect_and_handshake(&endpoint, &identity, &args.endpoint, &fault_peer).await?;
    network::wait_for_selected_path(&connection, false, CONNECTION_TIMEOUT)
        .await
        .context("fault-injection connection did not select the direct path")?;
    info!(
        remote_node_id = %connection.remote_id(),
        "fault-injection connection established over direct UDP path"
    );
    time::sleep(Duration::from_millis(args.fault_after_ms)).await;
    info!("cutting the direct UDP path while the connection is live");
    proxy.cut();
    endpoint.network_change().await;
    let recovery_timeout = Duration::from_secs(args.recovery_timeout_secs);
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |duration| duration.as_nanos() as u64);
    let ping = ControlMessage::Ping { nonce };
    protocol::write_value(&mut control.send, &ping)
        .await
        .context("unable to send post-recovery ping")?;
    let path_recovery = network::wait_for_selected_path(&connection, true, recovery_timeout);
    let pong = time::timeout(recovery_timeout, protocol::read_value(&mut control.recv));
    let (path_result, pong_result) = tokio::join!(path_recovery, pong);
    path_result.context("fault-injection connection did not recover over relay")?;
    let response: ControlMessage = pong_result
        .context("timed out waiting for post-recovery pong")?
        .context("unable to read post-recovery pong")?;
    let ControlMessage::Pong {
        nonce: response_nonce,
    } = response
    else {
        bail!("expected Pong after fault-injection recovery, received {response:?}");
    };
    if response_nonce != nonce {
        bail!("post-recovery pong nonce mismatch: expected {nonce}, received {response_nonce}");
    }
    info!(
        remote_node_id = %connection.remote_id(),
        nonce,
        "fault-injection connection remained usable after direct path loss"
    );
    if let Err(error) = control.send.finish() {
        debug!(error = %error, "control stream was already closed");
    }
    connection.close(0_u32.into(), b"fault-injection complete");
    diagnostics.abort();
    endpoint.close().await;
    Ok(())
}

async fn reconnect_after_close(args: ReconnectAfterCloseArgs) -> Result<()> {
    if args.attempts < 2 {
        bail!("--attempts must be at least 2 for a reconnect experiment");
    }
    let identity = NodeIdentity::load_or_create(&args.endpoint.data_dir)
        .context("unable to load node identity")?;
    let peer = network::parse_peer_descriptor(&args.peer)?;
    let endpoint = network::bind_endpoint(&identity, args.endpoint.network_config()?).await?;
    print_startup(&identity, &endpoint)?;
    if args.endpoint.uses_relay() {
        network::wait_for_relay(
            &endpoint,
            Duration::from_secs(args.endpoint.relay_timeout_secs),
        )
        .await;
        print_updated_peer_address(&endpoint)?;
    }

    let mut successful_connections = 0_u32;
    for attempt in 1..=args.attempts {
        info!(attempt, "reconnect attempt");
        match connect_and_handshake(&endpoint, &identity, &args.endpoint, &peer).await {
            Ok((connection, mut control, diagnostics)) => {
                successful_connections += 1;
                info!(
                    attempt,
                    remote_node_id = %connection.remote_id(),
                    "connection restored and control handshake usable"
                );
                if successful_connections == 1 {
                    info!(
                        drop_after_ms = args.drop_after_ms,
                        "simulating connectivity interruption"
                    );
                    time::sleep(Duration::from_millis(args.drop_after_ms)).await;
                    let closed = connection.closed();
                    connection.close(0_u32.into(), b"reconnect experiment interruption");
                    let reason = time::timeout(CONNECTION_TIMEOUT, closed)
                        .await
                        .context("timed out waiting for deliberate connection loss")?;
                    info!(remote_node_id = %connection.remote_id(), reason = ?reason, "connection lost");
                    if attempt < args.attempts {
                        time::sleep(Duration::from_millis(args.retry_delay_ms)).await;
                    }
                } else {
                    if let Err(error) = control.send.finish() {
                        debug!(error = %error, "control stream was already closed");
                    }
                    connection.close(0_u32.into(), b"reconnect experiment complete");
                    diagnostics.abort();
                    break;
                }
                if let Err(error) = control.send.finish() {
                    debug!(error = %error, "control stream was already closed");
                }
                diagnostics.abort();
            }
            Err(error) => {
                warn!(attempt, error = ?error, "connection attempt failed");
                if attempt < args.attempts {
                    time::sleep(Duration::from_millis(args.retry_delay_ms)).await;
                }
            }
        }
    }
    endpoint.close().await;
    if successful_connections < 2 {
        bail!("reconnect experiment did not establish two usable connections");
    }
    Ok(())
}

async fn connect_and_handshake(
    endpoint: &Endpoint,
    identity: &NodeIdentity,
    args: &EndpointArgs,
    peer: &EndpointAddr,
) -> Result<(
    iroh::endpoint::Connection,
    ControlChannel,
    network::PathDiagnostics,
)> {
    let connection = network::connect(endpoint, peer.clone(), CONNECTION_TIMEOUT).await?;
    let diagnostics = network::spawn_path_diagnostics(connection.clone());
    let (send, recv) = time::timeout(CONTROL_TIMEOUT, connection.open_bi())
        .await
        .context("timed out opening control stream")?
        .context("unable to open control stream")?;
    let mut control = ControlChannel { send, recv };
    time::timeout(
        CONTROL_TIMEOUT,
        protocol::exchange_handshake(
            &mut control,
            &LocalHandshake {
                node_id: identity.node_id_bytes(),
                device_name: args.device_name.clone(),
                platform: args.platform_name(),
                capabilities: vec![Capability::BinaryBlobStream],
            },
            *peer.id.as_bytes(),
        ),
    )
    .await
    .context("control handshake timed out")?
    .context("control handshake failed")?;
    Ok((connection, control, diagnostics))
}

async fn benchmark(args: BenchArgs) -> Result<()> {
    if args.bytes == 0 {
        bail!("--bytes must be greater than zero");
    }
    if args.protocol_iterations == 0 {
        bail!("--protocol-iterations must be greater than zero");
    }
    let protocol_result = benchmark_protocol(args.protocol_iterations)?;
    let transfer_result = benchmark_local_transfer(args.bytes).await?;
    println!(
        "protocol.encode_decode.ops_per_second={:.2}",
        protocol_result
    );
    println!(
        "transfer.localhost.mib_per_second={:.2}",
        transfer_result.mib_per_second
    );
    println!(
        "transfer.localhost.seconds={:.6}",
        transfer_result.elapsed.as_secs_f64()
    );
    println!("transfer.localhost.bytes={}", transfer_result.bytes);
    println!(
        "transfer.streaming_buffer_bytes={}",
        transfer::STREAM_BUFFER_SIZE
    );
    Ok(())
}

fn benchmark_protocol(iterations: u64) -> Result<f64> {
    let message = ControlMessage::DeviceMetadata {
        device_name: "benchmark-node".to_owned(),
        platform: "benchmark".to_owned(),
    };
    let start = Instant::now();
    for _ in 0..iterations {
        let encoded = protocol::encode_message(black_box(&message))?;
        let decoded = protocol::decode_message(black_box(&encoded))?;
        black_box(decoded);
    }
    let seconds = start.elapsed().as_secs_f64();
    Ok(iterations as f64 / seconds.max(f64::MIN_POSITIVE))
}

struct TransferBenchmarkResult {
    bytes: u64,
    elapsed: Duration,
    mib_per_second: f64,
}

async fn benchmark_local_transfer(bytes: u64) -> Result<TransferBenchmarkResult> {
    let root = benchmark_directory();
    let receive_dir = root.join("received");
    fs::create_dir_all(&root).await?;
    let source_path = root.join("benchmark.bin");
    create_benchmark_file(&source_path, bytes).await?;
    let metadata = transfer::metadata_for_file(&source_path).await?;

    let sender_identity = NodeIdentity::ephemeral();
    let receiver_identity = NodeIdentity::ephemeral();
    let sender = network::bind_endpoint(
        &sender_identity,
        NetworkConfig {
            relay_mode: RelayModeConfig::Disabled,
            relay_only: false,
            relay_url: None,
            insecure_relay_tls: false,
        },
    )
    .await?;
    let receiver = network::bind_endpoint(
        &receiver_identity,
        NetworkConfig {
            relay_mode: RelayModeConfig::Disabled,
            relay_only: false,
            relay_url: None,
            insecure_relay_tls: false,
        },
    )
    .await?;
    let receiver_addr = network::local_endpoint_addr(&receiver);
    let (done_tx, done_rx) = oneshot::channel();
    let receiver_task = tokio::spawn(async move {
        let incoming = receiver
            .accept()
            .await
            .context("benchmark receiver did not receive a connection")?;
        let connection = incoming
            .await
            .context("benchmark receiver handshake failed")?;
        let (send, recv) = connection.accept_bi().await?;
        let mut control = ControlChannel { send, recv };
        time::timeout(
            CONTROL_TIMEOUT,
            protocol::exchange_handshake(
                &mut control,
                &LocalHandshake {
                    node_id: receiver_identity.node_id_bytes(),
                    device_name: "benchmark-receiver".to_owned(),
                    platform: "benchmark".to_owned(),
                    capabilities: vec![Capability::BinaryBlobStream],
                },
                *connection.remote_id().as_bytes(),
            ),
        )
        .await
        .context("benchmark receiver control handshake timed out")??;
        let mut data = connection.accept_uni().await?;
        let result = transfer::receive_file(&mut data, &receive_dir).await?;
        let ack = ControlMessage::TransferAck {
            byte_len: result.byte_len,
            blake3: result.blake3,
        };
        protocol::write_value(&mut control.send, &ack).await?;
        done_rx
            .await
            .map_err(|_| anyhow::anyhow!("benchmark sender dropped completion signal"))?;
        connection.close(0_u32.into(), b"benchmark complete");
        receiver.close().await;
        Ok::<transfer::TransferResult, anyhow::Error>(result)
    });

    let connection = network::connect(&sender, receiver_addr.clone(), CONNECTION_TIMEOUT).await?;
    let (send, recv) = connection.open_bi().await?;
    let mut control = ControlChannel { send, recv };
    time::timeout(
        CONTROL_TIMEOUT,
        protocol::exchange_handshake(
            &mut control,
            &LocalHandshake {
                node_id: sender_identity.node_id_bytes(),
                device_name: "benchmark-sender".to_owned(),
                platform: "benchmark".to_owned(),
                capabilities: vec![Capability::BinaryBlobStream],
            },
            *receiver_addr.id.as_bytes(),
        ),
    )
    .await
    .context("benchmark sender control handshake timed out")??;
    let mut data = connection.open_uni().await?;
    let start = Instant::now();
    transfer::send_file(&mut data, &source_path, &metadata).await?;
    let ack: ControlMessage = protocol::read_value(&mut control.recv).await?;
    let elapsed = start.elapsed();
    let ControlMessage::TransferAck { byte_len, blake3 } = ack else {
        bail!("benchmark receiver returned an unexpected control message");
    };
    if byte_len != metadata.byte_len || blake3 != metadata.blake3 {
        bail!("benchmark receiver returned an invalid transfer acknowledgement");
    }
    done_tx
        .send(())
        .map_err(|_| anyhow::anyhow!("benchmark receiver dropped completion signal"))?;
    let received = receiver_task.await??;
    sender.close().await;
    let mib_per_second =
        bytes as f64 / elapsed.as_secs_f64().max(f64::MIN_POSITIVE) / (1024.0 * 1024.0);
    let result = TransferBenchmarkResult {
        bytes: received.byte_len,
        elapsed,
        mib_per_second,
    };
    fs::remove_dir_all(&root).await?;
    Ok(result)
}

async fn create_benchmark_file(path: &Path, bytes: u64) -> Result<()> {
    let mut file = fs::File::create(path).await?;
    let mut buffer = vec![0_u8; transfer::STREAM_BUFFER_SIZE];
    for (index, byte) in buffer.iter_mut().enumerate() {
        *byte = (index % 251) as u8;
    }
    let mut remaining = bytes;
    while remaining > 0 {
        let count = remaining.min(buffer.len() as u64) as usize;
        file.write_all(&buffer[..count]).await?;
        remaining -= count as u64;
    }
    file.flush().await?;
    Ok(())
}

fn benchmark_directory() -> PathBuf {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |duration| duration.as_nanos());
    std::env::temp_dir().join(format!("rift-spike-benchmark-{}-{nanos}", process::id()))
}

#[cfg(test)]
mod tests {
    use anyhow::{Context, Result};
    use tokio::time;

    use super::*;

    const TEST_TIMEOUT: Duration = Duration::from_secs(15);

    async fn wait_for_staged_transfer(receive_dir: &Path, file_name: &str) -> Result<()> {
        let prefix = format!(".{file_name}.");
        time::timeout(TEST_TIMEOUT, async {
            loop {
                let mut entries = fs::read_dir(receive_dir).await?;
                while let Some(entry) = entries.next_entry().await? {
                    let name = entry.file_name();
                    let name = name.to_string_lossy();
                    if name.starts_with(&prefix) && name.ends_with(".part") {
                        return Ok::<(), anyhow::Error>(());
                    }
                }
                time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .context("timed out waiting for transfer to stage its output")??;
        Ok(())
    }

    #[tokio::test]
    async fn control_frame_survives_concurrent_unidirectional_stream() -> Result<()> {
        time::timeout(TEST_TIMEOUT, async {
            let sender_identity = NodeIdentity::ephemeral();
            let receiver_identity = NodeIdentity::ephemeral();
            let sender = network::bind_endpoint(
                &sender_identity,
                NetworkConfig {
                    relay_mode: RelayModeConfig::Disabled,
                    relay_only: false,
                    relay_url: None,
                    insecure_relay_tls: false,
                },
            )
            .await?;
            let receiver = network::bind_endpoint(
                &receiver_identity,
                NetworkConfig {
                    relay_mode: RelayModeConfig::Disabled,
                    relay_only: false,
                    relay_url: None,
                    insecure_relay_tls: false,
                },
            )
            .await?;
            let receive_dir = tempfile::tempdir()?;
            let source_dir = tempfile::tempdir()?;
            let source_path = source_dir.path().join("concurrent.bin");
            let payload = b"concurrent transfer payload".repeat(128);
            fs::write(&source_path, &payload).await?;
            let metadata = transfer::metadata_for_file(&source_path).await?;
            let independent_path = source_dir.path().join("independent.bin");
            let independent_payload = b"independent transfer payload".repeat(64);
            fs::write(&independent_path, &independent_payload).await?;
            let independent_metadata = transfer::metadata_for_file(&independent_path).await?;
            let stalled_path = source_dir.path().join("stalled.bin");
            let stalled_payload = vec![0x5a; 64 * 1024];
            fs::write(&stalled_path, &stalled_payload).await?;
            let stalled_metadata = transfer::metadata_for_file(&stalled_path).await?;
            let context = Arc::new(ServerContext {
                identity: receiver_identity.clone(),
                device_name: "receiver".to_owned(),
                platform: "test".to_owned(),
                receive_dir: receive_dir.path().to_owned(),
            });
            let receiver_for_server = receiver.clone();
            let server_task = tokio::spawn(async move {
                let incoming = receiver_for_server
                    .accept()
                    .await
                    .context("receiver endpoint closed before accepting")?;
                handle_connection(incoming, context).await
            });

            let receiver_address = network::local_endpoint_addr(&receiver);
            let connection =
                network::connect(&sender, receiver_address.clone(), TEST_TIMEOUT).await?;
            let (send, recv) = connection.open_bi().await?;
            let mut control = ControlChannel { send, recv };
            protocol::exchange_handshake(
                &mut control,
                &LocalHandshake {
                    node_id: sender_identity.node_id_bytes(),
                    device_name: "sender".to_owned(),
                    platform: "test".to_owned(),
                    capabilities: vec![Capability::BinaryBlobStream],
                },
                *receiver_address.id.as_bytes(),
            )
            .await?;
            let ControlChannel {
                send: mut control_send,
                recv: mut control_recv,
            } = control;

            let partial_message = ControlMessage::DeviceMetadata {
                device_name: "x".repeat(128 * 1024),
                platform: "test".to_owned(),
            };
            let frame = protocol::encode_message(&partial_message)?;
            let split_at = 4 + 1024;
            assert!(frame.len() > split_at);
            control_send.write_all(&frame[..split_at]).await?;
            time::sleep(Duration::from_millis(100)).await;

            let mut data_stream = connection.open_uni().await?;
            transfer::send_file(&mut data_stream, &source_path, &metadata).await?;
            let acknowledgement: ControlMessage =
                time::timeout(TEST_TIMEOUT, protocol::read_value(&mut control_recv))
                    .await
                    .context("timed out waiting for transfer acknowledgement")??;
            assert_eq!(
                acknowledgement,
                ControlMessage::TransferAck {
                    byte_len: metadata.byte_len,
                    blake3: metadata.blake3,
                }
            );

            control_send.write_all(&frame[split_at..]).await?;
            let nonce = 41;
            protocol::write_value(&mut control_send, &ControlMessage::Ping { nonce }).await?;
            let response: ControlMessage =
                time::timeout(TEST_TIMEOUT, protocol::read_value(&mut control_recv))
                    .await
                    .context("timed out waiting for pong")??;
            assert_eq!(response, ControlMessage::Pong { nonce });

            let mut stalled_stream = connection.open_uni().await?;
            protocol::write_value(&mut stalled_stream, &stalled_metadata).await?;
            stalled_stream.write_all(&stalled_payload[..1024]).await?;
            wait_for_staged_transfer(receive_dir.path(), "stalled.bin").await?;
            let stalled_nonce = 42;
            protocol::write_value(
                &mut control_send,
                &ControlMessage::Ping {
                    nonce: stalled_nonce,
                },
            )
            .await?;
            let stalled_response: ControlMessage =
                time::timeout(TEST_TIMEOUT, protocol::read_value(&mut control_recv))
                    .await
                    .context("timed out waiting for pong while transfer stalled")??;
            assert_eq!(
                stalled_response,
                ControlMessage::Pong {
                    nonce: stalled_nonce,
                }
            );

            let mut independent_stream = connection.open_uni().await?;
            transfer::send_file(
                &mut independent_stream,
                &independent_path,
                &independent_metadata,
            )
            .await?;
            let independent_ack: ControlMessage =
                time::timeout(TEST_TIMEOUT, protocol::read_value(&mut control_recv))
                    .await
                    .context("timed out waiting for independent transfer acknowledgement")??;
            assert_eq!(
                independent_ack,
                ControlMessage::TransferAck {
                    byte_len: independent_metadata.byte_len,
                    blake3: independent_metadata.blake3,
                }
            );
            stalled_stream
                .finish()
                .map_err(|error| anyhow::anyhow!(error.to_string()))?;

            control_send
                .finish()
                .map_err(|error| anyhow::anyhow!(error.to_string()))?;
            let server_result = time::timeout(TEST_TIMEOUT, server_task)
                .await
                .context("server task did not finish")?
                .context("server task failed to join")?;
            server_result?;
            connection.close(0_u32.into(), b"test complete");
            sender.close().await;
            receiver.close().await;
            Ok::<(), anyhow::Error>(())
        })
        .await
        .context("concurrent control/data scenario timed out")??;
        Ok(())
    }
}
