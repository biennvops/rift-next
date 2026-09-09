//! Resident Rift daemon runtime.
//!
//! One `Daemon` exclusively owns one data directory, persistent Iroh identity, trust
//! journal, endpoint, pending pairing registry, authorized session registry, local IPC
//! listener, and every asynchronous child task.

mod ipc_server;
mod local;

use std::{
    collections::BTreeMap,
    fmt, io,
    net::SocketAddr,
    path::{Path, PathBuf},
    sync::Arc,
    time::Duration,
};

use rift_core::{DeviceId, TrustState};
use rift_identity::{IdentityError, IdentityStore};
use rift_ipc::{
    ErrorCode, ErrorResponse, Event, MAX_PEER_PAGE_SIZE, PairingAttemptId, PairingOutcome,
    PeerInfo, PeerPage, PendingPairingInfo, RUNTIME_DESCRIPTOR_VERSION, Request, Response,
    RuntimeDescriptor, RuntimeState, SessionCloseReason, SessionId, SessionInfo, Status,
};
use rift_session::{
    AuthorizedConnection, ConnectionPurpose, PairingError, PendingPairing, SessionAdmission,
    SessionConfig, SessionError, SessionManager, pairing_metadata,
};
use rift_transport_iroh::{
    AddressLookupConfiguration, DEFAULT_CONNECTION_TIMEOUT, DEFAULT_HANDSHAKE_TIMEOUT,
    DisposableConnectionHandle, EndpointAddr, EndpointConfig, RelayConfiguration, RiftEndpoint,
    TransportError,
};
use rift_trust::{TrustEntry, TrustStore, TrustStoreError};
use thiserror::Error;
use tokio::sync::{OwnedSemaphorePermit, Semaphore, broadcast, mpsc, oneshot, watch};
use tracing::{debug, info, warn};

use local::{IDENTITY_FILE_NAME, LocalListener, RuntimeArtifacts, RuntimeLock, TRUST_FILE_NAME};

/// Default concurrent incoming bootstrap bound.
pub const DEFAULT_MAX_INFLIGHT_CONNECTIONS: usize = 32;
/// Default active authorized-session bound.
pub const DEFAULT_MAX_ACTIVE_SESSIONS: usize = 64;
/// Default per-peer active-session bound.
pub const DEFAULT_MAX_SESSIONS_PER_PEER: usize = 4;
/// Default pending pairing-confirmation bound.
pub const DEFAULT_MAX_PENDING_PAIRINGS: usize = 8;
/// Default authenticated local IPC client bound.
pub const DEFAULT_MAX_IPC_CLIENTS: usize = 8;
/// Default graceful shutdown deadline.
pub const DEFAULT_SHUTDOWN_TIMEOUT: Duration = Duration::from_secs(10);

const HARD_MAX_INFLIGHT_CONNECTIONS: usize = 256;
const HARD_MAX_ACTIVE_SESSIONS: usize = 128;
const HARD_MAX_SESSIONS_PER_PEER: usize = 16;
const HARD_MAX_PENDING_PAIRINGS: usize = 64;
const HARD_MAX_IPC_CLIENTS: usize = 64;
const COMMAND_QUEUE_CAPACITY: usize = 256;
const EVENT_QUEUE_CAPACITY: usize = 64;
const PAIRING_COMMAND_CAPACITY: usize = 2;
const ERROR_MESSAGE_MAX_BYTES: usize = 512;

/// Concrete resident-daemon configuration.
#[derive(Clone, Debug)]
pub struct DaemonConfig {
    /// Explicit data directory exclusively owned by this daemon instance.
    pub data_dir: PathBuf,
    /// Local bounded display name advertised in Hello and status.
    pub device_name: String,
    /// Local bounded platform value advertised in Hello and status.
    pub platform: String,
    /// Production relay behavior.
    pub relay: RelayConfiguration,
    /// External known-peer lookup, independent from relay routing.
    pub address_lookup: AddressLookupConfiguration,
    /// Optional explicit Iroh bind address, primarily for deterministic local tests.
    pub bind_addr: Option<SocketAddr>,
    /// Iroh connect/accept deadline.
    pub connection_timeout: Duration,
    /// Hello/control deadline.
    pub handshake_timeout: Duration,
    /// Pairing phase and local-confirmation deadline.
    pub pairing_timeout: Duration,
    /// Maximum concurrent incoming bootstrap/pairing setup tasks.
    pub max_inflight_connections: usize,
    /// Maximum active authorized sessions.
    pub max_active_sessions: usize,
    /// Maximum active authorized sessions for one peer identity.
    pub max_sessions_per_peer: usize,
    /// Maximum pending local pairing confirmations.
    pub max_pending_pairings: usize,
    /// Maximum concurrent local IPC clients.
    pub max_ipc_clients: usize,
    /// Deadline for joining every owned child task during shutdown.
    pub shutdown_timeout: Duration,
}

impl DaemonConfig {
    /// Builds the default bounded configuration for one explicit data directory.
    pub fn new(data_dir: impl Into<PathBuf>, device_name: impl Into<String>) -> Self {
        Self {
            data_dir: data_dir.into(),
            device_name: device_name.into(),
            platform: std::env::consts::OS.to_owned(),
            relay: RelayConfiguration::Disabled,
            address_lookup: AddressLookupConfiguration::Disabled,
            bind_addr: None,
            connection_timeout: DEFAULT_CONNECTION_TIMEOUT,
            handshake_timeout: DEFAULT_HANDSHAKE_TIMEOUT,
            pairing_timeout: rift_session::DEFAULT_PAIRING_TIMEOUT,
            max_inflight_connections: DEFAULT_MAX_INFLIGHT_CONNECTIONS,
            max_active_sessions: DEFAULT_MAX_ACTIVE_SESSIONS,
            max_sessions_per_peer: DEFAULT_MAX_SESSIONS_PER_PEER,
            max_pending_pairings: DEFAULT_MAX_PENDING_PAIRINGS,
            max_ipc_clients: DEFAULT_MAX_IPC_CLIENTS,
            shutdown_timeout: DEFAULT_SHUTDOWN_TIMEOUT,
        }
    }

    fn validate(&self) -> Result<(), DaemonError> {
        validate_nonzero_duration(self.connection_timeout, "connection_timeout")?;
        validate_nonzero_duration(self.handshake_timeout, "handshake_timeout")?;
        validate_nonzero_duration(self.pairing_timeout, "pairing_timeout")?;
        validate_nonzero_duration(self.shutdown_timeout, "shutdown_timeout")?;
        validate_count(
            self.max_inflight_connections,
            HARD_MAX_INFLIGHT_CONNECTIONS,
            "max_inflight_connections",
        )?;
        validate_count(
            self.max_active_sessions,
            HARD_MAX_ACTIVE_SESSIONS,
            "max_active_sessions",
        )?;
        validate_count(
            self.max_sessions_per_peer,
            HARD_MAX_SESSIONS_PER_PEER,
            "max_sessions_per_peer",
        )?;
        validate_count(
            self.max_pending_pairings,
            HARD_MAX_PENDING_PAIRINGS,
            "max_pending_pairings",
        )?;
        validate_count(
            self.max_ipc_clients,
            HARD_MAX_IPC_CLIENTS,
            "max_ipc_clients",
        )?;
        if self.max_sessions_per_peer > self.max_active_sessions {
            return Err(DaemonError::InvalidConfiguration(
                "max_sessions_per_peer must not exceed max_active_sessions",
            ));
        }
        Ok(())
    }
}

/// Startup, ownership, and shutdown failures for the resident runtime.
#[derive(Debug, Error)]
pub enum DaemonError {
    /// A configured duration/count or metadata value is invalid.
    #[error("invalid daemon configuration: {0}")]
    InvalidConfiguration(&'static str),
    /// The explicit path cannot safely act as a data directory.
    #[error("invalid daemon data directory: {0}")]
    InvalidDataDirectory(&'static str),
    /// Another process holds the OS lock for this data directory.
    #[error("another Rift daemon already owns this data directory")]
    AlreadyRunning,
    /// Trust state exists without the persistent identity that created it.
    #[error("identity.key is missing while trust.journal exists")]
    IdentityMissingWithExistingState,
    /// A filesystem operation failed.
    #[error("daemon {operation} failed: {source}")]
    Io {
        /// Bounded operation that failed.
        operation: &'static str,
        #[source]
        source: io::Error,
    },
    /// A Unix security boundary has the wrong permission bits.
    #[error("{path} has mode {actual:o}; required mode is {expected:o}")]
    InsecurePermissions {
        /// Path with unsafe mode.
        path: PathBuf,
        /// Observed Unix mode.
        actual: u32,
        /// Required Unix mode.
        expected: u32,
    },
    /// The persistent identity failed closed.
    #[error("persistent identity failed: {0}")]
    Identity(#[from] IdentityError),
    /// The trust journal could not open or mutate.
    #[error("durable trust failed: {0}")]
    Trust(#[from] TrustStoreError),
    /// Session configuration was invalid.
    #[error("session runtime configuration failed: {0}")]
    Session(#[from] SessionError),
    /// The Iroh endpoint could not bind.
    #[error("Rift endpoint startup failed: {0}")]
    Transport(#[from] TransportError),
    /// The operating system could not generate a runtime capability.
    #[error("unable to obtain OS runtime randomness: {0}")]
    Randomness(#[source] getrandom::Error),
    /// Runtime descriptor JSON serialization failed.
    #[error("unable to encode runtime descriptor: {0}")]
    DescriptorEncode(#[source] serde_json::Error),
    /// Unix-domain socket paths cannot exceed the platform bound.
    #[error("IPC socket path has {actual} bytes; platform maximum is {maximum}")]
    IpcAddressTooLong {
        /// Actual encoded path bytes.
        actual: usize,
        /// Platform maximum pathname bytes.
        maximum: usize,
    },
    /// `runtime.json` cannot portably represent a non-UTF-8 local address.
    #[error("IPC address is not valid UTF-8")]
    NonUtf8IpcAddress,
    /// A tracked task panicked or was unexpectedly cancelled.
    #[error("owned daemon task failed: {0}")]
    Task(#[source] tokio::task::JoinError),
    /// Owned child tasks exceeded the configured shutdown deadline.
    #[error("daemon shutdown timed out with {remaining_tasks} owned tasks remaining")]
    ShutdownTimeout {
        /// Tasks aborted after the graceful deadline.
        remaining_tasks: usize,
    },
}

/// Errors returned by a cloneable runtime handle.
#[derive(Clone, Debug, Error, Eq, PartialEq)]
pub enum DaemonHandleError {
    /// The owning runtime no longer receives commands.
    #[error("daemon runtime stopped")]
    Stopped,
    /// The requested operation failed with a stable IPC-visible category.
    #[error("daemon operation failed: {0:?}")]
    Operation(ErrorResponse),
}

/// Cloneable control and test seam for one running [`Daemon`].
#[derive(Clone)]
pub struct DaemonHandle {
    commands: mpsc::Sender<RuntimeCommand>,
    device_id: DeviceId,
    endpoint_addr: EndpointAddr,
    descriptor_path: PathBuf,
}

impl fmt::Debug for DaemonHandle {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("DaemonHandle")
            .field("device_id", &self.device_id)
            .field("descriptor_path", &self.descriptor_path)
            .finish_non_exhaustive()
    }
}

impl DaemonHandle {
    /// Returns the persistent public device identity.
    pub const fn device_id(&self) -> DeviceId {
        self.device_id
    }

    /// Returns the current transient Iroh address for Rust-level discovery tests/callers.
    pub fn endpoint_addr(&self) -> EndpointAddr {
        self.endpoint_addr.clone()
    }

    /// Returns the private runtime descriptor path used by local clients.
    pub fn runtime_descriptor_path(&self) -> &Path {
        &self.descriptor_path
    }

    /// Executes one transport-independent runtime-management request.
    pub async fn request(&self, request: Request) -> Result<Response, DaemonHandleError> {
        let (reply, response) = oneshot::channel();
        self.commands
            .send(RuntimeCommand::Request { request, reply })
            .await
            .map_err(|_| DaemonHandleError::Stopped)?;
        response
            .await
            .map_err(|_| DaemonHandleError::Stopped)?
            .map_err(DaemonHandleError::Operation)
    }

    /// Starts attended pairing to a transient Rust-level endpoint address.
    pub async fn begin_pairing(
        &self,
        peer: EndpointAddr,
    ) -> Result<PairingAttemptId, DaemonHandleError> {
        let (reply, response) = oneshot::channel();
        self.commands
            .send(RuntimeCommand::BeginPairing { peer, reply })
            .await
            .map_err(|_| DaemonHandleError::Stopped)?;
        response.await.map_err(|_| DaemonHandleError::Stopped)?
    }

    /// Dials a transient address and admits only an already-trusted peer.
    pub async fn connect_authenticated(
        &self,
        peer: EndpointAddr,
    ) -> Result<SessionId, DaemonHandleError> {
        let (reply, response) = oneshot::channel();
        self.commands
            .send(RuntimeCommand::ConnectAuthenticated { peer, reply })
            .await
            .map_err(|_| DaemonHandleError::Stopped)?;
        response.await.map_err(|_| DaemonHandleError::Stopped)?
    }

    /// Requests graceful shutdown and waits through cleanup and task joins.
    pub async fn shutdown(&self) -> Result<(), DaemonHandleError> {
        let (reply, response) = oneshot::channel();
        self.commands
            .send(RuntimeCommand::Shutdown { reply })
            .await
            .map_err(|_| DaemonHandleError::Stopped)?;
        response.await.map_err(|_| DaemonHandleError::Stopped)?
    }
}

#[derive(Clone)]
struct LocalHelloMetadata {
    device_name: String,
    platform: String,
}

/// Initialized resident runtime. Serving begins in [`run_until_shutdown`](Self::run_until_shutdown).
pub struct Daemon {
    config: DaemonConfig,
    metadata: LocalHelloMetadata,
    device_id: DeviceId,
    endpoint: Arc<RiftEndpoint>,
    trust_store: Arc<TrustStore>,
    session_manager: Arc<SessionManager>,
    listener: LocalListener,
    runtime_lock: Option<RuntimeLock>,
    artifacts: RuntimeArtifacts,
    descriptor: RuntimeDescriptor,
    auth_token: AuthToken,
    commands: mpsc::Receiver<RuntimeCommand>,
    handle: DaemonHandle,
    events: broadcast::Sender<Event>,
    shutdown: watch::Sender<bool>,
    tasks: tokio::task::JoinSet<TaskOutput>,
    pending_slots: Arc<Semaphore>,
    pending_pairings: BTreeMap<PairingAttemptId, PendingRecord>,
    sessions: BTreeMap<SessionId, SessionRecord>,
    next_pairing_id: u64,
    next_session_id: u64,
    ipc_clients: usize,
    state: RuntimeState,
}

impl Daemon {
    /// Initializes all durable state, endpoint, local IPC binding, and readiness descriptor.
    pub async fn start(config: DaemonConfig) -> Result<Self, DaemonError> {
        config.validate()?;
        let _validated_metadata = pairing_metadata(
            config.device_name.clone(),
            config.platform.clone(),
        )
        .map_err(|_| {
            DaemonError::InvalidConfiguration("device_name or platform exceeds Hello bounds")
        })?;
        let metadata = LocalHelloMetadata {
            device_name: config.device_name.clone(),
            platform: config.platform.clone(),
        };
        local::prepare_data_directory(&config.data_dir)?;
        let runtime_lock = RuntimeLock::acquire(&config.data_dir)?;
        let artifacts = RuntimeArtifacts::prepare(&config.data_dir)?;

        let identity_path = config.data_dir.join(IDENTITY_FILE_NAME);
        let trust_path = config.data_dir.join(TRUST_FILE_NAME);
        let identity_exists = path_exists(&identity_path, "inspect identity state")?;
        let trust_exists = path_exists(&trust_path, "inspect trust state")?;
        if trust_exists && !identity_exists {
            return Err(DaemonError::IdentityMissingWithExistingState);
        }
        let identity = IdentityStore::load_or_create(&identity_path)?;
        if identity_exists && !trust_exists {
            warn!("persistent identity exists but peer trust state is absent");
        }
        let device_id = identity.device_id();
        let trust_store = Arc::new(TrustStore::open(&trust_path).await?);
        let session_manager = Arc::new(SessionManager::with_config(
            Arc::clone(&trust_store),
            SessionConfig {
                pairing_timeout: config.pairing_timeout,
            },
        )?);
        let endpoint = Arc::new(
            RiftEndpoint::bind(
                identity.into_secret_key(),
                EndpointConfig {
                    relay: config.relay.clone(),
                    address_lookup: config.address_lookup,
                    bind_addr: config.bind_addr,
                    connection_timeout: config.connection_timeout,
                    handshake_timeout: config.handshake_timeout,
                },
            )
            .await?,
        );
        let runtime_id = random_hex(16)?;
        let auth_token = AuthToken::generate()?;
        let (listener, ipc) = LocalListener::bind(&artifacts, &runtime_id)?;
        let descriptor = RuntimeDescriptor {
            descriptor_version: RUNTIME_DESCRIPTOR_VERSION,
            pid: std::process::id(),
            runtime_id,
            ipc,
            auth_token: auth_token.descriptor_value().to_owned(),
        };
        artifacts.publish(&descriptor)?;

        let (command_sender, commands) = mpsc::channel(COMMAND_QUEUE_CAPACITY);
        let (events, _event_receiver) = broadcast::channel(EVENT_QUEUE_CAPACITY);
        let (shutdown, _shutdown_receiver) = watch::channel(false);
        let handle = DaemonHandle {
            commands: command_sender,
            device_id,
            endpoint_addr: endpoint.local_addr(),
            descriptor_path: artifacts.descriptor_path().to_path_buf(),
        };
        info!(local_device_id = %device_id, "Rift daemon ready");
        Ok(Self {
            pending_slots: Arc::new(Semaphore::new(config.max_pending_pairings)),
            config,
            metadata,
            device_id,
            endpoint,
            trust_store,
            session_manager,
            listener,
            runtime_lock: Some(runtime_lock),
            artifacts,
            descriptor,
            auth_token,
            commands,
            handle,
            events,
            shutdown,
            tasks: tokio::task::JoinSet::new(),
            pending_pairings: BTreeMap::new(),
            sessions: BTreeMap::new(),
            next_pairing_id: 1,
            next_session_id: 1,
            ipc_clients: 0,
            state: RuntimeState::Running,
        })
    }

    /// Returns a cloneable runtime control handle.
    pub fn handle(&self) -> DaemonHandle {
        self.handle.clone()
    }

    /// Returns the atomically published runtime descriptor without exposing it in Debug.
    pub fn runtime_descriptor(&self) -> &RuntimeDescriptor {
        &self.descriptor
    }

    /// Serves network and IPC work until explicit shutdown or a fatal owned-task failure.
    pub async fn run_until_shutdown(mut self) -> Result<(), DaemonError> {
        for _ in 0..self.config.max_inflight_connections {
            self.spawn_accept_worker();
        }

        let mut shutdown_reply = None;
        let mut fatal_error = None;
        loop {
            tokio::select! {
                accepted = self.listener.accept(), if self.ipc_clients < self.config.max_ipc_clients => {
                    match accepted {
                        Ok(stream) => self.spawn_ipc_client(stream),
                        Err(source) => {
                            fatal_error = Some(DaemonError::Io {
                                operation: "accept local IPC client",
                                source,
                            });
                            break;
                        }
                    }
                }
                command = self.commands.recv() => {
                    match command {
                        Some(RuntimeCommand::Shutdown { reply }) => {
                            shutdown_reply = Some(reply);
                            break;
                        }
                        Some(command) => self.handle_command(command).await,
                        None => break,
                    }
                }
                task = self.tasks.join_next(), if !self.tasks.is_empty() => {
                    match task {
                        Some(Ok(output)) => {
                            let respawn_accept = self.handle_task_output(output).await;
                            if respawn_accept {
                                self.spawn_accept_worker();
                            }
                        }
                        Some(Err(error)) => {
                            fatal_error = Some(DaemonError::Task(error));
                            self.state = RuntimeState::Failed;
                            break;
                        }
                        None => {}
                    }
                }
            }
        }

        let shutdown_result = self.shutdown_runtime().await;
        if let Some(reply) = shutdown_reply {
            let response = if shutdown_result.is_ok() && fatal_error.is_none() {
                Ok(())
            } else {
                Err(DaemonHandleError::Operation(operation_error(
                    ErrorCode::Internal,
                    "daemon shutdown did not complete cleanly",
                )))
            };
            send_oneshot(reply, response);
        }
        if let Some(error) = fatal_error {
            return Err(error);
        }
        shutdown_result
    }

    fn spawn_accept_worker(&mut self) {
        let endpoint = Arc::clone(&self.endpoint);
        let manager = Arc::clone(&self.session_manager);
        let metadata = self.metadata.clone();
        let pending_slots = Arc::clone(&self.pending_slots);
        self.tasks.spawn(async move {
            TaskOutput::Incoming(accept_incoming(endpoint, manager, metadata, pending_slots).await)
        });
    }

    fn spawn_ipc_client(&mut self, stream: local::LocalStream) {
        self.ipc_clients += 1;
        let token = self.auth_token.clone();
        let handle = self.handle.clone();
        let events = self.events.subscribe();
        let shutdown = self.shutdown.subscribe();
        self.tasks.spawn(async move {
            TaskOutput::IpcClient(
                ipc_server::serve_client(stream, token, handle, events, shutdown).await,
            )
        });
    }

    async fn handle_command(&mut self, command: RuntimeCommand) {
        match command {
            RuntimeCommand::Request { request, reply } => {
                if let Request::ConfirmPairing {
                    attempt_id,
                    accepted,
                } = request
                {
                    self.confirm_pairing(attempt_id, accepted, reply).await;
                } else {
                    let response = self.execute_request(request).await;
                    send_oneshot(reply, response);
                }
            }
            RuntimeCommand::BeginPairing { peer, reply } => {
                self.spawn_outbound(peer, OutboundReply::Pairing(reply));
            }
            RuntimeCommand::ConnectAuthenticated { peer, reply } => {
                self.spawn_outbound(peer, OutboundReply::Session(reply));
            }
            RuntimeCommand::Shutdown { reply } => {
                send_oneshot(
                    reply,
                    Err(DaemonHandleError::Operation(operation_error(
                        ErrorCode::ShuttingDown,
                        "daemon shutdown is already in progress",
                    ))),
                );
            }
        }
    }

    fn spawn_outbound(&mut self, peer: EndpointAddr, reply: OutboundReply) {
        let endpoint = Arc::clone(&self.endpoint);
        let manager = Arc::clone(&self.session_manager);
        let metadata = self.metadata.clone();
        let pending_slots = Arc::clone(&self.pending_slots);
        let pairing = matches!(reply, OutboundReply::Pairing(_));
        self.tasks.spawn(async move {
            let result =
                prepare_outbound(endpoint, manager, metadata, pending_slots, peer, pairing).await;
            TaskOutput::Outbound { result, reply }
        });
    }

    async fn execute_request(&mut self, request: Request) -> OperationResult<Response> {
        match request {
            Request::GetStatus {} => Ok(Response::Status {
                status: self.status(),
            }),
            Request::ListPeers { after, limit } => {
                if limit == 0 {
                    return Err(operation_error(
                        ErrorCode::InvalidRequest,
                        "peer page limit must be greater than zero",
                    ));
                }
                let page = self
                    .trust_store
                    .list_page(after, usize::from(limit.min(MAX_PEER_PAGE_SIZE)))
                    .await
                    .map_err(persistence_error)?;
                Ok(Response::Peers {
                    page: PeerPage {
                        entries: page.entries.into_iter().map(peer_info).collect(),
                        next_cursor: page.next_cursor,
                    },
                })
            }
            Request::ListSessions {} => Ok(Response::Sessions {
                sessions: self
                    .sessions
                    .values()
                    .map(|record| record.info.clone())
                    .collect(),
            }),
            Request::ListPendingPairings {} => Ok(Response::PendingPairings {
                pairings: self
                    .pending_pairings
                    .values()
                    .map(PendingRecord::current_info)
                    .collect(),
            }),
            Request::RevokePeer { device_id } => {
                self.trust_store
                    .revoke(device_id)
                    .await
                    .map_err(persistence_error)?;
                self.invalidate_peer(device_id, SessionCloseReason::Revoked)
                    .await;
                self.emit(Event::TrustChanged {
                    device_id,
                    state: Some(TrustState::Revoked),
                });
                Ok(Response::PeerRevoked { device_id })
            }
            Request::ForgetPeer { device_id } => {
                self.trust_store
                    .forget(device_id)
                    .await
                    .map_err(persistence_error)?;
                self.invalidate_peer(device_id, SessionCloseReason::Forgotten)
                    .await;
                self.emit(Event::TrustChanged {
                    device_id,
                    state: None,
                });
                Ok(Response::PeerForgotten { device_id })
            }
            Request::DisconnectSession { session_id } => {
                let Some(record) = self.sessions.remove(&session_id) else {
                    return Err(operation_error(
                        ErrorCode::SessionNotFound,
                        "active session was not found",
                    ));
                };
                record.closer.close();
                self.emit(Event::SessionClosed {
                    session_id,
                    device_id: record.info.device_id,
                    reason: SessionCloseReason::Disconnected,
                });
                Ok(Response::SessionDisconnected { session_id })
            }
            Request::ConfirmPairing { .. } => Err(operation_error(
                ErrorCode::Internal,
                "pairing confirmation dispatch invariant failed",
            )),
        }
    }

    async fn confirm_pairing(
        &mut self,
        attempt_id: PairingAttemptId,
        accepted: bool,
        reply: OperationReply<Response>,
    ) {
        let Some(record) = self.pending_pairings.get_mut(&attempt_id) else {
            send_oneshot(
                reply,
                Err(operation_error(
                    ErrorCode::PairingNotFound,
                    "pending pairing was not found",
                )),
            );
            return;
        };
        if record.resolving {
            send_oneshot(
                reply,
                Err(operation_error(
                    ErrorCode::PairingNotFound,
                    "pending pairing is already resolving",
                )),
            );
            return;
        }
        record.resolving = true;
        let commands = record.commands.clone();
        if commands
            .send(PairingCommand::Confirm { accepted, reply })
            .await
            .is_err()
        {
            self.pending_pairings.remove(&attempt_id);
        }
    }

    async fn invalidate_peer(&mut self, device_id: DeviceId, reason: SessionCloseReason) {
        let pairing_ids = self
            .pending_pairings
            .iter()
            .filter_map(|(id, record)| (record.info.device_id == device_id).then_some(*id))
            .collect::<Vec<_>>();
        for attempt_id in pairing_ids {
            if let Some(record) = self.pending_pairings.remove(&attempt_id) {
                record.closer.close();
                match record.commands.send(PairingCommand::Cancel).await {
                    Ok(()) | Err(_) => {}
                }
                self.emit(Event::PairingResolved {
                    attempt_id,
                    device_id,
                    outcome: PairingOutcome::Cancelled,
                });
            }
        }

        let session_ids = self
            .sessions
            .iter()
            .filter_map(|(id, record)| (record.info.device_id == device_id).then_some(*id))
            .collect::<Vec<_>>();
        for session_id in session_ids {
            if let Some(record) = self.sessions.remove(&session_id) {
                record.closer.close();
                self.emit(Event::SessionClosed {
                    session_id,
                    device_id,
                    reason,
                });
            }
        }
    }

    async fn handle_task_output(&mut self, output: TaskOutput) -> bool {
        match output {
            TaskOutput::Incoming(result) => {
                match result {
                    Ok(candidate) => {
                        if let Err(error) = self.register_candidate(candidate).await {
                            debug!(error_code = ?error.code, "incoming Rift connection rejected");
                        }
                    }
                    Err(error) => {
                        debug!(error_code = ?error.code, "incoming Rift connection setup failed");
                    }
                }
                true
            }
            TaskOutput::Outbound { result, reply } => {
                match (result, reply) {
                    (
                        Ok(ConnectionCandidate::Pending(pending, permit)),
                        OutboundReply::Pairing(reply),
                    ) => {
                        let result = self
                            .register_pending(pending, permit)
                            .map_err(DaemonHandleError::Operation);
                        send_oneshot(reply, result);
                    }
                    (
                        Ok(ConnectionCandidate::Authorized(connection)),
                        OutboundReply::Session(reply),
                    ) => {
                        let result = self
                            .register_session(connection)
                            .await
                            .map_err(DaemonHandleError::Operation);
                        send_oneshot(reply, result);
                    }
                    (
                        Ok(ConnectionCandidate::Authorized(connection)),
                        OutboundReply::Pairing(reply),
                    ) => {
                        connection.close();
                        send_oneshot(
                            reply,
                            Err(DaemonHandleError::Operation(operation_error(
                                ErrorCode::PeerAlreadyTrusted,
                                "peer is already trusted",
                            ))),
                        );
                    }
                    (
                        Ok(ConnectionCandidate::Pending(pending, _permit)),
                        OutboundReply::Session(reply),
                    ) => {
                        if let Some(handle) = pending.disposable_handle() {
                            handle.close();
                        }
                        send_oneshot(
                            reply,
                            Err(DaemonHandleError::Operation(operation_error(
                                ErrorCode::PeerNotTrusted,
                                "peer requires pairing before authenticated connection",
                            ))),
                        );
                    }
                    (Err(error), OutboundReply::Pairing(reply)) => {
                        send_oneshot(reply, Err(DaemonHandleError::Operation(error)));
                    }
                    (Err(error), OutboundReply::Session(reply)) => {
                        send_oneshot(reply, Err(DaemonHandleError::Operation(error)));
                    }
                }
                false
            }
            TaskOutput::PairingEnded {
                attempt_id,
                device_id,
                result,
                reply,
            } => {
                self.finish_pairing(attempt_id, device_id, result, reply)
                    .await;
                false
            }
            TaskOutput::SessionEnded {
                session_id,
                device_id,
                reason,
            } => {
                if self.sessions.remove(&session_id).is_some() {
                    self.emit(Event::SessionClosed {
                        session_id,
                        device_id,
                        reason,
                    });
                }
                false
            }
            TaskOutput::IpcClient(result) => {
                self.ipc_clients = self.ipc_clients.saturating_sub(1);
                if let Err(error) = result {
                    debug!(error = %error, "local IPC client disconnected");
                }
                false
            }
        }
    }

    async fn register_candidate(&mut self, candidate: ConnectionCandidate) -> OperationResult<()> {
        match candidate {
            ConnectionCandidate::Authorized(connection) => {
                self.register_session(connection).await.map(|_| ())
            }
            ConnectionCandidate::Pending(pending, permit) => {
                self.register_pending(pending, permit).map(|_| ())
            }
        }
    }

    fn register_pending(
        &mut self,
        pending: PendingPairing,
        permit: OwnedSemaphorePermit,
    ) -> OperationResult<PairingAttemptId> {
        if self.pending_pairings.len() >= self.config.max_pending_pairings {
            if let Some(handle) = pending.disposable_handle() {
                handle.close();
            }
            return Err(operation_error(
                ErrorCode::CapacityExceeded,
                "pending pairing capacity reached",
            ));
        }
        let closer = pending.disposable_handle().ok_or_else(|| {
            operation_error(
                ErrorCode::Internal,
                "pending pairing lost its disposable connection",
            )
        })?;
        let attempt_id = PairingAttemptId(self.allocate_pairing_id()?);
        let peer = pending.peer().clone();
        let deadline = pending.confirmation_deadline();
        let info = PendingPairingInfo {
            attempt_id,
            device_id: peer.device_id,
            device_name: peer.device_name,
            platform: peer.platform,
            verification_code: pending.verification_code().to_string(),
            timeout_remaining_ms: remaining_millis(deadline),
        };
        let (commands, command_receiver) = mpsc::channel(PAIRING_COMMAND_CAPACITY);
        self.pending_pairings.insert(
            attempt_id,
            PendingRecord {
                info: info.clone(),
                deadline,
                closer,
                commands,
                resolving: false,
            },
        );
        let shutdown = self.shutdown.subscribe();
        self.tasks.spawn(run_pending_pairing(
            attempt_id,
            pending,
            command_receiver,
            shutdown,
            permit,
        ));
        self.emit(Event::PairingPending { pairing: info });
        Ok(attempt_id)
    }

    async fn register_session(
        &mut self,
        connection: AuthorizedConnection,
    ) -> OperationResult<SessionId> {
        let device_id = connection.remote_device_id();
        if self.trust_store.state(device_id).await != Some(TrustState::Trusted) {
            connection.close();
            return Err(operation_error(
                ErrorCode::PeerNotTrusted,
                "durable trust no longer authorizes this peer",
            ));
        }
        if self.sessions.len() >= self.config.max_active_sessions {
            connection.close();
            return Err(operation_error(
                ErrorCode::CapacityExceeded,
                "active session capacity reached",
            ));
        }
        let peer_count = self
            .sessions
            .values()
            .filter(|record| record.info.device_id == device_id)
            .count();
        if peer_count >= self.config.max_sessions_per_peer {
            connection.close();
            return Err(operation_error(
                ErrorCode::CapacityExceeded,
                "per-peer session capacity reached",
            ));
        }
        let session_id = SessionId(self.allocate_session_id()?);
        let trusted = connection.trusted_peer().clone();
        let closer = connection.disposable_handle();
        let info = SessionInfo {
            session_id,
            device_id,
            device_name: trusted.device_name,
            platform: trusted.platform,
        };
        self.sessions.insert(
            session_id,
            SessionRecord {
                info: info.clone(),
                closer,
            },
        );
        let shutdown = self.shutdown.subscribe();
        self.tasks
            .spawn(run_session(session_id, connection, shutdown));
        self.emit(Event::SessionOpened { session: info });
        Ok(session_id)
    }

    async fn finish_pairing(
        &mut self,
        attempt_id: PairingAttemptId,
        device_id: DeviceId,
        result: PairingTaskResult,
        reply: Option<OperationReply<Response>>,
    ) {
        let registered = self.pending_pairings.remove(&attempt_id).is_some();
        let (outcome, response) = match result {
            PairingTaskResult::Authorized(connection) if registered => {
                match self.register_session(*connection).await {
                    Ok(session_id) => (
                        PairingOutcome::Accepted,
                        Ok(Response::PairingResolved {
                            attempt_id,
                            accepted: true,
                            session_id: Some(session_id),
                        }),
                    ),
                    Err(error) => (PairingOutcome::Failed, Err(error)),
                }
            }
            PairingTaskResult::Authorized(connection) => {
                connection.close();
                (
                    PairingOutcome::Cancelled,
                    Err(operation_error(
                        ErrorCode::PairingNotFound,
                        "pairing was invalidated before authorization",
                    )),
                )
            }
            PairingTaskResult::Rejected => (
                PairingOutcome::Rejected,
                Ok(Response::PairingResolved {
                    attempt_id,
                    accepted: false,
                    session_id: None,
                }),
            ),
            PairingTaskResult::Expired => (
                PairingOutcome::Expired,
                Err(operation_error(
                    ErrorCode::PairingNotFound,
                    "pairing confirmation expired",
                )),
            ),
            PairingTaskResult::Cancelled => (
                PairingOutcome::Cancelled,
                Err(operation_error(
                    ErrorCode::PairingNotFound,
                    "pairing was cancelled",
                )),
            ),
            PairingTaskResult::Failed(error) => (PairingOutcome::Failed, Err(error)),
        };
        if registered {
            self.emit(Event::PairingResolved {
                attempt_id,
                device_id,
                outcome,
            });
        }
        if let Some(reply) = reply {
            send_oneshot(reply, response);
        }
    }

    fn allocate_pairing_id(&mut self) -> OperationResult<u64> {
        let id = self.next_pairing_id;
        self.next_pairing_id = self.next_pairing_id.checked_add(1).ok_or_else(|| {
            operation_error(ErrorCode::Internal, "pairing attempt ID space exhausted")
        })?;
        Ok(id)
    }

    fn allocate_session_id(&mut self) -> OperationResult<u64> {
        let id = self.next_session_id;
        self.next_session_id = self
            .next_session_id
            .checked_add(1)
            .ok_or_else(|| operation_error(ErrorCode::Internal, "session ID space exhausted"))?;
        Ok(id)
    }

    fn status(&self) -> Status {
        Status {
            daemon_version: env!("CARGO_PKG_VERSION").to_owned(),
            device_id: self.device_id,
            device_name: self.config.device_name.clone(),
            platform: self.config.platform.clone(),
            state: self.state,
            active_sessions: u32::try_from(self.sessions.len()).unwrap_or(u32::MAX),
            pending_pairings: u32::try_from(self.pending_pairings.len()).unwrap_or(u32::MAX),
            pairing_enabled: true,
        }
    }

    fn emit(&self, event: Event) {
        match self.events.send(event) {
            Ok(_) | Err(_) => {}
        }
    }

    async fn shutdown_runtime(&mut self) -> Result<(), DaemonError> {
        self.state = RuntimeState::ShuttingDown;
        let descriptor_result = self.artifacts.unpublish_descriptor();
        self.emit(Event::DaemonShuttingDown);
        self.endpoint.close().await;

        let pending = std::mem::take(&mut self.pending_pairings);
        for (attempt_id, record) in pending {
            record.closer.close();
            match record.commands.try_send(PairingCommand::Cancel) {
                Ok(()) | Err(_) => {}
            }
            self.emit(Event::PairingResolved {
                attempt_id,
                device_id: record.info.device_id,
                outcome: PairingOutcome::Cancelled,
            });
        }
        let sessions = std::mem::take(&mut self.sessions);
        for (session_id, record) in sessions {
            record.closer.close();
            self.emit(Event::SessionClosed {
                session_id,
                device_id: record.info.device_id,
                reason: SessionCloseReason::Shutdown,
            });
        }
        match self.shutdown.send(true) {
            Ok(()) | Err(_) => {}
        }

        let join_result = tokio::time::timeout(self.config.shutdown_timeout, async {
            while let Some(result) = self.tasks.join_next().await {
                if let Err(error) = result {
                    return Err(DaemonError::Task(error));
                }
            }
            Ok(())
        })
        .await;
        let task_result = match join_result {
            Ok(result) => result,
            Err(_) => {
                let remaining_tasks = self.tasks.len();
                self.tasks.abort_all();
                while let Some(result) = self.tasks.join_next().await {
                    match result {
                        Ok(_) => {}
                        Err(error) if error.is_cancelled() => {}
                        Err(error) => return Err(DaemonError::Task(error)),
                    }
                }
                Err(DaemonError::ShutdownTimeout { remaining_tasks })
            }
        };
        let cleanup_result = self.artifacts.cleanup();
        let lock_result = match self.runtime_lock.take() {
            Some(runtime_lock) => runtime_lock.release(),
            None => Ok(()),
        };
        self.state = RuntimeState::Stopped;
        descriptor_result?;
        task_result?;
        cleanup_result?;
        lock_result
    }
}

#[derive(Clone)]
pub(crate) struct AuthToken {
    encoded: String,
}

impl AuthToken {
    fn generate() -> Result<Self, DaemonError> {
        let mut bytes = [0_u8; 32];
        getrandom::fill(&mut bytes).map_err(DaemonError::Randomness)?;
        Ok(Self {
            encoded: hex::encode(bytes),
        })
    }

    fn descriptor_value(&self) -> &str {
        &self.encoded
    }

    pub(crate) fn matches(&self, candidate: &str) -> bool {
        if candidate.len() != self.encoded.len() {
            return false;
        }
        let mut difference = 0_u8;
        let mut valid_lower_hex = true;
        for (candidate, expected) in candidate.bytes().zip(self.encoded.bytes()) {
            valid_lower_hex &= candidate.is_ascii_digit() || (b'a'..=b'f').contains(&candidate);
            difference |= candidate ^ expected;
        }
        valid_lower_hex && difference == 0
    }
}

impl fmt::Debug for AuthToken {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("AuthToken(..)")
    }
}

type OperationResult<T> = Result<T, ErrorResponse>;
type OperationReply<T> = oneshot::Sender<OperationResult<T>>;

enum RuntimeCommand {
    Request {
        request: Request,
        reply: OperationReply<Response>,
    },
    BeginPairing {
        peer: EndpointAddr,
        reply: oneshot::Sender<Result<PairingAttemptId, DaemonHandleError>>,
    },
    ConnectAuthenticated {
        peer: EndpointAddr,
        reply: oneshot::Sender<Result<SessionId, DaemonHandleError>>,
    },
    Shutdown {
        reply: oneshot::Sender<Result<(), DaemonHandleError>>,
    },
}

enum OutboundReply {
    Pairing(oneshot::Sender<Result<PairingAttemptId, DaemonHandleError>>),
    Session(oneshot::Sender<Result<SessionId, DaemonHandleError>>),
}

enum TaskOutput {
    Incoming(OperationResult<ConnectionCandidate>),
    Outbound {
        result: OperationResult<ConnectionCandidate>,
        reply: OutboundReply,
    },
    PairingEnded {
        attempt_id: PairingAttemptId,
        device_id: DeviceId,
        result: PairingTaskResult,
        reply: Option<OperationReply<Response>>,
    },
    SessionEnded {
        session_id: SessionId,
        device_id: DeviceId,
        reason: SessionCloseReason,
    },
    IpcClient(Result<(), ipc_server::ClientError>),
}

enum ConnectionCandidate {
    Authorized(AuthorizedConnection),
    Pending(PendingPairing, OwnedSemaphorePermit),
}

enum PairingCommand {
    Confirm {
        accepted: bool,
        reply: OperationReply<Response>,
    },
    Cancel,
}

enum PairingTaskResult {
    Authorized(Box<AuthorizedConnection>),
    Rejected,
    Expired,
    Cancelled,
    Failed(ErrorResponse),
}

struct PendingRecord {
    info: PendingPairingInfo,
    deadline: tokio::time::Instant,
    closer: DisposableConnectionHandle,
    commands: mpsc::Sender<PairingCommand>,
    resolving: bool,
}

impl PendingRecord {
    fn current_info(&self) -> PendingPairingInfo {
        let mut info = self.info.clone();
        info.timeout_remaining_ms = remaining_millis(self.deadline);
        info
    }
}

struct SessionRecord {
    info: SessionInfo,
    closer: DisposableConnectionHandle,
}

async fn accept_incoming(
    endpoint: Arc<RiftEndpoint>,
    manager: Arc<SessionManager>,
    metadata: LocalHelloMetadata,
    pending_slots: Arc<Semaphore>,
) -> OperationResult<ConnectionCandidate> {
    let metadata = pairing_metadata(metadata.device_name, metadata.platform).map_err(|_| {
        operation_error(
            ErrorCode::Internal,
            "local Hello metadata failed validation after startup",
        )
    })?;
    let bootstrapped = endpoint
        .accept_and_bootstrap(metadata)
        .await
        .map_err(connection_error)?;
    match manager
        .accept_inbound(bootstrapped)
        .await
        .map_err(session_error)?
    {
        SessionAdmission::Authorized(connection) => Ok(ConnectionCandidate::Authorized(connection)),
        SessionAdmission::Pairable(pairable) => {
            let permit = pending_slots.try_acquire_owned().map_err(|_| {
                pairable.close();
                operation_error(
                    ErrorCode::CapacityExceeded,
                    "pending pairing capacity reached",
                )
            })?;
            let pending = pairable.respond_to_pairing().await.map_err(pairing_error)?;
            Ok(ConnectionCandidate::Pending(pending, permit))
        }
    }
}

async fn prepare_outbound(
    endpoint: Arc<RiftEndpoint>,
    manager: Arc<SessionManager>,
    metadata: LocalHelloMetadata,
    pending_slots: Arc<Semaphore>,
    peer: EndpointAddr,
    pairing: bool,
) -> OperationResult<ConnectionCandidate> {
    let metadata = pairing_metadata(metadata.device_name, metadata.platform).map_err(|_| {
        operation_error(
            ErrorCode::Internal,
            "local Hello metadata failed validation after startup",
        )
    })?;
    let bootstrapped = endpoint
        .connect_and_bootstrap(peer, metadata)
        .await
        .map_err(connection_error)?;
    match manager
        .prepare_outbound(
            bootstrapped,
            if pairing {
                ConnectionPurpose::Pairing
            } else {
                ConnectionPurpose::AuthorizedSession
            },
        )
        .await
        .map_err(session_error)?
    {
        SessionAdmission::Authorized(connection) => Ok(ConnectionCandidate::Authorized(connection)),
        SessionAdmission::Pairable(pairable) if pairing => {
            let permit = pending_slots.try_acquire_owned().map_err(|_| {
                pairable.close();
                operation_error(
                    ErrorCode::CapacityExceeded,
                    "pending pairing capacity reached",
                )
            })?;
            let pending = pairable.initiate_pairing().await.map_err(pairing_error)?;
            Ok(ConnectionCandidate::Pending(pending, permit))
        }
        SessionAdmission::Pairable(pairable) => {
            pairable.close();
            Err(operation_error(
                ErrorCode::PeerNotTrusted,
                "peer requires pairing before authenticated connection",
            ))
        }
    }
}

async fn run_pending_pairing(
    attempt_id: PairingAttemptId,
    pending: PendingPairing,
    mut commands: mpsc::Receiver<PairingCommand>,
    mut shutdown: watch::Receiver<bool>,
    _permit: OwnedSemaphorePermit,
) -> TaskOutput {
    let device_id = pending.remote_device_id();
    let deadline = pending.confirmation_deadline();
    tokio::select! {
        command = commands.recv() => {
            match command {
                Some(PairingCommand::Confirm { accepted, reply }) => {
                    resolve_pending_pairing(
                        attempt_id,
                        device_id,
                        pending,
                        accepted,
                        reply,
                        commands,
                        shutdown,
                    ).await
                }
                Some(PairingCommand::Cancel) | None => TaskOutput::PairingEnded {
                    attempt_id,
                    device_id,
                    result: PairingTaskResult::Cancelled,
                    reply: None,
                },
            }
        }
        _ = tokio::time::sleep_until(deadline) => TaskOutput::PairingEnded {
            attempt_id,
            device_id,
            result: PairingTaskResult::Expired,
            reply: None,
        },
        _ = pending.closed() => TaskOutput::PairingEnded {
            attempt_id,
            device_id,
            result: PairingTaskResult::Failed(operation_error(
                ErrorCode::ConnectionFailed,
                "pairing connection closed before confirmation",
            )),
            reply: None,
        },
        changed = shutdown.changed() => {
            let _shutdown_changed = changed;
            TaskOutput::PairingEnded {
                attempt_id,
                device_id,
                result: PairingTaskResult::Cancelled,
                reply: None,
            }
        }
    }
}

async fn resolve_pending_pairing(
    attempt_id: PairingAttemptId,
    device_id: DeviceId,
    pending: PendingPairing,
    accepted: bool,
    reply: OperationReply<Response>,
    mut commands: mpsc::Receiver<PairingCommand>,
    mut shutdown: watch::Receiver<bool>,
) -> TaskOutput {
    let confirmation = pending.confirm(accepted);
    tokio::pin!(confirmation);
    let result = tokio::select! {
        result = &mut confirmation => match result {
            Ok(connection) => PairingTaskResult::Authorized(Box::new(connection)),
            Err(PairingError::Rejected { .. }) => PairingTaskResult::Rejected,
            Err(PairingError::Timeout { .. }) => PairingTaskResult::Expired,
            Err(error) => PairingTaskResult::Failed(pairing_error(error)),
        },
        command = commands.recv() => {
            let _cancelled = command;
            PairingTaskResult::Cancelled
        },
        changed = shutdown.changed() => {
            let _shutdown_changed = changed;
            PairingTaskResult::Cancelled
        },
    };
    TaskOutput::PairingEnded {
        attempt_id,
        device_id,
        result,
        reply: Some(reply),
    }
}

async fn run_session(
    session_id: SessionId,
    connection: AuthorizedConnection,
    mut shutdown: watch::Receiver<bool>,
) -> TaskOutput {
    let device_id = connection.remote_device_id();
    let reason = tokio::select! {
        _ = connection.closed() => SessionCloseReason::ConnectionClosed,
        changed = shutdown.changed() => {
            let _shutdown_changed = changed;
            connection.close();
            SessionCloseReason::Shutdown
        }
    };
    TaskOutput::SessionEnded {
        session_id,
        device_id,
        reason,
    }
}

fn peer_info(entry: TrustEntry) -> PeerInfo {
    match entry {
        TrustEntry::Trusted(peer) => PeerInfo {
            device_id: peer.device_id,
            state: TrustState::Trusted,
            device_name: Some(peer.device_name),
            platform: Some(peer.platform),
        },
        TrustEntry::Revoked(device_id) => PeerInfo {
            device_id,
            state: TrustState::Revoked,
            device_name: None,
            platform: None,
        },
    }
}

fn remaining_millis(deadline: tokio::time::Instant) -> u64 {
    u64::try_from(
        deadline
            .saturating_duration_since(tokio::time::Instant::now())
            .as_millis(),
    )
    .unwrap_or(u64::MAX)
}

fn validate_nonzero_duration(duration: Duration, name: &'static str) -> Result<(), DaemonError> {
    if duration.is_zero() {
        return Err(DaemonError::InvalidConfiguration(name));
    }
    Ok(())
}

fn validate_count(value: usize, maximum: usize, name: &'static str) -> Result<(), DaemonError> {
    if value == 0 || value > maximum {
        return Err(DaemonError::InvalidConfiguration(name));
    }
    Ok(())
}

fn path_exists(path: &Path, operation: &'static str) -> Result<bool, DaemonError> {
    path.try_exists()
        .map_err(|source| DaemonError::Io { operation, source })
}

fn random_hex(byte_len: usize) -> Result<String, DaemonError> {
    let mut bytes = vec![0_u8; byte_len];
    getrandom::fill(&mut bytes).map_err(DaemonError::Randomness)?;
    Ok(hex::encode(bytes))
}

fn session_error(error: SessionError) -> ErrorResponse {
    match error {
        SessionError::Intent(error) => connection_error(error),
        SessionError::PurposeNotAllowed { .. } => operation_error(
            ErrorCode::PeerNotTrusted,
            "requested connection purpose is not allowed",
        ),
        SessionError::PeerRevoked(_) => {
            operation_error(ErrorCode::PeerNotTrusted, "peer is durably revoked")
        }
        SessionError::InvalidPairingTimeout => operation_error(
            ErrorCode::Internal,
            "session manager configuration is invalid",
        ),
    }
}

fn connection_error(error: TransportError) -> ErrorResponse {
    operation_error(ErrorCode::ConnectionFailed, error.to_string())
}

fn pairing_error(error: PairingError) -> ErrorResponse {
    match error {
        PairingError::Trust(error) => persistence_error(error),
        error => operation_error(ErrorCode::ConnectionFailed, error.to_string()),
    }
}

fn persistence_error(error: TrustStoreError) -> ErrorResponse {
    operation_error(ErrorCode::PersistenceFailed, error.to_string())
}

fn operation_error(code: ErrorCode, message: impl Into<String>) -> ErrorResponse {
    ErrorResponse::new(code, bounded_message(message.into()))
}

fn bounded_message(mut message: String) -> String {
    if message.len() <= ERROR_MESSAGE_MAX_BYTES {
        return message;
    }
    let mut boundary = ERROR_MESSAGE_MAX_BYTES;
    while !message.is_char_boundary(boundary) {
        boundary = boundary.saturating_sub(1);
    }
    message.truncate(boundary);
    message
}

fn send_oneshot<T>(sender: oneshot::Sender<T>, value: T) {
    match sender.send(value) {
        Ok(()) | Err(_) => {}
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn configuration_counts_are_nonzero_and_hard_bounded() {
        let mut config = DaemonConfig::new("unused", "test");
        assert!(config.validate().is_ok());
        config.max_pending_pairings = 0;
        assert!(matches!(
            config.validate(),
            Err(DaemonError::InvalidConfiguration("max_pending_pairings"))
        ));
        config.max_pending_pairings = HARD_MAX_PENDING_PAIRINGS + 1;
        assert!(matches!(
            config.validate(),
            Err(DaemonError::InvalidConfiguration("max_pending_pairings"))
        ));
    }

    #[test]
    fn bearer_token_validation_is_exact_lowercase_and_debug_redacted()
    -> Result<(), Box<dyn std::error::Error>> {
        let token = AuthToken::generate()?;
        let value = token.descriptor_value().to_owned();
        assert_eq!(value.len(), 64);
        assert!(token.matches(&value));
        assert!(!token.matches(&format!("A{}", &value[1..])));
        let replacement = if value.starts_with('0') { "1" } else { "0" };
        assert!(!token.matches(&format!("{replacement}{}", &value[1..])));
        assert!(!format!("{token:?}").contains(&value));
        Ok(())
    }

    #[test]
    fn maximum_registry_responses_fit_the_ipc_frame_bound() -> Result<(), Box<dyn std::error::Error>>
    {
        let device_id = DeviceId::from_bytes([u8::MAX; 32]);
        let device_name = "\0".repeat(rift_core::MAX_DEVICE_NAME_LEN);
        let platform = "\0".repeat(rift_core::MAX_PLATFORM_LEN);
        let sessions = (0..HARD_MAX_ACTIVE_SESSIONS)
            .map(|index| SessionInfo {
                session_id: SessionId(u64::try_from(index).unwrap_or(u64::MAX)),
                device_id,
                device_name: device_name.clone(),
                platform: platform.clone(),
            })
            .collect();
        let pairings = (0..HARD_MAX_PENDING_PAIRINGS)
            .map(|index| PendingPairingInfo {
                attempt_id: PairingAttemptId(u64::try_from(index).unwrap_or(u64::MAX)),
                device_id,
                device_name: device_name.clone(),
                platform: platform.clone(),
                verification_code: "999999".to_owned(),
                timeout_remaining_ms: u64::MAX,
            })
            .collect();
        let entries = (0..usize::from(MAX_PEER_PAGE_SIZE))
            .map(|_| PeerInfo {
                device_id,
                state: TrustState::Trusted,
                device_name: Some(device_name.clone()),
                platform: Some(platform.clone()),
            })
            .collect();
        let responses = [
            Response::Sessions { sessions },
            Response::PendingPairings { pairings },
            Response::Peers {
                page: PeerPage {
                    entries,
                    next_cursor: Some(device_id),
                },
            },
        ];
        for response in responses {
            let frame = rift_ipc::encode_json_frame(&response)?;
            assert!(frame.len() - size_of::<u32>() <= rift_ipc::MAX_IPC_FRAME_LEN);
        }
        Ok(())
    }

    #[test]
    fn operation_error_messages_are_utf8_safely_bounded() {
        let error = operation_error(ErrorCode::Internal, "é".repeat(600));
        assert!(error.message.len() <= ERROR_MESSAGE_MAX_BYTES);
        assert!(error.message.is_char_boundary(error.message.len()));
    }
}
