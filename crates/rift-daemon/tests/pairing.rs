use std::{collections::BTreeMap, error::Error, io, time::Duration};

use rift_core::{DeviceId, TrustState};
use rift_daemon::{Daemon, DaemonConfig, DaemonError, DaemonHandle, DaemonHandleError};
use rift_ipc::{
    ClientMessage, ErrorCode, ErrorResponse, Event, IPC_PROTOCOL_VERSION, PairingAttemptId,
    PendingPairingInfo, Request, Response, RuntimeDescriptor, ServerMessage, SessionInfo,
    read_json_frame, write_json_frame,
};
use tempfile::TempDir;

type TestResult<T = ()> = Result<T, Box<dyn Error + Send + Sync>>;

#[cfg(unix)]
type ClientStream = tokio::net::UnixStream;
#[cfg(windows)]
type ClientStream = tokio::net::windows::named_pipe::NamedPipeClient;

fn test_config(directory: &TempDir, name: &str) -> DaemonConfig {
    let mut config = DaemonConfig::new(directory.path(), name);
    config.platform = "integration-test".to_owned();
    config.bind_addr =
        Some("127.0.0.1:0".parse().unwrap_or_else(|_| {
            std::net::SocketAddr::new(std::net::Ipv4Addr::LOCALHOST.into(), 0)
        }));
    config.connection_timeout = Duration::from_secs(3);
    config.handshake_timeout = Duration::from_secs(3);
    config.pairing_timeout = Duration::from_secs(3);
    config.shutdown_timeout = Duration::from_secs(5);
    config.max_inflight_connections = 4;
    config
}

struct RunningDaemon {
    handle: DaemonHandle,
    descriptor: RuntimeDescriptor,
    task: tokio::task::JoinHandle<Result<(), DaemonError>>,
}

impl RunningDaemon {
    fn spawn(daemon: Daemon) -> Self {
        let handle = daemon.handle();
        let descriptor = daemon.runtime_descriptor().clone();
        let task = tokio::spawn(daemon.run_until_shutdown());
        Self {
            handle,
            descriptor,
            task,
        }
    }

    async fn start(directory: &TempDir, name: &str) -> TestResult<Self> {
        let daemon = Daemon::start(test_config(directory, name)).await?;
        Ok(Self::spawn(daemon))
    }

    async fn shutdown(self) -> TestResult {
        self.handle.shutdown().await?;
        self.task.await??;
        Ok(())
    }
}

#[cfg(unix)]
async fn connect(descriptor: &RuntimeDescriptor) -> io::Result<ClientStream> {
    tokio::net::UnixStream::connect(&descriptor.ipc.address).await
}

#[cfg(windows)]
async fn connect(descriptor: &RuntimeDescriptor) -> io::Result<ClientStream> {
    tokio::net::windows::named_pipe::ClientOptions::new().open(&descriptor.ipc.address)
}

struct IpcClient {
    stream: ClientStream,
    next_request_id: u64,
    events: Vec<Event>,
    responses: BTreeMap<u64, Result<Response, ErrorResponse>>,
}

impl IpcClient {
    async fn authenticate(descriptor: &RuntimeDescriptor) -> TestResult<Self> {
        let mut stream = connect(descriptor).await?;
        write_json_frame(
            &mut stream,
            &ClientMessage::Authenticate {
                version: IPC_PROTOCOL_VERSION,
                token: descriptor.auth_token.clone(),
            },
        )
        .await?;
        assert_eq!(
            read_json_frame::<_, ServerMessage>(&mut stream).await?,
            ServerMessage::Authenticated {
                version: IPC_PROTOCOL_VERSION
            }
        );
        Ok(Self {
            stream,
            next_request_id: 1,
            events: Vec::new(),
            responses: BTreeMap::new(),
        })
    }

    async fn send_request(&mut self, request: Request) -> TestResult<u64> {
        let id = self.next_request_id;
        self.next_request_id = self
            .next_request_id
            .checked_add(1)
            .ok_or_else(|| io::Error::other("request ID exhausted"))?;
        write_json_frame(&mut self.stream, &ClientMessage::Request { id, request }).await?;
        Ok(id)
    }

    async fn wait_response(&mut self, id: u64) -> TestResult<Response> {
        loop {
            if let Some(response) = self.responses.remove(&id) {
                return response.map_err(ipc_error);
            }
            match read_json_frame::<_, ServerMessage>(&mut self.stream).await? {
                ServerMessage::Response {
                    id: response_id,
                    result,
                } => {
                    self.responses.insert(response_id, Ok(result));
                }
                ServerMessage::Error {
                    id: response_id,
                    error,
                } => {
                    self.responses.insert(response_id, Err(error));
                }
                ServerMessage::Event { event } => self.events.push(event),
                message => {
                    return Err(io::Error::other(format!(
                        "unexpected IPC message while awaiting response: {message:?}"
                    ))
                    .into());
                }
            }
        }
    }

    async fn request(&mut self, request: Request) -> TestResult<Response> {
        let id = self.send_request(request).await?;
        self.wait_response(id).await
    }

    async fn pairing_pending(&mut self) -> TestResult<PendingPairingInfo> {
        loop {
            if let Some(index) = self
                .events
                .iter()
                .position(|event| matches!(event, Event::PairingPending { .. }))
            {
                let Event::PairingPending { pairing } = self.events.remove(index) else {
                    return Err("pairing event changed after selection".into());
                };
                return Ok(pairing);
            }
            match read_json_frame::<_, ServerMessage>(&mut self.stream).await? {
                ServerMessage::Event { event } => self.events.push(event),
                message => {
                    return Err(io::Error::other(format!(
                        "unexpected IPC message while awaiting pairing: {message:?}"
                    ))
                    .into());
                }
            }
        }
    }

    async fn pairing_resolved(
        &mut self,
        attempt_id: PairingAttemptId,
    ) -> TestResult<rift_ipc::PairingOutcome> {
        loop {
            if let Some(index) = self.events.iter().position(|event| {
                matches!(
                    event,
                    Event::PairingResolved {
                        attempt_id: event_id,
                        ..
                    } if *event_id == attempt_id
                )
            }) {
                let Event::PairingResolved { outcome, .. } = self.events.remove(index) else {
                    return Err("pairing resolution changed after selection".into());
                };
                return Ok(outcome);
            }
            match read_json_frame::<_, ServerMessage>(&mut self.stream).await? {
                ServerMessage::Event { event } => self.events.push(event),
                ServerMessage::Response { id, result } => {
                    self.responses.insert(id, Ok(result));
                }
                ServerMessage::Error { id, error } => {
                    self.responses.insert(id, Err(error));
                }
                message => {
                    return Err(io::Error::other(format!(
                        "unexpected IPC message while awaiting pairing resolution: {message:?}"
                    ))
                    .into());
                }
            }
        }
    }

    async fn session_opened(&mut self) -> TestResult<SessionInfo> {
        loop {
            if let Some(index) = self
                .events
                .iter()
                .position(|event| matches!(event, Event::SessionOpened { .. }))
            {
                let Event::SessionOpened { session } = self.events.remove(index) else {
                    return Err("session event changed after selection".into());
                };
                return Ok(session);
            }
            match read_json_frame::<_, ServerMessage>(&mut self.stream).await? {
                ServerMessage::Event { event } => self.events.push(event),
                message => {
                    return Err(io::Error::other(format!(
                        "unexpected IPC message while awaiting session: {message:?}"
                    ))
                    .into());
                }
            }
        }
    }
}

fn ipc_error(error: ErrorResponse) -> Box<dyn Error + Send + Sync> {
    io::Error::other(format!("IPC {:?}: {}", error.code, error.message)).into()
}

async fn pair_through_ipc(
    first: &RunningDaemon,
    second: &RunningDaemon,
    first_client: &mut IpcClient,
    second_client: &mut IpcClient,
) -> TestResult<(SessionInfo, SessionInfo)> {
    let first_attempt = first
        .handle
        .begin_pairing(second.handle.endpoint_addr())
        .await?;
    let first_pending = first_client.pairing_pending().await?;
    let second_pending = second_client.pairing_pending().await?;
    assert_eq!(first_pending.attempt_id, first_attempt);
    assert_eq!(first_pending.device_id, second.handle.device_id());
    assert_eq!(second_pending.device_id, first.handle.device_id());
    assert_eq!(
        first_pending.verification_code,
        second_pending.verification_code
    );

    let first_request = first_client
        .send_request(Request::ConfirmPairing {
            attempt_id: first_pending.attempt_id,
            accepted: true,
        })
        .await?;
    let second_request = second_client
        .send_request(Request::ConfirmPairing {
            attempt_id: second_pending.attempt_id,
            accepted: true,
        })
        .await?;
    let (first_response, second_response) = tokio::try_join!(
        first_client.wait_response(first_request),
        second_client.wait_response(second_request)
    )?;
    assert!(matches!(
        first_response,
        Response::PairingResolved {
            accepted: true,
            session_id: Some(_),
            ..
        }
    ));
    assert!(matches!(
        second_response,
        Response::PairingResolved {
            accepted: true,
            session_id: Some(_),
            ..
        }
    ));
    let first_session = first_client.session_opened().await?;
    let second_session = second_client.session_opened().await?;
    Ok((first_session, second_session))
}

fn assert_trusted_page(response: Response, expected: DeviceId) -> TestResult {
    let Response::Peers { page } = response else {
        return Err("ListPeers returned the wrong response".into());
    };
    assert!(
        page.entries
            .iter()
            .any(|peer| { peer.device_id == expected && peer.state == TrustState::Trusted })
    );
    Ok(())
}

#[tokio::test]
async fn two_daemon_pairing_restart_and_live_revocation_flow_through_ipc() -> TestResult {
    tokio::time::timeout(Duration::from_secs(40), async {
        let first_directory = TempDir::new()?;
        let second_directory = TempDir::new()?;
        let first = RunningDaemon::start(&first_directory, "Node A").await?;
        let second = RunningDaemon::start(&second_directory, "Node B").await?;
        let first_id = first.handle.device_id();
        let second_id = second.handle.device_id();
        let mut first_client = IpcClient::authenticate(&first.descriptor).await?;
        let mut second_client = IpcClient::authenticate(&second.descriptor).await?;

        let (first_session, second_session) =
            pair_through_ipc(&first, &second, &mut first_client, &mut second_client).await?;
        assert_eq!(first_session.device_id, second_id);
        assert_eq!(second_session.device_id, first_id);
        assert_trusted_page(
            first_client
                .request(Request::ListPeers {
                    after: None,
                    limit: 128,
                })
                .await?,
            second_id,
        )?;
        assert_trusted_page(
            second_client
                .request(Request::ListPeers {
                    after: None,
                    limit: 128,
                })
                .await?,
            first_id,
        )?;

        assert_eq!(
            first_client
                .request(Request::ForgetPeer {
                    device_id: second_id,
                })
                .await?,
            Response::PeerForgotten {
                device_id: second_id,
            }
        );
        assert_eq!(
            second_client
                .request(Request::ForgetPeer {
                    device_id: first_id,
                })
                .await?,
            Response::PeerForgotten {
                device_id: first_id,
            }
        );
        let Response::Sessions { sessions } =
            first_client.request(Request::ListSessions {}).await?
        else {
            return Err("ListSessions returned the wrong response after forget".into());
        };
        assert!(sessions.is_empty());
        assert!(
            first
                .handle
                .connect_authenticated(second.handle.endpoint_addr())
                .await
                .is_err()
        );
        let (first_session, second_session) =
            pair_through_ipc(&first, &second, &mut first_client, &mut second_client).await?;
        assert_eq!(first_session.device_id, second_id);
        assert_eq!(second_session.device_id, first_id);

        drop(first_client);
        drop(second_client);
        first.shutdown().await?;
        second.shutdown().await?;

        let first = RunningDaemon::start(&first_directory, "Node A").await?;
        let second = RunningDaemon::start(&second_directory, "Node B").await?;
        assert_eq!(first.handle.device_id(), first_id);
        assert_eq!(second.handle.device_id(), second_id);
        let mut first_client = IpcClient::authenticate(&first.descriptor).await?;
        let mut second_client = IpcClient::authenticate(&second.descriptor).await?;

        let outbound_session = first
            .handle
            .connect_authenticated(second.handle.endpoint_addr())
            .await?;
        let first_opened = first_client.session_opened().await?;
        let second_opened = second_client.session_opened().await?;
        assert_eq!(first_opened.session_id, outbound_session);
        assert_eq!(first_opened.device_id, second_id);
        assert_eq!(second_opened.device_id, first_id);
        assert!(
            !first_client
                .events
                .iter()
                .any(|event| matches!(event, Event::PairingPending { .. }))
        );
        assert!(
            !second_client
                .events
                .iter()
                .any(|event| matches!(event, Event::PairingPending { .. }))
        );

        let response = first_client
            .request(Request::RevokePeer {
                device_id: second_id,
            })
            .await?;
        assert_eq!(
            response,
            Response::PeerRevoked {
                device_id: second_id
            }
        );
        let Response::Sessions { sessions } =
            first_client.request(Request::ListSessions {}).await?
        else {
            return Err("ListSessions returned the wrong response".into());
        };
        assert!(sessions.is_empty());
        assert!(
            first
                .handle
                .connect_authenticated(second.handle.endpoint_addr())
                .await
                .is_err()
        );

        drop(first_client);
        drop(second_client);
        first.shutdown().await?;
        second.shutdown().await?;
        Ok::<_, Box<dyn Error + Send + Sync>>(())
    })
    .await
    .map_err(|_| "two-daemon lifecycle test timed out")??;
    Ok(())
}

#[tokio::test]
async fn duplicate_dial_keeps_canonical_session_even_at_global_capacity() -> TestResult {
    tokio::time::timeout(Duration::from_secs(20), async {
        let first_directory = TempDir::new()?;
        let second_directory = TempDir::new()?;
        let mut first_config = test_config(&first_directory, "Bound A");
        let mut second_config = test_config(&second_directory, "Bound B");
        first_config.max_active_sessions = 1;
        second_config.max_active_sessions = 1;
        let first = RunningDaemon::spawn(Daemon::start(first_config).await?);
        let second = RunningDaemon::spawn(Daemon::start(second_config).await?);
        let mut first_client = IpcClient::authenticate(&first.descriptor).await?;
        let mut second_client = IpcClient::authenticate(&second.descriptor).await?;
        let (first_session, _second_session) =
            pair_through_ipc(&first, &second, &mut first_client, &mut second_client).await?;

        assert_eq!(
            first
                .handle
                .connect_authenticated(second.handle.endpoint_addr())
                .await?,
            first_session.session_id
        );
        let Response::Sessions { sessions } =
            first_client.request(Request::ListSessions {}).await?
        else {
            return Err("ListSessions returned the wrong capacity response".into());
        };
        assert_eq!(sessions, vec![first_session]);

        drop(first_client);
        drop(second_client);
        first.shutdown().await?;
        second.shutdown().await?;
        Ok::<_, Box<dyn Error + Send + Sync>>(())
    })
    .await
    .map_err(|_| "active session bound test timed out")??;
    Ok(())
}

#[tokio::test]
async fn pending_pairings_expire_and_release_registry_slots() -> TestResult {
    tokio::time::timeout(Duration::from_secs(10), async {
        let first_directory = TempDir::new()?;
        let second_directory = TempDir::new()?;
        let mut first_config = test_config(&first_directory, "Expiry A");
        let mut second_config = test_config(&second_directory, "Expiry B");
        first_config.pairing_timeout = Duration::from_secs(2);
        second_config.pairing_timeout = Duration::from_secs(30);
        first_config.max_pending_pairings = 1;
        second_config.max_pending_pairings = 1;
        let first = RunningDaemon::spawn(Daemon::start(first_config).await?);
        let second = RunningDaemon::spawn(Daemon::start(second_config).await?);
        let mut first_client = IpcClient::authenticate(&first.descriptor).await?;
        let mut second_client = IpcClient::authenticate(&second.descriptor).await?;

        first
            .handle
            .begin_pairing(second.handle.endpoint_addr())
            .await?;
        let first_pending = first_client.pairing_pending().await?;
        let second_pending = second_client.pairing_pending().await?;
        assert!(
            first
                .handle
                .begin_pairing(second.handle.endpoint_addr())
                .await
                .is_err()
        );
        let Response::PendingPairings { pairings } = first_client
            .request(Request::ListPendingPairings {})
            .await?
        else {
            return Err("ListPendingPairings returned the wrong bounded response".into());
        };
        assert_eq!(pairings.len(), 1);
        assert_eq!(
            first_client
                .pairing_resolved(first_pending.attempt_id)
                .await?,
            rift_ipc::PairingOutcome::Expired
        );
        assert_eq!(
            second_client
                .pairing_resolved(second_pending.attempt_id)
                .await?,
            rift_ipc::PairingOutcome::Failed
        );
        let replacement_attempt = first
            .handle
            .begin_pairing(second.handle.endpoint_addr())
            .await?;
        assert_ne!(replacement_attempt, first_pending.attempt_id);
        let Response::PendingPairings { pairings } = first_client
            .request(Request::ListPendingPairings {})
            .await?
        else {
            return Err("ListPendingPairings returned the wrong replacement response".into());
        };
        assert_eq!(pairings.len(), 1);
        assert_eq!(pairings[0].attempt_id, replacement_attempt);

        drop(first_client);
        drop(second_client);
        first.shutdown().await?;
        second.shutdown().await?;
        Ok::<_, Box<dyn Error + Send + Sync>>(())
    })
    .await
    .map_err(|_| "pairing expiry test timed out")??;
    Ok(())
}

#[tokio::test]
async fn revoke_racing_pairing_confirmation_cannot_leave_authorization() -> TestResult {
    tokio::time::timeout(Duration::from_secs(20), async {
        let first_directory = TempDir::new()?;
        let second_directory = TempDir::new()?;
        let first = RunningDaemon::start(&first_directory, "Race A").await?;
        let second = RunningDaemon::start(&second_directory, "Race B").await?;
        let mut first_client = IpcClient::authenticate(&first.descriptor).await?;
        let mut second_client = IpcClient::authenticate(&second.descriptor).await?;
        first
            .handle
            .begin_pairing(second.handle.endpoint_addr())
            .await?;
        let first_pending = first_client.pairing_pending().await?;
        let second_pending = second_client.pairing_pending().await?;

        let first_confirmation = first_client
            .send_request(Request::ConfirmPairing {
                attempt_id: first_pending.attempt_id,
                accepted: true,
            })
            .await?;
        let revocation = first_client
            .send_request(Request::RevokePeer {
                device_id: second.handle.device_id(),
            })
            .await?;
        let second_confirmation = second_client
            .send_request(Request::ConfirmPairing {
                attempt_id: second_pending.attempt_id,
                accepted: true,
            })
            .await?;

        assert_eq!(
            first_client.wait_response(revocation).await?,
            Response::PeerRevoked {
                device_id: second.handle.device_id(),
            }
        );
        let _first_resolution = first_client.wait_response(first_confirmation).await;
        let _second_resolution = second_client.wait_response(second_confirmation).await;

        let Response::Peers { page } = first_client
            .request(Request::ListPeers {
                after: None,
                limit: 128,
            })
            .await?
        else {
            return Err("ListPeers returned the wrong race response".into());
        };
        assert!(page.entries.iter().any(|peer| {
            peer.device_id == second.handle.device_id() && peer.state == TrustState::Revoked
        }));
        let Response::Sessions { sessions } =
            first_client.request(Request::ListSessions {}).await?
        else {
            return Err("ListSessions returned the wrong race response".into());
        };
        assert!(sessions.is_empty());
        let Response::PendingPairings { pairings } = first_client
            .request(Request::ListPendingPairings {})
            .await?
        else {
            return Err("ListPendingPairings returned the wrong race response".into());
        };
        assert!(pairings.is_empty());
        assert!(
            first
                .handle
                .connect_authenticated(second.handle.endpoint_addr())
                .await
                .is_err()
        );

        drop(first_client);
        drop(second_client);
        first.shutdown().await?;
        second.shutdown().await?;
        Ok::<_, Box<dyn Error + Send + Sync>>(())
    })
    .await
    .map_err(|_| "pairing/revocation race test timed out")??;
    Ok(())
}

#[tokio::test]
async fn forget_racing_pairing_confirmation_cannot_leave_trust_or_authorization() -> TestResult {
    tokio::time::timeout(Duration::from_secs(20), async {
        let first_directory = TempDir::new()?;
        let second_directory = TempDir::new()?;
        let first = RunningDaemon::start(&first_directory, "Forget race A").await?;
        let second = RunningDaemon::start(&second_directory, "Forget race B").await?;
        let mut first_client = IpcClient::authenticate(&first.descriptor).await?;
        let mut second_client = IpcClient::authenticate(&second.descriptor).await?;
        first
            .handle
            .begin_pairing(second.handle.endpoint_addr())
            .await?;
        let first_pending = first_client.pairing_pending().await?;
        let second_pending = second_client.pairing_pending().await?;

        let first_confirmation = first_client
            .send_request(Request::ConfirmPairing {
                attempt_id: first_pending.attempt_id,
                accepted: true,
            })
            .await?;
        let forget = first_client
            .send_request(Request::ForgetPeer {
                device_id: second.handle.device_id(),
            })
            .await?;
        let second_confirmation = second_client
            .send_request(Request::ConfirmPairing {
                attempt_id: second_pending.attempt_id,
                accepted: true,
            })
            .await?;

        assert_eq!(
            first_client.wait_response(forget).await?,
            Response::PeerForgotten {
                device_id: second.handle.device_id(),
            }
        );
        let _first_resolution = first_client.wait_response(first_confirmation).await;
        let _second_resolution = second_client.wait_response(second_confirmation).await;

        let Response::Peers { page } = first_client
            .request(Request::ListPeers {
                after: None,
                limit: 128,
            })
            .await?
        else {
            return Err("ListPeers returned the wrong forget-race response".into());
        };
        assert!(
            !page
                .entries
                .iter()
                .any(|peer| peer.device_id == second.handle.device_id())
        );

        let Response::Sessions { sessions } =
            first_client.request(Request::ListSessions {}).await?
        else {
            return Err("ListSessions returned the wrong forget-race response".into());
        };
        assert!(sessions.is_empty());
        let Response::PendingPairings { pairings } = first_client
            .request(Request::ListPendingPairings {})
            .await?
        else {
            return Err("ListPendingPairings returned the wrong forget-race response".into());
        };
        assert!(pairings.is_empty());

        assert!(matches!(
            first
                .handle
                .connect_authenticated(second.handle.endpoint_addr())
                .await,
            Err(DaemonHandleError::Operation(error))
                if error.code == ErrorCode::PeerNotTrusted
        ));

        drop(first_client);
        drop(second_client);
        first.shutdown().await?;
        second.shutdown().await?;
        Ok::<_, Box<dyn Error + Send + Sync>>(())
    })
    .await
    .map_err(|_| "pairing/forget race test timed out")??;
    Ok(())
}

#[test]
fn pairing_attempt_ids_are_runtime_local_values() {
    assert_ne!(PairingAttemptId(1), PairingAttemptId(2));
}

async fn connectivity(handle: &DaemonHandle) -> TestResult<Vec<rift_ipc::PeerConnectivityInfo>> {
    let Response::PeerConnectivity { page } = handle
        .request(Request::ListPeerConnectivity {
            after: None,
            limit: 128,
        })
        .await?
    else {
        return Err("unexpected connectivity response".into());
    };
    Ok(page.entries)
}

impl IpcClient {
    async fn connectivity_changed(
        &mut self,
        state: rift_ipc::ConnectivityState,
    ) -> TestResult<rift_ipc::PeerConnectivityInfo> {
        loop {
            if let Some(index) = self.events.iter().position(|event| {
                matches!(event,
                Event::PeerConnectivityChanged { connectivity } if connectivity.state == state)
            }) && let Event::PeerConnectivityChanged { connectivity } = self.events.remove(index)
            {
                return Ok(connectivity);
            }
            match read_json_frame::<_, ServerMessage>(&mut self.stream).await? {
                ServerMessage::Event { event } => self.events.push(event),
                message => {
                    return Err(io::Error::other(format!(
                        "unexpected message waiting for connectivity: {message:?}"
                    ))
                    .into());
                }
            }
        }
    }
}

#[tokio::test]
async fn whole_connection_loss_reconnects_automatically_without_pairing() -> TestResult {
    tokio::time::timeout(Duration::from_secs(15), async {
        let first_directory = TempDir::new()?;
        let second_directory = TempDir::new()?;
        let first = RunningDaemon::start(&first_directory, "Reconnect A").await?;
        let second = RunningDaemon::start(&second_directory, "Reconnect B").await?;
        first
            .handle
            .remember_peer_addr(second.handle.endpoint_addr())
            .await?;
        second
            .handle
            .remember_peer_addr(first.handle.endpoint_addr())
            .await?;
        let mut first_client = IpcClient::authenticate(&first.descriptor).await?;
        let mut second_client = IpcClient::authenticate(&second.descriptor).await?;
        let (old_a, old_b) =
            pair_through_ipc(&first, &second, &mut first_client, &mut second_client).await?;
        first
            .handle
            .session_handle_for_test(old_a.session_id)
            .await?
            .close();
        let (new_a, new_b) = tokio::try_join!(
            first_client.session_opened(),
            second_client.session_opened()
        )?;
        assert_ne!(old_a.session_id, new_a.session_id);
        assert_ne!(old_b.session_id, new_b.session_id);
        assert_eq!(new_a.device_id, second.handle.device_id());
        assert_eq!(new_b.device_id, first.handle.device_id());
        for handle in [&first.handle, &second.handle] {
            let Response::Sessions { sessions } = handle.request(Request::ListSessions {}).await?
            else {
                return Err("wrong sessions response".into());
            };
            assert_eq!(sessions.len(), 1);
            let Response::PendingPairings { pairings } =
                handle.request(Request::ListPendingPairings {}).await?
            else {
                return Err("wrong pairing response".into());
            };
            assert!(pairings.is_empty());
            assert_eq!(connectivity(handle).await?.len(), 1);
        }
        assert!(
            !first_client
                .events
                .iter()
                .chain(&second_client.events)
                .any(|event| matches!(event, Event::PairingPending { .. }))
        );
        drop(first_client);
        drop(second_client);
        first.shutdown().await?;
        second.shutdown().await?;
        Ok::<_, Box<dyn Error + Send + Sync>>(())
    })
    .await??;
    Ok(())
}

#[tokio::test]
async fn asymmetric_forget_blocks_automatic_session_reconnect_without_pairing_or_hot_loop()
-> TestResult {
    use rift_ipc::{ConnectivityFailure, ConnectivityState};
    tokio::time::timeout(Duration::from_secs(15), async {
        let first_directory = TempDir::new()?;
        let second_directory = TempDir::new()?;
        let first = RunningDaemon::start(&first_directory, "Asymmetric A").await?;
        let second = RunningDaemon::start(&second_directory, "Asymmetric B").await?;
        let mut first_client = IpcClient::authenticate(&first.descriptor).await?;
        let mut second_client = IpcClient::authenticate(&second.descriptor).await?;
        pair_through_ipc(&first, &second, &mut first_client, &mut second_client).await?;
        second_client
            .request(Request::ForgetPeer {
                device_id: first.handle.device_id(),
            })
            .await?;
        let blocked = first_client
            .connectivity_changed(ConnectivityState::Blocked)
            .await?;
        assert_eq!(
            blocked.last_failure,
            Some(ConnectivityFailure::PurposeRejected)
        );
        assert_eq!(blocked.retry_in_ms, None);
        let snapshot = connectivity(&first.handle).await?;
        assert_eq!(snapshot, vec![blocked]);
        let Response::PendingPairings { pairings } = second_client
            .request(Request::ListPendingPairings {})
            .await?
        else {
            return Err("wrong pairing response".into());
        };
        assert!(pairings.is_empty());
        assert!(
            !second_client
                .events
                .iter()
                .any(|event| matches!(event, Event::PairingPending { .. }))
        );
        assert_trusted_page(
            first_client
                .request(Request::ListPeers {
                    after: None,
                    limit: 128,
                })
                .await?,
            second.handle.device_id(),
        )?;
        assert!(connectivity(&second.handle).await?.is_empty());
        // No timer is armed for the rejection; repeated observation does not advance attempts.
        assert_eq!(connectivity(&first.handle).await?, snapshot);
        drop(first_client);
        drop(second_client);
        first.shutdown().await?;
        second.shutdown().await?;
        Ok::<_, Box<dyn Error + Send + Sync>>(())
    })
    .await??;
    Ok(())
}

#[tokio::test]
async fn disconnect_suspends_local_outbound_and_identity_only_connect_resumes_it() -> TestResult {
    use rift_ipc::ConnectivityState;
    tokio::time::timeout(Duration::from_secs(15), async {
        let first_directory = TempDir::new()?;
        let second_directory = TempDir::new()?;
        let first = RunningDaemon::start(&first_directory, "Suspend A").await?;
        let second = RunningDaemon::start(&second_directory, "Suspend B").await?;
        let mut first_client = IpcClient::authenticate(&first.descriptor).await?;
        let mut second_client = IpcClient::authenticate(&second.descriptor).await?;
        let (old_a, _) =
            pair_through_ipc(&first, &second, &mut first_client, &mut second_client).await?;
        first_client
            .request(Request::DisconnectSession {
                session_id: old_a.session_id,
            })
            .await?;
        let snapshot = connectivity(&first.handle).await?;
        assert_eq!(snapshot[0].state, ConnectivityState::Suspended);
        assert_eq!(snapshot[0].retry_in_ms, None);
        // B has no hint, so it settles Unresolved instead of racing the local suspension.
        second_client
            .connectivity_changed(ConnectivityState::Unresolved)
            .await?;
        let Response::PeerConnected { session_id, .. } = first_client
            .request(Request::ConnectPeer {
                device_id: second.handle.device_id(),
            })
            .await?
        else {
            return Err("wrong ConnectPeer response".into());
        };
        assert_ne!(session_id, old_a.session_id);
        assert_eq!(
            connectivity(&first.handle).await?[0].state,
            ConnectivityState::Connected
        );
        let Response::PeerConnected {
            session_id: same_id,
            ..
        } = first_client
            .request(Request::ConnectPeer {
                device_id: second.handle.device_id(),
            })
            .await?
        else {
            return Err("wrong connected response".into());
        };
        assert_eq!(same_id, session_id);
        assert_trusted_page(
            first_client
                .request(Request::ListPeers {
                    after: None,
                    limit: 128,
                })
                .await?,
            second.handle.device_id(),
        )?;
        drop(first_client);
        drop(second_client);
        first.shutdown().await?;
        second.shutdown().await?;
        Ok::<_, Box<dyn Error + Send + Sync>>(())
    })
    .await??;
    Ok(())
}

#[tokio::test]
async fn identity_only_pairing_ipc_requires_unknown_routable_peer_and_explicit_confirmation()
-> TestResult {
    tokio::time::timeout(Duration::from_secs(15), async {
        let first_directory = TempDir::new()?;
        let second_directory = TempDir::new()?;
        let first = RunningDaemon::start(&first_directory, "IPC A").await?;
        let second = RunningDaemon::start(&second_directory, "IPC B").await?;
        let peer_id = second.handle.device_id();
        assert!(matches!(first.handle.request(Request::BeginPairing { device_id: peer_id }).await, Err(DaemonHandleError::Operation(error)) if error.code == ErrorCode::PeerUnresolved));
        assert!(matches!(first.handle.request(Request::ConnectPeer { device_id: peer_id }).await, Err(DaemonHandleError::Operation(error)) if error.code == ErrorCode::PeerNotTrusted));
        assert!(matches!(first.handle.request(Request::BeginPairing { device_id: first.handle.device_id() }).await, Err(DaemonHandleError::Operation(error)) if error.code == ErrorCode::InvalidRequest));
        first.handle.remember_peer_addr(second.handle.endpoint_addr()).await?;
        let mut first_client = IpcClient::authenticate(&first.descriptor).await?;
        let mut second_client = IpcClient::authenticate(&second.descriptor).await?;
        let Response::PairingStarted { attempt_id } = first_client.request(Request::BeginPairing { device_id: peer_id }).await? else { return Err("wrong BeginPairing response".into()); };
        let first_pending = first_client.pairing_pending().await?;
        let second_pending = second_client.pairing_pending().await?;
        assert_eq!(attempt_id, first_pending.attempt_id);
        assert_eq!(first_pending.verification_code, second_pending.verification_code);
        assert!(connectivity(&first.handle).await?.is_empty());
        let (a, b) = tokio::try_join!(
            first_client.request(Request::ConfirmPairing { attempt_id, accepted: true }),
            second_client.request(Request::ConfirmPairing { attempt_id: second_pending.attempt_id, accepted: true }),
        )?;
        assert!(matches!(a, Response::PairingResolved { accepted: true, .. }));
        assert!(matches!(b, Response::PairingResolved { accepted: true, .. }));
        assert!(matches!(first.handle.request(Request::BeginPairing { device_id: peer_id }).await, Err(DaemonHandleError::Operation(error)) if error.code == ErrorCode::PeerAlreadyTrusted));
        first.handle.request(Request::RevokePeer { device_id: peer_id }).await?;
        assert!(matches!(first.handle.request(Request::BeginPairing { device_id: peer_id }).await, Err(DaemonHandleError::Operation(error)) if error.code == ErrorCode::PeerNotTrusted));
        drop(first_client); drop(second_client);
        first.shutdown().await?; second.shutdown().await?;
        Ok::<_, Box<dyn Error + Send + Sync>>(())
    }).await??;
    Ok(())
}

#[tokio::test]
async fn injected_memory_lookup_reconnects_by_identity_after_daemon_restart() -> TestResult {
    use rift_transport_iroh::{AddressLookupConfiguration, MemoryLookup};
    tokio::time::timeout(Duration::from_secs(20), async {
        let first_directory = TempDir::new()?;
        let second_directory = TempDir::new()?;
        let lookup = MemoryLookup::new();
        let mut first_config = test_config(&first_directory, "Restart A");
        first_config.address_lookup = AddressLookupConfiguration::Memory(lookup.clone());
        let mut second_config = test_config(&second_directory, "Restart B");
        second_config.address_lookup = AddressLookupConfiguration::Memory(lookup.clone());
        let first = RunningDaemon::spawn(Daemon::start(first_config.clone()).await?);
        let second = RunningDaemon::spawn(Daemon::start(second_config.clone()).await?);
        lookup.add_endpoint_info(first.handle.endpoint_addr());
        lookup.add_endpoint_info(second.handle.endpoint_addr());
        let first_id = first.handle.device_id();
        let second_id = second.handle.device_id();
        let mut first_client = IpcClient::authenticate(&first.descriptor).await?;
        let mut second_client = IpcClient::authenticate(&second.descriptor).await?;
        pair_through_ipc(&first, &second, &mut first_client, &mut second_client).await?;
        drop(first_client);
        drop(second_client);
        first.shutdown().await?;
        second.shutdown().await?;

        let first_daemon = Daemon::start(first_config).await?;
        let second_daemon = Daemon::start(second_config).await?;
        assert_eq!(first_daemon.handle().device_id(), first_id);
        assert_eq!(second_daemon.handle().device_id(), second_id);
        let _previous = lookup.set_endpoint_info(first_daemon.handle().endpoint_addr());
        let _previous = lookup.set_endpoint_info(second_daemon.handle().endpoint_addr());
        let first = RunningDaemon::spawn(first_daemon);
        let second = RunningDaemon::spawn(second_daemon);
        // Read state via the control handle, then use an authenticated event stream for
        // whichever daemon has not completed automatic startup dialing yet.
        let mut first_client = IpcClient::authenticate(&first.descriptor).await?;
        if connectivity(&first.handle).await?[0].session_id.is_none() {
            first_client
                .connectivity_changed(rift_ipc::ConnectivityState::Connected)
                .await?;
        }
        let mut second_client = IpcClient::authenticate(&second.descriptor).await?;
        if connectivity(&second.handle).await?[0].session_id.is_none() {
            second_client
                .connectivity_changed(rift_ipc::ConnectivityState::Connected)
                .await?;
        }
        for handle in [&first.handle, &second.handle] {
            let Response::PendingPairings { pairings } =
                handle.request(Request::ListPendingPairings {}).await?
            else {
                return Err("wrong pairing response".into());
            };
            assert!(pairings.is_empty());
            assert_eq!(
                connectivity(handle).await?[0].state,
                rift_ipc::ConnectivityState::Connected
            );
        }
        drop(first_client);
        drop(second_client);
        first.shutdown().await?;
        second.shutdown().await?;
        Ok::<_, Box<dyn Error + Send + Sync>>(())
    })
    .await??;
    Ok(())
}
