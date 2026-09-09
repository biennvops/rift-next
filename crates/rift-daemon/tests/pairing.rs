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
async fn active_session_bounds_reject_new_connections_without_eviction() -> TestResult {
    tokio::time::timeout(Duration::from_secs(20), async {
        let first_directory = TempDir::new()?;
        let second_directory = TempDir::new()?;
        let mut first_config = test_config(&first_directory, "Bound A");
        let mut second_config = test_config(&second_directory, "Bound B");
        first_config.max_active_sessions = 1;
        first_config.max_sessions_per_peer = 1;
        second_config.max_active_sessions = 1;
        second_config.max_sessions_per_peer = 1;
        let first = RunningDaemon::spawn(Daemon::start(first_config).await?);
        let second = RunningDaemon::spawn(Daemon::start(second_config).await?);
        let mut first_client = IpcClient::authenticate(&first.descriptor).await?;
        let mut second_client = IpcClient::authenticate(&second.descriptor).await?;
        let (first_session, _second_session) =
            pair_through_ipc(&first, &second, &mut first_client, &mut second_client).await?;

        assert!(
            first
                .handle
                .connect_authenticated(second.handle.endpoint_addr())
                .await
                .is_err()
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
