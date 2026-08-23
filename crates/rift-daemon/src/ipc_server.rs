use std::{collections::BTreeSet, future::Future, pin::Pin, time::Duration};

use futures_util::{StreamExt, stream::FuturesUnordered};
use rift_ipc::{
    ClientMessage, ErrorCode, ErrorResponse, Event, FrameError, IPC_PROTOCOL_VERSION, Request,
    ServerMessage, read_json_frame, write_json_frame,
};
use thiserror::Error;
use tokio::sync::{broadcast, mpsc, watch};

use crate::{AuthToken, DaemonHandle, DaemonHandleError, local::LocalStream};

const AUTHENTICATION_TIMEOUT: Duration = Duration::from_secs(5);
const OUTGOING_QUEUE_CAPACITY: usize = 64;
const MAX_OUTSTANDING_REQUESTS: usize = 16;

type ResponseFuture = Pin<Box<dyn Future<Output = (u64, ServerMessage)> + Send>>;

#[derive(Debug, Error)]
pub(crate) enum ClientError {
    #[error("local IPC authentication timed out")]
    AuthenticationTimeout,
    #[error("local IPC authentication failed")]
    AuthenticationFailed,
    #[error("local IPC frame failed: {0}")]
    Frame(#[from] FrameError),
    #[error("local IPC client sent an authentication frame after authentication")]
    DuplicateAuthentication,
    #[error("local IPC client reused outstanding request ID {0}")]
    DuplicateRequestId(u64),
    #[error("local IPC client exceeded {MAX_OUTSTANDING_REQUESTS} outstanding requests")]
    TooManyOutstandingRequests,
    #[error("local IPC client lagged its bounded outgoing queue")]
    OutgoingQueueFull,
    #[error("local IPC event receiver lagged by {0} events")]
    EventLagged(u64),
    #[error("local IPC writer task stopped")]
    WriterStopped,
    #[error("local IPC writer task failed: {0}")]
    WriterTask(#[source] tokio::task::JoinError),
}

pub(crate) async fn serve_client(
    mut stream: LocalStream,
    auth_token: AuthToken,
    handle: DaemonHandle,
    mut events: broadcast::Receiver<Event>,
    mut shutdown: watch::Receiver<bool>,
) -> Result<(), ClientError> {
    let first = tokio::time::timeout(
        AUTHENTICATION_TIMEOUT,
        read_json_frame::<_, ClientMessage>(&mut stream),
    )
    .await
    .map_err(|_| ClientError::AuthenticationTimeout)??;
    let ClientMessage::Authenticate { version, token } = first else {
        return Err(ClientError::AuthenticationFailed);
    };
    if version != IPC_PROTOCOL_VERSION || !auth_token.matches(&token) {
        return Err(ClientError::AuthenticationFailed);
    }
    tokio::time::timeout(
        AUTHENTICATION_TIMEOUT,
        write_json_frame(
            &mut stream,
            &ServerMessage::Authenticated {
                version: IPC_PROTOCOL_VERSION,
            },
        ),
    )
    .await
    .map_err(|_| ClientError::AuthenticationTimeout)??;

    let (mut reader, writer) = tokio::io::split(stream);
    let (outgoing_tx, outgoing_rx) = mpsc::channel(OUTGOING_QUEUE_CAPACITY);
    let mut writer_tasks = tokio::task::JoinSet::new();
    writer_tasks.spawn(writer_loop(writer, outgoing_rx));
    let mut requests = FuturesUnordered::<ResponseFuture>::new();
    let mut outstanding_ids = BTreeSet::new();
    let mut result = Ok(());
    let mut graceful_shutdown = false;
    let mut shutdown_event_queued = false;

    loop {
        tokio::select! {
            biased;
            changed = shutdown.changed() => {
                if changed.is_err() || *shutdown.borrow() {
                    if !shutdown_event_queued
                        && outgoing_tx
                            .try_send(ServerMessage::Event {
                                event: Event::DaemonShuttingDown,
                            })
                            .is_err()
                    {
                        result = Err(ClientError::OutgoingQueueFull);
                    } else {
                        graceful_shutdown = true;
                    }
                    break;
                }
            }
            writer = writer_tasks.join_next() => {
                result = match writer {
                    Some(Ok(Ok(()))) | None => Err(ClientError::WriterStopped),
                    Some(Ok(Err(error))) => Err(ClientError::Frame(error)),
                    Some(Err(error)) => Err(ClientError::WriterTask(error)),
                };
                break;
            }
            event = events.recv() => {
                match event {
                    Ok(event) => {
                        shutdown_event_queued |= matches!(event, Event::DaemonShuttingDown);
                        if outgoing_tx.try_send(ServerMessage::Event { event }).is_err() {
                            result = Err(ClientError::OutgoingQueueFull);
                            break;
                        }
                    }
                    Err(broadcast::error::RecvError::Lagged(count)) => {
                        result = Err(ClientError::EventLagged(count));
                        break;
                    }
                    Err(broadcast::error::RecvError::Closed) => break,
                }
            }
            completed = requests.next(), if !requests.is_empty() => {
                if let Some((id, message)) = completed {
                    outstanding_ids.remove(&id);
                    if outgoing_tx.try_send(message).is_err() {
                        result = Err(ClientError::OutgoingQueueFull);
                        break;
                    }
                }
            }
            message = read_json_frame::<_, ClientMessage>(&mut reader),
                if requests.len() < MAX_OUTSTANDING_REQUESTS =>
            {
                match message {
                    Ok(ClientMessage::Request { id, request }) => {
                        if !outstanding_ids.insert(id) {
                            result = Err(ClientError::DuplicateRequestId(id));
                            break;
                        }
                        requests.push(request_future(handle.clone(), id, request));
                    }
                    Ok(ClientMessage::Authenticate { .. }) => {
                        result = Err(ClientError::DuplicateAuthentication);
                        break;
                    }
                    Err(FrameError::TruncatedPrefix { actual: 0 }) => break,
                    Err(error) => {
                        result = Err(ClientError::Frame(error));
                        break;
                    }
                }
            }
            else => {
                if requests.len() >= MAX_OUTSTANDING_REQUESTS {
                    result = Err(ClientError::TooManyOutstandingRequests);
                }
                break;
            }
        }
    }

    drop(outgoing_tx);
    if graceful_shutdown {
        match tokio::time::timeout(Duration::from_secs(1), writer_tasks.join_next()).await {
            Ok(Some(Ok(Ok(())))) => {}
            Ok(Some(Ok(Err(error)))) => result = Err(ClientError::Frame(error)),
            Ok(Some(Err(error))) => result = Err(ClientError::WriterTask(error)),
            Ok(None) => result = Err(ClientError::WriterStopped),
            Err(_) => result = Err(ClientError::OutgoingQueueFull),
        }
    }
    writer_tasks.abort_all();
    while let Some(joined) = writer_tasks.join_next().await {
        if let Err(error) = joined
            && !error.is_cancelled()
            && result.is_ok()
        {
            result = Err(ClientError::WriterTask(error));
        }
    }
    result
}

fn request_future(handle: DaemonHandle, id: u64, request: Request) -> ResponseFuture {
    Box::pin(async move {
        let message = match handle.request(request).await {
            Ok(result) => ServerMessage::Response { id, result },
            Err(DaemonHandleError::Operation(error)) => ServerMessage::Error { id, error },
            Err(DaemonHandleError::Stopped) => ServerMessage::Error {
                id,
                error: ErrorResponse::new(ErrorCode::ShuttingDown, "daemon is shutting down"),
            },
        };
        (id, message)
    })
}

async fn writer_loop<W>(
    mut writer: W,
    mut outgoing: mpsc::Receiver<ServerMessage>,
) -> Result<(), FrameError>
where
    W: tokio::io::AsyncWrite + Unpin,
{
    while let Some(message) = outgoing.recv().await {
        write_json_frame(&mut writer, &message).await?;
    }
    Ok(())
}
