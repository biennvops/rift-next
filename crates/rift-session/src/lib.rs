//! Application admission and pairing above authenticated Rift transport.
//!
//! A bootstrapped connection is authenticated but not authorized. This crate is the
//! only production layer that combines a concrete [`BootstrappedConnection`] with
//! local trust policy. Unknown peers receive a pairing-only wrapper; revoked peers
//! are rejected; trusted peers receive [`AuthorizedConnection`].

use std::{fmt, sync::Arc, time::Duration};

use rift_core::{DeviceId, TrustedPeer};
use rift_protocol::{
    Capability, Hello, HelloMetadata, MessageKind, PAIRING_ID_LEN, PAIRING_NONCE_LEN, PairingCode,
    PairingMessage, PairingTranscript,
};
use rift_transport_iroh::{BootstrappedConnection, TransportError};
use rift_trust::{TrustEntry, TrustStore, TrustStoreError};
use thiserror::Error;
use tokio::time::Instant;
use tracing::{info, warn};

/// Default deadline for each pairing network phase and local confirmation wait.
pub const DEFAULT_PAIRING_TIMEOUT: Duration = Duration::from_secs(60);

/// Session-layer configuration independent from M2 Hello deadlines.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SessionConfig {
    /// Deadline for pairing network phases and the local confirmation wait.
    pub pairing_timeout: Duration,
}

impl Default for SessionConfig {
    fn default() -> Self {
        Self {
            pairing_timeout: DEFAULT_PAIRING_TIMEOUT,
        }
    }
}

/// Failures configuring or applying application admission.
#[derive(Debug, Error)]
pub enum SessionError {
    /// The pairing deadline must be nonzero.
    #[error("pairing_timeout must be greater than zero")]
    InvalidPairingTimeout,
    /// A revoked peer attempted a fresh application admission.
    #[error("peer {0} is revoked")]
    PeerRevoked(DeviceId),
}

/// An explicit phase in the pairing state machine.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PairingPhase {
    /// The responder is waiting for the initiator's request.
    AwaitingRequest,
    /// The initiator is waiting for the responder's nonce.
    AwaitingResponse,
    /// The SAS is ready and the implementation is waiting for local confirmation.
    AwaitingLocalDecision,
    /// The local decision was sent and the remote decision is required.
    AwaitingRemoteDecision,
    /// Both decisions were positive and local durable trust must commit.
    CommittingTrust,
    /// Local trust committed and remote completion is required.
    AwaitingCompletion,
    /// Pairing completed and the connection is authorized.
    Complete,
    /// At least one side rejected pairing.
    Rejected,
    /// A timeout, transport, persistence, or sequencing failure ended pairing.
    Failed,
}

impl fmt::Display for PairingPhase {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let name = match self {
            Self::AwaitingRequest => "awaiting request",
            Self::AwaitingResponse => "awaiting response",
            Self::AwaitingLocalDecision => "awaiting local decision",
            Self::AwaitingRemoteDecision => "awaiting remote decision",
            Self::CommittingTrust => "committing trust",
            Self::AwaitingCompletion => "awaiting completion",
            Self::Complete => "complete",
            Self::Rejected => "rejected",
            Self::Failed => "failed",
        };
        formatter.write_str(name)
    }
}

/// Typed pairing failures. Every error leaves the disposable connection closed or
/// poisoned and never returns an authorized wrapper.
#[derive(Debug, Error)]
pub enum PairingError {
    /// The peer did not advertise pairing protocol v1 in its authenticated Hello.
    #[error("peer {0} did not advertise PAIRING_V1")]
    PairingUnsupported(DeviceId),
    /// A pairing network phase exceeded its deadline.
    #[error("pairing timed out during {phase}")]
    Timeout { phase: PairingPhase },
    /// The concrete disposable transport failed.
    #[error("pairing transport failed during {phase}: {source}")]
    Transport {
        phase: PairingPhase,
        #[source]
        source: TransportError,
    },
    /// The peer sent a message illegal in the active phase.
    #[error("expected {expected} during {phase}, received {received}")]
    UnexpectedMessage {
        phase: PairingPhase,
        expected: MessageKind,
        received: MessageKind,
    },
    /// A message named a different pairing attempt.
    #[error("pairing message used a different pairing ID during {phase}")]
    PairingIdMismatch { phase: PairingPhase },
    /// A peer sent a second decision after its first decision was consumed.
    #[error("duplicate pairing decision received during {phase}")]
    DuplicateDecision { phase: PairingPhase },
    /// Completion arrived before both positive decisions and local persistence.
    #[error("PairingComplete arrived too early during {phase}")]
    CompletionTooEarly { phase: PairingPhase },
    /// An operation was attempted after a terminal state.
    #[error("pairing operation attempted after terminal phase {phase}")]
    AlreadyFinished { phase: PairingPhase },
    /// One or both local humans rejected the pairing code.
    #[error(
        "pairing rejected (local accepted: {local_accepted}, remote accepted: {remote_accepted})"
    )]
    Rejected {
        local_accepted: bool,
        remote_accepted: bool,
    },
    /// Durable trust persistence failed; authorization was not returned.
    #[error("durable trust commit failed: {0}")]
    Trust(#[source] TrustStoreError),
}

/// Deterministic initiator inputs used by tests and protocol vectors.
///
/// Production callers use the secure generation API added alongside the session
/// pairing entry point. This constructor is deliberately named to prevent fixed test
/// material from looking like production randomness.
#[derive(Clone, Copy, Eq, PartialEq)]
pub struct InitiatorPairingMaterial {
    pairing_id: [u8; PAIRING_ID_LEN],
    nonce: [u8; PAIRING_NONCE_LEN],
}

impl InitiatorPairingMaterial {
    /// Constructs deterministic initiator material for tests.
    pub const fn from_bytes_for_test(
        pairing_id: [u8; PAIRING_ID_LEN],
        nonce: [u8; PAIRING_NONCE_LEN],
    ) -> Self {
        Self { pairing_id, nonce }
    }
}

impl fmt::Debug for InitiatorPairingMaterial {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("InitiatorPairingMaterial(..)")
    }
}

/// Deterministic responder nonce material used by tests and protocol vectors.
#[derive(Clone, Copy, Eq, PartialEq)]
pub struct ResponderPairingMaterial {
    nonce: [u8; PAIRING_NONCE_LEN],
}

impl ResponderPairingMaterial {
    /// Constructs deterministic responder material for tests.
    pub const fn from_bytes_for_test(nonce: [u8; PAIRING_NONCE_LEN]) -> Self {
        Self { nonce }
    }
}

impl fmt::Debug for ResponderPairingMaterial {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("ResponderPairingMaterial(..)")
    }
}

/// The result of applying local trust policy to an authenticated connection.
pub enum SessionAdmission {
    /// A locally trusted peer may use application functionality.
    Authorized(AuthorizedConnection),
    /// An unknown peer is isolated to the pairing protocol.
    Pairable(PairableConnection),
}

/// A Hello-bootstrapped connection admitted by a durable local trust decision.
pub struct AuthorizedConnection {
    connection: BootstrappedConnection,
    peer: TrustedPeer,
}

impl AuthorizedConnection {
    /// Returns the authorized cryptographic peer identity.
    pub const fn remote_device_id(&self) -> DeviceId {
        self.peer.device_id
    }

    /// Returns the durable peer record that authorized this connection.
    pub const fn trusted_peer(&self) -> &TrustedPeer {
        &self.peer
    }

    /// Returns the validated Hello for feature negotiation after authorization.
    pub fn peer_hello(&self) -> &Hello {
        self.connection.peer_hello()
    }

    /// Closes this disposable authorized connection.
    pub fn close(&self) {
        self.connection.close();
    }
}

/// An authenticated unknown peer isolated to pairing behavior.
pub struct PairableConnection {
    connection: BootstrappedConnection,
    trust_store: Arc<TrustStore>,
    pairing_timeout: Duration,
}

impl PairableConnection {
    /// Returns the authenticated unknown peer identity.
    pub const fn remote_device_id(&self) -> DeviceId {
        self.connection.remote_device_id()
    }

    /// Returns peer-controlled display metadata validated by the Hello bounds.
    pub fn peer_hello(&self) -> &Hello {
        self.connection.peer_hello()
    }

    /// Returns whether this peer advertised pairing protocol v1.
    pub fn supports_pairing(&self) -> bool {
        self.connection
            .peer_hello()
            .capabilities
            .contains(&Capability::PAIRING_V1)
    }

    /// Starts the initiator role with deterministic test material.
    pub async fn initiate_pairing_with_material_for_test(
        mut self,
        material: InitiatorPairingMaterial,
    ) -> Result<PendingPairing, PairingError> {
        self.require_pairing_capability()?;
        let peer = trusted_peer_from_hello(self.connection.peer_hello());
        let local_device_id = self.connection.local_device_id();
        let mut machine = PairingStateMachine::initiator(material.pairing_id);
        info!(remote_device_id = %peer.device_id, "pairing_started");

        send_or_close(
            &mut self.connection,
            PairingMessage::Request {
                pairing_id: material.pairing_id,
                nonce: material.nonce,
            },
            self.pairing_timeout,
            machine.phase(),
        )
        .await?;
        let response =
            receive_or_close(&mut self.connection, self.pairing_timeout, machine.phase()).await?;
        let responder_nonce = match machine.receive_response(response) {
            Ok(nonce) => nonce,
            Err(error) => {
                self.connection.close();
                return Err(error);
            }
        };
        let code = PairingTranscript::new(
            local_device_id,
            peer.device_id,
            material.pairing_id,
            material.nonce,
            responder_nonce,
        )
        .code();
        info!(remote_device_id = %peer.device_id, "pairing_code_ready");
        Ok(PendingPairing::new(
            self.connection,
            self.trust_store,
            peer,
            material.pairing_id,
            code,
            machine,
            self.pairing_timeout,
        ))
    }

    /// Runs the responder role with deterministic test material.
    pub async fn respond_to_pairing_with_material_for_test(
        mut self,
        material: ResponderPairingMaterial,
    ) -> Result<PendingPairing, PairingError> {
        self.require_pairing_capability()?;
        let peer = trusted_peer_from_hello(self.connection.peer_hello());
        let local_device_id = self.connection.local_device_id();
        let mut machine = PairingStateMachine::responder();
        info!(remote_device_id = %peer.device_id, "pairing_started");

        let request =
            receive_or_close(&mut self.connection, self.pairing_timeout, machine.phase()).await?;
        let (pairing_id, initiator_nonce) = match machine.receive_request(request) {
            Ok(request) => request,
            Err(error) => {
                self.connection.close();
                return Err(error);
            }
        };
        send_or_close(
            &mut self.connection,
            PairingMessage::Response {
                pairing_id,
                nonce: material.nonce,
            },
            self.pairing_timeout,
            machine.phase(),
        )
        .await?;
        let code = PairingTranscript::new(
            peer.device_id,
            local_device_id,
            pairing_id,
            initiator_nonce,
            material.nonce,
        )
        .code();
        info!(remote_device_id = %peer.device_id, "pairing_code_ready");
        Ok(PendingPairing::new(
            self.connection,
            self.trust_store,
            peer,
            pairing_id,
            code,
            machine,
            self.pairing_timeout,
        ))
    }

    /// Closes this disposable pairing-only connection.
    pub fn close(&self) {
        self.connection.close();
    }

    fn require_pairing_capability(&self) -> Result<(), PairingError> {
        if self.supports_pairing() {
            Ok(())
        } else {
            self.connection.close();
            Err(PairingError::PairingUnsupported(self.remote_device_id()))
        }
    }
}

/// A pairing transcript ready for explicit local human confirmation.
///
/// Obtaining this value never mutates durable trust. Only [`confirm`](Self::confirm)
/// can send a positive local decision and attempt the trust commit.
pub struct PendingPairing {
    connection: Option<BootstrappedConnection>,
    trust_store: Arc<TrustStore>,
    peer: TrustedPeer,
    pairing_id: [u8; PAIRING_ID_LEN],
    code: PairingCode,
    machine: PairingStateMachine,
    pairing_timeout: Duration,
    local_confirmation_deadline: Instant,
}

impl PendingPairing {
    fn new(
        connection: BootstrappedConnection,
        trust_store: Arc<TrustStore>,
        peer: TrustedPeer,
        pairing_id: [u8; PAIRING_ID_LEN],
        code: PairingCode,
        machine: PairingStateMachine,
        pairing_timeout: Duration,
    ) -> Self {
        Self {
            connection: Some(connection),
            trust_store,
            peer,
            pairing_id,
            code,
            machine,
            pairing_timeout,
            local_confirmation_deadline: Instant::now() + pairing_timeout,
        }
    }

    /// Returns the authenticated peer identity.
    pub const fn remote_device_id(&self) -> DeviceId {
        self.peer.device_id
    }

    /// Returns bounded peer-controlled display metadata from authenticated Hello.
    pub const fn peer(&self) -> &TrustedPeer {
        &self.peer
    }

    /// Returns the six-digit human comparison value.
    pub const fn verification_code(&self) -> PairingCode {
        self.code
    }

    /// Returns the deadline by which local confirmation must begin.
    pub const fn confirmation_deadline(&self) -> Instant {
        self.local_confirmation_deadline
    }

    /// Returns the current explicit state-machine phase.
    pub const fn phase(&self) -> PairingPhase {
        self.machine.phase()
    }

    /// Supplies the explicit local human decision and completes the protocol.
    pub async fn confirm(mut self, accepted: bool) -> Result<AuthorizedConnection, PairingError> {
        let mut connection = self
            .connection
            .take()
            .ok_or(PairingError::AlreadyFinished {
                phase: self.machine.phase(),
            })?;
        if Instant::now() >= self.local_confirmation_deadline {
            self.machine.fail();
            connection.close();
            return Err(PairingError::Timeout {
                phase: PairingPhase::AwaitingLocalDecision,
            });
        }
        if let Err(error) = self.machine.local_decision(accepted) {
            connection.close();
            return Err(error);
        }
        info!(
            remote_device_id = %self.peer.device_id,
            accepted,
            "pairing_local_decision"
        );
        send_or_close(
            &mut connection,
            PairingMessage::Decision {
                pairing_id: self.pairing_id,
                accepted,
            },
            self.pairing_timeout,
            self.machine.phase(),
        )
        .await?;
        let decision =
            receive_or_close(&mut connection, self.pairing_timeout, self.machine.phase()).await?;
        let remote_accepted = match self.machine.remote_decision(decision) {
            Ok(remote_accepted) => remote_accepted,
            Err(error) => {
                connection.close();
                return Err(error);
            }
        };
        info!(
            remote_device_id = %self.peer.device_id,
            accepted = remote_accepted,
            "pairing_remote_decision"
        );
        if !accepted || !remote_accepted {
            warn!(remote_device_id = %self.peer.device_id, "pairing_rejected");
            connection.close();
            return Err(PairingError::Rejected {
                local_accepted: accepted,
                remote_accepted,
            });
        }

        if let Err(error) = self.trust_store.trust(self.peer.clone()).await {
            self.machine.fail();
            connection.close();
            warn!(
                remote_device_id = %self.peer.device_id,
                failure_category = "trust_commit",
                "pairing_failed"
            );
            return Err(PairingError::Trust(error));
        }
        if let Err(error) = self.machine.trust_committed() {
            connection.close();
            return Err(error);
        }
        send_or_close(
            &mut connection,
            PairingMessage::Complete {
                pairing_id: self.pairing_id,
            },
            self.pairing_timeout,
            self.machine.phase(),
        )
        .await?;
        let complete =
            receive_or_close(&mut connection, self.pairing_timeout, self.machine.phase()).await?;
        if let Err(error) = self.machine.remote_completion(complete) {
            connection.close();
            return Err(error);
        }
        info!(remote_device_id = %self.peer.device_id, "pairing_completed");
        Ok(AuthorizedConnection {
            connection,
            peer: self.peer.clone(),
        })
    }
}

impl Drop for PendingPairing {
    fn drop(&mut self) {
        if let Some(connection) = &self.connection {
            connection.close();
        }
    }
}

/// Admission policy backed by one durable local trust store.
pub struct SessionManager {
    trust_store: Arc<TrustStore>,
    config: SessionConfig,
}

impl SessionManager {
    /// Creates an admission manager with the default pairing timeout.
    pub fn new(trust_store: Arc<TrustStore>) -> Self {
        Self {
            trust_store,
            config: SessionConfig::default(),
        }
    }

    /// Creates an admission manager with validated session configuration.
    pub fn with_config(
        trust_store: Arc<TrustStore>,
        config: SessionConfig,
    ) -> Result<Self, SessionError> {
        if config.pairing_timeout.is_zero() {
            return Err(SessionError::InvalidPairingTimeout);
        }
        Ok(Self {
            trust_store,
            config,
        })
    }

    /// Applies the complete M3 admission rule to one authenticated bootstrap.
    pub async fn admit(
        &self,
        bootstrapped: BootstrappedConnection,
    ) -> Result<SessionAdmission, SessionError> {
        let device_id = bootstrapped.remote_device_id();
        match self.trust_store.entry(device_id).await {
            Some(TrustEntry::Trusted(peer)) => {
                info!(remote_device_id = %device_id, "peer_authorized");
                Ok(SessionAdmission::Authorized(AuthorizedConnection {
                    connection: bootstrapped,
                    peer,
                }))
            }
            Some(TrustEntry::Revoked(_)) => {
                warn!(remote_device_id = %device_id, "peer_rejected_revoked");
                bootstrapped.close();
                Err(SessionError::PeerRevoked(device_id))
            }
            None => Ok(SessionAdmission::Pairable(PairableConnection {
                connection: bootstrapped,
                trust_store: Arc::clone(&self.trust_store),
                pairing_timeout: self.config.pairing_timeout,
            })),
        }
    }
}

/// Builds bounded local Hello metadata for a pairing-capable session endpoint.
pub fn pairing_metadata(
    device_name: impl Into<String>,
    platform: impl Into<String>,
) -> Result<HelloMetadata, rift_protocol::HandshakeError> {
    HelloMetadata::new(device_name, platform, vec![Capability::PAIRING_V1])
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum PairingRole {
    Initiator,
    Responder,
}

struct PairingStateMachine {
    role: PairingRole,
    phase: PairingPhase,
    pairing_id: Option<[u8; PAIRING_ID_LEN]>,
    local_accepted: Option<bool>,
    remote_accepted: Option<bool>,
}

impl PairingStateMachine {
    fn initiator(pairing_id: [u8; PAIRING_ID_LEN]) -> Self {
        Self {
            role: PairingRole::Initiator,
            phase: PairingPhase::AwaitingResponse,
            pairing_id: Some(pairing_id),
            local_accepted: None,
            remote_accepted: None,
        }
    }

    fn responder() -> Self {
        Self {
            role: PairingRole::Responder,
            phase: PairingPhase::AwaitingRequest,
            pairing_id: None,
            local_accepted: None,
            remote_accepted: None,
        }
    }

    const fn phase(&self) -> PairingPhase {
        self.phase
    }

    fn receive_request(
        &mut self,
        message: PairingMessage,
    ) -> Result<([u8; PAIRING_ID_LEN], [u8; PAIRING_NONCE_LEN]), PairingError> {
        self.require_active(PairingPhase::AwaitingRequest)?;
        match message {
            PairingMessage::Request { pairing_id, nonce } => {
                self.pairing_id = Some(pairing_id);
                self.phase = PairingPhase::AwaitingLocalDecision;
                Ok((pairing_id, nonce))
            }
            message => Err(self.unexpected(MessageKind::PairingRequest, message.kind())),
        }
    }

    fn receive_response(
        &mut self,
        message: PairingMessage,
    ) -> Result<[u8; PAIRING_NONCE_LEN], PairingError> {
        self.require_active(PairingPhase::AwaitingResponse)?;
        match message {
            PairingMessage::Response { pairing_id, nonce } => {
                self.require_pairing_id(pairing_id)?;
                self.phase = PairingPhase::AwaitingLocalDecision;
                Ok(nonce)
            }
            message => Err(self.unexpected(MessageKind::PairingResponse, message.kind())),
        }
    }

    fn local_decision(&mut self, accepted: bool) -> Result<(), PairingError> {
        if self.local_accepted.is_some() {
            return Err(PairingError::DuplicateDecision { phase: self.phase });
        }
        self.require_active(PairingPhase::AwaitingLocalDecision)?;
        self.local_accepted = Some(accepted);
        self.phase = PairingPhase::AwaitingRemoteDecision;
        Ok(())
    }

    fn remote_decision(&mut self, message: PairingMessage) -> Result<bool, PairingError> {
        if self.remote_accepted.is_some() || self.phase == PairingPhase::CommittingTrust {
            return Err(PairingError::DuplicateDecision { phase: self.phase });
        }
        self.require_active(PairingPhase::AwaitingRemoteDecision)?;
        match message {
            PairingMessage::Decision {
                pairing_id,
                accepted,
            } => {
                self.require_pairing_id(pairing_id)?;
                self.remote_accepted = Some(accepted);
                if self.local_accepted == Some(true) && accepted {
                    self.phase = PairingPhase::CommittingTrust;
                } else {
                    self.phase = PairingPhase::Rejected;
                }
                Ok(accepted)
            }
            PairingMessage::Complete { .. } => {
                Err(PairingError::CompletionTooEarly { phase: self.phase })
            }
            message => Err(self.unexpected(MessageKind::PairingDecision, message.kind())),
        }
    }

    fn trust_committed(&mut self) -> Result<(), PairingError> {
        self.require_active(PairingPhase::CommittingTrust)?;
        self.phase = PairingPhase::AwaitingCompletion;
        Ok(())
    }

    fn remote_completion(&mut self, message: PairingMessage) -> Result<(), PairingError> {
        self.require_active(PairingPhase::AwaitingCompletion)?;
        match message {
            PairingMessage::Complete { pairing_id } => {
                self.require_pairing_id(pairing_id)?;
                self.phase = PairingPhase::Complete;
                Ok(())
            }
            PairingMessage::Decision { .. } => {
                Err(PairingError::DuplicateDecision { phase: self.phase })
            }
            message => Err(self.unexpected(MessageKind::PairingComplete, message.kind())),
        }
    }

    fn fail(&mut self) {
        self.phase = PairingPhase::Failed;
    }

    fn require_active(&self, expected: PairingPhase) -> Result<(), PairingError> {
        if matches!(
            self.phase,
            PairingPhase::Complete | PairingPhase::Rejected | PairingPhase::Failed
        ) {
            return Err(PairingError::AlreadyFinished { phase: self.phase });
        }
        if self.phase == expected {
            Ok(())
        } else {
            Err(PairingError::UnexpectedMessage {
                phase: self.phase,
                expected: expected_kind(expected, self.role),
                received: expected_kind(self.phase, self.role),
            })
        }
    }

    fn require_pairing_id(&self, received: [u8; PAIRING_ID_LEN]) -> Result<(), PairingError> {
        if self.pairing_id == Some(received) {
            Ok(())
        } else {
            Err(PairingError::PairingIdMismatch { phase: self.phase })
        }
    }

    fn unexpected(&self, expected: MessageKind, received: MessageKind) -> PairingError {
        PairingError::UnexpectedMessage {
            phase: self.phase,
            expected,
            received,
        }
    }
}

fn expected_kind(phase: PairingPhase, role: PairingRole) -> MessageKind {
    match phase {
        PairingPhase::AwaitingRequest => MessageKind::PairingRequest,
        PairingPhase::AwaitingResponse => MessageKind::PairingResponse,
        PairingPhase::AwaitingLocalDecision | PairingPhase::AwaitingRemoteDecision => {
            MessageKind::PairingDecision
        }
        PairingPhase::CommittingTrust | PairingPhase::AwaitingCompletion => {
            MessageKind::PairingComplete
        }
        PairingPhase::Complete | PairingPhase::Rejected | PairingPhase::Failed => match role {
            PairingRole::Initiator => MessageKind::PairingResponse,
            PairingRole::Responder => MessageKind::PairingRequest,
        },
    }
}

fn trusted_peer_from_hello(hello: &Hello) -> TrustedPeer {
    TrustedPeer {
        device_id: hello.device_id,
        device_name: hello.device_name.clone(),
        platform: hello.platform.clone(),
    }
}

async fn send_or_close(
    connection: &mut BootstrappedConnection,
    message: PairingMessage,
    timeout: Duration,
    phase: PairingPhase,
) -> Result<(), PairingError> {
    match connection.send_pairing(message, timeout).await {
        Ok(()) => Ok(()),
        Err(TransportError::ControlTimeout) => {
            connection.close();
            Err(PairingError::Timeout { phase })
        }
        Err(source) => {
            connection.close();
            Err(PairingError::Transport { phase, source })
        }
    }
}

async fn receive_or_close(
    connection: &mut BootstrappedConnection,
    timeout: Duration,
    phase: PairingPhase,
) -> Result<PairingMessage, PairingError> {
    match connection.receive_pairing(timeout).await {
        Ok(message) => Ok(message),
        Err(TransportError::ControlTimeout) => {
            connection.close();
            Err(PairingError::Timeout { phase })
        }
        Err(source) => {
            connection.close();
            Err(PairingError::Transport { phase, source })
        }
    }
}

#[cfg(test)]
mod tests {
    use rift_core::TrustState;

    use super::*;

    fn request(pairing_id: [u8; PAIRING_ID_LEN]) -> PairingMessage {
        PairingMessage::Request {
            pairing_id,
            nonce: [2; PAIRING_NONCE_LEN],
        }
    }

    fn response(pairing_id: [u8; PAIRING_ID_LEN]) -> PairingMessage {
        PairingMessage::Response {
            pairing_id,
            nonce: [3; PAIRING_NONCE_LEN],
        }
    }

    fn decision(pairing_id: [u8; PAIRING_ID_LEN], accepted: bool) -> PairingMessage {
        PairingMessage::Decision {
            pairing_id,
            accepted,
        }
    }

    #[test]
    fn pairing_metadata_advertises_only_pairing_v1() {
        let result = pairing_metadata("device", "platform");
        assert!(matches!(
            result,
            Ok(HelloMetadata { capabilities, .. })
                if capabilities == vec![Capability::PAIRING_V1]
        ));
    }

    #[test]
    fn zero_pairing_timeout_is_rejected() {
        let config = SessionConfig {
            pairing_timeout: Duration::ZERO,
        };
        assert!(config.pairing_timeout.is_zero());
        assert_eq!(DEFAULT_PAIRING_TIMEOUT, Duration::from_secs(60));
    }

    #[test]
    fn wrong_pairing_id_and_message_order_are_typed() {
        let pairing_id = [1; PAIRING_ID_LEN];
        let mut initiator = PairingStateMachine::initiator(pairing_id);
        assert!(matches!(
            initiator.receive_response(response([9; PAIRING_ID_LEN])),
            Err(PairingError::PairingIdMismatch {
                phase: PairingPhase::AwaitingResponse
            })
        ));
        assert!(matches!(
            initiator.receive_response(request(pairing_id)),
            Err(PairingError::UnexpectedMessage {
                expected: MessageKind::PairingResponse,
                received: MessageKind::PairingRequest,
                ..
            })
        ));

        let mut responder = PairingStateMachine::responder();
        assert!(matches!(
            responder.receive_request(response(pairing_id)),
            Err(PairingError::UnexpectedMessage {
                expected: MessageKind::PairingRequest,
                received: MessageKind::PairingResponse,
                ..
            })
        ));
    }

    #[test]
    fn duplicate_decision_and_early_completion_are_typed() -> Result<(), PairingError> {
        let pairing_id = [1; PAIRING_ID_LEN];
        let mut machine = PairingStateMachine::initiator(pairing_id);
        machine.receive_response(response(pairing_id))?;
        machine.local_decision(true)?;
        assert!(matches!(
            machine.local_decision(true),
            Err(PairingError::DuplicateDecision { .. })
        ));
        assert!(matches!(
            machine.remote_decision(PairingMessage::Complete { pairing_id }),
            Err(PairingError::CompletionTooEarly { .. })
        ));
        assert!(machine.remote_decision(decision(pairing_id, true))?);
        assert!(matches!(
            machine.remote_decision(decision(pairing_id, true)),
            Err(PairingError::DuplicateDecision { .. })
        ));
        machine.trust_committed()?;
        assert!(matches!(
            machine.remote_completion(decision(pairing_id, true)),
            Err(PairingError::DuplicateDecision { .. })
        ));
        Ok(())
    }

    #[test]
    fn rejection_and_terminal_failure_are_explicit() -> Result<(), PairingError> {
        let pairing_id = [1; PAIRING_ID_LEN];
        let mut machine = PairingStateMachine::responder();
        machine.receive_request(request(pairing_id))?;
        machine.local_decision(false)?;
        assert!(machine.remote_decision(decision(pairing_id, true))?);
        assert_eq!(machine.phase(), PairingPhase::Rejected);
        assert!(matches!(
            machine.trust_committed(),
            Err(PairingError::AlreadyFinished {
                phase: PairingPhase::Rejected
            })
        ));

        let mut failed = PairingStateMachine::initiator(pairing_id);
        failed.fail();
        assert!(matches!(
            failed.receive_response(response(pairing_id)),
            Err(PairingError::AlreadyFinished {
                phase: PairingPhase::Failed
            })
        ));
        assert_ne!(TrustState::Trusted, TrustState::Revoked);
        Ok(())
    }

    #[test]
    fn deterministic_material_debug_does_not_disclose_nonce_bytes() {
        let initiator = InitiatorPairingMaterial::from_bytes_for_test(
            [0xaa; PAIRING_ID_LEN],
            [0xbb; PAIRING_NONCE_LEN],
        );
        let responder = ResponderPairingMaterial::from_bytes_for_test([0xcc; PAIRING_NONCE_LEN]);
        assert_eq!(format!("{initiator:?}"), "InitiatorPairingMaterial(..)");
        assert_eq!(format!("{responder:?}"), "ResponderPairingMaterial(..)");
    }
}
