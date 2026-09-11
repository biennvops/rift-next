//! Logical transfer sequencing, independent of sessions, I/O, and persistence.

use rift_core::{DeviceId, TransferId};
use rift_protocol::{DataStreamHeader, TransferMetadata, TransferTerminalStatus};
use thiserror::Error;

/// The local role in one immutable transfer.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TransferDirection {
    /// This device owns the source file.
    Outgoing,
    /// This device decides whether to receive the offered file.
    Incoming,
}

/// A monotonically increasing worker generation within one logical transfer.
///
/// The daemon must additionally fence by transfer key and canonical SessionId.
/// Generations are runtime-only and must never be restored across daemon launches.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TransferAttempt(u64);

/// Explicit logical state. Durable transitions have separately named methods.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TransferState {
    /// Prepared outgoing metadata waiting for an authorized capable session.
    Queued,
    /// Outgoing Offer sent, waiting for receiver acceptance.
    Offered,
    /// Incoming offer waiting for a local decision; no payload permission.
    PendingOffer,
    /// Receiver acceptance is known, at this exact receiver-authoritative offset.
    Accepted { offset: u64 },
    /// One outgoing worker owns this suffix attempt.
    Sending { attempt: TransferAttempt },
    /// One incoming worker owns this suffix attempt.
    Receiving { attempt: TransferAttempt },
    /// Incoming bytes are verified, but not yet durably published and terminal.
    Completing { attempt: TransferAttempt },
    /// Sender finished its stream but has not received the receiver's outcome.
    WaitingForTerminal { attempt: TransferAttempt },
    /// Connection lost; outgoing reoffers or accepted incoming rechecks its staging.
    Paused,
    /// Local terminal state persisted; replay it until the peer acknowledges.
    TerminalAwaitingAck(TransferTerminalStatus),
    /// Protocol settlement may release the active record, retaining completed files.
    Settled(TransferTerminalStatus),
}

/// Idempotent response to a repeated incoming offer with identical metadata.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum OfferReplay {
    /// A decision is still pending; do not emit a second local prompt.
    Pending,
    /// Acceptance already exists; respond with the freshly reconciled durable offset.
    Accept { offset: u64 },
    /// Replay the persisted outcome; never receive another payload for this record.
    Terminal(TransferTerminalStatus),
}

/// One keyed immutable logical transfer; no session, path, task, or file handle.
///
/// This machine does not make writes durable. Its owner must persist acceptance
/// or terminal state before calling the corresponding `*_persisted` transition,
/// and must reserve capacity before starting an attempt. Pause invalidates worker
/// results immediately, but does not cancel or join tasks: the owner must do both
/// before another worker may use the same stream/staging resources.
#[derive(Debug)]
pub struct LogicalTransfer {
    peer: DeviceId,
    transfer_id: TransferId,
    metadata: TransferMetadata,
    direction: TransferDirection,
    state: TransferState,
    next_attempt: u64,
}

impl LogicalTransfer {
    /// Creates a prepared outgoing or newly offered incoming record.
    pub fn new(
        peer: DeviceId,
        transfer_id: TransferId,
        metadata: TransferMetadata,
        direction: TransferDirection,
    ) -> Self {
        let state = match direction {
            TransferDirection::Outgoing => TransferState::Queued,
            TransferDirection::Incoming => TransferState::PendingOffer,
        };
        Self {
            peer,
            transfer_id,
            metadata,
            direction,
            state,
            next_attempt: 0,
        }
    }

    /// The durable peer identity, never a presentation name or session identity.
    pub const fn peer(&self) -> DeviceId {
        self.peer
    }

    /// The identifier shared by all offers and attempts for this immutable file.
    pub const fn transfer_id(&self) -> TransferId {
        self.transfer_id
    }

    /// The immutable metadata; resumption never replaces it.
    pub const fn metadata(&self) -> &TransferMetadata {
        &self.metadata
    }

    /// The local role.
    pub const fn direction(&self) -> TransferDirection {
        self.direction
    }

    /// The current explicit logical state.
    pub const fn state(&self) -> TransferState {
        self.state
    }

    /// Records a sent outgoing offer, including replay after connection loss.
    pub fn offer_sent(&mut self) -> Result<(), TransferTransitionError> {
        self.require_direction(TransferDirection::Outgoing)?;
        if !matches!(
            self.state,
            TransferState::Queued | TransferState::Paused | TransferState::Offered
        ) {
            return Err(TransferTransitionError::UnexpectedState);
        }
        self.state = TransferState::Offered;
        Ok(())
    }

    /// Records remote acceptance of an already offered outgoing transfer.
    pub fn accept_received(&mut self, offset: u64) -> Result<(), TransferTransitionError> {
        self.require_direction(TransferDirection::Outgoing)?;
        self.check_offset(offset)?;
        if self.state != TransferState::Offered {
            return Err(TransferTransitionError::UnexpectedState);
        }
        self.state = TransferState::Accepted { offset };
        Ok(())
    }

    /// Records incoming acceptance only after its marker is durable.
    ///
    /// On resume the owner must reconcile the actual durable staging length rather
    /// than reuse a sender progress counter. Existing accepted records need no new
    /// user prompt. No method can accept while another attempt owns the receiver.
    pub fn acceptance_persisted(&mut self, offset: u64) -> Result<(), TransferTransitionError> {
        self.require_direction(TransferDirection::Incoming)?;
        self.check_offset(offset)?;
        match self.state {
            TransferState::PendingOffer if offset == 0 => {}
            TransferState::Paused | TransferState::Accepted { .. } => {}
            _ => return Err(TransferTransitionError::UnexpectedState),
        }
        self.state = TransferState::Accepted { offset };
        Ok(())
    }

    /// Checks a duplicate incoming offer without creating a new record or prompt.
    ///
    /// The owner supplies a freshly reconciled durable partial length. Before
    /// starting a paused receiver it must call `acceptance_persisted` with that
    /// length. An active receiver may replay Accept, but cannot start a second
    /// worker. Terminal records do not inspect or reopen a partial file.
    pub fn replay_offer(
        &self,
        metadata: &TransferMetadata,
        durable_offset: u64,
    ) -> Result<OfferReplay, TransferTransitionError> {
        self.require_direction(TransferDirection::Incoming)?;
        if metadata != &self.metadata {
            return Err(TransferTransitionError::ConflictingMetadata);
        }
        match self.state {
            TransferState::PendingOffer => Ok(OfferReplay::Pending),
            TransferState::TerminalAwaitingAck(status) | TransferState::Settled(status) => {
                Ok(OfferReplay::Terminal(status))
            }
            TransferState::Accepted { .. }
            | TransferState::Paused
            | TransferState::Receiving { .. }
            | TransferState::Completing { .. } => {
                self.check_offset(durable_offset)?;
                Ok(OfferReplay::Accept {
                    offset: durable_offset,
                })
            }
            _ => Err(TransferTransitionError::UnexpectedState),
        }
    }

    /// Starts exactly one sender after remote acceptance, returning its generation.
    pub fn start_send(&mut self) -> Result<(TransferAttempt, u64), TransferTransitionError> {
        self.require_direction(TransferDirection::Outgoing)?;
        let TransferState::Accepted { offset } = self.state else {
            return Err(TransferTransitionError::UnexpectedState);
        };
        let attempt = self.allocate_attempt()?;
        self.state = TransferState::Sending { attempt };
        Ok((attempt, offset))
    }

    /// Validates ID, exact range, current accepted offset, and exclusive reception.
    ///
    /// Peer/session authorization and worker capacity must be checked by the owner
    /// before this transition. Even a structurally valid header grants no acceptance.
    pub fn start_receive(
        &mut self,
        header: &DataStreamHeader,
    ) -> Result<TransferAttempt, TransferTransitionError> {
        self.require_direction(TransferDirection::Incoming)?;
        let DataStreamHeader::BlobV1 {
            transfer_id,
            offset,
            ..
        } = *header;
        if transfer_id != self.transfer_id {
            return Err(TransferTransitionError::WrongTransfer);
        }
        header
            .validate(self.metadata.byte_len())
            .map_err(|_| TransferTransitionError::InvalidOffset)?;
        if self.state != (TransferState::Accepted { offset }) {
            return Err(TransferTransitionError::UnexpectedState);
        }
        let attempt = self.allocate_attempt()?;
        self.state = TransferState::Receiving { attempt };
        Ok(attempt)
    }

    /// Records a joined successful send and clean stream finish, not completion.
    pub fn send_finished(
        &mut self,
        attempt: TransferAttempt,
    ) -> Result<(), TransferTransitionError> {
        self.require_direction(TransferDirection::Outgoing)?;
        if self.state != (TransferState::Sending { attempt }) {
            return Err(TransferTransitionError::StaleAttempt);
        }
        self.state = TransferState::WaitingForTerminal { attempt };
        Ok(())
    }

    /// Records a joined receive result with exact length, clean FIN, and full hash.
    ///
    /// The caller may use a locally verified full prefix (including an empty file)
    /// instead of opening a zero-length payload stream, but must still acquire an
    /// attempt and pass through this state before durable publication.
    pub fn payload_verified(
        &mut self,
        attempt: TransferAttempt,
    ) -> Result<(), TransferTransitionError> {
        self.require_direction(TransferDirection::Incoming)?;
        if self.state != (TransferState::Receiving { attempt }) {
            return Err(TransferTransitionError::StaleAttempt);
        }
        self.state = TransferState::Completing { attempt };
        Ok(())
    }

    /// Invalidates connection-bound work; terminal and pending-decision states survive.
    ///
    /// Returns the old worker generation to cancel/join, if one was active. This is
    /// not a path-migration notification and must not run just because routing changed.
    pub fn pause(&mut self) -> Option<TransferAttempt> {
        let attempt = match self.state {
            TransferState::Sending { attempt }
            | TransferState::Receiving { attempt }
            | TransferState::Completing { attempt }
            | TransferState::WaitingForTerminal { attempt } => Some(attempt),
            TransferState::Offered | TransferState::Accepted { .. } => None,
            _ => return None,
        };
        self.state = TransferState::Paused;
        attempt
    }

    /// Records a persisted local terminal outcome to replay until acknowledged.
    ///
    /// Incoming Completed additionally requires this exact current verified attempt;
    /// the owner must have synced and published output before persisting that outcome.
    /// Worker-generated outcomes must supply their attempt, including failures. A
    /// local user decision has no attempt. The daemon additionally fences SessionId.
    /// Cancellation cannot overwrite a completed terminal state.
    pub fn terminal_persisted(
        &mut self,
        status: TransferTerminalStatus,
        worker_attempt: Option<TransferAttempt>,
    ) -> Result<(), TransferTransitionError> {
        if let TransferState::TerminalAwaitingAck(existing) | TransferState::Settled(existing) =
            self.state
        {
            return if existing == status {
                Ok(())
            } else {
                Err(TransferTransitionError::ConflictingTerminal)
            };
        }
        if status == TransferTerminalStatus::Completed {
            self.require_direction(TransferDirection::Incoming)?;
        }
        if let Some(attempt) = worker_attempt {
            let current = match self.state {
                TransferState::Sending { attempt }
                | TransferState::Receiving { attempt }
                | TransferState::Completing { attempt }
                | TransferState::WaitingForTerminal { attempt } => Some(attempt),
                _ => None,
            };
            if current != Some(attempt) {
                return Err(TransferTransitionError::StaleAttempt);
            }
        }
        match status {
            TransferTerminalStatus::Completed => {
                let attempt = worker_attempt.ok_or(TransferTransitionError::StaleAttempt)?;
                if self.state != (TransferState::Completing { attempt }) {
                    return Err(TransferTransitionError::StaleAttempt);
                }
            }
            TransferTerminalStatus::Rejected => {
                self.require_direction(TransferDirection::Incoming)?;
                if self.state != TransferState::PendingOffer {
                    return Err(TransferTransitionError::UnexpectedState);
                }
            }
            TransferTerminalStatus::Cancelled | TransferTerminalStatus::Failed(_) => {}
        }
        self.state = TransferState::TerminalAwaitingAck(status);
        Ok(())
    }

    /// Settles a persisted peer outcome; the caller sends TerminalAck on success.
    ///
    /// Repeated peer terminal messages are acknowledged without resurrecting or
    /// replacing any local terminal decision. Unknown IDs are acknowledged by the
    /// registry without constructing a new LogicalTransfer. The receiver alone may
    /// report Completed or Rejected; either side may cancel or fail.
    pub fn peer_terminal_persisted(
        &mut self,
        status: TransferTerminalStatus,
    ) -> Result<(), TransferTransitionError> {
        if matches!(
            self.state,
            TransferState::TerminalAwaitingAck(_) | TransferState::Settled(_)
        ) {
            return Ok(());
        }
        if matches!(
            status,
            TransferTerminalStatus::Completed | TransferTerminalStatus::Rejected
        ) {
            self.require_direction(TransferDirection::Outgoing)?;
        }
        self.state = TransferState::Settled(status);
        Ok(())
    }

    /// Settles a locally persisted terminal receipt; duplicate acknowledgement is safe.
    pub fn terminal_ack_received(&mut self) -> Result<(), TransferTransitionError> {
        match self.state {
            TransferState::TerminalAwaitingAck(status) => {
                self.state = TransferState::Settled(status)
            }
            TransferState::Settled(_) => {}
            _ => return Err(TransferTransitionError::UnexpectedState),
        }
        Ok(())
    }

    fn check_offset(&self, offset: u64) -> Result<(), TransferTransitionError> {
        if offset > self.metadata.byte_len() {
            Err(TransferTransitionError::InvalidOffset)
        } else {
            Ok(())
        }
    }

    fn require_direction(
        &self,
        direction: TransferDirection,
    ) -> Result<(), TransferTransitionError> {
        if self.direction == direction {
            Ok(())
        } else {
            Err(TransferTransitionError::WrongDirection)
        }
    }

    fn allocate_attempt(&mut self) -> Result<TransferAttempt, TransferTransitionError> {
        self.next_attempt = self
            .next_attempt
            .checked_add(1)
            .ok_or(TransferTransitionError::AttemptExhausted)?;
        Ok(TransferAttempt(self.next_attempt))
    }
}

/// Typed sequencing failures without paths or unbounded diagnostic text.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum TransferTransitionError {
    /// An operation belongs to the opposite sender/receiver role.
    #[error("transfer operation has the wrong direction")]
    WrongDirection,
    /// The current logical state does not permit this operation.
    #[error("transfer operation is not valid in the current state")]
    UnexpectedState,
    /// A supplied offset or suffix range disagrees with immutable metadata.
    #[error("invalid transfer offset or remaining length")]
    InvalidOffset,
    /// A repeated offer changed the metadata for an existing key.
    #[error("transfer offer conflicts with immutable metadata")]
    ConflictingMetadata,
    /// A data header names a different logical transfer.
    #[error("data stream names the wrong transfer")]
    WrongTransfer,
    /// A worker result no longer belongs to the current active attempt.
    #[error("stale transfer attempt")]
    StaleAttempt,
    /// Runtime generation identifiers must never wrap and alias old work.
    #[error("transfer attempt generation exhausted")]
    AttemptExhausted,
    /// A terminal decision cannot be replaced by a different local outcome.
    #[error("transfer already has a different terminal outcome")]
    ConflictingTerminal,
}

#[cfg(test)]
mod tests;
