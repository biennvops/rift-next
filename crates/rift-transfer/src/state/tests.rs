use rift_protocol::{TransferFailureCode, TransferFileName};

use super::*;

type TestResult = Result<(), Box<dyn std::error::Error + Send + Sync>>;

fn transfer(
    direction: TransferDirection,
) -> Result<LogicalTransfer, rift_protocol::TransferMetadataError> {
    Ok(LogicalTransfer::new(
        DeviceId::from_bytes([1; 32]),
        TransferId::from_bytes([2; 16]),
        TransferMetadata::new(TransferFileName::new("file.bin")?, 7, [3; 32])?,
        direction,
    ))
}

fn header(offset: u64) -> DataStreamHeader {
    DataStreamHeader::BlobV1 {
        transfer_id: TransferId::from_bytes([2; 16]),
        offset,
        remaining_len: 7 - offset,
    }
}

#[test]
fn happy_path_requires_offer_acceptance_verification_and_terminal_ack() -> TestResult {
    let mut sender = transfer(TransferDirection::Outgoing)?;
    let mut receiver = transfer(TransferDirection::Incoming)?;
    assert_eq!(sender.peer(), DeviceId::from_bytes([1; 32]));
    assert_eq!(sender.transfer_id(), TransferId::from_bytes([2; 16]));
    assert_eq!(sender.direction(), TransferDirection::Outgoing);
    assert_eq!(sender.state(), TransferState::Queued);
    assert_eq!(receiver.state(), TransferState::PendingOffer);
    assert_eq!(sender.metadata(), receiver.metadata());
    sender.offer_sent()?;
    receiver.acceptance_persisted(0)?;
    sender.accept_received(0)?;
    let (send_attempt, offset) = sender.start_send()?;
    assert_eq!(offset, 0);
    let receive_attempt = receiver.start_receive(&header(0))?;
    sender.send_finished(send_attempt)?;
    assert_eq!(
        sender.state(),
        TransferState::WaitingForTerminal {
            attempt: send_attempt
        }
    );
    receiver.payload_verified(receive_attempt)?;
    assert_eq!(
        receiver.state(),
        TransferState::Completing {
            attempt: receive_attempt
        }
    );
    receiver.terminal_persisted(TransferTerminalStatus::Completed, Some(receive_attempt))?;
    assert_eq!(
        receiver.state(),
        TransferState::TerminalAwaitingAck(TransferTerminalStatus::Completed)
    );
    sender.peer_terminal_persisted(TransferTerminalStatus::Completed)?;
    receiver.terminal_ack_received()?;
    assert_eq!(
        sender.state(),
        TransferState::Settled(TransferTerminalStatus::Completed)
    );
    assert_eq!(receiver.state(), sender.state());
    Ok(())
}

#[test]
fn all_preacceptance_and_premature_completion_operations_fail_without_mutation() -> TestResult {
    let mut sender = transfer(TransferDirection::Outgoing)?;
    let mut receiver = transfer(TransferDirection::Incoming)?;
    assert_eq!(
        sender.accept_received(0),
        Err(TransferTransitionError::UnexpectedState)
    );
    assert_eq!(
        sender.start_send(),
        Err(TransferTransitionError::UnexpectedState)
    );
    assert_eq!(
        sender.terminal_ack_received(),
        Err(TransferTransitionError::UnexpectedState)
    );
    assert_eq!(
        receiver.start_receive(&header(0)),
        Err(TransferTransitionError::UnexpectedState)
    );
    assert_eq!(
        receiver.acceptance_persisted(1),
        Err(TransferTransitionError::UnexpectedState)
    );
    assert_eq!(
        receiver.payload_verified(TransferAttempt(1)),
        Err(TransferTransitionError::StaleAttempt)
    );
    assert_eq!(
        receiver.terminal_persisted(TransferTerminalStatus::Completed, None),
        Err(TransferTransitionError::StaleAttempt)
    );
    assert_eq!(
        receiver.terminal_ack_received(),
        Err(TransferTransitionError::UnexpectedState)
    );
    assert_eq!(receiver.state(), TransferState::PendingOffer);
    assert_eq!(sender.state(), TransferState::Queued);
    receiver.acceptance_persisted(0)?;
    let attempt = receiver.start_receive(&header(0))?;
    assert_eq!(
        receiver.terminal_persisted(TransferTerminalStatus::Completed, Some(attempt)),
        Err(TransferTransitionError::StaleAttempt)
    );
    assert_eq!(receiver.state(), TransferState::Receiving { attempt });
    Ok(())
}

#[test]
fn wrong_role_operations_are_typed_and_nonmutating() -> TestResult {
    let mut sender = transfer(TransferDirection::Outgoing)?;
    let mut receiver = transfer(TransferDirection::Incoming)?;
    assert_eq!(
        sender.acceptance_persisted(0),
        Err(TransferTransitionError::WrongDirection)
    );
    assert_eq!(
        sender.start_receive(&header(0)),
        Err(TransferTransitionError::WrongDirection)
    );
    assert_eq!(
        sender.payload_verified(TransferAttempt(1)),
        Err(TransferTransitionError::WrongDirection)
    );
    assert_eq!(
        sender.replay_offer(sender.metadata(), 0),
        Err(TransferTransitionError::WrongDirection)
    );
    assert_eq!(
        sender.terminal_persisted(TransferTerminalStatus::Completed, Some(TransferAttempt(1))),
        Err(TransferTransitionError::WrongDirection)
    );
    assert_eq!(
        sender.terminal_persisted(TransferTerminalStatus::Rejected, None),
        Err(TransferTransitionError::WrongDirection)
    );
    assert_eq!(
        receiver.offer_sent(),
        Err(TransferTransitionError::WrongDirection)
    );
    assert_eq!(
        receiver.accept_received(0),
        Err(TransferTransitionError::WrongDirection)
    );
    assert_eq!(
        receiver.start_send(),
        Err(TransferTransitionError::WrongDirection)
    );
    assert_eq!(
        receiver.send_finished(TransferAttempt(1)),
        Err(TransferTransitionError::WrongDirection)
    );
    for status in [
        TransferTerminalStatus::Completed,
        TransferTerminalStatus::Rejected,
    ] {
        assert_eq!(
            receiver.peer_terminal_persisted(status),
            Err(TransferTransitionError::WrongDirection)
        );
    }
    assert_eq!(sender.state(), TransferState::Queued);
    assert_eq!(receiver.state(), TransferState::PendingOffer);
    Ok(())
}

#[test]
fn duplicate_offers_are_idempotent_and_conflicts_never_replace_metadata() -> TestResult {
    let mut receiver = transfer(TransferDirection::Incoming)?;
    let original = receiver.metadata().clone();
    assert_eq!(receiver.replay_offer(&original, 0)?, OfferReplay::Pending);
    assert_eq!(receiver.replay_offer(&original, 0)?, OfferReplay::Pending);
    let changed = TransferMetadata::new(TransferFileName::new("other.bin")?, 7, [3; 32])?;
    assert_eq!(
        receiver.replay_offer(&changed, 0),
        Err(TransferTransitionError::ConflictingMetadata)
    );
    receiver.acceptance_persisted(0)?;
    assert_eq!(
        receiver.replay_offer(&original, 0)?,
        OfferReplay::Accept { offset: 0 }
    );
    let first = receiver.start_receive(&header(0))?;
    assert_eq!(
        receiver.replay_offer(&original, 3)?,
        OfferReplay::Accept { offset: 3 }
    );
    assert_eq!(
        receiver.start_receive(&header(0)),
        Err(TransferTransitionError::UnexpectedState)
    );
    assert_eq!(
        receiver.acceptance_persisted(3),
        Err(TransferTransitionError::UnexpectedState)
    );
    assert_eq!(receiver.pause(), Some(first));
    assert_eq!(
        receiver.replay_offer(&original, 3)?,
        OfferReplay::Accept { offset: 3 }
    );
    assert_eq!(
        receiver.start_receive(&header(3)),
        Err(TransferTransitionError::UnexpectedState)
    );
    receiver.acceptance_persisted(3)?;
    let resumed = receiver.start_receive(&header(3))?;
    receiver.payload_verified(resumed)?;
    assert_eq!(
        receiver.replay_offer(&original, 7)?,
        OfferReplay::Accept { offset: 7 }
    );
    receiver.terminal_persisted(TransferTerminalStatus::Completed, Some(resumed))?;
    for _ in 0..2 {
        assert_eq!(
            receiver.replay_offer(&original, u64::MAX)?,
            OfferReplay::Terminal(TransferTerminalStatus::Completed)
        );
        assert_eq!(
            receiver.replay_offer(&changed, 0),
            Err(TransferTransitionError::ConflictingMetadata)
        );
        receiver.terminal_ack_received()?;
    }
    assert_eq!(receiver.metadata(), &original);
    Ok(())
}

#[test]
fn invalid_ranges_wrong_ids_and_offset_mismatches_never_acquire_attempts() -> TestResult {
    let mut receiver = transfer(TransferDirection::Incoming)?;
    let mut sender = transfer(TransferDirection::Outgoing)?;
    sender.offer_sent()?;
    for offset in [8, u64::MAX] {
        assert_eq!(
            sender.accept_received(offset),
            Err(TransferTransitionError::InvalidOffset)
        );
        assert_eq!(
            receiver.acceptance_persisted(offset),
            Err(TransferTransitionError::InvalidOffset)
        );
    }
    receiver.acceptance_persisted(0)?;
    for stream_header in [
        DataStreamHeader::BlobV1 {
            transfer_id: receiver.transfer_id(),
            offset: 8,
            remaining_len: 0,
        },
        DataStreamHeader::BlobV1 {
            transfer_id: receiver.transfer_id(),
            offset: 0,
            remaining_len: 8,
        },
        DataStreamHeader::BlobV1 {
            transfer_id: receiver.transfer_id(),
            offset: u64::MAX,
            remaining_len: u64::MAX,
        },
    ] {
        assert_eq!(
            receiver.start_receive(&stream_header),
            Err(TransferTransitionError::InvalidOffset)
        );
    }
    let wrong_id = DataStreamHeader::BlobV1 {
        transfer_id: TransferId::from_bytes([9; 16]),
        offset: 0,
        remaining_len: 7,
    };
    assert_eq!(
        receiver.start_receive(&wrong_id),
        Err(TransferTransitionError::WrongTransfer)
    );
    assert_eq!(
        receiver.start_receive(&header(3)),
        Err(TransferTransitionError::UnexpectedState)
    );
    assert_eq!(
        receiver.replay_offer(receiver.metadata(), 8),
        Err(TransferTransitionError::InvalidOffset)
    );
    assert_eq!(receiver.next_attempt, 0);
    assert_eq!(receiver.state(), TransferState::Accepted { offset: 0 });
    Ok(())
}

#[test]
fn replacement_fences_old_receive_verification_and_publication() -> TestResult {
    let mut receiver = transfer(TransferDirection::Incoming)?;
    receiver.acceptance_persisted(0)?;
    let old = receiver.start_receive(&header(0))?;
    receiver.payload_verified(old)?;
    assert_eq!(receiver.pause(), Some(old));
    assert_eq!(
        receiver.payload_verified(old),
        Err(TransferTransitionError::StaleAttempt)
    );
    assert_eq!(
        receiver.terminal_persisted(TransferTerminalStatus::Completed, Some(old)),
        Err(TransferTransitionError::StaleAttempt)
    );
    receiver.acceptance_persisted(3)?;
    let current = receiver.start_receive(&header(3))?;
    assert_ne!(old, current);
    assert_eq!(
        receiver.payload_verified(old),
        Err(TransferTransitionError::StaleAttempt)
    );
    receiver.payload_verified(current)?;
    assert_eq!(
        receiver.terminal_persisted(TransferTerminalStatus::Completed, Some(old)),
        Err(TransferTransitionError::StaleAttempt)
    );
    assert_eq!(
        receiver.state(),
        TransferState::Completing { attempt: current }
    );
    receiver.terminal_persisted(TransferTerminalStatus::Completed, Some(current))?;
    Ok(())
}

#[test]
fn sender_reoffers_same_metadata_and_obeys_new_receiver_offset_after_loss() -> TestResult {
    let mut sender = transfer(TransferDirection::Outgoing)?;
    let original = sender.metadata().clone();
    assert_eq!(sender.pause(), None);
    assert_eq!(sender.state(), TransferState::Queued);
    sender.offer_sent()?;
    sender.offer_sent()?;
    sender.accept_received(0)?;
    let (old, _) = sender.start_send()?;
    assert_eq!(
        sender.offer_sent(),
        Err(TransferTransitionError::UnexpectedState)
    );
    assert_eq!(
        sender.start_send(),
        Err(TransferTransitionError::UnexpectedState)
    );
    assert_eq!(
        sender.accept_received(3),
        Err(TransferTransitionError::UnexpectedState)
    );
    assert_eq!(sender.pause(), Some(old));
    assert_eq!(
        sender.send_finished(old),
        Err(TransferTransitionError::StaleAttempt)
    );
    assert_eq!(sender.pause(), None);
    sender.offer_sent()?;
    sender.accept_received(3)?;
    let (current, offset) = sender.start_send()?;
    assert_eq!(offset, 3);
    assert_ne!(old, current);
    assert_eq!(
        sender.send_finished(old),
        Err(TransferTransitionError::StaleAttempt)
    );
    sender.send_finished(current)?;
    assert_eq!(sender.pause(), Some(current));
    sender.offer_sent()?;
    sender.peer_terminal_persisted(TransferTerminalStatus::Completed)?;
    assert_eq!(
        sender.state(),
        TransferState::Settled(TransferTerminalStatus::Completed)
    );
    assert_eq!(sender.metadata(), &original);
    Ok(())
}

#[test]
fn reject_cancel_failure_and_terminal_replay_are_monotonic() -> TestResult {
    for status in [
        TransferTerminalStatus::Rejected,
        TransferTerminalStatus::Cancelled,
        TransferTerminalStatus::Failed(TransferFailureCode::Integrity),
        TransferTerminalStatus::Failed(TransferFailureCode::SourceChanged),
        TransferTerminalStatus::Failed(TransferFailureCode::Io),
        TransferTerminalStatus::Failed(TransferFailureCode::Resource),
        TransferTerminalStatus::Failed(TransferFailureCode::Protocol),
    ] {
        let mut receiver = transfer(TransferDirection::Incoming)?;
        receiver.terminal_persisted(status, None)?;
        for _ in 0..2 {
            receiver.terminal_persisted(status, None)?;
            assert_eq!(receiver.pause(), None);
            assert_eq!(
                receiver.acceptance_persisted(0),
                Err(TransferTransitionError::UnexpectedState)
            );
            assert_eq!(
                receiver.start_receive(&header(0)),
                Err(TransferTransitionError::UnexpectedState)
            );
            assert_eq!(
                receiver.terminal_persisted(TransferTerminalStatus::Completed, None),
                Err(TransferTransitionError::ConflictingTerminal)
            );
            let old_state = receiver.state();
            receiver.peer_terminal_persisted(TransferTerminalStatus::Completed)?;
            assert_eq!(receiver.state(), old_state);
            receiver.terminal_ack_received()?;
        }
        assert_eq!(receiver.state(), TransferState::Settled(status));
    }
    let mut receiver = transfer(TransferDirection::Incoming)?;
    receiver.acceptance_persisted(0)?;
    assert_eq!(
        receiver.terminal_persisted(TransferTerminalStatus::Rejected, None),
        Err(TransferTransitionError::UnexpectedState)
    );
    let attempt = receiver.start_receive(&header(0))?;
    receiver.terminal_persisted(TransferTerminalStatus::Cancelled, None)?;
    assert_eq!(
        receiver.payload_verified(attempt),
        Err(TransferTransitionError::StaleAttempt)
    );
    Ok(())
}

#[test]
fn peer_cancellation_and_failure_settle_once_without_resurrection() -> TestResult {
    for direction in [TransferDirection::Incoming, TransferDirection::Outgoing] {
        for status in [
            TransferTerminalStatus::Cancelled,
            TransferTerminalStatus::Failed(TransferFailureCode::Io),
        ] {
            let mut transfer = transfer(direction)?;
            transfer.peer_terminal_persisted(status)?;
            transfer.peer_terminal_persisted(status)?;
            transfer.peer_terminal_persisted(TransferTerminalStatus::Completed)?;
            assert_eq!(transfer.state(), TransferState::Settled(status));
            assert_eq!(transfer.pause(), None);
        }
    }
    Ok(())
}

#[test]
fn accepted_and_pending_loss_preserve_the_local_decision_boundary() -> TestResult {
    let mut receiver = transfer(TransferDirection::Incoming)?;
    assert_eq!(receiver.pause(), None);
    assert_eq!(receiver.state(), TransferState::PendingOffer);
    receiver.acceptance_persisted(0)?;
    assert_eq!(receiver.pause(), None);
    assert_eq!(receiver.state(), TransferState::Paused);
    receiver.acceptance_persisted(7)?;
    receiver.acceptance_persisted(7)?;
    let attempt = receiver.start_receive(&header(7))?;
    receiver.payload_verified(attempt)?;
    receiver.terminal_persisted(TransferTerminalStatus::Completed, Some(attempt))?;
    let mut sender = transfer(TransferDirection::Outgoing)?;
    sender.offer_sent()?;
    assert_eq!(sender.pause(), None);
    assert_eq!(sender.state(), TransferState::Paused);
    Ok(())
}

#[test]
fn generation_exhaustion_fails_closed_without_wrapping_or_starting_work() -> TestResult {
    for direction in [TransferDirection::Incoming, TransferDirection::Outgoing] {
        let mut transfer = transfer(direction)?;
        match direction {
            TransferDirection::Incoming => transfer.acceptance_persisted(0)?,
            TransferDirection::Outgoing => {
                transfer.offer_sent()?;
                transfer.accept_received(0)?;
            }
        }
        transfer.next_attempt = u64::MAX;
        let result = match direction {
            TransferDirection::Incoming => transfer.start_receive(&header(0)),
            TransferDirection::Outgoing => transfer.start_send().map(|(attempt, _)| attempt),
        };
        assert_eq!(result, Err(TransferTransitionError::AttemptExhausted));
        assert_eq!(transfer.next_attempt, u64::MAX);
        assert_eq!(transfer.state(), TransferState::Accepted { offset: 0 });
    }
    Ok(())
}

#[test]
fn late_worker_failure_cannot_fail_a_resumed_transfer() -> TestResult {
    for direction in [TransferDirection::Incoming, TransferDirection::Outgoing] {
        let mut transfer = transfer(direction)?;
        let mut attempts = Vec::new();
        for offset in [0, 3] {
            let attempt = match direction {
                TransferDirection::Incoming => {
                    transfer.acceptance_persisted(offset)?;
                    transfer.start_receive(&header(offset))?
                }
                TransferDirection::Outgoing => {
                    transfer.offer_sent()?;
                    transfer.accept_received(offset)?;
                    transfer.start_send()?.0
                }
            };
            attempts.push(attempt);
            if offset == 0 {
                assert_eq!(transfer.pause(), Some(attempt));
                assert_eq!(
                    transfer.terminal_persisted(
                        TransferTerminalStatus::Failed(TransferFailureCode::Io),
                        Some(attempt)
                    ),
                    Err(TransferTransitionError::StaleAttempt)
                );
            }
        }
        let state = transfer.state();
        assert_eq!(
            transfer.terminal_persisted(
                TransferTerminalStatus::Failed(TransferFailureCode::Io),
                Some(attempts[0])
            ),
            Err(TransferTransitionError::StaleAttempt)
        );
        assert_eq!(transfer.state(), state);
        transfer.terminal_persisted(
            TransferTerminalStatus::Failed(TransferFailureCode::Io),
            Some(attempts[1]),
        )?;
        assert_eq!(
            transfer.state(),
            TransferState::TerminalAwaitingAck(TransferTerminalStatus::Failed(
                TransferFailureCode::Io
            ))
        );
    }
    Ok(())
}
