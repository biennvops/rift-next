//! One bounded supervisor policy map; no per-peer tasks, queues, or timer allocations.

use std::{collections::BTreeMap, time::Duration};

use rift_core::DeviceId;
use rift_ipc::{ConnectivityFailure, ConnectivityState, PeerConnectivityInfo, SessionId};
use tokio::time::Instant;

pub(crate) const MAX_MANAGED_PEERS: usize = 4096;
pub(crate) const START_SPACING: Duration = Duration::from_millis(100);
const STABLE_RESET: Duration = Duration::from_secs(30);

/// Equal-jitter exponential backoff from an injected sample, capped at 60 seconds.
/// Exported for deterministic performance measurement; no I/O or runtime allocation.
pub fn retry_delay(attempt: u32, sample: u32) -> Duration {
    let cap_ms = 1000_u64
        .saturating_mul(1_u64 << attempt.saturating_sub(1).min(6))
        .min(60_000);
    let half = cap_ms / 2;
    Duration::from_millis(half + u64::from(sample) * half / u64::from(u32::MAX))
}

pub(crate) struct Peer {
    pub(crate) state: ConnectivityState,
    pub(crate) session_id: Option<SessionId>,
    pub(crate) attempt: u32,
    pub(crate) due: Option<Instant>,
    pub(crate) last_failure: Option<ConnectivityFailure>,
    pub(crate) suspended: bool,
    connected_since: Option<Instant>,
    pub(crate) last_emitted: Option<PeerConnectivityInfo>,
}

impl Peer {
    fn new(now: Instant) -> Self {
        Self {
            state: ConnectivityState::Disconnected,
            session_id: None,
            attempt: 0,
            due: Some(now),
            last_failure: None,
            suspended: false,
            connected_since: None,
            last_emitted: None,
        }
    }

    pub(crate) fn info(&self, device_id: DeviceId, now: Instant) -> PeerConnectivityInfo {
        PeerConnectivityInfo {
            device_id,
            state: self.state,
            session_id: self.session_id,
            retry_attempt: self.attempt,
            retry_in_ms: self.due.map(|due| {
                u64::try_from(due.saturating_duration_since(now).as_millis()).unwrap_or(u64::MAX)
            }),
            last_failure: self.last_failure,
        }
    }

    pub(crate) fn connected(&mut self, session_id: SessionId, now: Instant) {
        self.session_id = Some(session_id);
        self.state = ConnectivityState::Connected;
        self.due = None;
        self.last_failure = None;
        // Canonical replacement is not a loss and must not reset the stability clock.
        self.connected_since.get_or_insert(now);
    }

    pub(crate) fn lost(&mut self, now: Instant, sample: u32) {
        self.session_id = None;
        if self
            .connected_since
            .take()
            .is_some_and(|since| now.duration_since(since) >= STABLE_RESET)
        {
            self.attempt = 0;
        }
        if self.suspended {
            self.state = ConnectivityState::Suspended;
            self.due = None;
        } else {
            self.failed(ConnectivityFailure::Network, now, sample);
        }
    }

    pub(crate) fn failed(&mut self, failure: ConnectivityFailure, now: Instant, sample: u32) {
        self.last_failure = Some(failure);
        self.due = None;
        self.state = match failure {
            ConnectivityFailure::Unresolved => ConnectivityState::Unresolved,
            ConnectivityFailure::Network | ConnectivityFailure::Capacity => {
                self.attempt = self.attempt.saturating_add(1);
                self.due = Some(now + retry_delay(self.attempt, sample));
                ConnectivityState::Backoff
            }
            _ => ConnectivityState::Blocked,
        };
    }

    pub(crate) fn resume(&mut self, now: Instant) {
        self.suspended = false;
        if self.session_id.is_none() {
            self.state = ConnectivityState::Disconnected;
            self.due = Some(now);
        }
    }

    pub(crate) fn suspend(&mut self) {
        self.suspended = true;
        self.due = None;
        if self.session_id.is_none() {
            self.state = ConnectivityState::Suspended;
        }
    }
}

pub(crate) struct Scheduler {
    pub(crate) peers: BTreeMap<DeviceId, Peer>,
    next_start: Instant,
}

impl Scheduler {
    pub(crate) fn new(now: Instant) -> Self {
        Self {
            peers: BTreeMap::new(),
            next_start: now,
        }
    }

    pub(crate) fn insert(&mut self, id: DeviceId, now: Instant) -> bool {
        if self.peers.contains_key(&id) {
            return true;
        }
        if self.peers.len() == MAX_MANAGED_PEERS {
            return false;
        }
        self.peers.insert(id, Peer::new(now));
        true
    }

    pub(crate) fn deadline(&self) -> Option<Instant> {
        self.peers
            .values()
            .filter_map(|peer| peer.due)
            .min()
            .map(|due| due.max(self.next_start))
    }

    pub(crate) fn take_due(&mut self, now: Instant) -> Option<DeviceId> {
        if now < self.next_start {
            return None;
        }
        let id = self
            .peers
            .iter()
            .filter_map(|(id, peer)| peer.due.map(|due| (*id, due)))
            .filter(|(_, due)| *due <= now)
            .min_by_key(|(id, due)| (*due, *id))
            .map(|(id, _)| id)?;
        self.next_start = now + START_SPACING;
        if let Some(peer) = self.peers.get_mut(&id) {
            peer.due = None;
            peer.state = ConnectivityState::Connecting;
        }
        Some(id)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn backoff_jitter_cap_stability_and_short_flaps_are_deterministic() {
        assert_eq!(retry_delay(1, 0), Duration::from_millis(500));
        assert_eq!(retry_delay(1, u32::MAX), Duration::from_secs(1));
        assert_eq!(retry_delay(2, u32::MAX), Duration::from_secs(2));
        assert_eq!(retry_delay(u32::MAX, u32::MAX), Duration::from_secs(60));
        assert_eq!(retry_delay(99, 0), Duration::from_secs(30));
        let now = Instant::now();
        let mut peer = Peer::new(now);
        peer.failed(ConnectivityFailure::Network, now, 0);
        peer.connected(SessionId(1), now);
        peer.lost(now + Duration::from_secs(1), 0);
        assert_eq!(peer.attempt, 2);
        peer.connected(SessionId(2), now + Duration::from_secs(2));
        peer.connected(SessionId(3), now + Duration::from_secs(20));
        peer.lost(now + Duration::from_secs(32), 0);
        assert_eq!(peer.attempt, 1);
    }

    #[test]
    fn manual_bypass_suspension_inbound_and_nonretryable_failures() {
        let now = Instant::now();
        let mut peer = Peer::new(now);
        peer.failed(ConnectivityFailure::Network, now, 0);
        peer.resume(now);
        assert_eq!(peer.due, Some(now));
        assert_eq!(peer.attempt, 1);
        peer.suspend();
        assert_eq!(peer.due, None);
        peer.connected(SessionId(1), now);
        peer.lost(now + Duration::from_secs(1), 0);
        assert_eq!(peer.state, ConnectivityState::Suspended);
        assert_eq!(peer.due, None);
        peer.resume(now);
        for failure in [
            ConnectivityFailure::Unresolved,
            ConnectivityFailure::PurposeRejected,
            ConnectivityFailure::Protocol,
            ConnectivityFailure::NotTrusted,
            ConnectivityFailure::Cancelled,
        ] {
            peer.failed(failure, now, 0);
            assert_eq!(peer.due, None);
        }
    }

    #[test]
    fn large_peer_map_is_bounded_rate_limited_and_has_no_stale_timer_queue() {
        let now = Instant::now();
        let mut scheduler = Scheduler::new(now);
        for index in 0..MAX_MANAGED_PEERS {
            let mut bytes = [0; 32];
            bytes[..8].copy_from_slice(&(index as u64).to_be_bytes());
            assert!(scheduler.insert(DeviceId::from_bytes(bytes), now));
        }
        assert!(!scheduler.insert(DeviceId::from_bytes([255; 32]), now));
        assert_eq!(scheduler.peers.len(), MAX_MANAGED_PEERS);
        for index in 0..1000 {
            let time = now + START_SPACING * index;
            assert!(scheduler.take_due(time).is_some());
            assert_eq!(scheduler.take_due(time), None);
            assert!(
                scheduler
                    .deadline()
                    .is_some_and(|next| next >= time + START_SPACING)
            );
        }
        scheduler.peers.clear();
        assert_eq!(scheduler.deadline(), None);
        assert_eq!(scheduler.take_due(now + Duration::from_secs(1000)), None);
    }
}
