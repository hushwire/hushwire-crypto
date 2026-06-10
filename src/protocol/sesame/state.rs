//! Sesame session state: the per-session entry stored in a device record and
//! its lifecycle state (initiating vs. established).

use serde::{Deserialize, Serialize};

use crate::types::Timestamp;

/// Session state in the Sesame lifecycle.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum SessionState {
    /// Session created locally but not yet confirmed by a decrypt from the peer.
    Initiating,
    /// Established session confirmed by a successful decrypt from the peer.
    Regular,
}

/// Entry for a single session within a device record.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionEntry {
    /// Serialized Double Ratchet session state.
    pub session_data: Vec<u8>,
    /// Lifecycle state of this session.
    pub state: SessionState,
    /// Timestamp the session was created.
    pub created_at: Timestamp,
    /// Timestamp the session was last used (sent or decrypted on).
    pub last_used: Timestamp,
    /// Deterministic dual-init convergence tie-breaker: the session's initial
    /// root-key id (see [`crate::protocol::ratchet::RatchetSession::root_key_id`]),
    /// identical on both peers for the same logical session. When a device
    /// holds several competing dual-init sessions, both sides pick the one with
    /// the highest priority as active for sending, so they converge without
    /// coordination. `0` for legacy/migrated sessions (treated as "no
    /// preference" -- a tie keeps the current active to avoid disrupting an
    /// already-working single session on upgrade).
    #[serde(default)]
    pub convergence_priority: u64,
}

impl SessionEntry {
    /// Creates a session entry with convergence priority `0` (no preference).
    pub fn new(session_data: Vec<u8>, state: SessionState, now: impl Into<Timestamp>) -> Self {
        Self::new_with_priority(session_data, state, now, 0)
    }

    /// Creates a session entry with an explicit `convergence_priority`, stamping
    /// both `created_at` and `last_used` with `now`.
    pub fn new_with_priority(
        session_data: Vec<u8>,
        state: SessionState,
        now: impl Into<Timestamp>,
        convergence_priority: u64,
    ) -> Self {
        let now = now.into();
        Self {
            session_data,
            state,
            created_at: now,
            last_used: now,
            convergence_priority,
        }
    }

    /// Updates `last_used` to `now`.
    pub fn touch(&mut self, now: impl Into<Timestamp>) {
        self.last_used = now.into();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn session_entry_creation() {
        let entry = SessionEntry::new(vec![1, 2, 3], SessionState::Initiating, 100u64);
        assert_eq!(entry.state, SessionState::Initiating);
        assert_eq!(entry.created_at, Timestamp(100));
        assert_eq!(entry.last_used, Timestamp(100));
    }

    #[test]
    fn session_entry_touch_updates_last_used() {
        let mut entry = SessionEntry::new(vec![], SessionState::Regular, 100u64);
        entry.touch(200u64);
        assert_eq!(entry.last_used, Timestamp(200));
        assert_eq!(entry.created_at, Timestamp(100));
    }

    #[test]
    fn session_state_serde() {
        let state = SessionState::Initiating;
        let bytes = postcard::to_allocvec(&state).unwrap();
        let restored: SessionState = postcard::from_bytes(&bytes).unwrap();
        assert_eq!(restored, SessionState::Initiating);
    }

    #[test]
    fn session_entry_serde() {
        let entry = SessionEntry::new(vec![10, 20], SessionState::Regular, 42u64);
        let bytes = postcard::to_allocvec(&entry).unwrap();
        let restored: SessionEntry = postcard::from_bytes(&bytes).unwrap();
        assert_eq!(restored.state, SessionState::Regular);
        assert_eq!(restored.session_data, vec![10, 20]);
        assert_eq!(restored.created_at, Timestamp(42));
    }
}
