//! Signal Sesame protocol: multi-device session management.
//!
//! Sesame tracks, per remote user, a set of per-device session records and the
//! lifecycle of the Double Ratchet sessions held against each device. It handles
//! device-list refresh (add/remove/identity-change), dual-init convergence (both
//! peers deterministically agreeing on a single active session), and staleness-
//! based pruning and re-establishment.

pub mod convergence;
pub mod lifecycle;
pub mod state;

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

use crate::primitives::keys::IdentityPublicKey;
use crate::types::Timestamp;

use self::lifecycle::{is_stale_for_receiving, is_stale_for_sending};
use self::state::{SessionEntry, SessionState};

/// Record for a single device of a remote user.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeviceRecord {
    /// Session currently used for sending to this device, if any.
    pub active_session: Option<SessionEntry>,
    /// Archived sessions kept as fallbacks for decrypting (bounded by
    /// [`Self::MAX_INACTIVE_SESSIONS`]).
    pub inactive_sessions: Vec<SessionEntry>,
    /// Last-known identity public key for this device; a change triggers session reset.
    pub identity_key: Option<IdentityPublicKey>,
}

impl DeviceRecord {
    /// Creates an empty device record with no sessions or identity key.
    pub fn new() -> Self {
        Self {
            active_session: None,
            inactive_sessions: vec![],
            identity_key: None,
        }
    }

    /// Maximum archived (inactive) sessions retained per device. A peer that
    /// converged onto a different dual-init root must stay decryptable, so old
    /// sessions are kept as inactive fallbacks -- but bounded so a re-init storm
    /// cannot grow the list without limit. Mirrors libsignal's archived-session
    /// cap (it keeps the most recent; older ones are pruned by staleness).
    pub const MAX_INACTIVE_SESSIONS: usize = 10;

    /// Inserts a freshly-established session as the active one, demoting the
    /// previous active session into the inactive list and pruning to the cap.
    pub fn insert_session(&mut self, session: SessionEntry) {
        // A freshly-established session becomes active for sending: that is the
        // point of (re-)establishing. Deterministic convergence happens later,
        // on decrypt, once we observe which session the peer is actually using
        // -- so a stale/dead session can never out-rank a live establishment.
        if let Some(old_active) = self.active_session.take() {
            self.inactive_sessions.insert(0, old_active);
        }
        self.active_session = Some(session);
        if self.inactive_sessions.len() > Self::MAX_INACTIVE_SESSIONS {
            self.inactive_sessions.truncate(Self::MAX_INACTIVE_SESSIONS);
        }
    }

    /// Record a successful decrypt on the session at `logical_index` (0 = the
    /// active session, n = `inactive_sessions[n-1]`): store its advanced
    /// `updated_data` and promote it Initiating -> Regular / touch it.
    ///
    /// Deterministic dual-init convergence: a decrypt PROVES the peer is using
    /// that session, so it is eligible to become active. We promote an inactive
    /// session only when its `convergence_priority` is STRICTLY GREATER than the
    /// current active's. Because the priority is the session's initial root-key
    /// id (identical on both peers), both sides converge UP to the same
    /// highest-priority mutually-used session without oscillating; a tie keeps
    /// the incumbent (so legacy priority-0 sessions are undisturbed), and a
    /// stale session that receives no traffic is never promoted.
    ///
    /// Returns the (possibly unchanged) active session's data so the caller can
    /// sync its flat-store cache.
    pub fn record_decrypt_success(
        &mut self,
        logical_index: usize,
        updated_data: Vec<u8>,
        now: impl Into<Timestamp>,
    ) -> Option<Vec<u8>> {
        let now = now.into();
        if logical_index == 0 {
            if let Some(active) = self.active_session.as_mut() {
                active.session_data = updated_data;
                active.last_used = now;
                if active.state == SessionState::Initiating {
                    active.state = SessionState::Regular;
                }
            }
        } else {
            let idx = logical_index - 1;
            if let Some(entry) = self.inactive_sessions.get_mut(idx) {
                entry.session_data = updated_data;
                entry.last_used = now;
                if entry.state == SessionState::Initiating {
                    entry.state = SessionState::Regular;
                }
                let active_priority = self
                    .active_session
                    .as_ref()
                    .map(|s| s.convergence_priority)
                    .unwrap_or(0);
                if self.active_session.is_none()
                    || self.inactive_sessions[idx].convergence_priority > active_priority
                {
                    let promoted = self.inactive_sessions.remove(idx);
                    if let Some(old_active) = self.active_session.take() {
                        self.inactive_sessions.insert(0, old_active);
                    }
                    self.active_session = Some(promoted);
                }
            }
        }
        self.active_session.as_ref().map(|s| s.session_data.clone())
    }

    /// Drops inactive sessions that are stale for receiving (unused past `MAXRECV`).
    pub fn prune_stale(&mut self, now: Timestamp) {
        self.inactive_sessions
            .retain(|s| !is_stale_for_receiving(s.last_used, now));
    }

    /// Returns `true` if there is no active session or the active one is stale
    /// for sending (older than `MAXSEND`) and must be re-established.
    pub fn needs_reestablish(&self, now: Timestamp) -> bool {
        match &self.active_session {
            None => true,
            Some(s) => is_stale_for_sending(s.created_at, now),
        }
    }
}

impl Default for DeviceRecord {
    fn default() -> Self {
        Self::new()
    }
}

/// Record for a remote user, containing per-device session records.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct UserRecord {
    /// Per-device session records keyed by device id.
    pub devices: HashMap<String, DeviceRecord>,
}

impl UserRecord {
    /// Creates an empty user record with no device entries.
    pub fn new() -> Self {
        Self {
            devices: HashMap::new(),
        }
    }

    /// Returns the device record for `device_id`, creating an empty one if absent.
    pub fn get_or_create_device(&mut self, device_id: &str) -> &mut DeviceRecord {
        self.devices.entry(device_id.to_string()).or_default()
    }

    /// Returns the device record for `device_id`, if present.
    pub fn get_device(&self, device_id: &str) -> Option<&DeviceRecord> {
        self.devices.get(device_id)
    }

    /// Returns a mutable reference to the device record for `device_id`, if present.
    pub fn get_device_mut(&mut self, device_id: &str) -> Option<&mut DeviceRecord> {
        self.devices.get_mut(device_id)
    }

    /// Removes the device record for `device_id`.
    pub fn remove_device(&mut self, device_id: &str) {
        self.devices.remove(device_id);
    }

    /// Returns the ids of all known devices.
    pub fn device_ids(&self) -> Vec<String> {
        self.devices.keys().cloned().collect()
    }

    /// Reconciles the local device set against the server's device list, adding
    /// new devices and removing those absent from the server, then returns the
    /// resulting [`DeviceChanges`]. A removed device whose active session is still
    /// fresh for receiving is retained so in-flight messages stay decryptable.
    pub fn refresh_devices(
        &mut self,
        server_device_ids: &[String],
        now: Timestamp,
    ) -> DeviceChanges {
        let mut changes = DeviceChanges::default();

        let current: std::collections::HashSet<String> = self.devices.keys().cloned().collect();
        let server: std::collections::HashSet<String> = server_device_ids.iter().cloned().collect();

        for new_id in server.difference(&current) {
            self.devices.insert(new_id.clone(), DeviceRecord::new());
            changes.added.push(new_id.clone());
        }

        for removed_id in current.difference(&server) {
            if let Some(device) = self.devices.get(removed_id)
                && let Some(ref active) = device.active_session
                && !is_stale_for_receiving(active.last_used, now)
            {
                continue;
            }
            self.devices.remove(removed_id);
            changes.removed.push(removed_id.clone());
        }

        changes
    }
}

/// Changes detected when refreshing device records against server state.
#[derive(Debug, Default)]
pub struct DeviceChanges {
    /// Device ids newly added because the server reported them.
    pub added: Vec<String>,
    /// Device ids removed because the server no longer reports them.
    pub removed: Vec<String>,
}

#[cfg(test)]
mod tests {
    use self::state::SessionState;
    use super::*;

    fn now() -> Timestamp {
        Timestamp::from(1000000)
    }

    fn make_session(state: SessionState) -> SessionEntry {
        SessionEntry::new(vec![1, 2, 3], state, now())
    }

    #[test]
    fn device_record_insert_session() {
        let mut device = DeviceRecord::new();
        assert!(device.active_session.is_none());

        device.insert_session(make_session(SessionState::Initiating));
        assert!(device.active_session.is_some());
        assert!(device.inactive_sessions.is_empty());

        device.insert_session(make_session(SessionState::Regular));
        assert_eq!(
            device.active_session.as_ref().unwrap().state,
            SessionState::Regular
        );
        assert_eq!(device.inactive_sessions.len(), 1);
    }

    #[test]
    fn device_record_needs_reestablish() {
        let mut device = DeviceRecord::new();
        assert!(device.needs_reestablish(now()));

        device.insert_session(make_session(SessionState::Regular));
        assert!(!device.needs_reestablish(now()));
        assert!(device.needs_reestablish(Timestamp(now().0 + lifecycle::MAXSEND + 1)));
    }

    #[test]
    fn device_record_prune_stale() {
        let mut device = DeviceRecord::new();
        let old_session = SessionEntry::new(vec![], SessionState::Regular, 0);
        device.inactive_sessions.push(old_session);
        device
            .inactive_sessions
            .push(make_session(SessionState::Regular));

        device.prune_stale(Timestamp(lifecycle::MAXRECV + 2));
        assert_eq!(device.inactive_sessions.len(), 1);
    }

    #[test]
    fn user_record_get_or_create() {
        let mut user = UserRecord::new();
        let device = user.get_or_create_device("dev-1");
        assert!(device.active_session.is_none());

        device.insert_session(make_session(SessionState::Regular));
        let device2 = user.get_device("dev-1").unwrap();
        assert!(device2.active_session.is_some());
    }

    #[test]
    fn user_record_refresh_adds_new_devices() {
        let mut user = UserRecord::new();
        user.get_or_create_device("dev-1");

        let changes =
            user.refresh_devices(&["dev-1".into(), "dev-2".into(), "dev-3".into()], now());
        assert_eq!(changes.added.len(), 2);
        assert_eq!(user.devices.len(), 3);
    }

    #[test]
    fn user_record_refresh_removes_old_devices() {
        let mut user = UserRecord::new();
        user.get_or_create_device("dev-1");
        user.get_or_create_device("dev-2");

        let changes = user.refresh_devices(&["dev-1".into()], now());
        assert_eq!(changes.removed.len(), 1);
        assert_eq!(user.devices.len(), 1);
    }

    #[test]
    fn user_record_refresh_keeps_devices_within_maxrecv() {
        let mut user = UserRecord::new();
        let device = user.get_or_create_device("dev-1");
        device.insert_session(SessionEntry::new(vec![], SessionState::Regular, now()));

        let changes = user.refresh_devices(&[], now());
        assert!(changes.removed.is_empty());
        assert_eq!(user.devices.len(), 1);
    }

    #[test]
    fn user_record_serde_roundtrip() {
        let mut user = UserRecord::new();
        let device = user.get_or_create_device("dev-1");
        device.insert_session(make_session(SessionState::Regular));

        let bytes = postcard::to_allocvec(&user).unwrap();
        let restored: UserRecord = postcard::from_bytes(&bytes).unwrap();
        assert!(restored.get_device("dev-1").is_some());
    }

    #[test]
    fn convergence_simultaneous_initiation() {
        let mut device = DeviceRecord::new();

        // Both sides create Initiating sessions with distinct priorities.
        device.insert_session(SessionEntry::new_with_priority(
            vec![1],
            SessionState::Initiating,
            now(),
            7,
        ));
        device
            .inactive_sessions
            .push(SessionEntry::new_with_priority(
                vec![2],
                SessionState::Initiating,
                now(),
                3,
            ));

        // A message decrypts on the active (priority-7) session.
        device.record_decrypt_success(0, vec![1], Timestamp(now().0 + 1));
        assert_eq!(
            device.active_session.as_ref().unwrap().state,
            SessionState::Regular
        );

        // A message decrypts on the inactive (priority-3) session. It is
        // advanced, but the higher-priority session stays active (deterministic
        // convergence) -- both peers agree on priority 7.
        device.record_decrypt_success(1, vec![2], Timestamp(now().0 + 2));
        assert_eq!(
            device.active_session.as_ref().unwrap().convergence_priority,
            7
        );
        assert_eq!(device.inactive_sessions.len(), 1);
    }

    #[test]
    fn multi_device_user() {
        let mut user = UserRecord::new();
        for i in 0..3 {
            let device = user.get_or_create_device(&format!("dev-{i}"));
            device.insert_session(make_session(SessionState::Regular));
        }
        assert_eq!(user.devices.len(), 3);
        assert_eq!(user.device_ids().len(), 3);
    }

    #[test]
    fn get_device_mut_modifies_device() {
        let mut user = UserRecord::new();
        let device = user.get_or_create_device("dev-1");
        device.insert_session(make_session(SessionState::Initiating));

        let device_mut = user.get_device_mut("dev-1").unwrap();
        device_mut.insert_session(make_session(SessionState::Regular));
        assert_eq!(
            user.get_device("dev-1")
                .unwrap()
                .active_session
                .as_ref()
                .unwrap()
                .state,
            SessionState::Regular
        );

        assert!(user.get_device_mut("nonexistent").is_none());
    }

    #[test]
    fn remove_device_deletes_entry() {
        let mut user = UserRecord::new();
        user.get_or_create_device("dev-1");
        user.get_or_create_device("dev-2");
        assert_eq!(user.devices.len(), 2);

        user.remove_device("dev-1");
        assert_eq!(user.devices.len(), 1);
        assert!(user.get_device("dev-1").is_none());
        assert!(user.get_device("dev-2").is_some());

        user.remove_device("nonexistent");
        assert_eq!(user.devices.len(), 1);
    }

    #[test]
    fn decrypt_promotes_higher_priority_inactive() {
        let mut device = DeviceRecord::new();
        device.active_session = Some(SessionEntry::new_with_priority(
            vec![1],
            SessionState::Regular,
            now(),
            2,
        ));
        device
            .inactive_sessions
            .push(SessionEntry::new_with_priority(
                vec![2],
                SessionState::Initiating,
                now(),
                8,
            ));

        // A decrypt on the higher-priority inactive session promotes it.
        device.record_decrypt_success(1, vec![2], now());
        assert_eq!(
            device.active_session.as_ref().unwrap().convergence_priority,
            8
        );
        assert_eq!(device.inactive_sessions.len(), 1);
        assert_eq!(device.inactive_sessions[0].convergence_priority, 2);
    }
}
