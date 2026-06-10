//! Dual-init convergence.
//!
//! When both peers establish a session simultaneously (each initiates against
//! the other's prekey bundle), a device ends up holding several competing
//! sessions. To avoid forking -- each side sending on a different session --
//! both peers deterministically select the same session as active by comparing
//! each session's `convergence_priority` (see [`SessionEntry`]), which is the
//! session's initial root-key id and therefore identical on both peers.
//!
//! The selection logic lives on [`super::DeviceRecord`]
//! ([`record_decrypt_success`](super::DeviceRecord::record_decrypt_success) and
//! [`insert_session`](super::DeviceRecord::insert_session)). This module
//! holds the behavioural tests.
//!
//! [`SessionEntry`]: super::state::SessionEntry

#[cfg(test)]
mod tests {
    use crate::protocol::sesame::DeviceRecord;
    use crate::protocol::sesame::state::{SessionEntry, SessionState};
    use crate::types::Timestamp;

    fn entry(state: SessionState, priority: u64) -> SessionEntry {
        SessionEntry::new_with_priority(vec![priority as u8], state, 100u64, priority)
    }

    #[test]
    fn active_initiating_becomes_regular_on_decrypt() {
        let mut device = DeviceRecord {
            active_session: Some(entry(SessionState::Initiating, 5)),
            inactive_sessions: vec![],
            identity_key: None,
        };
        device.record_decrypt_success(0, vec![9], 200u64);
        let active = device.active_session.as_ref().unwrap();
        assert_eq!(active.state, SessionState::Regular);
        assert_eq!(active.session_data, vec![9]);
        assert_eq!(active.last_used, Timestamp(200));
    }

    #[test]
    fn decrypt_on_higher_priority_inactive_promotes_it() {
        // Active is the lower-priority session; a message decrypts on a
        // higher-priority inactive one. Because a decrypt proves the peer uses
        // it, and its priority is strictly higher, it is promoted to active so
        // both peers converge up to the same session.
        let mut device = DeviceRecord {
            active_session: Some(entry(SessionState::Regular, 3)),
            inactive_sessions: vec![entry(SessionState::Initiating, 9)],
            identity_key: None,
        };
        let new_active = device.record_decrypt_success(1, vec![42], 300u64);
        assert_eq!(
            device.active_session.as_ref().unwrap().convergence_priority,
            9
        );
        assert_eq!(
            device.active_session.as_ref().unwrap().session_data,
            vec![42]
        );
        assert_eq!(new_active, Some(vec![42]));
        // The displaced lower-priority session is retained as inactive.
        assert_eq!(device.inactive_sessions.len(), 1);
        assert_eq!(device.inactive_sessions[0].convergence_priority, 3);
    }

    #[test]
    fn decrypt_on_lower_priority_inactive_does_not_demote() {
        // Higher-priority active (9); a message decrypts on the lower-priority
        // inactive (3). It is advanced + marked Regular, but the high-priority
        // session STAYS active for sending so both peers stay converged up.
        let mut device = DeviceRecord {
            active_session: Some(entry(SessionState::Regular, 9)),
            inactive_sessions: vec![entry(SessionState::Initiating, 3)],
            identity_key: None,
        };
        let new_active = device.record_decrypt_success(1, vec![42], 300u64);
        assert_eq!(
            device.active_session.as_ref().unwrap().convergence_priority,
            9
        );
        let inactive = &device.inactive_sessions[0];
        assert_eq!(inactive.convergence_priority, 3);
        assert_eq!(inactive.session_data, vec![42]);
        assert_eq!(inactive.state, SessionState::Regular);
        // Active is unchanged (the high-priority session), not the decrypted one.
        assert_eq!(new_active, Some(vec![9]));
    }

    #[test]
    fn priority_tie_keeps_incumbent_active() {
        // Two priority-0 (e.g. migrated) sessions: a decrypt on the inactive one
        // must NOT demote the incumbent (tie -> keep active), so a working
        // single-session pair is not disrupted on upgrade.
        let mut device = DeviceRecord {
            active_session: Some(entry(SessionState::Regular, 0)),
            inactive_sessions: vec![entry(SessionState::Regular, 0)],
            identity_key: None,
        };
        let incumbent = device.active_session.as_ref().unwrap().session_data.clone();
        device.record_decrypt_success(1, vec![42], 300u64);
        assert_eq!(
            device.active_session.as_ref().unwrap().session_data,
            incumbent
        );
    }

    #[test]
    fn insert_session_makes_new_session_active() {
        // A freshly-established session becomes active regardless of priority
        // (establishment intent); convergence only happens later on decrypt.
        let mut device = DeviceRecord::new();
        device.insert_session(entry(SessionState::Regular, 5));
        device.insert_session(entry(SessionState::Regular, 2));
        assert_eq!(
            device.active_session.as_ref().unwrap().convergence_priority,
            2
        );
        assert_eq!(device.inactive_sessions.len(), 1);
        assert_eq!(device.inactive_sessions[0].convergence_priority, 5);
    }
}
