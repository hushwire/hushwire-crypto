//! Sesame session lifecycle thresholds and staleness checks: when an active
//! session is too old to send on and when an inactive session may be deleted.

use crate::types::Timestamp;

/// Maximum assumed message delivery delay (2 hours in seconds).
pub const MAXLATENCY: u64 = 2 * 60 * 60;

/// Maximum age for an active session before re-establishing (30 days in seconds).
pub const MAXSEND: u64 = 30 * 24 * 60 * 60;

/// Maximum age before deleting inactive sessions (60 days in seconds).
pub const MAXRECV: u64 = 60 * 24 * 60 * 60;

// Constraint: MAXRECV > MAXSEND + 2*MAXLATENCY
const _: () = assert!(MAXRECV > MAXSEND + 2 * MAXLATENCY);

/// Returns `true` if a session created at `created_at` is older than `MAXSEND`
/// and must be re-established before sending.
pub fn is_stale_for_sending(created_at: Timestamp, now: Timestamp) -> bool {
    now.0.saturating_sub(created_at.0) > MAXSEND
}

/// Returns `true` if a session last used at `last_used` has exceeded `MAXRECV`
/// and may be deleted.
pub fn is_stale_for_receiving(last_used: Timestamp, now: Timestamp) -> bool {
    now.0.saturating_sub(last_used.0) > MAXRECV
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn stale_sending() {
        let created = Timestamp(0);
        assert!(!is_stale_for_sending(created, Timestamp(MAXSEND - 1)));
        assert!(!is_stale_for_sending(created, Timestamp(MAXSEND)));
        assert!(is_stale_for_sending(created, Timestamp(MAXSEND + 1)));
    }

    #[test]
    fn stale_receiving() {
        let last_used = Timestamp(0);
        assert!(!is_stale_for_receiving(last_used, Timestamp(MAXRECV - 1)));
        assert!(!is_stale_for_receiving(last_used, Timestamp(MAXRECV)));
        assert!(is_stale_for_receiving(last_used, Timestamp(MAXRECV + 1)));
    }
}
