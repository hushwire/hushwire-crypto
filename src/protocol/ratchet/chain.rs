//! Symmetric-key ratchet chain.
//!
//! A [`ChainState`] holds one Double Ratchet symmetric chain (a sending or a
//! receiving chain). Each [`ChainState::advance`] applies `KDF_CK` to the
//! current chain key, yielding the next chain key and this step's message key
//! while bumping the message counter.

use serde::{Deserialize, Serialize};

use crate::types::{ChainKey, MessageKey};

/// Symmetric chain state for sending or receiving.
#[derive(Clone, Serialize, Deserialize)]
pub struct ChainState {
    /// Current chain key; ratcheted forward by `KDF_CK` on each [`ChainState::advance`].
    pub chain_key: ChainKey,
    /// Number of message keys derived from this chain so far (the next message's index).
    pub message_number: u32,
}

impl std::fmt::Debug for ChainState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ChainState")
            .field("message_number", &self.message_number)
            .finish_non_exhaustive()
    }
}

impl ChainState {
    /// Create a chain starting from `chain_key` with a message number of 0.
    pub fn new(chain_key: ChainKey) -> Self {
        Self {
            chain_key,
            message_number: 0,
        }
    }

    /// Advance the chain one step: derive the next chain key and this step's
    /// message key via `KDF_CK`, increment the message number, and return the
    /// message key.
    pub fn advance(&mut self) -> MessageKey {
        let out = crate::primitives::kdf::kdf_ck(&self.chain_key);
        self.chain_key = out.chain_key;
        self.message_number += 1;
        out.message_key
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn advance_increments_number() {
        let mut chain = ChainState::new(ChainKey::from([1u8; 32]));
        assert_eq!(chain.message_number, 0);
        let _mk = chain.advance();
        assert_eq!(chain.message_number, 1);
        let _mk = chain.advance();
        assert_eq!(chain.message_number, 2);
    }

    #[test]
    fn advance_produces_distinct_message_keys() {
        let mut chain = ChainState::new(ChainKey::from([1u8; 32]));
        let mk1 = chain.advance();
        let mk2 = chain.advance();
        assert_ne!(mk1, mk2);
    }

    #[test]
    fn advance_changes_chain_key() {
        let mut chain = ChainState::new(ChainKey::from([1u8; 32]));
        let ck_before = chain.chain_key.clone();
        chain.advance();
        assert_ne!(chain.chain_key, ck_before);
    }
}
