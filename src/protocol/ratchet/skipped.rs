//! Skipped-message-key store.
//!
//! Holds message keys for messages that were skipped over (arrived out of
//! order or are still in flight) so they can decrypt later. Keys are indexed by
//! the sending chain's DH public key and the message number within that chain,
//! and the store is bounded by [`MAX_SKIP`].

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

use crate::types::MessageKey;

/// Maximum number of message keys that may be skipped (and thus stored). Caps
/// both the gap a single receive may skip and the size of the skipped-key store,
/// bounding work and memory against malicious counters.
pub const MAX_SKIP: u32 = 2000;

#[derive(Clone)]
struct SkippedKey {
    message_key: MessageKey,
    dh: [u8; 32],
}

#[derive(Serialize, Deserialize)]
struct SkippedKeyEntry {
    message_number: u32,
    message_key: MessageKey,
    #[serde(default)]
    dh: [u8; 32],
}

/// Storage for skipped message keys.
///
/// When messages arrive out of order, the receiver must advance the chain
/// past missing messages, storing their keys for later decryption.
#[derive(Clone, Default)]
pub struct SkippedKeys {
    keys: HashMap<(u32, [u8; 32]), SkippedKey>,
}

impl Serialize for SkippedKeys {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let entries: Vec<SkippedKeyEntry> = self
            .keys
            .iter()
            .map(|((n, _), sk)| SkippedKeyEntry {
                message_number: *n,
                message_key: sk.message_key.clone(),
                dh: sk.dh,
            })
            .collect();
        entries.serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for SkippedKeys {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let entries: Vec<SkippedKeyEntry> = Vec::deserialize(deserializer)?;
        let mut keys = HashMap::new();
        for e in entries {
            keys.insert(
                (e.message_number, e.dh),
                SkippedKey {
                    message_key: e.message_key,
                    dh: e.dh,
                },
            );
        }
        Ok(Self { keys })
    }
}

impl SkippedKeys {
    /// Create an empty skipped-key store.
    pub fn new() -> Self {
        Self {
            keys: HashMap::new(),
        }
    }

    /// Store `message_key` under `(dh, message_number)`. No-op once the store has
    /// reached [`MAX_SKIP`] entries, bounding memory.
    pub fn insert(&mut self, message_number: u32, dh: [u8; 32], message_key: MessageKey) {
        if self.keys.len() >= MAX_SKIP as usize {
            return;
        }
        self.keys
            .insert((message_number, dh), SkippedKey { message_key, dh });
    }

    /// Look up and remove a skipped key by `(dh, message_number)`.
    pub fn try_remove_by_dh(&mut self, dh: &[u8; 32], message_number: u32) -> Option<MessageKey> {
        self.keys
            .remove(&(message_number, *dh))
            .map(|sk| sk.message_key)
    }

    /// Number of skipped keys currently stored.
    pub fn len(&self) -> usize {
        self.keys.len()
    }

    /// Whether the store holds no skipped keys.
    pub fn is_empty(&self) -> bool {
        self.keys.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn insert_and_remove() {
        let mut store = SkippedKeys::new();
        let dh = [1u8; 32];
        let mk = MessageKey::from([2u8; 32]);
        store.insert(5, dh, mk.clone());
        assert_eq!(store.len(), 1);

        let retrieved = store.try_remove_by_dh(&dh, 5);
        assert_eq!(retrieved, Some(mk));
        assert!(store.is_empty());
    }

    #[test]
    fn try_remove_by_dh_finds_skipped_key() {
        let mut store = SkippedKeys::new();
        let dh = [9u8; 32];
        let mk = MessageKey::from([2u8; 32]);
        store.insert(3, dh, mk.clone());

        assert!(store.try_remove_by_dh(&[8u8; 32], 3).is_none());
        assert!(store.try_remove_by_dh(&dh, 4).is_none());
        assert_eq!(store.try_remove_by_dh(&dh, 3), Some(mk));
        assert!(store.is_empty());
    }

    #[test]
    fn remove_nonexistent_returns_none() {
        let mut store = SkippedKeys::new();
        assert!(store.try_remove_by_dh(&[0u8; 32], 0).is_none());
    }

    #[test]
    fn different_chains_stored_independently() {
        let mut store = SkippedKeys::new();
        let dh1 = [1u8; 32];
        let dh2 = [2u8; 32];
        store.insert(0, dh1, MessageKey::from([10u8; 32]));
        store.insert(0, dh2, MessageKey::from([20u8; 32]));
        assert_eq!(store.len(), 2);

        assert_eq!(
            store.try_remove_by_dh(&dh1, 0),
            Some(MessageKey::from([10u8; 32]))
        );
        assert_eq!(
            store.try_remove_by_dh(&dh2, 0),
            Some(MessageKey::from([20u8; 32]))
        );
    }
}
