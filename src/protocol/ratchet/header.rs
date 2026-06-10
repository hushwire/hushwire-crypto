//! Double Ratchet message header.
//!
//! Carries the EC ratchet public key and message counters plus the SPQR
//! `SCKA_HEADER` (the post-quantum half of the Triple Ratchet). The serialized
//! header is bound into each message's AEAD associated data, so every field is
//! authenticated by that message's AEAD tag.

use serde::{Deserialize, Serialize};

use crate::protocol::braid::Message as BraidMessage;
use crate::types::DhPublicKey;

/// Message header containing the EC Double Ratchet public key and counters, plus
/// the SPQR `SCKA_HEADER` (`scka_msg`, `pqN`) -- the post-quantum half of the
/// Triple Ratchet.
///
/// The whole serialized header is bound into the AEAD associated data (see
/// `ratchet::build_ad`), so every field below is authenticated by the message's
/// own AEAD tag: an on-path attacker cannot strip, forge, or reorder the braid
/// codeword or the PQ counter without breaking decryption of the carrying message.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MessageHeader {
    /// The sender's current EC ratchet public key; a value not yet seen by the
    /// receiver triggers a DH ratchet step.
    pub dh_public_key: DhPublicKey,
    /// Number of messages in the sender's previous sending chain, so the receiver
    /// can skip any unreceived keys from that chain before the DH ratchet step.
    pub previous_chain_length: u32,
    /// Index of this message within the sender's current sending chain.
    pub message_number: u32,
    /// The braid codeword streamed alongside this message (the SCKA message, one
    /// step of the post-quantum ratchet). Always present (may be
    /// [`crate::protocol::braid::MsgType::Idle`]).
    pub braid_msg: BraidMessage,
    /// The SPQR per-message counter (`pqN`) for this message -- the position in the
    /// current epoch's PQ KDF chain. The receiver uses it to derive and pair the
    /// post-quantum message key that is combined with the EC message key via
    /// `KDF_HYBRID`. Together with `braid_msg` this is the spec's
    /// `SCKA_HEADER = (scka_msg, pqN)`.
    pub pq_message_number: u32,
}

impl MessageHeader {
    /// Serialize the header to its wire bytes (postcard), as bound into the AEAD AD.
    pub fn serialize(&self) -> Vec<u8> {
        postcard::to_allocvec(self).expect("header serialization cannot fail")
    }

    /// Deserialize a header from its wire bytes, returning a
    /// [`crate::error::CryptoError::Serialization`] on malformed input.
    pub fn deserialize(data: &[u8]) -> crate::error::Result<Self> {
        postcard::from_bytes(data)
            .map_err(|e| crate::error::CryptoError::Serialization(e.to_string()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn header_roundtrip() {
        let header = MessageHeader {
            dh_public_key: DhPublicKey::from([1u8; 32]),
            previous_chain_length: 5,
            message_number: 10,
            braid_msg: crate::protocol::braid::Message::idle(7),
            pq_message_number: 42,
        };
        let bytes = header.serialize();
        let restored = MessageHeader::deserialize(&bytes).unwrap();
        assert_eq!(restored.dh_public_key, DhPublicKey::from([1u8; 32]));
        assert_eq!(restored.previous_chain_length, 5);
        assert_eq!(restored.message_number, 10);
        assert_eq!(restored.braid_msg.epoch, 7);
        assert_eq!(restored.pq_message_number, 42);
    }
}
