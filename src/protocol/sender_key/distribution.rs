//! The [`SenderKeyDistributionMessage`] that bootstraps a group member's
//! sender key chain, mirroring Signal.

use serde::{Deserialize, Serialize};

/// Sender key distribution message sent to group members.
///
/// `signing_key` carries the sender's per-sender-key Ed25519 public key,
/// mirroring Signal. When present, each `SenderKeyMessage` on this chain is
/// authenticated with a per-message Ed25519 signature, so no group member can
/// forge another member's messages (the private signing key never leaves the
/// sender). The signing key is bound to a real identity by the authenticated
/// pairwise channel this distribution message travels over.
///
/// `signing_key` is `None` for HMAC-authenticated chains (voice frames), where
/// per-frame signatures would be prohibitively expensive; those rely on the
/// voice transport layer for authentication. See `SenderKeyAuth`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SenderKeyDistributionMessage {
    /// Identifier of the group this chain belongs to.
    pub group_id: Vec<u8>,
    /// The chain key at `iteration`, from which recipients derive message keys.
    pub chain_key: [u8; 32],
    /// Chain iteration the `chain_key` is positioned at.
    pub iteration: u32,
    /// The sender's per-sender-key Ed25519 public key for signed chains, or
    /// `None` for HMAC-authenticated (voice) chains.
    pub signing_key: Option<[u8; 32]>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn serde_roundtrip() {
        let msg = SenderKeyDistributionMessage {
            group_id: b"group-1".to_vec(),
            chain_key: [1u8; 32],
            iteration: 0,
            signing_key: Some([2u8; 32]),
        };
        let bytes = postcard::to_allocvec(&msg).unwrap();
        let restored: SenderKeyDistributionMessage = postcard::from_bytes(&bytes).unwrap();
        assert_eq!(restored.group_id, b"group-1");
        assert_eq!(restored.chain_key, [1u8; 32]);
        assert_eq!(restored.signing_key, Some([2u8; 32]));
    }
}
