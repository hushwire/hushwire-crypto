//! Async storage traits for the Signal Protocol state the caller must persist.
//!
//! Defines the identity key store, session store, prekey / signed prekey /
//! Kyber prekey stores, sender key store, and Sesame store, along with their
//! associated record types and the [`Direction`] enum. The crate provides the
//! protocol logic; the caller supplies the backing persistence by implementing
//! these traits.

use crate::address::ProtocolAddress;
use crate::error::Result;
use crate::primitives::keys::IdentityPublicKey;
use crate::types::{
    DhPublicKey, KyberPreKeyId, PreKeyId, RegistrationId, SignedPreKeyId, Timestamp,
};

/// Direction of a protocol operation, used for identity key trust decisions.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Direction {
    /// Outbound operation: encrypting/sending to the remote party.
    Sending,
    /// Inbound operation: decrypting/receiving from the remote party.
    Receiving,
}

/// Identity key store: persists and validates remote identity keys.
pub trait IdentityKeyStore: Send + Sync {
    /// Returns the local long-term identity key pair.
    fn get_identity_key_pair(
        &self,
    ) -> impl std::future::Future<Output = Result<crate::primitives::keys::IdentityKeyPair>> + Send;

    /// Returns the local registration id.
    fn get_local_registration_id(
        &self,
    ) -> impl std::future::Future<Output = Result<RegistrationId>> + Send;

    /// Records the remote `identity` key for `address`, returning `true` if it
    /// replaced a different previously stored key (an identity change).
    fn save_identity(
        &mut self,
        address: &ProtocolAddress,
        identity: &IdentityPublicKey,
    ) -> impl std::future::Future<Output = Result<bool>> + Send;

    /// Returns whether `identity` is trusted for `address` in the given
    /// `direction` (trust-on-first-use: unknown identities are trusted).
    fn is_trusted_identity(
        &self,
        address: &ProtocolAddress,
        identity: &IdentityPublicKey,
        direction: Direction,
    ) -> impl std::future::Future<Output = Result<bool>> + Send;

    /// Returns the stored identity key for `address`, or `None` if unknown.
    fn get_identity(
        &self,
        address: &ProtocolAddress,
    ) -> impl std::future::Future<Output = Result<Option<IdentityPublicKey>>> + Send;
}

/// Prekey record for storage.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct PreKeyRecord {
    /// Identifier for this one-time prekey.
    pub id: PreKeyId,
    /// Curve25519 public key.
    pub public_key: DhPublicKey,
    /// Curve25519 private key bytes.
    pub private_key: Vec<u8>,
}

/// Signed prekey record for storage.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct SignedPreKeyRecord {
    /// Identifier for this signed prekey.
    pub id: SignedPreKeyId,
    /// Curve25519 public key.
    pub public_key: DhPublicKey,
    /// Curve25519 private key bytes.
    pub private_key: Vec<u8>,
    /// Signature over `public_key` by the local identity key.
    pub signature: Vec<u8>,
    /// Time the key was generated.
    pub timestamp: Timestamp,
}

/// Kyber prekey record for storage.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct KyberPreKeyRecord {
    /// Identifier for this Kyber prekey.
    pub id: KyberPreKeyId,
    /// Kyber (ML-KEM) public key bytes.
    pub public_key: Vec<u8>,
    /// Kyber (ML-KEM) secret key bytes.
    pub secret_key: Vec<u8>,
    /// Signature over `public_key` by the local identity key.
    pub signature: Vec<u8>,
    /// Time the key was generated.
    pub timestamp: Timestamp,
    /// Whether this is a last-resort key (reusable when no one-time keys remain).
    pub is_last_resort: bool,
}

/// Session record: opaque serialized ratchet state.
///
/// When a session is overwritten (e.g., during dual-init race
/// resolution), the old state is archived in `previous_states`. On
/// decrypt failure with the active session, previous states are tried
/// in order; the first to succeed is promoted to active.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct SessionRecord {
    /// Serialized active ratchet state.
    pub data: Vec<u8>,
    /// Archived prior ratchet states, newest first, tried on decrypt failure.
    #[serde(default)]
    pub previous_states: Vec<Vec<u8>>,
}

/// Sender key record: opaque serialized sender key state.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct SenderKeyRecord {
    /// Serialized sender key (group ratchet) state.
    pub data: Vec<u8>,
}

/// Sesame user record: opaque serialized multi-device session state.
///
/// Like [`SessionRecord`] and [`SenderKeyRecord`], this is an opaque byte blob
/// from the store's perspective. The caller serializes the Sesame user record
/// (devices and their session entries) into `data` before storing and
/// deserializes it on load; the store only persists the bytes.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct SesameUserRecord {
    /// Serialized Sesame user record (per-device session state).
    pub data: Vec<u8>,
}

/// Prekey store.
pub trait PreKeyStore: Send + Sync {
    /// Loads the prekey record for `id`.
    fn get_pre_key(
        &self,
        id: &PreKeyId,
    ) -> impl std::future::Future<Output = Result<PreKeyRecord>> + Send;
    /// Stores `record` under `id`.
    fn save_pre_key(
        &mut self,
        id: &PreKeyId,
        record: &PreKeyRecord,
    ) -> impl std::future::Future<Output = Result<()>> + Send;
    /// Removes the prekey for `id` (called after it is consumed).
    fn remove_pre_key(
        &mut self,
        id: &PreKeyId,
    ) -> impl std::future::Future<Output = Result<()>> + Send;
}

/// Signed prekey store.
pub trait SignedPreKeyStore: Send + Sync {
    /// Loads the signed prekey record for `id`.
    fn get_signed_pre_key(
        &self,
        id: &SignedPreKeyId,
    ) -> impl std::future::Future<Output = Result<SignedPreKeyRecord>> + Send;
    /// Stores `record` under `id`.
    fn save_signed_pre_key(
        &mut self,
        id: &SignedPreKeyId,
        record: &SignedPreKeyRecord,
    ) -> impl std::future::Future<Output = Result<()>> + Send;
}

/// Kyber prekey store.
pub trait KyberPreKeyStore: Send + Sync {
    /// Loads the Kyber prekey record for `id`.
    fn get_kyber_pre_key(
        &self,
        id: &KyberPreKeyId,
    ) -> impl std::future::Future<Output = Result<KyberPreKeyRecord>> + Send;
    /// Stores `record` under `id`.
    fn save_kyber_pre_key(
        &mut self,
        id: &KyberPreKeyId,
        record: &KyberPreKeyRecord,
    ) -> impl std::future::Future<Output = Result<()>> + Send;
    /// Marks the Kyber prekey `id` as consumed (no-op for last-resort keys).
    fn mark_kyber_pre_key_used(
        &mut self,
        id: &KyberPreKeyId,
    ) -> impl std::future::Future<Output = Result<()>> + Send;
}

/// Session store.
pub trait SessionStore: Send + Sync {
    /// Loads the session record for `address`, or `None` if no session exists.
    fn load_session(
        &self,
        address: &ProtocolAddress,
    ) -> impl std::future::Future<Output = Result<Option<SessionRecord>>> + Send;
    /// Stores `record` as the session for `address`.
    fn store_session(
        &mut self,
        address: &ProtocolAddress,
        record: &SessionRecord,
    ) -> impl std::future::Future<Output = Result<()>> + Send;
}

/// Sender key store.
pub trait SenderKeyStore: Send + Sync {
    /// Stores `record` keyed by `sender` and group `distribution_id`.
    fn store_sender_key(
        &mut self,
        sender: &ProtocolAddress,
        distribution_id: &[u8; 16],
        record: &SenderKeyRecord,
    ) -> impl std::future::Future<Output = Result<()>> + Send;

    /// Loads the sender key for `sender` and `distribution_id`, or `None`.
    fn load_sender_key(
        &self,
        sender: &ProtocolAddress,
        distribution_id: &[u8; 16],
    ) -> impl std::future::Future<Output = Result<Option<SenderKeyRecord>>> + Send;
}

/// Store for Sesame user records (multi-device session management).
///
/// Deals in opaque [`SesameUserRecord`] bytes; the caller is responsible for
/// (de)serializing its [`crate::protocol::sesame::UserRecord`] into the record.
pub trait SesameStore: Send + Sync {
    /// Loads the Sesame user record for `user_id`, or `None` if absent.
    fn load_user_record(
        &self,
        user_id: uuid::Uuid,
    ) -> impl std::future::Future<Output = Result<Option<SesameUserRecord>>> + Send;

    /// Stores `record` for `user_id`.
    fn store_user_record(
        &mut self,
        user_id: uuid::Uuid,
        record: &SesameUserRecord,
    ) -> impl std::future::Future<Output = Result<()>> + Send;

    /// Removes the Sesame user record for `user_id`.
    fn remove_user_record(
        &mut self,
        user_id: uuid::Uuid,
    ) -> impl std::future::Future<Output = Result<()>> + Send;

    /// Returns the ids of all users with stored Sesame records.
    fn list_users(&self) -> impl std::future::Future<Output = Result<Vec<uuid::Uuid>>> + Send;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn prekey_record_serde() {
        let record = PreKeyRecord {
            id: PreKeyId::from(1),
            public_key: DhPublicKey::from([1u8; 32]),
            private_key: vec![2u8; 32],
        };
        let bytes = postcard::to_allocvec(&record).unwrap();
        let restored: PreKeyRecord = postcard::from_bytes(&bytes).unwrap();
        assert_eq!(restored.id, PreKeyId::from(1));
        assert_eq!(restored.public_key, DhPublicKey::from([1u8; 32]));
    }

    #[test]
    fn signed_prekey_record_serde() {
        let record = SignedPreKeyRecord {
            id: SignedPreKeyId::from(5),
            public_key: DhPublicKey::from([3u8; 32]),
            private_key: vec![4u8; 32],
            signature: vec![5u8; 64],
            timestamp: Timestamp::from(1234567890),
        };
        let bytes = postcard::to_allocvec(&record).unwrap();
        let restored: SignedPreKeyRecord = postcard::from_bytes(&bytes).unwrap();
        assert_eq!(restored.id, SignedPreKeyId::from(5));
        assert_eq!(restored.timestamp, Timestamp::from(1234567890));
    }

    #[test]
    fn kyber_prekey_record_serde() {
        let record = KyberPreKeyRecord {
            id: KyberPreKeyId::from(10),
            public_key: vec![6u8; 64],
            secret_key: vec![7u8; 64],
            signature: vec![8u8; 64],
            timestamp: Timestamp::from(9999999),
            is_last_resort: true,
        };
        let bytes = postcard::to_allocvec(&record).unwrap();
        let restored: KyberPreKeyRecord = postcard::from_bytes(&bytes).unwrap();
        assert_eq!(restored.id, KyberPreKeyId::from(10));
        assert!(restored.is_last_resort);
    }

    #[test]
    fn session_record_serde() {
        let record = SessionRecord {
            data: vec![1, 2, 3, 4, 5],
            previous_states: vec![vec![6, 7], vec![8, 9]],
        };
        let bytes = postcard::to_allocvec(&record).unwrap();
        let restored: SessionRecord = postcard::from_bytes(&bytes).unwrap();
        assert_eq!(restored.data, vec![1, 2, 3, 4, 5]);
        assert_eq!(restored.previous_states.len(), 2);
        assert_eq!(restored.previous_states[0], vec![6, 7]);
    }

    #[test]
    fn session_record_backward_compat_postcard_rejects_old_format() {
        // postcard uses positional encoding -- #[serde(default)] does NOT
        // handle missing trailing fields. Old-format records (data only)
        // fail with DeserializeUnexpectedEnd. The CryptoStore in the SDK
        // handles this with a try-new-then-fallback-to-old pattern.
        #[derive(serde::Serialize)]
        struct OldSessionRecord {
            data: Vec<u8>,
        }
        let old = OldSessionRecord {
            data: vec![1, 2, 3],
        };
        let bytes = postcard::to_allocvec(&old).unwrap();
        assert!(postcard::from_bytes::<SessionRecord>(&bytes).is_err());
    }

    #[test]
    fn sender_key_record_serde() {
        let record = SenderKeyRecord {
            data: vec![10, 20, 30],
        };
        let bytes = postcard::to_allocvec(&record).unwrap();
        let restored: SenderKeyRecord = postcard::from_bytes(&bytes).unwrap();
        assert_eq!(restored.data, vec![10, 20, 30]);
    }
}
