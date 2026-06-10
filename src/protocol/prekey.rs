//! Prekey bundles and the PQXDH initial message.
//!
//! A [`PreKeyBundle`] is the set of public keys a user publishes to the server
//! so that an initiator can run PQXDH (post-quantum X3DH) without the recipient
//! being online. [`PqxdhInitialMessage`] is what the initiator sends alongside
//! its first ciphertext so the responder can derive the same shared secret.

use serde::{Deserialize, Serialize};

use crate::primitives::keys::IdentityPublicKey;
use crate::types::{
    DeviceId, DhPublicKey, KyberPreKeyId, PreKeyId, RegistrationId, SignedPreKeyId,
};

/// Prekey bundle published by a user for PQXDH key agreement.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PreKeyBundle {
    /// Registration ID identifying this device's key set.
    pub registration_id: RegistrationId,
    /// Device the bundle belongs to.
    pub device_id: DeviceId,
    /// Long-term identity public key (Ed25519/Curve25519).
    pub identity_key: IdentityPublicKey,
    /// ID of the signed prekey included below.
    pub signed_pre_key_id: SignedPreKeyId,
    /// Public Curve25519 signed prekey.
    pub signed_pre_key_public: DhPublicKey,
    /// Identity-key signature over the signed prekey.
    pub signed_pre_key_signature: Vec<u8>,
    /// Optional one-time prekey, consumed once per handshake when present.
    pub one_time_pre_key: Option<OneTimePreKey>,
    /// ML-KEM-1024 post-quantum prekey.
    pub kyber_pre_key: KyberPreKey,
}

/// One-time prekey (optional in the bundle).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OneTimePreKey {
    /// ID identifying this one-time prekey.
    pub id: PreKeyId,
    /// Public Curve25519 key.
    pub public_key: DhPublicKey,
}

/// ML-KEM prekey for post-quantum key encapsulation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KyberPreKey {
    /// ID identifying this Kyber prekey.
    pub id: KyberPreKeyId,
    /// Serialized ML-KEM-1024 encapsulation (public) key.
    pub public_key: Vec<u8>,
    /// Identity-key signature over the encapsulation key.
    pub signature: Vec<u8>,
    /// Whether this is the reusable last-resort prekey rather than a one-time one.
    pub is_last_resort: bool,
}

/// Initial message sent by the PQXDH initiator (Alice).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PqxdhInitialMessage {
    /// Initiator's registration ID.
    pub registration_id: RegistrationId,
    /// Initiator's ephemeral Curve25519 public key.
    pub ephemeral_public_key: DhPublicKey,
    /// ID of the responder's signed prekey used in the handshake.
    pub signed_pre_key_id: SignedPreKeyId,
    /// ID of the responder's one-time prekey, if one was consumed.
    pub one_time_pre_key_id: Option<PreKeyId>,
    /// ID of the responder's Kyber prekey used for encapsulation.
    pub kyber_pre_key_id: KyberPreKeyId,
    /// ML-KEM-1024 ciphertext encapsulated to the responder's Kyber prekey.
    pub kyber_ciphertext: Vec<u8>,
    /// Initiator's long-term identity public key.
    pub identity_key: IdentityPublicKey,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::primitives::keys::IdentityKeyPair;

    #[test]
    fn prekey_bundle_serde_roundtrip() {
        let kp = IdentityKeyPair::generate();
        let bundle = PreKeyBundle {
            registration_id: RegistrationId::from(1),
            device_id: DeviceId::from(2),
            identity_key: kp.public_key(),
            signed_pre_key_id: SignedPreKeyId::from(3),
            signed_pre_key_public: DhPublicKey::from([4u8; 32]),
            signed_pre_key_signature: vec![5u8; 64],
            one_time_pre_key: Some(OneTimePreKey {
                id: PreKeyId::from(6),
                public_key: DhPublicKey::from([7u8; 32]),
            }),
            kyber_pre_key: KyberPreKey {
                id: KyberPreKeyId::from(8),
                public_key: vec![9u8; 1184],
                signature: vec![10u8; 64],
                is_last_resort: false,
            },
        };
        let bytes = postcard::to_allocvec(&bundle).unwrap();
        let restored: PreKeyBundle = postcard::from_bytes(&bytes).unwrap();
        assert_eq!(restored.registration_id, RegistrationId::from(1));
        assert_eq!(restored.device_id, DeviceId::from(2));
        assert_eq!(restored.signed_pre_key_id, SignedPreKeyId::from(3));
        assert_eq!(
            restored.one_time_pre_key.as_ref().unwrap().id,
            PreKeyId::from(6)
        );
        assert_eq!(restored.kyber_pre_key.id, KyberPreKeyId::from(8));
    }

    #[test]
    fn prekey_bundle_without_opk() {
        let kp = IdentityKeyPair::generate();
        let bundle = PreKeyBundle {
            registration_id: RegistrationId::from(1),
            device_id: DeviceId::from(1),
            identity_key: kp.public_key(),
            signed_pre_key_id: SignedPreKeyId::from(1),
            signed_pre_key_public: DhPublicKey::from([0u8; 32]),
            signed_pre_key_signature: vec![0u8; 64],
            one_time_pre_key: None,
            kyber_pre_key: KyberPreKey {
                id: KyberPreKeyId::from(1),
                public_key: vec![0u8; 1184],
                signature: vec![0u8; 64],
                is_last_resort: true,
            },
        };
        let bytes = postcard::to_allocvec(&bundle).unwrap();
        let restored: PreKeyBundle = postcard::from_bytes(&bytes).unwrap();
        assert!(restored.one_time_pre_key.is_none());
        assert!(restored.kyber_pre_key.is_last_resort);
    }

    #[test]
    fn initial_message_serde_roundtrip() {
        let kp = IdentityKeyPair::generate();
        let msg = PqxdhInitialMessage {
            registration_id: RegistrationId::from(42),
            ephemeral_public_key: DhPublicKey::from([1u8; 32]),
            signed_pre_key_id: SignedPreKeyId::from(5),
            one_time_pre_key_id: Some(PreKeyId::from(10)),
            kyber_pre_key_id: KyberPreKeyId::from(3),
            kyber_ciphertext: vec![2u8; 1088],
            identity_key: kp.public_key(),
        };
        let bytes = postcard::to_allocvec(&msg).unwrap();
        let restored: PqxdhInitialMessage = postcard::from_bytes(&bytes).unwrap();
        assert_eq!(restored.registration_id, RegistrationId::from(42));
        assert_eq!(restored.one_time_pre_key_id, Some(PreKeyId::from(10)));
    }
}
