//! Sealed sender certificates: the self-signed `ServerCertificate` and the
//! `SenderCertificate` the server issues to bind a sender's identity key to its
//! UUID/device, both Ed25519-signed. Mirrors Signal's sealed sender trust chain.

use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};

use crate::error::{CryptoError, Result};
use crate::primitives::keys::IdentityPublicKey;
use crate::types::{DeviceId, SenderUuid, ServerKeyId, SigningPublicKey, Timestamp};

/// Server certificate containing the server's Ed25519 public key.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServerCertificate {
    /// Identifier for this server signing key.
    pub key_id: ServerKeyId,
    /// The server's Ed25519 public key.
    pub public_key: SigningPublicKey,
    /// Ed25519 signature over `key_id || public_key`, made by the same key
    /// (self-signed).
    pub signature: Vec<u8>,
}

impl ServerCertificate {
    /// Build a self-signed certificate for `key_id` using `signing_key`.
    pub fn new(key_id: impl Into<ServerKeyId>, signing_key: &SigningKey) -> Self {
        let key_id = key_id.into();
        let public_key = SigningPublicKey::from(signing_key.verifying_key().to_bytes());
        let mut data = Vec::new();
        data.extend_from_slice(&key_id.0.to_be_bytes());
        data.extend_from_slice(public_key.as_bytes());
        let signature = signing_key.sign(&data).to_bytes().to_vec();
        Self {
            key_id,
            public_key,
            signature,
        }
    }

    /// Verify the self-signature over `key_id || public_key`.
    pub fn verify_self_signed(&self) -> Result<()> {
        let vk = VerifyingKey::from_bytes(self.public_key.as_bytes())
            .map_err(|_| CryptoError::InvalidCertificate("invalid server public key".into()))?;
        let mut data = Vec::new();
        data.extend_from_slice(&self.key_id.0.to_be_bytes());
        data.extend_from_slice(self.public_key.as_bytes());
        verify_ed25519(&vk, &data, &self.signature)
    }
}

/// Sender certificate proving the sender's identity, signed by the server.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SenderCertificate {
    /// UUID of the sender this certificate is issued to.
    pub sender_uuid: SenderUuid,
    /// Device of the sender this certificate is issued to.
    pub sender_device_id: DeviceId,
    /// The sender's identity public key bound by this certificate.
    pub identity_key: IdentityPublicKey,
    /// Time after which this certificate is no longer valid.
    pub expiration: Timestamp,
    /// The server certificate whose key signed this sender certificate.
    pub server_certificate: ServerCertificate,
    /// Ed25519 signature by the server over the sender's UUID, device,
    /// identity key, and expiration.
    pub server_signature: Vec<u8>,
}

impl SenderCertificate {
    /// Build a sender certificate signed by the server's `server_signing_key`.
    pub fn new(
        sender_uuid: impl Into<SenderUuid>,
        sender_device_id: impl Into<DeviceId>,
        identity_key: IdentityPublicKey,
        expiration: impl Into<Timestamp>,
        server_signing_key: &SigningKey,
        server_certificate: ServerCertificate,
    ) -> Self {
        let sender_uuid = sender_uuid.into();
        let sender_device_id = sender_device_id.into();
        let expiration = expiration.into();
        let cert_data =
            Self::signable_data(&sender_uuid, sender_device_id, &identity_key, expiration);
        let server_signature = server_signing_key.sign(&cert_data).to_bytes().to_vec();
        Self {
            sender_uuid,
            sender_device_id,
            identity_key,
            expiration,
            server_certificate,
            server_signature,
        }
    }

    fn signable_data(
        sender_uuid: &SenderUuid,
        sender_device_id: DeviceId,
        identity_key: &IdentityPublicKey,
        expiration: Timestamp,
    ) -> Vec<u8> {
        let mut data = Vec::with_capacity(16 + 4 + 32 + 8);
        data.extend_from_slice(sender_uuid.0.as_bytes());
        data.extend_from_slice(&sender_device_id.0.to_be_bytes());
        data.extend_from_slice(&identity_key.as_bytes());
        data.extend_from_slice(&expiration.0.to_be_bytes());
        data
    }

    /// Validate the certificate: not expired at `now`, the server certificate
    /// is self-signed by `trust_root`, and the server signature over the
    /// sender fields verifies.
    pub fn validate(&self, trust_root: &VerifyingKey, now: Timestamp) -> Result<()> {
        if now >= self.expiration {
            return Err(CryptoError::ExpiredCertificate);
        }

        self.server_certificate.verify_self_signed()?;

        let server_vk = VerifyingKey::from_bytes(self.server_certificate.public_key.as_bytes())
            .map_err(|_| CryptoError::InvalidCertificate("invalid server key".into()))?;

        if server_vk.to_bytes() != trust_root.to_bytes() {
            return Err(CryptoError::InvalidCertificate(
                "server certificate not signed by trust root".into(),
            ));
        }

        let cert_data = Self::signable_data(
            &self.sender_uuid,
            self.sender_device_id,
            &self.identity_key,
            self.expiration,
        );
        verify_ed25519(&server_vk, &cert_data, &self.server_signature)
    }
}

fn verify_ed25519(key: &VerifyingKey, data: &[u8], signature: &[u8]) -> Result<()> {
    let sig_bytes: [u8; 64] = signature
        .try_into()
        .map_err(|_| CryptoError::InvalidSignature)?;
    let sig = Signature::from_bytes(&sig_bytes);
    key.verify(data, &sig)
        .map_err(|_| CryptoError::InvalidCertificate("signature verification failed".into()))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_server_key() -> SigningKey {
        SigningKey::from_bytes(&[1u8; 32])
    }

    #[test]
    fn server_certificate_self_verify() {
        let sk = test_server_key();
        let cert = ServerCertificate::new(1u32, &sk);
        assert!(cert.verify_self_signed().is_ok());
    }

    #[test]
    fn server_certificate_tampered_fails() {
        let sk = test_server_key();
        let mut cert = ServerCertificate::new(1u32, &sk);
        cert.key_id = ServerKeyId::from(2);
        assert!(cert.verify_self_signed().is_err());
    }

    #[test]
    fn sender_certificate_valid() {
        let sk = test_server_key();
        let server_cert = ServerCertificate::new(1u32, &sk);
        let identity = crate::primitives::keys::IdentityKeyPair::generate();
        let sender_cert = SenderCertificate::new(
            SenderUuid::from(uuid::Uuid::nil()),
            1u32,
            identity.public_key(),
            u64::MAX,
            &sk,
            server_cert,
        );
        let trust_root = sk.verifying_key();
        assert!(sender_cert.validate(&trust_root, Timestamp(0)).is_ok());
    }

    #[test]
    fn sender_certificate_expired() {
        let sk = test_server_key();
        let server_cert = ServerCertificate::new(1u32, &sk);
        let identity = crate::primitives::keys::IdentityKeyPair::generate();
        let sender_cert = SenderCertificate::new(
            SenderUuid::from(uuid::Uuid::nil()),
            1u32,
            identity.public_key(),
            100u64,
            &sk,
            server_cert,
        );
        let trust_root = sk.verifying_key();
        assert!(matches!(
            sender_cert.validate(&trust_root, Timestamp(200)),
            Err(CryptoError::ExpiredCertificate)
        ));
    }

    #[test]
    fn sender_certificate_wrong_trust_root() {
        let sk = test_server_key();
        let server_cert = ServerCertificate::new(1u32, &sk);
        let identity = crate::primitives::keys::IdentityKeyPair::generate();
        let sender_cert = SenderCertificate::new(
            SenderUuid::from(uuid::Uuid::nil()),
            1u32,
            identity.public_key(),
            u64::MAX,
            &sk,
            server_cert,
        );
        let wrong_root = SigningKey::from_bytes(&[2u8; 32]).verifying_key();
        assert!(sender_cert.validate(&wrong_root, Timestamp(0)).is_err());
    }

    #[test]
    fn sender_certificate_tampered_signature() {
        let sk = test_server_key();
        let server_cert = ServerCertificate::new(1u32, &sk);
        let identity = crate::primitives::keys::IdentityKeyPair::generate();
        let mut sender_cert = SenderCertificate::new(
            SenderUuid::from(uuid::Uuid::nil()),
            1u32,
            identity.public_key(),
            u64::MAX,
            &sk,
            server_cert,
        );
        sender_cert.server_signature = vec![0u8; 64];
        let trust_root = sk.verifying_key();
        assert!(sender_cert.validate(&trust_root, Timestamp(0)).is_err());
    }

    #[test]
    fn truncated_server_signature_rejected() {
        let sk = test_server_key();
        let mut cert = ServerCertificate::new(1u32, &sk);
        cert.signature = vec![0u8; 32];
        assert!(cert.verify_self_signed().is_err());
    }

    #[test]
    fn truncated_sender_signature_rejected() {
        let sk = test_server_key();
        let server_cert = ServerCertificate::new(1u32, &sk);
        let identity = crate::primitives::keys::IdentityKeyPair::generate();
        let mut sender_cert = SenderCertificate::new(
            SenderUuid::from(uuid::Uuid::nil()),
            1u32,
            identity.public_key(),
            u64::MAX,
            &sk,
            server_cert,
        );
        sender_cert.server_signature = vec![0u8; 32];
        let trust_root = sk.verifying_key();
        assert!(sender_cert.validate(&trust_root, Timestamp(0)).is_err());
    }
}
