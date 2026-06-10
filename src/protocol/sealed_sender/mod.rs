//! Sealed sender: hide the sender's identity from the server.
//!
//! Implements Signal's two-layer sealed sender v2 ([`seal`]/[`unseal`]) plus
//! the [`certificate`] trust chain (server and sender certificates). The outer
//! envelope wraps pre-encrypted Double Ratchet ciphertext and binds the
//! sender's `SenderCertificate` so the recipient can authenticate the sender
//! without the server learning who sent the message.

pub mod certificate;

use rand::RngExt as _;
use sha2::{Digest, Sha256};
use x25519_dalek::{PublicKey as X25519Public, StaticSecret as X25519Secret};
use zeroize::Zeroize;

use crate::error::{CryptoError, Result};
use crate::primitives::kdf::hkdf_sha256;
use crate::primitives::keys::{IdentityKeyPair, IdentityPublicKey};
use crate::types::{DeviceId, SenderUuid, Timestamp};

use self::certificate::SenderCertificate;

const SEALED_SENDER_STATIC_INFO: &[u8] = b"HushwireSealedSender";
const SEALED_SENDER_MESSAGE_INFO: &[u8] = b"HushwireSealedSenderMessage";

/// Derive the layer-1 `(chain_key, static_cipher_key)` pair from the layer-1 DH
/// output, salted by the ephemeral public key. Seal and unseal derive these
/// identically (only the DH operands' order differs), so it lives here once.
fn derive_layer1_keys(layer1_dh: &[u8; 32], salt: &[u8; 32]) -> ([u8; 32], [u8; 32]) {
    let mut material = hkdf_sha256(layer1_dh, Some(salt), SEALED_SENDER_STATIC_INFO, 64);
    let mut chain_key = [0u8; 32];
    let mut static_cipher_key = [0u8; 32];
    chain_key.copy_from_slice(&material[..32]);
    static_cipher_key.copy_from_slice(&material[32..64]);
    material.zeroize();
    (chain_key, static_cipher_key)
}

/// Sealed sender envelope hiding the sender's identity from the server.
///
/// Two-layer construction matching Signal's sealed sender v2:
/// - Layer 1 (`encrypted_static`): sender's X25519 public key, encrypted with
///   `DH(ephemeral, recipient)`.
/// - Layer 2 (`encrypted_message`): inner message (cert + content), encrypted
///   with `DH(ephemeral, recipient) + DH(sender_identity, recipient)`.
///
/// The sender identity DH prevents recipient-key-compromise forgery: an attacker
/// who steals the recipient's private key can *read* messages but cannot forge
/// messages from a specific sender without also compromising that sender's
/// identity key.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct SealedSenderEnvelope {
    /// Ephemeral X25519 public key used for the layer-1 DH.
    pub ephemeral_public: [u8; 32],
    /// Layer 1: the sender's X25519 public key, AEAD-encrypted under
    /// `DH(ephemeral, recipient)`.
    pub encrypted_static: Vec<u8>,
    /// SHA-256 hash of the `SenderCertificate`, carried unencrypted so the
    /// recipient can reconstruct the AEAD associated data; re-checked against
    /// the decrypted certificate.
    pub cert_hash: [u8; 32],
    /// Layer 2: the inner message (certificate + content), AEAD-encrypted under
    /// `chain_key || DH(sender_identity, recipient)`.
    pub encrypted_message: Vec<u8>,
}

/// Result of unsealing a sealed sender message.
pub struct UnsealedMessage {
    /// Authenticated UUID of the sender, from the validated certificate.
    pub sender_uuid: SenderUuid,
    /// Authenticated device of the sender, from the validated certificate.
    pub sender_device_id: DeviceId,
    /// The sender's identity public key, from the validated certificate.
    pub sender_identity: IdentityPublicKey,
    /// The decrypted inner content (pre-encrypted Double Ratchet ciphertext).
    pub content: Vec<u8>,
}

/// Seal content for a recipient, hiding the sender's identity from the server.
///
/// `content` must be pre-encrypted Double Ratchet ciphertext (a serialized
/// `RatchetMessage`). This function provides the outer envelope only; inner
/// message encryption is the caller's responsibility.
///
/// Two-layer encryption:
/// 1. Encrypt sender's X25519 identity key with `DH(ephemeral, recipient)`.
/// 2. Encrypt `InnerMessage` with `chain_key || DH(sender_identity, recipient)`,
///    binding the `SenderCertificate` hash in the AEAD associated data.
pub fn seal(
    sender_identity: &IdentityKeyPair,
    sender_cert: &SenderCertificate,
    content: &[u8],
    recipient_identity: &IdentityPublicKey,
) -> Result<Vec<u8>> {
    let recipient_x25519 = recipient_identity.to_x25519();

    let mut eph_bytes = [0u8; 32];
    rand::rng().fill(&mut eph_bytes[..]);
    let eph_secret = X25519Secret::from(eph_bytes);
    eph_bytes.zeroize();
    let eph_public = X25519Public::from(&eph_secret);

    // Layer 1: DH(ephemeral, recipient)
    let e_a = eph_secret.diffie_hellman(&recipient_x25519);
    let mut salt = [0u8; 32];
    salt.copy_from_slice(eph_public.as_bytes());
    let (mut chain_key, mut static_cipher_key) = derive_layer1_keys(e_a.as_bytes(), &salt);

    // Encrypt sender's X25519 public key
    let sender_x25519_pub = sender_identity.x25519_public_key();
    let encrypted_static = crate::primitives::aead::encrypt(
        &static_cipher_key,
        sender_x25519_pub.as_bytes(),
        eph_public.as_bytes(),
    )?;
    static_cipher_key.zeroize();

    // Layer 2: DH(sender_identity, recipient)
    let sender_x25519_priv = sender_identity.x25519_private_key();
    let e_b = sender_x25519_priv.diffie_hellman(&recipient_x25519);

    let mut layer2_input = Vec::with_capacity(64);
    layer2_input.extend_from_slice(&chain_key);
    layer2_input.extend_from_slice(e_b.as_bytes());
    chain_key.zeroize();

    let mut message_key_vec =
        hkdf_sha256(&layer2_input, Some(&salt), SEALED_SENDER_MESSAGE_INFO, 32);
    layer2_input.zeroize();
    let mut message_key = [0u8; 32];
    message_key.copy_from_slice(&message_key_vec);
    message_key_vec.zeroize();

    // Build inner message and compute cert hash for AD binding
    let inner = InnerMessage {
        sender_certificate: sender_cert.clone(),
        content: content.to_vec(),
    };
    let inner_bytes =
        postcard::to_allocvec(&inner).map_err(|e| CryptoError::Serialization(e.to_string()))?;

    let cert_bytes = postcard::to_allocvec(sender_cert)
        .map_err(|e| CryptoError::Serialization(e.to_string()))?;
    let cert_hash: [u8; 32] = Sha256::digest(&cert_bytes).into();

    // AD = ephemeral_public || encrypted_static || cert_hash
    let mut ad = Vec::with_capacity(32 + encrypted_static.len() + 32);
    ad.extend_from_slice(eph_public.as_bytes());
    ad.extend_from_slice(&encrypted_static);
    ad.extend_from_slice(&cert_hash);

    let encrypted_message = crate::primitives::aead::encrypt(&message_key, &inner_bytes, &ad)?;
    message_key.zeroize();

    let envelope = SealedSenderEnvelope {
        ephemeral_public: eph_public.to_bytes(),
        encrypted_static,
        cert_hash,
        encrypted_message,
    };

    postcard::to_allocvec(&envelope).map_err(|e| CryptoError::Serialization(e.to_string()))
}

/// Unseal a sealed sender message.
///
/// Two-layer decryption:
/// 1. Derive layer-1 key from `DH(recipient, ephemeral)`, decrypt sender's
///    X25519 public key.
/// 2. Derive layer-2 key from `chain_key || DH(recipient, sender_static)`,
///    decrypt and validate the inner message.
pub fn unseal(
    envelope_bytes: &[u8],
    recipient_identity: &IdentityKeyPair,
    trust_root: &ed25519_dalek::VerifyingKey,
    now: impl Into<Timestamp>,
) -> Result<UnsealedMessage> {
    let now = now.into();
    let envelope: SealedSenderEnvelope = postcard::from_bytes(envelope_bytes)
        .map_err(|e| CryptoError::Serialization(e.to_string()))?;

    let eph_public = X25519Public::from(envelope.ephemeral_public);
    let our_x25519 = recipient_identity.x25519_private_key();

    // Layer 1: DH(recipient, ephemeral)
    let e_a = our_x25519.diffie_hellman(&eph_public);
    let mut salt = [0u8; 32];
    salt.copy_from_slice(eph_public.as_bytes());
    let (mut chain_key, mut static_cipher_key) = derive_layer1_keys(e_a.as_bytes(), &salt);

    // Decrypt sender's X25519 public key
    let sender_x25519_bytes = crate::primitives::aead::decrypt(
        &static_cipher_key,
        &envelope.encrypted_static,
        eph_public.as_bytes(),
    )?;
    static_cipher_key.zeroize();

    let sender_x25519_arr: [u8; 32] = sender_x25519_bytes
        .as_slice()
        .try_into()
        .map_err(|_| CryptoError::InvalidKey)?;
    let sender_x25519 = X25519Public::from(sender_x25519_arr);

    // Layer 2: DH(recipient, sender_static)
    let e_b = our_x25519.diffie_hellman(&sender_x25519);

    let mut layer2_input = Vec::with_capacity(64);
    layer2_input.extend_from_slice(&chain_key);
    layer2_input.extend_from_slice(e_b.as_bytes());
    chain_key.zeroize();

    let mut message_key_vec =
        hkdf_sha256(&layer2_input, Some(&salt), SEALED_SENDER_MESSAGE_INFO, 32);
    layer2_input.zeroize();
    let mut message_key = [0u8; 32];
    message_key.copy_from_slice(&message_key_vec);
    message_key_vec.zeroize();

    // AD = ephemeral_public || encrypted_static || cert_hash
    // cert_hash is carried unencrypted in the envelope so the recipient can
    // reconstruct the AD for AEAD decryption. Post-decryption, we verify the
    // hash matches the actual certificate inside the decrypted message.
    let mut ad = Vec::with_capacity(32 + envelope.encrypted_static.len() + 32);
    ad.extend_from_slice(eph_public.as_bytes());
    ad.extend_from_slice(&envelope.encrypted_static);
    ad.extend_from_slice(&envelope.cert_hash);

    let inner_bytes =
        crate::primitives::aead::decrypt(&message_key, &envelope.encrypted_message, &ad)?;
    message_key.zeroize();

    let inner: InnerMessage = postcard::from_bytes(&inner_bytes)
        .map_err(|e| CryptoError::Serialization(e.to_string()))?;

    // Verify cert_hash matches the actual decrypted certificate
    let cert_bytes = postcard::to_allocvec(&inner.sender_certificate)
        .map_err(|e| CryptoError::Serialization(e.to_string()))?;
    let actual_hash: [u8; 32] = Sha256::digest(&cert_bytes).into();
    if actual_hash != envelope.cert_hash {
        return Err(CryptoError::InvalidCertificate(
            "certificate hash mismatch".into(),
        ));
    }

    inner.sender_certificate.validate(trust_root, now)?;

    // Verify sender's X25519 key matches the certificate identity
    let cert_x25519 = inner.sender_certificate.identity_key.to_x25519();
    if cert_x25519.as_bytes() != sender_x25519.as_bytes() {
        return Err(CryptoError::InvalidCertificate(
            "sender static key does not match certificate identity".into(),
        ));
    }

    Ok(UnsealedMessage {
        sender_uuid: inner.sender_certificate.sender_uuid,
        sender_device_id: inner.sender_certificate.sender_device_id,
        sender_identity: inner.sender_certificate.identity_key,
        content: inner.content,
    })
}

#[derive(serde::Serialize, serde::Deserialize)]
struct InnerMessage {
    sender_certificate: SenderCertificate,
    content: Vec<u8>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::primitives::keys::IdentityKeyPair;
    use crate::protocol::sealed_sender::certificate::ServerCertificate;
    use ed25519_dalek::SigningKey;

    fn setup() -> (
        IdentityKeyPair,
        IdentityKeyPair,
        SenderCertificate,
        SigningKey,
    ) {
        let server_sk = SigningKey::from_bytes(&[1u8; 32]);
        let server_cert = ServerCertificate::new(1u32, &server_sk);

        let alice = IdentityKeyPair::generate();
        let bob = IdentityKeyPair::generate();

        let sender_cert = SenderCertificate::new(
            SenderUuid::from(uuid::Uuid::nil()),
            1u32,
            alice.public_key(),
            u64::MAX,
            &server_sk,
            server_cert,
        );

        (alice, bob, sender_cert, server_sk)
    }

    #[test]
    fn seal_unseal_roundtrip() {
        let (alice, bob, sender_cert, server_sk) = setup();
        let trust_root = server_sk.verifying_key();

        let content = b"secret message for bob";
        let sealed = seal(&alice, &sender_cert, content, &bob.public_key()).unwrap();
        let unsealed = unseal(&sealed, &bob, &trust_root, 0u64).unwrap();

        assert_eq!(unsealed.content, content);
        assert_eq!(unsealed.sender_uuid, SenderUuid::from(uuid::Uuid::nil()));
        assert_eq!(unsealed.sender_device_id, DeviceId::from(1));
        assert_eq!(unsealed.sender_identity, alice.public_key());
    }

    #[test]
    fn wrong_recipient_fails() {
        let (alice, bob, sender_cert, server_sk) = setup();
        let trust_root = server_sk.verifying_key();
        let eve = IdentityKeyPair::generate();

        let sealed = seal(&alice, &sender_cert, b"secret", &bob.public_key()).unwrap();
        assert!(unseal(&sealed, &eve, &trust_root, 0).is_err());
    }

    #[test]
    fn expired_cert_rejected() {
        let server_sk = SigningKey::from_bytes(&[1u8; 32]);
        let server_cert = ServerCertificate::new(1u32, &server_sk);
        let alice = IdentityKeyPair::generate();
        let bob = IdentityKeyPair::generate();

        let sender_cert = SenderCertificate::new(
            SenderUuid::from(uuid::Uuid::nil()),
            1u32,
            alice.public_key(),
            100u64,
            &server_sk,
            server_cert,
        );

        let sealed = seal(&alice, &sender_cert, b"msg", &bob.public_key()).unwrap();
        let trust_root = server_sk.verifying_key();
        assert!(matches!(
            unseal(&sealed, &bob, &trust_root, 200u64),
            Err(CryptoError::ExpiredCertificate)
        ));
    }

    #[test]
    fn wrong_trust_root_rejected() {
        let (alice, _bob, sender_cert, _server_sk) = setup();
        let bob = IdentityKeyPair::generate();
        let wrong_root = SigningKey::from_bytes(&[99u8; 32]).verifying_key();

        let sealed = seal(&alice, &sender_cert, b"msg", &bob.public_key()).unwrap();
        assert!(unseal(&sealed, &bob, &wrong_root, 0).is_err());
    }

    #[test]
    fn tampered_envelope_fails() {
        let (alice, bob, sender_cert, server_sk) = setup();
        let trust_root = server_sk.verifying_key();

        let mut sealed = seal(&alice, &sender_cert, b"msg", &bob.public_key()).unwrap();
        let len = sealed.len();
        sealed[len - 1] ^= 0xFF;
        assert!(unseal(&sealed, &bob, &trust_root, 0).is_err());
    }

    #[test]
    fn mismatched_sender_identity_rejected() {
        let server_sk = SigningKey::from_bytes(&[1u8; 32]);
        let server_cert = ServerCertificate::new(1u32, &server_sk);
        let alice = IdentityKeyPair::generate();
        let mallory = IdentityKeyPair::generate();
        let bob = IdentityKeyPair::generate();

        // Certificate claims Alice's identity
        let sender_cert = SenderCertificate::new(
            SenderUuid::from(uuid::Uuid::nil()),
            1u32,
            alice.public_key(),
            u64::MAX,
            &server_sk,
            server_cert,
        );

        // Mallory tries to seal with Alice's cert but Mallory's identity key.
        // Layer 1 encrypts Mallory's X25519 key, but the cert contains
        // Alice's identity. The identity mismatch is detected on unseal.
        let result = seal(&mallory, &sender_cert, b"forged", &bob.public_key());
        // seal() succeeds (sender doesn't self-validate), but unseal detects
        // the mismatch between encrypted_static and certificate identity.
        let sealed = result.unwrap();
        let trust_root = server_sk.verifying_key();
        assert!(matches!(
            unseal(&sealed, &bob, &trust_root, 0),
            Err(CryptoError::InvalidCertificate(_))
        ));
    }

    #[test]
    fn two_layer_uses_different_keys() {
        let (alice, bob, sender_cert, server_sk) = setup();
        let trust_root = server_sk.verifying_key();

        let sealed1 = seal(&alice, &sender_cert, b"msg1", &bob.public_key()).unwrap();
        let sealed2 = seal(&alice, &sender_cert, b"msg1", &bob.public_key()).unwrap();

        // Different ephemeral keys -> different ciphertext
        assert_ne!(sealed1, sealed2);

        // Both decrypt correctly
        let u1 = unseal(&sealed1, &bob, &trust_root, 0u64).unwrap();
        let u2 = unseal(&sealed2, &bob, &trust_root, 0u64).unwrap();
        assert_eq!(u1.content, b"msg1");
        assert_eq!(u2.content, b"msg1");
    }
}
