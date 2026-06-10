//! Organization metadata encryption using ChaCha20-Poly1305 with AAD.
//!
//! Encrypts an organization's names and other metadata with a per-org symmetric
//! key. A caller-supplied context identifier (e.g. the org's UUID) is used as
//! Additional Authenticated Data (AAD) to prevent ciphertext transplant attacks
//! between organizations.
//!
//! Also provides `MetadataKeyEnvelope` for server-blind metadata key
//! distribution: keys are encrypted per-recipient via X25519 ECDH +
//! ChaCha20-Poly1305 so the server only stores opaque blobs.

use bytes::Bytes;
use chacha20poly1305::{
    ChaCha20Poly1305, Nonce,
    aead::{Aead, KeyInit, OsRng, rand_core::RngCore},
};
use hkdf::Hkdf;
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use x25519_dalek::{PublicKey, StaticSecret};
use zeroize::Zeroizing;

use crate::error::{CryptoError, Result};

/// Nonce size for ChaCha20-Poly1305 (96 bits = 12 bytes).
const NONCE_SIZE: usize = 12;

/// Version byte for v1 MetadataKeyEnvelope serialization.
const METADATA_KEY_ENVELOPE_V1: u8 = 0x01;

/// Version byte for v2 symmetric (invite escrow) envelope.
const METADATA_KEY_ENVELOPE_V2: u8 = 0x02;

/// HKDF info string for metadata key envelope domain separation.
const METADATA_KEY_ENVELOPE_INFO: &[u8] = b"Hushwire-Metadata-Key-v1";

/// HKDF info string for deriving the server-visible invite lookup token.
const INVITE_TOKEN_INFO: &[u8] = b"hushwire-invite-token-v1";

/// HKDF info string for deriving the invite escrow encryption key.
const INVITE_ESCROW_INFO: &[u8] = b"hushwire-invite-escrow-v1";

/// Generate a random 32-byte ChaCha20-Poly1305 key for metadata encryption.
///
/// This key encrypts an organization's names and other metadata using
/// ChaCha20-Poly1305 with a caller-supplied context identifier as AAD. It is
/// distributed to members via X3DH sessions.
pub fn generate_metadata_key() -> [u8; 32] {
    let mut key = [0u8; 32];
    OsRng.fill_bytes(&mut key);
    key
}

/// Encrypted metadata key envelope for server-blind distribution.
///
/// Serialized as `0x01 || postcard(MetadataKeyEnvelope)`. The version
/// prefix allows future format changes without ambiguity. v1 blobs are
/// ~97 bytes, distinguishable from raw 32-byte legacy keys by length.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct MetadataKeyEnvelope {
    /// The ephemeral X25519 public key used for the ECDH with the recipient.
    pub ephemeral_public_key: Vec<u8>,
    /// The ChaCha20-Poly1305 nonce (12 bytes).
    pub nonce: Vec<u8>,
    /// The encrypted metadata key (with the appended Poly1305 tag).
    pub ciphertext: Vec<u8>,
}

/// Encrypt a 32-byte metadata key for a specific recipient.
///
/// Generates an ephemeral X25519 keypair, performs ECDH with the
/// recipient's Curve25519 identity key, derives a ChaCha20-Poly1305
/// key via HKDF-SHA256, and encrypts the metadata key.
///
/// Returns version-prefixed bytes: `0x01 || postcard(MetadataKeyEnvelope)`.
pub fn encrypt_metadata_key(
    metadata_key: &[u8; 32],
    recipient_curve25519_public: &[u8; 32],
) -> Result<Bytes> {
    let secret = StaticSecret::random_from_rng(OsRng);
    let ephemeral_public = PublicKey::from(&secret);

    let their_public = PublicKey::from(*recipient_curve25519_public);
    let shared_secret = secret.diffie_hellman(&their_public);

    if shared_secret.as_bytes() == &[0u8; 32] {
        return Err(CryptoError::InvalidKey);
    }

    let enc_key = derive_metadata_envelope_key(shared_secret.as_bytes());
    let cipher = ChaCha20Poly1305::new((&*enc_key).into());

    let mut nonce_bytes = [0u8; NONCE_SIZE];
    OsRng.fill_bytes(&mut nonce_bytes);
    let nonce = Nonce::from_slice(&nonce_bytes);

    let ciphertext = cipher
        .encrypt(nonce, metadata_key.as_slice())
        .map_err(|_| CryptoError::EncryptionFailed("metadata key encryption failed".into()))?;

    let envelope = MetadataKeyEnvelope {
        ephemeral_public_key: ephemeral_public.as_bytes().to_vec(),
        nonce: nonce_bytes.to_vec(),
        ciphertext,
    };

    let body = postcard::to_allocvec(&envelope)
        .map_err(|e| CryptoError::EncryptionFailed(e.to_string()))?;

    let mut result = Vec::with_capacity(1 + body.len());
    result.push(METADATA_KEY_ENVELOPE_V1);
    result.extend_from_slice(&body);
    Ok(result.into())
}

/// Decrypt a metadata key from a version-prefixed envelope.
///
/// Parses the version byte, deserializes the postcard body, performs
/// reverse ECDH with the recipient's Curve25519 private key, and
/// decrypts the 32-byte metadata key.
pub fn decrypt_metadata_key(
    envelope_bytes: &[u8],
    our_curve25519_private: &[u8; 32],
) -> Result<[u8; 32]> {
    if envelope_bytes.is_empty() {
        return Err(CryptoError::DecryptionFailed(
            "empty metadata key envelope".into(),
        ));
    }

    let version = envelope_bytes[0];
    if version != METADATA_KEY_ENVELOPE_V1 {
        return Err(CryptoError::DecryptionFailed(format!(
            "unsupported metadata key envelope version: {version}"
        )));
    }

    let envelope: MetadataKeyEnvelope = postcard::from_bytes(&envelope_bytes[1..])
        .map_err(|e| CryptoError::DecryptionFailed(e.to_string()))?;

    let their_pub_bytes: [u8; 32] = envelope
        .ephemeral_public_key
        .as_slice()
        .try_into()
        .map_err(|_| CryptoError::DecryptionFailed("invalid ephemeral key length".into()))?;

    let secret = StaticSecret::from(*our_curve25519_private);
    let their_public = PublicKey::from(their_pub_bytes);
    let shared_secret = secret.diffie_hellman(&their_public);

    if shared_secret.as_bytes() == &[0u8; 32] {
        return Err(CryptoError::InvalidKey);
    }

    let enc_key = derive_metadata_envelope_key(shared_secret.as_bytes());
    let cipher = ChaCha20Poly1305::new((&*enc_key).into());

    let nonce_bytes: [u8; NONCE_SIZE] = envelope
        .nonce
        .as_slice()
        .try_into()
        .map_err(|_| CryptoError::DecryptionFailed("invalid nonce length".into()))?;
    let nonce = Nonce::from_slice(&nonce_bytes);

    let plaintext = cipher
        .decrypt(nonce, envelope.ciphertext.as_slice())
        .map_err(|_| CryptoError::DecryptionFailed("metadata key decryption failed".into()))?;

    plaintext
        .try_into()
        .map_err(|_| CryptoError::DecryptionFailed("decrypted key wrong length".into()))
}

fn hkdf_sha256(ikm: &[u8; 32], info: &[u8]) -> [u8; 32] {
    let hk = Hkdf::<Sha256>::new(Some(&[0u8; 32]), ikm);
    let mut out = [0u8; 32];
    hk.expand(info, &mut out)
        .expect("32 bytes is a valid HKDF-SHA256 output length");
    out
}

fn derive_metadata_envelope_key(shared_secret: &[u8; 32]) -> Zeroizing<[u8; 32]> {
    Zeroizing::new(hkdf_sha256(shared_secret, METADATA_KEY_ENVELOPE_INFO))
}

// -- Invite secret HKDF derivation ------------------------------------------

/// Derive the server-visible invite lookup token from an invite secret.
pub fn derive_invite_token(secret: &[u8; 32]) -> [u8; 32] {
    hkdf_sha256(secret, INVITE_TOKEN_INFO)
}

/// Derive the escrow encryption key from an invite secret.
pub fn derive_invite_escrow_key(secret: &[u8; 32]) -> Zeroizing<[u8; 32]> {
    Zeroizing::new(hkdf_sha256(secret, INVITE_ESCROW_INFO))
}

/// Generate a random 32-byte invite secret.
pub fn generate_invite_secret() -> [u8; 32] {
    let mut secret = [0u8; 32];
    OsRng.fill_bytes(&mut secret);
    secret
}

// -- Symmetric metadata key encryption (invite escrow) ----------------------

/// Envelope for symmetric (invite escrow) metadata key encryption.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SymmetricMetadataKeyEnvelope {
    /// The ChaCha20-Poly1305 nonce (12 bytes).
    pub nonce: Vec<u8>,
    /// The encrypted metadata key (with the appended Poly1305 tag).
    pub ciphertext: Vec<u8>,
}

/// Encrypt a metadata key with a symmetric escrow key (for invite escrow).
///
/// Uses ChaCha20-Poly1305 with the provided AAD to prevent
/// cross-context transplant attacks.
///
/// Returns version-prefixed bytes: `0x02 || postcard(SymmetricMetadataKeyEnvelope)`.
pub fn encrypt_metadata_key_symmetric(
    metadata_key: &[u8; 32],
    escrow_key: &[u8; 32],
    aad: &[u8],
) -> Result<Bytes> {
    let cipher = ChaCha20Poly1305::new(escrow_key.into());

    let mut nonce_bytes = [0u8; NONCE_SIZE];
    OsRng.fill_bytes(&mut nonce_bytes);
    let nonce = Nonce::from_slice(&nonce_bytes);

    let payload = chacha20poly1305::aead::Payload {
        msg: metadata_key.as_slice(),
        aad,
    };

    let ciphertext = cipher.encrypt(nonce, payload).map_err(|_| {
        CryptoError::EncryptionFailed("symmetric metadata key encryption failed".into())
    })?;

    let envelope = SymmetricMetadataKeyEnvelope {
        nonce: nonce_bytes.to_vec(),
        ciphertext,
    };

    let body = postcard::to_allocvec(&envelope)
        .map_err(|e| CryptoError::EncryptionFailed(e.to_string()))?;

    let mut result = Vec::with_capacity(1 + body.len());
    result.push(METADATA_KEY_ENVELOPE_V2);
    result.extend_from_slice(&body);
    Ok(result.into())
}

/// Decrypt a metadata key from a v2 symmetric envelope.
///
/// Parses the `0x02` version byte, deserializes the postcard body, and
/// decrypts with ChaCha20-Poly1305 using the provided AAD.
pub fn decrypt_metadata_key_symmetric(
    envelope_bytes: &[u8],
    escrow_key: &[u8; 32],
    aad: &[u8],
) -> Result<[u8; 32]> {
    if envelope_bytes.is_empty() {
        return Err(CryptoError::DecryptionFailed(
            "empty symmetric metadata key envelope".into(),
        ));
    }

    let version = envelope_bytes[0];
    if version != METADATA_KEY_ENVELOPE_V2 {
        return Err(CryptoError::DecryptionFailed(format!(
            "expected symmetric envelope version 0x02, got 0x{version:02x}"
        )));
    }

    let envelope: SymmetricMetadataKeyEnvelope = postcard::from_bytes(&envelope_bytes[1..])
        .map_err(|e| CryptoError::DecryptionFailed(e.to_string()))?;

    let nonce_bytes: [u8; NONCE_SIZE] = envelope
        .nonce
        .as_slice()
        .try_into()
        .map_err(|_| CryptoError::DecryptionFailed("invalid nonce length".into()))?;
    let nonce = Nonce::from_slice(&nonce_bytes);

    let cipher = ChaCha20Poly1305::new(escrow_key.into());

    let payload = chacha20poly1305::aead::Payload {
        msg: envelope.ciphertext.as_slice(),
        aad,
    };

    let plaintext = cipher.decrypt(nonce, payload).map_err(|_| {
        CryptoError::DecryptionFailed("symmetric metadata key decryption failed".into())
    })?;

    plaintext
        .try_into()
        .map_err(|_| CryptoError::DecryptionFailed("decrypted key wrong length".into()))
}

/// Encrypt metadata (organization name, channel name, etc.) with a per-org key.
///
/// Uses ChaCha20-Poly1305 with the provided AAD to bind the ciphertext to a
/// specific context (e.g. the org's UUID), preventing transplant attacks.
///
/// Returns `nonce || ciphertext` (12 bytes nonce + encrypted data + 16 bytes tag).
pub fn encrypt_metadata(key: &[u8; 32], plaintext: &[u8], aad: &[u8]) -> Result<Bytes> {
    let cipher = ChaCha20Poly1305::new(key.into());

    let mut nonce_bytes = [0u8; NONCE_SIZE];
    OsRng.fill_bytes(&mut nonce_bytes);
    let nonce = Nonce::from_slice(&nonce_bytes);

    let payload = chacha20poly1305::aead::Payload {
        msg: plaintext,
        aad,
    };

    let ciphertext = cipher
        .encrypt(nonce, payload)
        .map_err(|_| CryptoError::EncryptionFailed("metadata encryption failed".into()))?;

    let mut result = Vec::with_capacity(NONCE_SIZE + ciphertext.len());
    result.extend_from_slice(&nonce_bytes);
    result.extend_from_slice(&ciphertext);
    Ok(result.into())
}

/// Decrypt metadata encrypted with [`encrypt_metadata`].
///
/// Expects `nonce || ciphertext` format. The AAD must match
/// what was used during encryption.
pub fn decrypt_metadata(key: &[u8; 32], encrypted: &[u8], aad: &[u8]) -> Result<Bytes> {
    if encrypted.len() < NONCE_SIZE {
        return Err(CryptoError::DecryptionFailed(
            "metadata ciphertext too short".into(),
        ));
    }

    let (nonce_bytes, ciphertext) = encrypted.split_at(NONCE_SIZE);
    let nonce = Nonce::from_slice(nonce_bytes);
    let cipher = ChaCha20Poly1305::new(key.into());

    let payload = chacha20poly1305::aead::Payload {
        msg: ciphertext,
        aad,
    };

    cipher
        .decrypt(nonce, payload)
        .map(Bytes::from)
        .map_err(|_| CryptoError::DecryptionFailed("metadata decryption failed".into()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn metadata_key_generation() {
        let key = generate_metadata_key();
        assert_ne!(key, [0u8; 32]);
    }

    #[test]
    fn metadata_keys_are_unique() {
        let k1 = generate_metadata_key();
        let k2 = generate_metadata_key();
        assert_ne!(k1, k2);
    }

    #[test]
    fn encrypt_decrypt_roundtrip() {
        let key = generate_metadata_key();
        let org_id = uuid::Uuid::new_v4();
        let plaintext = b"Gaming Community";

        let encrypted = encrypt_metadata(&key, plaintext, org_id.as_bytes()).unwrap();
        let decrypted = decrypt_metadata(&key, &encrypted, org_id.as_bytes()).unwrap();

        assert_eq!(decrypted, plaintext.as_slice());
    }

    #[test]
    fn wrong_key_fails() {
        let key1 = generate_metadata_key();
        let key2 = generate_metadata_key();
        let org_id = uuid::Uuid::new_v4();

        let encrypted = encrypt_metadata(&key1, b"secret", org_id.as_bytes()).unwrap();
        let result = decrypt_metadata(&key2, &encrypted, org_id.as_bytes());

        assert!(result.is_err());
    }

    #[test]
    fn wrong_aad_fails() {
        let key = generate_metadata_key();
        let org_a = uuid::Uuid::new_v4();
        let org_b = uuid::Uuid::new_v4();

        let encrypted = encrypt_metadata(&key, b"secret", org_a.as_bytes()).unwrap();
        let result = decrypt_metadata(&key, &encrypted, org_b.as_bytes());

        // Decryption fails because AAD doesn't match (transplant attack prevented).
        assert!(result.is_err());
    }

    #[test]
    fn ciphertext_too_short_fails() {
        let key = generate_metadata_key();
        let org_id = uuid::Uuid::new_v4();
        let result = decrypt_metadata(&key, &[0u8; 5], org_id.as_bytes());
        assert!(result.is_err());
    }

    #[test]
    fn different_nonces_produce_different_ciphertext() {
        let key = generate_metadata_key();
        let org_id = uuid::Uuid::new_v4();
        let plaintext = b"same plaintext";

        let ct1 = encrypt_metadata(&key, plaintext, org_id.as_bytes()).unwrap();
        let ct2 = encrypt_metadata(&key, plaintext, org_id.as_bytes()).unwrap();

        // Nonces are random, so ciphertext should differ.
        assert_ne!(ct1, ct2);

        // But both decrypt to the same plaintext.
        assert_eq!(
            decrypt_metadata(&key, &ct1, org_id.as_bytes()).unwrap(),
            decrypt_metadata(&key, &ct2, org_id.as_bytes()).unwrap()
        );
    }

    // -- MetadataKeyEnvelope tests ----------------------------------------

    #[test]
    fn metadata_key_envelope_v1_roundtrip() {
        use crate::hushwire::provisioning::generate_provisioning_keypair;

        let metadata_key = generate_metadata_key();
        let (secret, public) = generate_provisioning_keypair();

        let encrypted = encrypt_metadata_key(&metadata_key, &public).unwrap();
        let decrypted = decrypt_metadata_key(&encrypted, &secret).unwrap();

        assert_eq!(decrypted, metadata_key);
    }

    #[test]
    fn metadata_key_envelope_encrypt_decrypt() {
        use crate::hushwire::provisioning::generate_provisioning_keypair;

        let metadata_key = [42u8; 32];
        let (recipient_secret, recipient_public) = generate_provisioning_keypair();

        let blob = encrypt_metadata_key(&metadata_key, &recipient_public).unwrap();
        assert_eq!(blob[0], 0x01);

        let decrypted = decrypt_metadata_key(&blob, &recipient_secret).unwrap();
        assert_eq!(decrypted, metadata_key);
    }

    #[test]
    fn metadata_key_envelope_wrong_key_fails() {
        use crate::hushwire::provisioning::generate_provisioning_keypair;

        let metadata_key = generate_metadata_key();
        let (_correct_secret, correct_public) = generate_provisioning_keypair();
        let (wrong_secret, _) = generate_provisioning_keypair();

        let blob = encrypt_metadata_key(&metadata_key, &correct_public).unwrap();
        let result = decrypt_metadata_key(&blob, &wrong_secret);

        assert!(result.is_err());
    }

    #[test]
    fn metadata_key_envelope_distinguishable_from_raw() {
        use crate::hushwire::provisioning::generate_provisioning_keypair;

        let metadata_key = generate_metadata_key();
        let (_, public) = generate_provisioning_keypair();

        let blob = encrypt_metadata_key(&metadata_key, &public).unwrap();

        // v1 blob must be longer than a raw 32-byte key
        assert!(blob.len() > 32);
        // Version prefix
        assert_eq!(blob[0], 0x01);
    }

    // -- Invite HKDF derivation tests -------------------------------------

    #[test]
    fn invite_hkdf_deterministic() {
        let secret = generate_invite_secret();
        let token1 = derive_invite_token(&secret);
        let token2 = derive_invite_token(&secret);
        assert_eq!(token1, token2);

        let key1 = derive_invite_escrow_key(&secret);
        let key2 = derive_invite_escrow_key(&secret);
        assert_eq!(*key1, *key2);
    }

    #[test]
    fn invite_hkdf_token_and_key_differ() {
        let secret = generate_invite_secret();
        let token = derive_invite_token(&secret);
        let key = derive_invite_escrow_key(&secret);
        assert_ne!(token, *key);
    }

    #[test]
    fn invite_hkdf_different_secrets_differ() {
        let s1 = generate_invite_secret();
        let s2 = generate_invite_secret();
        assert_ne!(derive_invite_token(&s1), derive_invite_token(&s2));
        assert_ne!(
            *derive_invite_escrow_key(&s1),
            *derive_invite_escrow_key(&s2)
        );
    }

    // -- Symmetric metadata key envelope tests ----------------------------

    #[test]
    fn symmetric_envelope_roundtrip() {
        let metadata_key = generate_metadata_key();
        let escrow_key = generate_metadata_key();
        let org_id = uuid::Uuid::new_v4();

        let blob =
            encrypt_metadata_key_symmetric(&metadata_key, &escrow_key, org_id.as_bytes()).unwrap();
        assert_eq!(blob[0], 0x02);

        let decrypted =
            decrypt_metadata_key_symmetric(&blob, &escrow_key, org_id.as_bytes()).unwrap();
        assert_eq!(decrypted, metadata_key);
    }

    #[test]
    fn symmetric_envelope_wrong_key_fails() {
        let metadata_key = generate_metadata_key();
        let correct_key = generate_metadata_key();
        let wrong_key = generate_metadata_key();
        let org_id = uuid::Uuid::new_v4();

        let blob =
            encrypt_metadata_key_symmetric(&metadata_key, &correct_key, org_id.as_bytes()).unwrap();
        let result = decrypt_metadata_key_symmetric(&blob, &wrong_key, org_id.as_bytes());
        assert!(result.is_err());
    }

    #[test]
    fn symmetric_envelope_wrong_aad_fails() {
        let metadata_key = generate_metadata_key();
        let escrow_key = generate_metadata_key();
        let org_a = uuid::Uuid::new_v4();
        let org_b = uuid::Uuid::new_v4();

        let blob =
            encrypt_metadata_key_symmetric(&metadata_key, &escrow_key, org_a.as_bytes()).unwrap();
        let result = decrypt_metadata_key_symmetric(&blob, &escrow_key, org_b.as_bytes());
        assert!(result.is_err());
    }

    #[test]
    fn symmetric_envelope_v1_rejected() {
        let metadata_key = generate_metadata_key();
        let escrow_key = generate_metadata_key();
        let org_id = uuid::Uuid::new_v4();

        // Encrypt with v1 (X25519) format, try to decrypt as v2 (symmetric)
        use crate::hushwire::provisioning::generate_provisioning_keypair;
        let (_, public) = generate_provisioning_keypair();
        let v1_blob = encrypt_metadata_key(&metadata_key, &public).unwrap();

        let result = decrypt_metadata_key_symmetric(&v1_blob, &escrow_key, org_id.as_bytes());
        assert!(result.is_err());
    }

    #[test]
    fn invite_escrow_full_flow() {
        let metadata_key = generate_metadata_key();
        let org_id = uuid::Uuid::new_v4();

        let secret = generate_invite_secret();
        let _token = derive_invite_token(&secret);
        let escrow_key = derive_invite_escrow_key(&secret);

        let blob =
            encrypt_metadata_key_symmetric(&metadata_key, &escrow_key, org_id.as_bytes()).unwrap();

        // Simulate acceptor deriving the same keys from the same secret
        let acceptor_escrow_key = derive_invite_escrow_key(&secret);
        let decrypted =
            decrypt_metadata_key_symmetric(&blob, &acceptor_escrow_key, org_id.as_bytes()).unwrap();

        assert_eq!(decrypted, metadata_key);
    }
}
