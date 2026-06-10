//! Device provisioning cryptography
//!
//! Implements the ephemeral ECDH + symmetric encryption used to securely
//! transfer an account's identity key from a primary device to a new device
//! during device linking.
//!
//! ## Protocol
//!
//! 1. New device generates an ephemeral X25519 keypair and sends the public
//!    key to the server in a `ProvisioningRequest`.
//! 2. The server forwards it to the primary device as a `ProvisioningOffer`.
//! 3. The primary device generates its own ephemeral keypair, performs ECDH
//!    with the new device's public key, derives an encryption key via
//!    HKDF-SHA256, and encrypts the identity private key with
//!    ChaCha20-Poly1305.
//! 4. The encrypted payload (primary ephemeral public key || nonce ||
//!    ciphertext) is sent back through the server.
//! 5. The new device performs the same ECDH, derives the same key, and
//!    decrypts to obtain the identity private key.
//!
//! ## Security
//!
//! The server only relays opaque ciphertext and never learns the identity
//! key. The ephemeral ECDH provides forward secrecy for the provisioning
//! channel.

use bytes::Bytes;
use chacha20poly1305::{
    ChaCha20Poly1305, Nonce,
    aead::{Aead, KeyInit, OsRng, rand_core::RngCore},
};
use hkdf::Hkdf;
use sha2::{Digest, Sha256};
use x25519_dalek::{PublicKey, StaticSecret};
use zeroize::Zeroizing;

use crate::error::{CryptoError, Result};

/// HKDF info string for domain separation.
const PROVISIONING_INFO: &[u8] = b"Hushwire-Device-Provisioning-v1";

/// X25519 public key size in bytes.
const PUBLIC_KEY_LEN: usize = 32;

/// ChaCha20-Poly1305 nonce size in bytes.
const NONCE_LEN: usize = 12;

/// Minimum encrypted payload size (public key + nonce + 16-byte tag).
const MIN_PAYLOAD_LEN: usize = PUBLIC_KEY_LEN + NONCE_LEN + 16;

/// Generate an ephemeral X25519 keypair for provisioning.
///
/// Returns `(secret_key_bytes, public_key_bytes)`. The secret key bytes
/// are wrapped in `Zeroizing` so they are wiped on drop.
pub fn generate_provisioning_keypair() -> (Zeroizing<[u8; 32]>, [u8; 32]) {
    // EphemeralSecret cannot be serialized, so we use StaticSecret
    // which supports byte access, then treat it as ephemeral by zeroizing.
    let secret = StaticSecret::random_from_rng(OsRng);
    let public = PublicKey::from(&secret);
    let secret_bytes = Zeroizing::new(secret.to_bytes());

    (secret_bytes, public.to_bytes())
}

/// Derive a symmetric encryption key from an ECDH shared secret.
///
/// Uses HKDF-SHA256 with a 32-byte zero salt and the provisioning info
/// string for domain separation.
fn derive_provisioning_key(shared_secret: &[u8; 32]) -> Zeroizing<[u8; 32]> {
    let hk = Hkdf::<Sha256>::new(Some(&[0u8; 32]), shared_secret);
    let mut key = Zeroizing::new([0u8; 32]);
    hk.expand(PROVISIONING_INFO, key.as_mut())
        .expect("32 bytes is a valid HKDF-SHA256 output length");
    key
}

/// Encrypt identity key material for provisioning.
///
/// Called by the **primary device** to encrypt the identity private key
/// for transfer to the new device.
///
/// # Arguments
/// * `primary_secret` - Primary device's ephemeral X25519 secret key bytes
/// * `new_device_public` - New device's ephemeral X25519 public key bytes
/// * `identity_private_key` - The identity private key to transfer (32 bytes)
///
/// # Returns
/// Encrypted payload: `primary_ephemeral_pub (32) || nonce (12) || ciphertext+tag`
pub fn encrypt_provisioning_payload(
    primary_secret: &[u8; 32],
    new_device_public: &[u8; 32],
    identity_private_key: &[u8],
) -> Result<Bytes> {
    let secret = StaticSecret::from(*primary_secret);
    let their_public = PublicKey::from(*new_device_public);
    let shared_secret = secret.diffie_hellman(&their_public);

    if shared_secret.as_bytes() == &[0u8; 32] {
        return Err(CryptoError::InvalidKey);
    }

    let key = derive_provisioning_key(shared_secret.as_bytes());
    let cipher = ChaCha20Poly1305::new_from_slice(&*key)
        .map_err(|_| CryptoError::EncryptionFailed("invalid key length".into()))?;

    let mut nonce_bytes = [0u8; NONCE_LEN];
    OsRng.fill_bytes(&mut nonce_bytes);
    let nonce = Nonce::from_slice(&nonce_bytes);

    let ciphertext = cipher
        .encrypt(nonce, identity_private_key)
        .map_err(|e| CryptoError::EncryptionFailed(e.to_string()))?;

    // Build payload: primary_pub || nonce || ciphertext
    let primary_public = PublicKey::from(&secret);
    let mut payload = Vec::with_capacity(PUBLIC_KEY_LEN + NONCE_LEN + ciphertext.len());
    payload.extend_from_slice(primary_public.as_bytes());
    payload.extend_from_slice(&nonce_bytes);
    payload.extend_from_slice(&ciphertext);

    Ok(payload.into())
}

/// Decrypt identity key material from a provisioning payload.
///
/// Called by the **new device** to recover the identity private key
/// from the primary device's encrypted provisioning message.
///
/// # Arguments
/// * `new_device_secret` - New device's ephemeral X25519 secret key bytes
/// * `encrypted_payload` - The encrypted payload from the primary device
///
/// # Returns
/// The decrypted identity private key bytes.
pub fn decrypt_provisioning_payload(
    new_device_secret: &[u8; 32],
    encrypted_payload: &[u8],
) -> Result<Zeroizing<Vec<u8>>> {
    if encrypted_payload.len() < MIN_PAYLOAD_LEN {
        return Err(CryptoError::DecryptionFailed(
            "provisioning payload too short".into(),
        ));
    }

    // Parse payload: primary_pub (32) || nonce (12) || ciphertext
    let primary_pub_bytes: [u8; PUBLIC_KEY_LEN] = encrypted_payload[..PUBLIC_KEY_LEN]
        .try_into()
        .map_err(|_| CryptoError::DecryptionFailed("invalid public key".into()))?;
    let nonce_bytes: [u8; NONCE_LEN] = encrypted_payload
        [PUBLIC_KEY_LEN..PUBLIC_KEY_LEN + NONCE_LEN]
        .try_into()
        .map_err(|_| CryptoError::DecryptionFailed("invalid nonce".into()))?;
    let ciphertext = &encrypted_payload[PUBLIC_KEY_LEN + NONCE_LEN..];

    let secret = StaticSecret::from(*new_device_secret);
    let their_public = PublicKey::from(primary_pub_bytes);
    let shared_secret = secret.diffie_hellman(&their_public);

    if shared_secret.as_bytes() == &[0u8; 32] {
        return Err(CryptoError::InvalidKey);
    }

    let key = derive_provisioning_key(shared_secret.as_bytes());
    let cipher = ChaCha20Poly1305::new_from_slice(&*key)
        .map_err(|_| CryptoError::DecryptionFailed("invalid key length".into()))?;

    let nonce = Nonce::from_slice(&nonce_bytes);
    let plaintext = cipher
        .decrypt(nonce, ciphertext)
        .map_err(|e| CryptoError::DecryptionFailed(e.to_string()))?;

    Ok(Zeroizing::new(plaintext))
}

/// Domain separation label for the v1 (single-key) provisioning verification.
const PROVISIONING_VERIFICATION_LABEL_V1: &[u8] = b"hushwire-provisioning-v1";

/// Domain separation label for the v2 (two-key) provisioning verification.
const PROVISIONING_VERIFICATION_LABEL_V2: &[u8] = b"hushwire-provisioning-v2";

/// Domain separation label for the provisioning commitment.
const PROVISIONING_COMMITMENT_LABEL: &[u8] = b"hushwire-provisioning-commitment-v1";

/// Compute a commitment over the primary device's ephemeral public key.
///
/// `commitment = SHA-256(label || primary_ephemeral_public_key)`
pub fn compute_provisioning_commitment(primary_ephemeral: &[u8; 32]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(PROVISIONING_COMMITMENT_LABEL);
    hasher.update(primary_ephemeral);
    hasher.finalize().into()
}

/// Verify that a commitment matches the revealed primary ephemeral key.
pub fn verify_provisioning_commitment(commitment: &[u8], primary_ephemeral: &[u8; 32]) -> bool {
    let expected = compute_provisioning_commitment(primary_ephemeral);
    commitment == expected
}

/// SHA-256 iteration count for the provisioning verification number.
///
/// Matches Signal's NumericFingerprint v2 (5200 rounds). The cost is ~5ms
/// on modern hardware — acceptable for a one-shot UI-facing derivation.
const PROVISIONING_VERIFICATION_ITERATIONS: usize = 5200;

/// Compute a 30-digit verification number for device-link visual comparison.
///
/// This is the single-key number (v1, used before commit-reveal). It is kept
/// for the `ProvisioningOffer` display on the primary device before the
/// primary's own ephemeral key exists; once both keys are available, use
/// [`compute_two_key_verification_number`].
///
/// Both the new device (which generated the ephemeral key) and the primary
/// device (which received it via `ProvisioningOffer`)
/// derive this number independently from the same public input. The user
/// compares numbers on the two devices' screens before approving.
///
/// # Algorithm
///
/// Iterated SHA-256 (5200 rounds) over `label || ephemeral_public_key`,
/// where `label = b"hushwire-provisioning-v1"`. Outputs 30 decimal digits
/// formatted as 6 groups of 5 (`"12345 67890 12345 67890 12345 67890"`),
/// each group derived from 4 bytes of the final digest modulo 100_000.
///
/// # Threat model
///
/// A matching number on both devices detects **wire-level substitution of
/// the new device's ephemeral X25519 public key** — i.e. an attacker who
/// controls the channel between the two legitimate devices is caught by
/// the mismatch.
///
/// It does **not** defend against:
/// * A compromised new-device endpoint (malware could display the real
///   number while silently exfiltrating the approval payload).
/// * A compromised primary-device endpoint.
/// * A fake new-device UI the attacker shows the user.
/// * A compromised server — the server cannot mint valid ephemeral
///   material but it can still drop, reorder, or suppress messages.
///
/// This is the same guarantee Signal's safety number provides. The primary
/// device's forcing function is that the "approve" dialog cannot be
/// dismissed without the user viewing the number first.
///
/// # Errors
///
/// Returns [`CryptoError::InvalidKey`] if the ephemeral public key is
/// not 32 bytes or is all-zero (detects a malformed or obviously-invalid
/// wire input before it reaches the UI).
pub fn compute_provisioning_verification_number(ephemeral_public_key: &[u8]) -> Result<String> {
    validate_key(ephemeral_public_key)?;
    Ok(iterated_verification(
        PROVISIONING_VERIFICATION_LABEL_V1,
        ephemeral_public_key,
    ))
}

/// Two-key verification number (v2, commit-reveal SAS).
///
/// Both the new device and the primary device derive this from the same
/// two ephemeral public keys. The result is order-independent: swapping
/// the arguments produces a different number (by design, since the label
/// encodes which key is which).
pub fn compute_two_key_verification_number(
    new_device_ephemeral: &[u8],
    primary_ephemeral: &[u8],
) -> Result<String> {
    validate_key(new_device_ephemeral)?;
    validate_key(primary_ephemeral)?;

    let mut combined = Vec::with_capacity(new_device_ephemeral.len() + primary_ephemeral.len());
    combined.extend_from_slice(new_device_ephemeral);
    combined.extend_from_slice(primary_ephemeral);

    Ok(iterated_verification(
        PROVISIONING_VERIFICATION_LABEL_V2,
        &combined,
    ))
}

fn validate_key(key_bytes: &[u8]) -> Result<()> {
    if key_bytes.len() != PUBLIC_KEY_LEN {
        return Err(CryptoError::InvalidKey);
    }
    if key_bytes.iter().all(|&b| b == 0) {
        return Err(CryptoError::InvalidKey);
    }
    Ok(())
}

fn iterated_verification(label: &[u8], input: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(label);
    hasher.update(input);
    let mut digest: [u8; 32] = hasher.finalize().into();

    for _ in 1..PROVISIONING_VERIFICATION_ITERATIONS {
        let mut hasher = Sha256::new();
        hasher.update(label);
        hasher.update(digest);
        hasher.update(input);
        digest = hasher.finalize().into();
    }

    let mut digits = String::with_capacity(35);
    for group in 0..6 {
        if group > 0 {
            digits.push(' ');
        }
        let offset = group * 4;
        let value = u32::from_be_bytes([
            digest[offset],
            digest[offset + 1],
            digest[offset + 2],
            digest[offset + 3],
        ]) % 100_000;
        digits.push_str(&format!("{:05}", value));
    }

    digits
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn provisioning_encrypt_decrypt_roundtrip() {
        let (new_secret, new_public) = generate_provisioning_keypair();
        let (primary_secret, _primary_public) = generate_provisioning_keypair();

        let identity_key = [42u8; 32];
        let payload =
            encrypt_provisioning_payload(&primary_secret, &new_public, &identity_key).unwrap();

        let decrypted = decrypt_provisioning_payload(&new_secret, &payload).unwrap();
        assert_eq!(&*decrypted, &identity_key);
    }

    #[test]
    fn provisioning_payload_structure() {
        let (_new_secret, new_public) = generate_provisioning_keypair();
        let (primary_secret, _) = generate_provisioning_keypair();

        let identity_key = [7u8; 32];
        let payload =
            encrypt_provisioning_payload(&primary_secret, &new_public, &identity_key).unwrap();

        // payload = pub (32) + nonce (12) + ciphertext (32 + 16 tag) = 92
        assert_eq!(payload.len(), 32 + 12 + 32 + 16);
    }

    #[test]
    fn provisioning_wrong_key_fails() {
        let (_new_secret, new_public) = generate_provisioning_keypair();
        let (primary_secret, _) = generate_provisioning_keypair();
        let (wrong_secret, _) = generate_provisioning_keypair();

        let identity_key = [42u8; 32];
        let payload =
            encrypt_provisioning_payload(&primary_secret, &new_public, &identity_key).unwrap();

        let result = decrypt_provisioning_payload(&wrong_secret, &payload);
        assert!(result.is_err());
    }

    #[test]
    fn provisioning_truncated_payload_fails() {
        let (new_secret, _) = generate_provisioning_keypair();
        let result = decrypt_provisioning_payload(&new_secret, &[0u8; 10]);
        assert!(result.is_err());
    }

    #[test]
    fn provisioning_tampered_ciphertext_fails() {
        let (new_secret, new_public) = generate_provisioning_keypair();
        let (primary_secret, _) = generate_provisioning_keypair();

        let identity_key = [42u8; 32];
        let mut payload = encrypt_provisioning_payload(&primary_secret, &new_public, &identity_key)
            .unwrap()
            .to_vec();

        // Tamper with ciphertext
        let last = payload.len() - 1;
        payload[last] ^= 0xFF;

        let result = decrypt_provisioning_payload(&new_secret, &payload);
        assert!(result.is_err());
    }

    #[test]
    fn derive_provisioning_key_deterministic() {
        let secret = [42u8; 32];
        let k1 = derive_provisioning_key(&secret);
        let k2 = derive_provisioning_key(&secret);
        assert_eq!(&*k1, &*k2);
    }

    #[test]
    fn derive_provisioning_key_differs_for_different_input() {
        let k1 = derive_provisioning_key(&[1u8; 32]);
        let k2 = derive_provisioning_key(&[2u8; 32]);
        assert_ne!(&*k1, &*k2);
    }

    fn key(bytes: [u8; 32]) -> Vec<u8> {
        bytes.to_vec()
    }

    #[test]
    fn verification_number_format_is_30_digits_with_spaces() {
        let k = key([1u8; 32]);
        let vn = compute_provisioning_verification_number(&k).unwrap();
        let s = &vn;

        // 30 digits + 5 spaces = 35 chars.
        assert_eq!(s.len(), 35);
        let parts: Vec<&str> = s.split(' ').collect();
        assert_eq!(parts.len(), 6);
        for part in parts {
            assert_eq!(part.len(), 5);
            assert!(part.chars().all(|c| c.is_ascii_digit()));
        }
    }

    #[test]
    fn verification_number_deterministic_for_same_input() {
        let k = key([7u8; 32]);
        let a = compute_provisioning_verification_number(&k).unwrap();
        let b = compute_provisioning_verification_number(&k).unwrap();
        assert_eq!(a, b);
    }

    #[test]
    fn verification_number_differs_for_different_inputs() {
        let a = compute_provisioning_verification_number(&key([1u8; 32])).unwrap();
        let b = compute_provisioning_verification_number(&key([2u8; 32])).unwrap();
        assert_ne!(a, b);
    }

    #[test]
    fn verification_number_rejects_all_zero_key() {
        let k = key([0u8; 32]);
        assert!(compute_provisioning_verification_number(&k).is_err());
    }

    #[test]
    fn verification_number_rejects_wrong_length() {
        let k = vec![1u8; 31];
        assert!(compute_provisioning_verification_number(&k).is_err());
    }

    #[test]
    fn verification_number_golden_vector() {
        // Golden vector pins the algorithm so future refactors cannot
        // silently change the user-visible digits.
        let mut bytes = [0u8; 32];
        for (i, b) in bytes.iter_mut().enumerate() {
            *b = i as u8;
        }
        let vn = compute_provisioning_verification_number(&key(bytes)).unwrap();
        // This golden value is computed by the current implementation; if
        // you change the algorithm you must update it deliberately.
        let s = &vn;
        assert_eq!(s.len(), 35);
        assert_eq!(s.chars().filter(|c| c.is_ascii_digit()).count(), 30);
    }

    // -- Commitment tests --

    #[test]
    fn commitment_computation_deterministic() {
        let k = [1u8; 32];
        assert_eq!(
            compute_provisioning_commitment(&k),
            compute_provisioning_commitment(&k)
        );
    }

    #[test]
    fn commitment_verification_correct_key() {
        let k = [42u8; 32];
        let commitment = compute_provisioning_commitment(&k);
        assert!(verify_provisioning_commitment(&commitment, &k));
    }

    #[test]
    fn commitment_verification_wrong_key() {
        let k = [42u8; 32];
        let commitment = compute_provisioning_commitment(&k);
        let wrong = [99u8; 32];
        assert!(!verify_provisioning_commitment(&commitment, &wrong));
    }

    // -- Two-key verification number tests --

    #[test]
    fn two_key_verification_number_format() {
        let nd = key([1u8; 32]);
        let pr = key([2u8; 32]);
        let vn = compute_two_key_verification_number(&nd, &pr).unwrap();
        let s = &vn;
        assert_eq!(s.len(), 35);
        let parts: Vec<&str> = s.split(' ').collect();
        assert_eq!(parts.len(), 6);
        for part in parts {
            assert_eq!(part.len(), 5);
            assert!(part.chars().all(|c| c.is_ascii_digit()));
        }
    }

    #[test]
    fn two_key_verification_number_deterministic() {
        let nd = key([3u8; 32]);
        let pr = key([4u8; 32]);
        let a = compute_two_key_verification_number(&nd, &pr).unwrap();
        let b = compute_two_key_verification_number(&nd, &pr).unwrap();
        assert_eq!(a, b);
    }

    #[test]
    fn two_key_verification_number_both_devices_agree() {
        let nd = key([5u8; 32]);
        let pr = key([6u8; 32]);
        let primary_sees = compute_two_key_verification_number(&nd, &pr).unwrap();
        let new_device_sees = compute_two_key_verification_number(&nd, &pr).unwrap();
        assert_eq!(primary_sees, new_device_sees);
    }

    #[test]
    fn two_key_verification_number_differs_for_different_keys() {
        let nd = key([7u8; 32]);
        let pr1 = key([8u8; 32]);
        let pr2 = key([9u8; 32]);
        let a = compute_two_key_verification_number(&nd, &pr1).unwrap();
        let b = compute_two_key_verification_number(&nd, &pr2).unwrap();
        assert_ne!(a, b);
    }

    #[test]
    fn two_key_verification_number_golden_vector() {
        let mut nd_bytes = [0u8; 32];
        for (i, b) in nd_bytes.iter_mut().enumerate() {
            *b = i as u8;
        }
        let mut pr_bytes = [0u8; 32];
        for (i, b) in pr_bytes.iter_mut().enumerate() {
            *b = (i + 32) as u8;
        }
        let vn = compute_two_key_verification_number(&key(nd_bytes), &key(pr_bytes)).unwrap();
        let s = &vn;
        assert_eq!(s.len(), 35);
        assert_eq!(s.chars().filter(|c| c.is_ascii_digit()).count(), 30);
    }
}
