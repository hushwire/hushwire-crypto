//! Recovery key management for identity recovery
//!
//! Generates, encodes, and manages recovery keys that allow users to
//! recover their account if they forget their password or lose all devices.
//!
//! A random 256-bit recovery key is generated at registration and displayed
//! as a 24-word BIP39 mnemonic. Two subkeys are derived via HKDF:
//!
//! - `recovery_wrapping_key`: wraps the per-device storage key and encrypts
//!   the server-side identity backup
//! - `server_verifier`: hashed and stored on the server to authenticate
//!   recovery requests (password reset, provisioning bypass)
//!
//! ## Key Wrapping Format
//!
//! ```text
//! "HWRK" || VERSION(0x01) || NONCE(12B) || CIPHERTEXT+TAG(48B)
//! ```

use crate::error::{CryptoError, Result};
use bytes::Bytes;
use chacha20poly1305::{
    ChaCha20Poly1305, Nonce,
    aead::{Aead, KeyInit, OsRng, Payload, rand_core::RngCore},
};
use hkdf::Hkdf;
use sha2::Sha256;
use zeroize::Zeroizing;

const RECOVERY_STORAGE_INFO: &[u8] = b"hushwire-recovery-storage-v1";
const RECOVERY_SERVER_INFO: &[u8] = b"hushwire-recovery-server-v1";
const WRAP_MAGIC: &[u8; 4] = b"HWRK";
const BACKUP_MAGIC: &[u8; 4] = b"HWIB";
const WRAP_VERSION: u8 = 0x01;
const NONCE_LEN: usize = 12;
const STORAGE_KEY_LEN: usize = 32;
const WRAP_HEADER_SIZE: usize = WRAP_MAGIC.len() + 1 + NONCE_LEN;

/// A 256-bit recovery key for account recovery.
///
/// Generated once at registration and displayed as a 24-word BIP39 mnemonic.
/// The user writes it down and stores it securely. Two subkeys are derived
/// from it via HKDF for different purposes (storage wrapping vs server auth).
pub struct RecoveryKey(Zeroizing<[u8; 32]>);

impl RecoveryKey {
    /// Generate a new random recovery key.
    pub fn generate() -> Self {
        let mut bytes = Zeroizing::new([0u8; 32]);
        OsRng.fill_bytes(&mut *bytes);
        Self(bytes)
    }

    /// Create from raw bytes.
    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(Zeroizing::new(bytes))
    }

    /// Access the raw bytes.
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    /// Encode as a BIP39 24-word mnemonic string.
    pub fn to_mnemonic(&self) -> Result<String> {
        let mnemonic = bip39::Mnemonic::from_entropy(&*self.0)
            .map_err(|e| CryptoError::StorageError(format!("BIP39 encode failed: {e}")))?;
        Ok(mnemonic.to_string())
    }

    /// Decode from a BIP39 24-word mnemonic string.
    ///
    /// Validates the checksum and wordlist membership.
    pub fn from_mnemonic(words: &str) -> Result<Self> {
        let mnemonic: bip39::Mnemonic = words
            .parse()
            .map_err(|e| CryptoError::StorageError(format!("BIP39 decode failed: {e}")))?;
        let (entropy, len) = mnemonic.to_entropy_array();
        if len != 32 {
            return Err(CryptoError::StorageError(format!(
                "Expected 32-byte entropy, got {len} bytes",
            )));
        }
        let bytes: [u8; 32] = entropy[..32]
            .try_into()
            .map_err(|_| CryptoError::StorageError("Entropy conversion failed".into()))?;
        Ok(Self(Zeroizing::new(bytes)))
    }

    /// Derive the recovery wrapping key for encrypting storage keys and
    /// identity backups.
    ///
    /// Uses HKDF-SHA256 with the username as salt for domain separation.
    /// Username bytes are used (not user_id) so the client can derive this
    /// key during recovery without knowing the server-assigned UUID.
    pub fn derive_wrapping_key(&self, username: &[u8]) -> Zeroizing<[u8; 32]> {
        derive_hkdf_key(&self.0, username, RECOVERY_STORAGE_INFO)
    }

    /// Derive the server verifier for authenticating recovery requests.
    ///
    /// The server stores `Argon2id(server_verifier)` and verifies it
    /// during `RecoverAccount` and `RecoveryLogin` requests.
    ///
    /// Username bytes are used as the HKDF salt so the client can derive
    /// the verifier during recovery using only the username + mnemonic.
    pub fn derive_server_verifier(&self, username: &[u8]) -> Zeroizing<[u8; 32]> {
        derive_hkdf_key(&self.0, username, RECOVERY_SERVER_INFO)
    }
}

fn derive_hkdf_key(ikm: &[u8; 32], salt: &[u8], info: &[u8]) -> Zeroizing<[u8; 32]> {
    let hk = Hkdf::<Sha256>::new(Some(salt), ikm);
    let mut key = Zeroizing::new([0u8; 32]);
    hk.expand(info, key.as_mut())
        .expect("32 bytes is a valid HKDF-SHA256 output length");
    key
}

/// Build a `magic || WRAP_VERSION` AAD for an AEAD-wrapped blob.
fn build_aad(magic: &[u8]) -> Vec<u8> {
    let mut aad = Vec::with_capacity(magic.len() + 1);
    aad.extend_from_slice(magic);
    aad.push(WRAP_VERSION);
    aad
}

/// Wrap (encrypt) a 32-byte storage key with a wrapping key.
///
/// Returns `HWRK || VERSION || NONCE(12B) || CIPHERTEXT+TAG(48B)`.
pub fn wrap_storage_key(wrapping_key: &[u8; 32], storage_key: &[u8; 32]) -> Result<Bytes> {
    let cipher = ChaCha20Poly1305::new(wrapping_key.into());

    let mut nonce_bytes = [0u8; NONCE_LEN];
    OsRng.fill_bytes(&mut nonce_bytes);
    let nonce = Nonce::from_slice(&nonce_bytes);

    let aad = build_aad(WRAP_MAGIC);
    let ciphertext = cipher
        .encrypt(
            nonce,
            Payload {
                msg: storage_key,
                aad: &aad,
            },
        )
        .map_err(|e| CryptoError::EncryptionFailed(format!("Key wrapping failed: {e}")))?;

    let mut output = Vec::with_capacity(WRAP_HEADER_SIZE + ciphertext.len());
    output.extend_from_slice(WRAP_MAGIC);
    output.push(WRAP_VERSION);
    output.extend_from_slice(&nonce_bytes);
    output.extend_from_slice(&ciphertext);

    Ok(output.into())
}

/// Unwrap (decrypt) a wrapped storage key blob.
///
/// Validates the HWRK magic, version, and AEAD tag before returning
/// the 32-byte storage key.
pub fn unwrap_storage_key(wrapping_key: &[u8; 32], wrapped: &[u8]) -> Result<Zeroizing<[u8; 32]>> {
    if wrapped.len() < WRAP_HEADER_SIZE {
        return Err(CryptoError::DecryptionFailed(
            "Wrapped key too short".into(),
        ));
    }
    if &wrapped[..WRAP_MAGIC.len()] != WRAP_MAGIC {
        return Err(CryptoError::DecryptionFailed(
            "Invalid wrapped key magic".into(),
        ));
    }
    if wrapped[WRAP_MAGIC.len()] != WRAP_VERSION {
        return Err(CryptoError::DecryptionFailed(format!(
            "Unsupported wrap version: {}",
            wrapped[WRAP_MAGIC.len()]
        )));
    }

    let nonce_start = WRAP_MAGIC.len() + 1;
    let nonce_end = nonce_start + NONCE_LEN;
    let nonce = Nonce::from_slice(&wrapped[nonce_start..nonce_end]);
    let ciphertext = &wrapped[nonce_end..];

    let cipher = ChaCha20Poly1305::new(wrapping_key.into());
    let aad = build_aad(WRAP_MAGIC);
    let plaintext = cipher
        .decrypt(
            nonce,
            Payload {
                msg: ciphertext,
                aad: &aad,
            },
        )
        .map_err(|e| CryptoError::DecryptionFailed(format!("Key unwrapping failed: {e}")))?;

    let bytes: [u8; STORAGE_KEY_LEN] = plaintext.try_into().map_err(|v: Vec<u8>| {
        CryptoError::DecryptionFailed(format!(
            "Unwrapped key wrong size: expected {STORAGE_KEY_LEN}, got {}",
            v.len()
        ))
    })?;

    Ok(Zeroizing::new(bytes))
}

/// Encrypt an identity backup with a wrapping key.
///
/// Returns `HWIB || VERSION || NONCE(12B) || CIPHERTEXT+TAG`.
/// The plaintext can be any length (typically an Ed25519 secret key).
pub fn wrap_identity_backup(wrapping_key: &[u8; 32], identity_secret: &[u8]) -> Result<Bytes> {
    let cipher = ChaCha20Poly1305::new(wrapping_key.into());

    let mut nonce_bytes = [0u8; NONCE_LEN];
    OsRng.fill_bytes(&mut nonce_bytes);
    let nonce = Nonce::from_slice(&nonce_bytes);

    let aad = build_aad(BACKUP_MAGIC);

    let ciphertext = cipher
        .encrypt(
            nonce,
            Payload {
                msg: identity_secret,
                aad: &aad,
            },
        )
        .map_err(|e| {
            CryptoError::EncryptionFailed(format!("Identity backup wrapping failed: {e}"))
        })?;

    let mut output = Vec::with_capacity(BACKUP_MAGIC.len() + 1 + NONCE_LEN + ciphertext.len());
    output.extend_from_slice(BACKUP_MAGIC);
    output.push(WRAP_VERSION);
    output.extend_from_slice(&nonce_bytes);
    output.extend_from_slice(&ciphertext);

    Ok(output.into())
}

/// Decrypt an identity backup blob.
///
/// Validates the HWIB magic, version, and AEAD tag before returning
/// the plaintext identity secret.
pub fn unwrap_identity_backup(
    wrapping_key: &[u8; 32],
    wrapped: &[u8],
) -> Result<Zeroizing<Vec<u8>>> {
    let header_size = BACKUP_MAGIC.len() + 1 + NONCE_LEN;
    if wrapped.len() < header_size {
        return Err(CryptoError::DecryptionFailed(
            "Identity backup too short".into(),
        ));
    }
    if &wrapped[..BACKUP_MAGIC.len()] != BACKUP_MAGIC {
        return Err(CryptoError::DecryptionFailed(
            "Invalid identity backup magic".into(),
        ));
    }
    if wrapped[BACKUP_MAGIC.len()] != WRAP_VERSION {
        return Err(CryptoError::DecryptionFailed(format!(
            "Unsupported identity backup version: {}",
            wrapped[BACKUP_MAGIC.len()]
        )));
    }

    let nonce_start = BACKUP_MAGIC.len() + 1;
    let nonce_end = nonce_start + NONCE_LEN;
    let nonce = Nonce::from_slice(&wrapped[nonce_start..nonce_end]);
    let ciphertext = &wrapped[nonce_end..];

    let cipher = ChaCha20Poly1305::new(wrapping_key.into());
    let aad = build_aad(BACKUP_MAGIC);

    let plaintext = cipher
        .decrypt(
            nonce,
            Payload {
                msg: ciphertext,
                aad: &aad,
            },
        )
        .map_err(|e| {
            CryptoError::DecryptionFailed(format!("Identity backup unwrapping failed: {e}"))
        })?;

    Ok(Zeroizing::new(plaintext))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generate_produces_nonzero_key() {
        let key = RecoveryKey::generate();
        assert_ne!(*key.as_bytes(), [0u8; 32]);
    }

    #[test]
    fn mnemonic_roundtrip() {
        let key = RecoveryKey::generate();
        let mnemonic = key.to_mnemonic().unwrap();
        let words: Vec<&str> = mnemonic.split_whitespace().collect();
        assert_eq!(words.len(), 24);

        let restored = RecoveryKey::from_mnemonic(&mnemonic).unwrap();
        assert_eq!(key.as_bytes(), restored.as_bytes());
    }

    #[test]
    fn mnemonic_deterministic() {
        let key = RecoveryKey::from_bytes([0x42; 32]);
        let m1 = key.to_mnemonic().unwrap();
        let m2 = key.to_mnemonic().unwrap();
        assert_eq!(m1, m2);
    }

    #[test]
    fn mnemonic_invalid_word() {
        let result = RecoveryKey::from_mnemonic(
            "notaword notaword notaword notaword notaword notaword notaword notaword notaword notaword notaword notaword notaword notaword notaword notaword notaword notaword notaword notaword notaword notaword notaword notaword",
        );
        assert!(result.is_err());
    }

    #[test]
    fn mnemonic_wrong_checksum() {
        let key = RecoveryKey::from_bytes([0x42; 32]);
        let mnemonic = key.to_mnemonic().unwrap();
        let mut words: Vec<&str> = mnemonic.split_whitespace().collect();
        let len = words.len();
        words.swap(len - 1, len - 2);
        let tampered = words.join(" ");
        let result = RecoveryKey::from_mnemonic(&tampered);
        assert!(result.is_err());
    }

    #[test]
    fn mnemonic_wrong_word_count() {
        let result = RecoveryKey::from_mnemonic("abandon abandon abandon");
        assert!(result.is_err());
    }

    #[test]
    fn hkdf_domain_separation() {
        let key = RecoveryKey::from_bytes([0x42; 32]);
        let username = b"test-username";
        let wrapping = key.derive_wrapping_key(username);
        let verifier = key.derive_server_verifier(username);
        assert_ne!(*wrapping, *verifier);
    }

    #[test]
    fn hkdf_different_users() {
        let key = RecoveryKey::from_bytes([0x42; 32]);
        let k1 = key.derive_wrapping_key(b"alice");
        let k2 = key.derive_wrapping_key(b"bob");
        assert_ne!(*k1, *k2);
    }

    #[test]
    fn hkdf_deterministic() {
        let key = RecoveryKey::from_bytes([0x42; 32]);
        let k1 = key.derive_wrapping_key(b"user");
        let k2 = key.derive_wrapping_key(b"user");
        assert_eq!(*k1, *k2);
    }

    #[test]
    fn wrap_unwrap_roundtrip() {
        let wrapping_key = [0xAA; 32];
        let storage_key = [0xBB; 32];
        let wrapped = wrap_storage_key(&wrapping_key, &storage_key).unwrap();
        let unwrapped = unwrap_storage_key(&wrapping_key, &wrapped).unwrap();
        assert_eq!(*unwrapped, storage_key);
    }

    #[test]
    fn wrap_format_header() {
        let wrapping_key = [0xAA; 32];
        let storage_key = [0xBB; 32];
        let wrapped = wrap_storage_key(&wrapping_key, &storage_key).unwrap();

        assert_eq!(&wrapped[..4], b"HWRK");
        assert_eq!(wrapped[4], WRAP_VERSION);
        // 4 magic + 1 version + 12 nonce + 32 ciphertext + 16 tag = 65
        assert_eq!(wrapped.len(), 65);
    }

    #[test]
    fn wrap_unique_nonces() {
        let wrapping_key = [0xAA; 32];
        let storage_key = [0xBB; 32];
        let w1 = wrap_storage_key(&wrapping_key, &storage_key).unwrap();
        let w2 = wrap_storage_key(&wrapping_key, &storage_key).unwrap();
        assert_ne!(w1, w2);

        // But both unwrap to the same key
        let u1 = unwrap_storage_key(&wrapping_key, &w1).unwrap();
        let u2 = unwrap_storage_key(&wrapping_key, &w2).unwrap();
        assert_eq!(*u1, *u2);
    }

    #[test]
    fn unwrap_wrong_key_fails() {
        let wrapping_key = [0xAA; 32];
        let wrong_key = [0xCC; 32];
        let storage_key = [0xBB; 32];
        let wrapped = wrap_storage_key(&wrapping_key, &storage_key).unwrap();
        assert!(unwrap_storage_key(&wrong_key, &wrapped).is_err());
    }

    #[test]
    fn unwrap_corrupted_ciphertext_fails() {
        let wrapping_key = [0xAA; 32];
        let storage_key = [0xBB; 32];
        let mut wrapped = wrap_storage_key(&wrapping_key, &storage_key)
            .unwrap()
            .to_vec();
        let len = wrapped.len();
        wrapped[len - 1] ^= 0xFF;
        assert!(unwrap_storage_key(&wrapping_key, &wrapped).is_err());
    }

    #[test]
    fn unwrap_truncated_fails() {
        let wrapping_key = [0xAA; 32];
        assert!(unwrap_storage_key(&wrapping_key, b"HWRK").is_err());
        assert!(unwrap_storage_key(&wrapping_key, b"").is_err());
    }

    #[test]
    fn unwrap_wrong_magic_fails() {
        let wrapping_key = [0xAA; 32];
        let storage_key = [0xBB; 32];
        let mut wrapped = wrap_storage_key(&wrapping_key, &storage_key)
            .unwrap()
            .to_vec();
        wrapped[0] = b'X';
        assert!(unwrap_storage_key(&wrapping_key, &wrapped).is_err());
    }

    #[test]
    fn unwrap_wrong_version_fails() {
        let wrapping_key = [0xAA; 32];
        let storage_key = [0xBB; 32];
        let mut wrapped = wrap_storage_key(&wrapping_key, &storage_key)
            .unwrap()
            .to_vec();
        wrapped[4] = 0xFF;
        assert!(unwrap_storage_key(&wrapping_key, &wrapped).is_err());
    }

    #[test]
    fn unwrap_version_tamper_aad_mismatch() {
        let wrapping_key = [0xAA; 32];
        let storage_key = [0xBB; 32];
        let wrapped = wrap_storage_key(&wrapping_key, &storage_key).unwrap();
        // Verify it works normally
        assert!(unwrap_storage_key(&wrapping_key, &wrapped).is_ok());

        // Tamper version byte -- AAD mismatch should cause decryption failure
        let mut tampered = wrapped.to_vec();
        tampered[4] = 0x02;
        assert!(
            unwrap_storage_key(&wrapping_key, &tampered).is_err(),
            "tampering version byte should cause AAD mismatch"
        );
    }

    #[test]
    fn full_recovery_flow() {
        let username = b"alice";

        let recovery_key = RecoveryKey::generate();
        let mnemonic = recovery_key.to_mnemonic().unwrap();

        let wrapping_key = recovery_key.derive_wrapping_key(username);

        let storage_key = [0x42; 32];
        let wrapped = wrap_storage_key(&wrapping_key, &storage_key).unwrap();

        let restored = RecoveryKey::from_mnemonic(&mnemonic).unwrap();
        let restored_wrapping = restored.derive_wrapping_key(username);
        let unwrapped = unwrap_storage_key(&restored_wrapping, &wrapped).unwrap();
        assert_eq!(*unwrapped, storage_key);

        let original_verifier = recovery_key.derive_server_verifier(username);
        let restored_verifier = restored.derive_server_verifier(username);
        assert_eq!(*original_verifier, *restored_verifier);
    }

    #[test]
    fn identity_backup_roundtrip() {
        let wrapping_key = [0xAA; 32];
        let identity_secret = [0x55u8; 32];
        let wrapped = wrap_identity_backup(&wrapping_key, &identity_secret).unwrap();
        let unwrapped = unwrap_identity_backup(&wrapping_key, &wrapped).unwrap();
        assert_eq!(&*unwrapped, &identity_secret);
    }

    #[test]
    fn identity_backup_format_header() {
        let wrapping_key = [0xAA; 32];
        let identity_secret = [0x55u8; 32];
        let wrapped = wrap_identity_backup(&wrapping_key, &identity_secret).unwrap();

        assert_eq!(&wrapped[..4], b"HWIB");
        assert_eq!(wrapped[4], WRAP_VERSION);
        // 4 magic + 1 version + 12 nonce + 32 ciphertext + 16 tag = 65
        assert_eq!(wrapped.len(), 65);
    }

    #[test]
    fn identity_backup_wrong_key_fails() {
        let wrapping_key = [0xAA; 32];
        let wrong_key = [0xCC; 32];
        let identity_secret = [0x55u8; 32];
        let wrapped = wrap_identity_backup(&wrapping_key, &identity_secret).unwrap();
        assert!(unwrap_identity_backup(&wrong_key, &wrapped).is_err());
    }

    #[test]
    fn identity_backup_tampered_ciphertext_fails() {
        let wrapping_key = [0xAA; 32];
        let identity_secret = [0x55u8; 32];
        let mut wrapped = wrap_identity_backup(&wrapping_key, &identity_secret)
            .unwrap()
            .to_vec();
        let len = wrapped.len();
        wrapped[len - 1] ^= 0xFF;
        assert!(unwrap_identity_backup(&wrapping_key, &wrapped).is_err());
    }

    #[test]
    fn identity_backup_truncated_fails() {
        let wrapping_key = [0xAA; 32];
        assert!(unwrap_identity_backup(&wrapping_key, b"HWIB").is_err());
        assert!(unwrap_identity_backup(&wrapping_key, b"").is_err());
    }

    #[test]
    fn identity_backup_wrong_magic_fails() {
        let wrapping_key = [0xAA; 32];
        let identity_secret = [0x55u8; 32];
        let mut wrapped = wrap_identity_backup(&wrapping_key, &identity_secret)
            .unwrap()
            .to_vec();
        wrapped[0] = b'X';
        assert!(unwrap_identity_backup(&wrapping_key, &wrapped).is_err());
    }

    #[test]
    fn identity_backup_variable_length() {
        let wrapping_key = [0xAA; 32];
        let long_secret = vec![0x77u8; 128];
        let wrapped = wrap_identity_backup(&wrapping_key, &long_secret).unwrap();
        let unwrapped = unwrap_identity_backup(&wrapping_key, &wrapped).unwrap();
        assert_eq!(&*unwrapped, &long_secret);
    }
}
