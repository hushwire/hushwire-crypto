//! XChaCha20-Poly1305 authenticated encryption.
//!
//! Provides the crate's symmetric AEAD primitive: a random 24-byte XNonce is
//! generated per encryption and prepended to the output as
//! `nonce || ciphertext || tag`. Used throughout the protocol wherever a
//! message key encrypts a payload.

use chacha20poly1305::{
    XChaCha20Poly1305, XNonce,
    aead::{Aead, KeyInit, OsRng, rand_core::RngCore},
};
use hkdf::Hkdf;
use sha2::Sha256;
use zeroize::Zeroize;

use crate::error::{CryptoError, Result};

const NONCE_SIZE: usize = 24;

/// Encrypt plaintext with XChaCha20-Poly1305.
///
/// The message key is expanded via HKDF into a 32-byte encryption key.
/// A random 24-byte nonce is generated and prepended to the ciphertext.
///
/// Returns: `nonce (24) || ciphertext || tag (16)`
pub fn encrypt(message_key: &[u8; 32], plaintext: &[u8], ad: &[u8]) -> Result<Vec<u8>> {
    let mut enc_key = derive_enc_key(message_key);
    let cipher = XChaCha20Poly1305::new((&enc_key).into());
    enc_key.zeroize();

    let mut nonce_bytes = [0u8; NONCE_SIZE];
    OsRng.fill_bytes(&mut nonce_bytes);
    let nonce = XNonce::from_slice(&nonce_bytes);

    let payload = chacha20poly1305::aead::Payload {
        msg: plaintext,
        aad: ad,
    };

    let ciphertext = cipher
        .encrypt(nonce, payload)
        .map_err(|_| CryptoError::EncryptionFailed("AEAD encrypt failed".into()))?;

    let mut result = Vec::with_capacity(NONCE_SIZE + ciphertext.len());
    result.extend_from_slice(&nonce_bytes);
    result.extend_from_slice(&ciphertext);
    Ok(result)
}

/// Decrypt ciphertext produced by [`encrypt`].
///
/// Expects: `nonce (24) || ciphertext || tag (16)`
pub fn decrypt(message_key: &[u8; 32], encrypted: &[u8], ad: &[u8]) -> Result<Vec<u8>> {
    if encrypted.len() < NONCE_SIZE + 16 {
        return Err(CryptoError::InvalidCiphertext);
    }

    let (nonce_bytes, ciphertext) = encrypted.split_at(NONCE_SIZE);
    let nonce = XNonce::from_slice(nonce_bytes);

    let mut enc_key = derive_enc_key(message_key);
    let cipher = XChaCha20Poly1305::new((&enc_key).into());
    enc_key.zeroize();

    let payload = chacha20poly1305::aead::Payload {
        msg: ciphertext,
        aad: ad,
    };

    cipher
        .decrypt(nonce, payload)
        .map_err(|_| CryptoError::DecryptionFailed("AEAD decrypt failed".into()))
}

fn derive_enc_key(message_key: &[u8; 32]) -> [u8; 32] {
    let hk = Hkdf::<Sha256>::new(Some(&[0u8; 32]), message_key);
    let mut key = [0u8; 32];
    hk.expand(b"HushwireMessageKey", &mut key)
        .expect("32 bytes is valid HKDF-SHA256 output");
    key
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encrypt_decrypt_roundtrip() {
        let key = [42u8; 32];
        let plaintext = b"hello, encrypted world";
        let ad = b"associated data";

        let encrypted = encrypt(&key, plaintext, ad).unwrap();
        let decrypted = decrypt(&key, &encrypted, ad).unwrap();
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn encrypt_decrypt_empty_plaintext() {
        let key = [1u8; 32];
        let encrypted = encrypt(&key, &[], &[]).unwrap();
        let decrypted = decrypt(&key, &encrypted, &[]).unwrap();
        assert!(decrypted.is_empty());
    }

    #[test]
    fn encrypt_decrypt_empty_ad() {
        let key = [1u8; 32];
        let plaintext = b"data";
        let encrypted = encrypt(&key, plaintext, &[]).unwrap();
        let decrypted = decrypt(&key, &encrypted, &[]).unwrap();
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn wrong_key_fails() {
        let key1 = [1u8; 32];
        let key2 = [2u8; 32];
        let encrypted = encrypt(&key1, b"secret", &[]).unwrap();
        assert!(decrypt(&key2, &encrypted, &[]).is_err());
    }

    #[test]
    fn wrong_ad_fails() {
        let key = [1u8; 32];
        let encrypted = encrypt(&key, b"secret", b"ad1").unwrap();
        assert!(decrypt(&key, &encrypted, b"ad2").is_err());
    }

    #[test]
    fn tampered_ciphertext_fails() {
        let key = [1u8; 32];
        let mut encrypted = encrypt(&key, b"secret", &[]).unwrap();
        let len = encrypted.len();
        encrypted[len - 1] ^= 0xff;
        assert!(decrypt(&key, &encrypted, &[]).is_err());
    }

    #[test]
    fn tampered_nonce_fails() {
        let key = [1u8; 32];
        let mut encrypted = encrypt(&key, b"secret", &[]).unwrap();
        encrypted[0] ^= 0xff;
        assert!(decrypt(&key, &encrypted, &[]).is_err());
    }

    #[test]
    fn too_short_ciphertext_fails() {
        let key = [1u8; 32];
        assert!(decrypt(&key, &[0u8; 39], &[]).is_err()); // 24 nonce + 16 tag - 1
    }

    #[test]
    fn different_nonces_produce_different_ciphertext() {
        let key = [1u8; 32];
        let plaintext = b"same data";
        let ct1 = encrypt(&key, plaintext, &[]).unwrap();
        let ct2 = encrypt(&key, plaintext, &[]).unwrap();
        assert_ne!(ct1, ct2);
        assert_eq!(
            decrypt(&key, &ct1, &[]).unwrap(),
            decrypt(&key, &ct2, &[]).unwrap()
        );
    }

    #[test]
    fn ciphertext_overhead() {
        let key = [1u8; 32];
        let plaintext = b"1234567890";
        let encrypted = encrypt(&key, plaintext, &[]).unwrap();
        // overhead = 24 (nonce) + 16 (tag) = 40 bytes
        assert_eq!(encrypted.len(), plaintext.len() + 40);
    }

    #[test]
    fn large_plaintext() {
        let key = [1u8; 32];
        let plaintext = vec![0xABu8; 100_000];
        let encrypted = encrypt(&key, &plaintext, &[]).unwrap();
        let decrypted = decrypt(&key, &encrypted, &[]).unwrap();
        assert_eq!(decrypted, plaintext);
    }
}
