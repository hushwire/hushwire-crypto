//! Password-based storage key derivation using Argon2id
//!
//! Derives a 256-bit storage encryption key from the user's password.
//! Uses Argon2id (memory-hard, side-channel resistant) with a domain-separated
//! salt derived from the username.
//!
//! This is the Bitwarden model: the password is the root of trust. The derived
//! key never leaves the device -- it encrypts local storage only. Server
//! authentication uses the plaintext password (or a session token) over TLS.

use crate::error::{CryptoError, Result};
use argon2::{Algorithm, Argon2, Params, Version};
use zeroize::Zeroizing;

/// Domain separation prefix for the salt.
const SALT_PREFIX: &[u8] = b"hushwire-storage-v1:";

/// Derive a 256-bit storage encryption key from a password.
///
/// Uses Argon2id with:
/// - **Memory**: 64 MiB (OWASP minimum recommendation)
/// - **Iterations**: 3
/// - **Parallelism**: 1 (WASM is single-threaded)
/// - **Salt**: `"hushwire-storage-v1:" || username`
///
/// The salt includes a version tag so parameters can be changed in the
/// future without silently producing wrong keys.
pub fn derive_storage_key(username: &str, password: &str) -> Result<Zeroizing<[u8; 32]>> {
    #[cfg(test)]
    let params = Params::new(1024, 1, 1, Some(32))
        .map_err(|e| CryptoError::StorageError(format!("Argon2 param error: {}", e)))?;

    #[cfg(not(test))]
    let params = Params::new(64 * 1024, 3, 1, Some(32))
        .map_err(|e| CryptoError::StorageError(format!("Argon2 param error: {}", e)))?;

    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);

    let mut salt = Vec::with_capacity(SALT_PREFIX.len() + username.len());
    salt.extend_from_slice(SALT_PREFIX);
    salt.extend_from_slice(username.as_bytes());

    let mut key = Zeroizing::new([0u8; 32]);
    argon2
        .hash_password_into(password.as_bytes(), &salt, &mut *key)
        .map_err(|e| CryptoError::StorageError(format!("Key derivation failed: {}", e)))?;

    Ok(key)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn derive_deterministic() {
        let k1 = derive_storage_key("alice", "hunter2").unwrap();
        let k2 = derive_storage_key("alice", "hunter2").unwrap();
        assert_eq!(*k1, *k2);
    }

    #[test]
    fn derive_different_passwords() {
        let k1 = derive_storage_key("alice", "password1").unwrap();
        let k2 = derive_storage_key("alice", "password2").unwrap();
        assert_ne!(*k1, *k2);
    }

    #[test]
    fn derive_different_usernames() {
        let k1 = derive_storage_key("alice", "hunter2").unwrap();
        let k2 = derive_storage_key("bob", "hunter2").unwrap();
        assert_ne!(*k1, *k2);
    }

    #[test]
    fn derive_empty_password() {
        let key = derive_storage_key("alice", "").unwrap();
        assert_ne!(*key, [0u8; 32]);
    }

    #[test]
    fn derive_unicode() {
        let key = derive_storage_key("user", "p@$$w0rd").unwrap();
        assert_ne!(*key, [0u8; 32]);
    }
}
