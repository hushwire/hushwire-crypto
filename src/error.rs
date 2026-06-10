//! Crate-wide error type for the clean-room Signal Protocol implementation.
//!
//! [`CryptoError`] enumerates every failure mode across the crypto primitives
//! (key agreement, the Double Ratchet, sender keys, sealed sender, and the
//! post-quantum braid), and [`Result`] is the crate's shorthand `Result` alias.

use thiserror::Error;

/// Errors returned by the crate's crypto primitives.
#[derive(Error, Debug)]
pub enum CryptoError {
    /// Supplied key material was malformed or the wrong length.
    #[error("invalid key material")]
    InvalidKey,

    /// A signature failed verification against the expected public key.
    #[error("invalid signature")]
    InvalidSignature,

    /// AEAD encryption failed; the payload describes the cause.
    #[error("encryption failed: {0}")]
    EncryptionFailed(String),

    /// AEAD decryption or authentication failed; the payload describes the cause.
    #[error("decryption failed: {0}")]
    DecryptionFailed(String),

    /// A ciphertext was malformed or had an unexpected structure.
    #[error("invalid ciphertext")]
    InvalidCiphertext,

    /// A session was in an unexpected or inconsistent state for the operation.
    #[error("invalid session state")]
    InvalidSessionState,

    /// A persistence backend operation failed; the payload describes the cause.
    #[error("storage error: {0}")]
    StorageError(String),

    /// A required record (e.g. session, prekey) was not found; the payload names it.
    #[error("not found: {0}")]
    NotFound(String),

    /// A prekey bundle was invalid or incomplete; the payload describes why.
    #[error("invalid prekey bundle: {0}")]
    InvalidPrekeyBundle(String),

    /// The peer's identity key differs from the previously trusted one.
    #[error("identity key changed")]
    IdentityKeyChanged,

    /// An identity key is not trusted; the payload describes the context.
    #[error("untrusted identity: {0}")]
    UntrustedIdentity(String),

    /// A message with an already-seen message key was received.
    #[error("duplicate message")]
    DuplicateMessage,

    /// The Double Ratchet skip gap exceeded the allowed limit (gap, limit).
    #[error("max skip exceeded: gap of {0} exceeds limit of {1}")]
    MaxSkipExceeded(u32, u32),

    /// A sealed-sender certificate is past its expiration.
    #[error("expired certificate")]
    ExpiredCertificate,

    /// A sealed-sender certificate was invalid; the payload describes why.
    #[error("invalid certificate: {0}")]
    InvalidCertificate(String),

    /// Serialization or deserialization failed; the payload describes the cause.
    #[error("serialization error: {0}")]
    Serialization(String),

    /// No sender key was available for the requested group.
    #[error("missing sender key for group")]
    MissingSenderKey,

    /// Message padding was malformed and could not be stripped.
    #[error("invalid message padding")]
    InvalidPadding,

    /// The post-quantum braid violated its erasure-coding contract.
    #[error("braid erasure contract violation: {0}")]
    BraidErasure(String),

    /// A KEM operation within the post-quantum braid failed.
    #[error("braid KEM error: {0}")]
    BraidKem(String),
}

impl From<postcard::Error> for CryptoError {
    fn from(err: postcard::Error) -> Self {
        CryptoError::Serialization(err.to_string())
    }
}

/// Convenience alias for results returning a [`CryptoError`].
pub type Result<T> = std::result::Result<T, CryptoError>;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn display_simple_variants() {
        assert_eq!(CryptoError::InvalidKey.to_string(), "invalid key material");
        assert_eq!(
            CryptoError::InvalidSignature.to_string(),
            "invalid signature"
        );
        assert_eq!(
            CryptoError::InvalidCiphertext.to_string(),
            "invalid ciphertext"
        );
        assert_eq!(
            CryptoError::DuplicateMessage.to_string(),
            "duplicate message"
        );
        assert_eq!(
            CryptoError::ExpiredCertificate.to_string(),
            "expired certificate"
        );
        assert_eq!(
            CryptoError::MissingSenderKey.to_string(),
            "missing sender key for group"
        );
    }

    #[test]
    fn display_parameterized_variants() {
        assert_eq!(
            CryptoError::MaxSkipExceeded(5000, 2000).to_string(),
            "max skip exceeded: gap of 5000 exceeds limit of 2000"
        );
        assert_eq!(
            CryptoError::EncryptionFailed("aead".into()).to_string(),
            "encryption failed: aead"
        );
    }

    #[test]
    fn from_postcard_error() {
        let bad: std::result::Result<u32, _> = postcard::from_bytes(&[]);
        let err: CryptoError = bad.unwrap_err().into();
        assert!(matches!(err, CryptoError::Serialization(_)));
    }
}
