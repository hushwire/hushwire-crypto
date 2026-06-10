//! Server trust-root key abstraction.
//!
//! The server's Ed25519 key is the trust root used to verify sender
//! certificates and message envelopes. This module defines a trait for
//! providing the public key bytes, with a real implementation backed by
//! `ed25519-dalek` and a mock for testing.

use ed25519_dalek::VerifyingKey;
use serde::de::Error as _;
use serde::{Deserialize, Deserializer, Serialize, Serializer};

/// Trait for providing the server's Ed25519 trust-root public key.
///
/// Every server MUST have a trust-root key; without one, envelope
/// verification cannot proceed. Implementations must be `Send + Sync`
/// so the key provider can be shared across async tasks.
pub trait TrustRoot:
    Send + Sync + std::fmt::Debug + Clone + Serialize + for<'de> Deserialize<'de>
{
    /// Returns the 32-byte Ed25519 public key.
    fn public_key_bytes(&self) -> [u8; 32];
}

/// Real server trust-root key backed by an `ed25519_dalek::VerifyingKey`.
#[derive(Debug, Clone)]
pub struct Ed25519TrustRoot {
    verifying_key: VerifyingKey,
}

impl Ed25519TrustRoot {
    /// Create from a verified `ed25519_dalek::VerifyingKey`.
    pub fn new(verifying_key: VerifyingKey) -> Self {
        Self { verifying_key }
    }

    /// Create from raw 32-byte public key, returning an error if the
    /// bytes are not a valid Ed25519 point.
    pub fn from_bytes(bytes: &[u8; 32]) -> Result<Self, ed25519_dalek::SignatureError> {
        let verifying_key = VerifyingKey::from_bytes(bytes)?;
        Ok(Self { verifying_key })
    }

    /// Access the underlying `VerifyingKey`.
    pub fn verifying_key(&self) -> &VerifyingKey {
        &self.verifying_key
    }
}

impl TrustRoot for Ed25519TrustRoot {
    fn public_key_bytes(&self) -> [u8; 32] {
        self.verifying_key.to_bytes()
    }
}

impl Serialize for Ed25519TrustRoot {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        self.verifying_key.to_bytes().serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for Ed25519TrustRoot {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let bytes: [u8; 32] = Deserialize::deserialize(deserializer)?;
        Self::from_bytes(&bytes).map_err(D::Error::custom)
    }
}

/// Mock server trust-root key for testing.
#[derive(Debug, Clone)]
pub struct MockTrustRoot {
    bytes: [u8; 32],
}

impl MockTrustRoot {
    /// Create a mock with the given key bytes.
    pub fn new(bytes: [u8; 32]) -> Self {
        Self { bytes }
    }

    /// Create a mock with an all-zero key.
    pub fn zeroed() -> Self {
        Self { bytes: [0u8; 32] }
    }
}

impl TrustRoot for MockTrustRoot {
    fn public_key_bytes(&self) -> [u8; 32] {
        self.bytes
    }
}

impl Serialize for MockTrustRoot {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        self.bytes.serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for MockTrustRoot {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let bytes: [u8; 32] = Deserialize::deserialize(deserializer)?;
        Ok(Self::new(bytes))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mock_trust_root_returns_configured_bytes() {
        let key = [42u8; 32];
        let mock = MockTrustRoot::new(key);
        assert_eq!(mock.public_key_bytes(), key);
    }

    #[test]
    fn mock_trust_root_zeroed() {
        let mock = MockTrustRoot::zeroed();
        assert_eq!(mock.public_key_bytes(), [0u8; 32]);
    }

    #[test]
    fn ed25519_trust_root_roundtrip() {
        let secret = ed25519_dalek::SigningKey::from_bytes(&[1u8; 32]);
        let public = secret.verifying_key();
        let key = Ed25519TrustRoot::new(public);
        assert_eq!(key.public_key_bytes(), public.to_bytes());
    }

    #[test]
    fn ed25519_trust_root_from_bytes() {
        let secret = ed25519_dalek::SigningKey::from_bytes(&[1u8; 32]);
        let public_bytes = secret.verifying_key().to_bytes();
        let key = Ed25519TrustRoot::from_bytes(&public_bytes).expect("valid Ed25519 point");
        assert_eq!(key.public_key_bytes(), public_bytes);
    }

    #[test]
    fn ed25519_trust_root_serde_roundtrip() {
        let secret = ed25519_dalek::SigningKey::from_bytes(&[1u8; 32]);
        let public = secret.verifying_key();
        let key = Ed25519TrustRoot::new(public);
        let json = serde_json::to_string(&key).unwrap();
        let deserialized: Ed25519TrustRoot = serde_json::from_str(&json).unwrap();
        assert_eq!(key.public_key_bytes(), deserialized.public_key_bytes());
    }

    #[test]
    fn mock_trust_root_serde_roundtrip() {
        let mock = MockTrustRoot::new([99u8; 32]);
        let json = serde_json::to_string(&mock).unwrap();
        let deserialized: MockTrustRoot = serde_json::from_str(&json).unwrap();
        assert_eq!(mock.public_key_bytes(), deserialized.public_key_bytes());
    }
}
