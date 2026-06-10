//! Core protocol newtypes: crypto keys, identifiers, byte blobs, and timestamps.
//!
//! Declarative macros (`define_crypto_key!`, `define_id!`, `define_bytes!`)
//! generate the wrappers with consistent conversions, serde, and redacted
//! `Debug`. Each invocation passes a doc string that becomes the type's docs.

use std::fmt;

use serde::{Deserialize, Serialize};
use uuid::Uuid;
use zeroize::{Zeroize, ZeroizeOnDrop};

macro_rules! define_crypto_key {
    ($(#[doc = $doc:expr])* $name:ident) => {
        $(#[doc = $doc])*
        #[derive(Clone, PartialEq, Eq, Hash, Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
        #[serde(transparent)]
        pub struct $name(
            /// Raw 32-byte key material.
            pub [u8; 32],
        );

        impl From<[u8; 32]> for $name {
            fn from(v: [u8; 32]) -> Self {
                Self(v)
            }
        }

        impl From<$name> for [u8; 32] {
            fn from(v: $name) -> Self {
                v.0
            }
        }

        impl AsRef<[u8; 32]> for $name {
            fn as_ref(&self) -> &[u8; 32] {
                &self.0
            }
        }

        impl $name {
            /// Returns the raw 32-byte key material.
            pub fn as_bytes(&self) -> &[u8; 32] {
                &self.0
            }
        }

        impl fmt::Debug for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                write!(f, "{}([REDACTED])", stringify!($name))
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                write!(f, "<{}>", stringify!($name))
            }
        }
    };
}

macro_rules! define_id {
    ($(#[doc = $doc:expr])* $name:ident) => {
        $(#[doc = $doc])*
        #[derive(
            Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize,
        )]
        #[serde(transparent)]
        pub struct $name(
            /// Raw numeric identifier.
            pub u32,
        );

        impl From<u32> for $name {
            fn from(v: u32) -> Self {
                Self(v)
            }
        }

        impl From<$name> for u32 {
            fn from(v: $name) -> Self {
                v.0
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                write!(f, "{}", self.0)
            }
        }
    };
}

macro_rules! define_bytes {
    ($(#[doc = $doc:expr])* $name:ident) => {
        $(#[doc = $doc])*
        #[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
        #[serde(transparent)]
        pub struct $name(
            /// Raw variable-length bytes.
            pub Vec<u8>,
        );

        impl From<Vec<u8>> for $name {
            fn from(v: Vec<u8>) -> Self {
                Self(v)
            }
        }

        impl From<$name> for Vec<u8> {
            fn from(v: $name) -> Self {
                v.0
            }
        }

        impl AsRef<[u8]> for $name {
            fn as_ref(&self) -> &[u8] {
                &self.0
            }
        }

        impl fmt::Debug for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                write!(f, "{}({} bytes)", stringify!($name), self.0.len())
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                write!(f, "<{} {} bytes>", stringify!($name), self.0.len())
            }
        }
    };
}

// -- Crypto key newtypes ([u8; 32], Zeroize + redacted Debug) --

define_crypto_key! {
    /// Double Ratchet root key.
    RootKey
}

define_crypto_key! {
    /// Double Ratchet / Sender Key chain key.
    ChainKey
}

define_crypto_key! {
    /// Per-message encryption key.
    MessageKey
}

define_crypto_key! {
    /// X25519 Diffie-Hellman public key.
    DhPublicKey
}

define_crypto_key! {
    /// Ed25519 signing public key.
    SigningPublicKey
}

define_crypto_key! {
    /// Ed25519 signing private key.
    SigningPrivateKey
}

// -- ID newtypes (u32, Copy + Ord + Hash) --

define_id! {
    /// Registration identifier.
    RegistrationId
}

define_id! {
    /// Device identifier (numeric, per Signal Protocol spec).
    DeviceId
}

define_id! {
    /// One-time pre-key identifier.
    PreKeyId
}

define_id! {
    /// Signed pre-key identifier.
    SignedPreKeyId
}

define_id! {
    /// Kyber (ML-KEM) pre-key identifier.
    KyberPreKeyId
}

define_id! {
    /// Server key identifier.
    ServerKeyId
}

define_id! {
    /// Message sequence number within a chain.
    MessageNumber
}

define_id! {
    /// Sender key chain iteration counter.
    ChainIteration
}

// -- Variable-length byte newtypes --

define_bytes! {
    /// Ed25519 signature bytes.
    Ed25519Signature
}

define_bytes! {
    /// ML-KEM public key bytes.
    KyberPublicKey
}

define_bytes! {
    /// ML-KEM ciphertext bytes.
    KyberCiphertext
}

define_bytes! {
    /// Encrypted payload bytes.
    Ciphertext
}

define_bytes! {
    /// Group identifier bytes.
    GroupId
}

// -- String + timestamp newtypes --

/// Sender identity UUID.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct SenderUuid(
    /// The underlying sender UUID.
    pub Uuid,
);

impl From<Uuid> for SenderUuid {
    fn from(v: Uuid) -> Self {
        Self(v)
    }
}

impl From<SenderUuid> for Uuid {
    fn from(v: SenderUuid) -> Self {
        v.0
    }
}

impl fmt::Display for SenderUuid {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// Unix timestamp in seconds.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct Timestamp(
    /// Seconds since the Unix epoch.
    pub u64,
);

impl From<u64> for Timestamp {
    fn from(v: u64) -> Self {
        Self(v)
    }
}

impl From<Timestamp> for u64 {
    fn from(v: Timestamp) -> Self {
        v.0
    }
}

impl fmt::Display for Timestamp {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn crypto_key_roundtrip() {
        let key = RootKey::from([42u8; 32]);
        assert_eq!(*key.as_bytes(), [42u8; 32]);
        let arr: [u8; 32] = key.into();
        assert_eq!(arr, [42u8; 32]);
    }

    #[test]
    fn crypto_key_serde_transparent() {
        let key = ChainKey::from([1u8; 32]);
        let bytes = postcard::to_allocvec(&key).unwrap();
        let raw_bytes = postcard::to_allocvec(&[1u8; 32]).unwrap();
        assert_eq!(bytes, raw_bytes);

        let restored: ChainKey = postcard::from_bytes(&bytes).unwrap();
        assert_eq!(restored, key);
    }

    #[test]
    fn crypto_key_debug_redacted() {
        let key = MessageKey::from([0u8; 32]);
        let debug = format!("{key:?}");
        assert!(debug.contains("REDACTED"));
        assert!(!debug.contains("0, 0, 0"));
    }

    #[test]
    fn crypto_key_zeroize() {
        let mut key = MessageKey::from([0xFF; 32]);
        key.zeroize();
        assert_eq!(key.0, [0u8; 32]);
    }

    #[test]
    fn id_roundtrip() {
        let id = PreKeyId::from(42);
        assert_eq!(id.0, 42);
        let v: u32 = id.into();
        assert_eq!(v, 42);
    }

    #[test]
    fn id_serde_transparent() {
        let id = DeviceId::from(7);
        let bytes = postcard::to_allocvec(&id).unwrap();
        let raw_bytes = postcard::to_allocvec(&7u32).unwrap();
        assert_eq!(bytes, raw_bytes);

        let restored: DeviceId = postcard::from_bytes(&bytes).unwrap();
        assert_eq!(restored, id);
    }

    #[test]
    fn id_display() {
        let id = RegistrationId::from(123);
        assert_eq!(id.to_string(), "123");
    }

    #[test]
    fn bytes_roundtrip() {
        let sig = Ed25519Signature::from(vec![1, 2, 3]);
        assert_eq!(sig.as_ref(), &[1, 2, 3]);
        let v: Vec<u8> = sig.into();
        assert_eq!(v, vec![1, 2, 3]);
    }

    #[test]
    fn bytes_serde_transparent() {
        let ct = Ciphertext::from(vec![10, 20, 30]);
        let bytes = postcard::to_allocvec(&ct).unwrap();
        let raw_bytes = postcard::to_allocvec(&vec![10u8, 20, 30]).unwrap();
        assert_eq!(bytes, raw_bytes);

        let restored: Ciphertext = postcard::from_bytes(&bytes).unwrap();
        assert_eq!(restored, ct);
    }

    #[test]
    fn sender_uuid_roundtrip() {
        let id = Uuid::new_v4();
        let sender = SenderUuid::from(id);
        assert_eq!(sender.0, id);
        assert_eq!(sender.to_string(), id.to_string());
        let back: Uuid = sender.into();
        assert_eq!(back, id);
    }

    #[test]
    fn timestamp_roundtrip() {
        let ts = Timestamp::from(1234567890);
        assert_eq!(ts.0, 1234567890);
        let v: u64 = ts.into();
        assert_eq!(v, 1234567890);
    }

    #[test]
    fn timestamp_ordering() {
        let a = Timestamp::from(100);
        let b = Timestamp::from(200);
        assert!(a < b);
    }

    #[test]
    fn sender_uuid_serde_transparent() {
        let id = Uuid::nil();
        let sender = SenderUuid::from(id);
        let bytes = postcard::to_allocvec(&sender).unwrap();
        let raw_bytes = postcard::to_allocvec(&id).unwrap();
        assert_eq!(bytes, raw_bytes);

        let restored: SenderUuid = postcard::from_bytes(&bytes).unwrap();
        assert_eq!(restored, sender);
    }

    #[test]
    fn timestamp_serde_transparent() {
        let ts = Timestamp::from(42u64);
        let bytes = postcard::to_allocvec(&ts).unwrap();
        let raw_bytes = postcard::to_allocvec(&42u64).unwrap();
        assert_eq!(bytes, raw_bytes);

        let restored: Timestamp = postcard::from_bytes(&bytes).unwrap();
        assert_eq!(restored, ts);
    }
}
