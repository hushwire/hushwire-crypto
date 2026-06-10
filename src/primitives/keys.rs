//! Identity and ephemeral key primitives.
//!
//! Ed25519 is the canonical identity format; X25519 keys are derived on-the-fly
//! for Diffie-Hellman. This eliminates XEdDSA -- a divergence from Signal, which
//! keeps Curve25519 canonical and signs via XEdDSA.

use curve25519_dalek::edwards::CompressedEdwardsY;
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use rand::RngExt as _;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha512};
use subtle::ConstantTimeEq;
use x25519_dalek::{PublicKey as X25519Public, StaticSecret as X25519Secret};
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::error::{CryptoError, Result};

/// Ed25519 identity key pair, with X25519 keys derived on-the-fly for DH
/// (see the module docs for the XEdDSA divergence rationale).
#[derive(Clone)]
pub struct IdentityKeyPair {
    signing_key: SigningKey,
    seed: Zeroizing<[u8; 32]>,
}

#[derive(Zeroize, ZeroizeOnDrop)]
struct Zeroizing<T: Zeroize>(T);

impl<T: Zeroize + Clone> Clone for Zeroizing<T> {
    fn clone(&self) -> Self {
        Self(self.0.clone())
    }
}

impl std::fmt::Debug for IdentityKeyPair {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("IdentityKeyPair")
            .field("public", &self.public_key())
            .finish_non_exhaustive()
    }
}

impl IdentityKeyPair {
    /// Generates a new identity key pair from a random Ed25519 seed.
    pub fn generate() -> Self {
        let mut seed = [0u8; 32];
        rand::rng().fill(&mut seed[..]);
        let signing_key = SigningKey::from_bytes(&seed);
        Self {
            signing_key,
            seed: Zeroizing(seed),
        }
    }

    /// Reconstructs an identity key pair from a stored 32-byte Ed25519 seed.
    pub fn from_seed(seed: &[u8; 32]) -> Self {
        let signing_key = SigningKey::from_bytes(seed);
        Self {
            signing_key,
            seed: Zeroizing(*seed),
        }
    }

    /// Returns the Ed25519 public identity key.
    pub fn public_key(&self) -> IdentityPublicKey {
        IdentityPublicKey(self.signing_key.verifying_key())
    }

    /// Signs `data` with the Ed25519 signing key, returning the 64-byte signature.
    pub fn sign(&self, data: &[u8]) -> Vec<u8> {
        self.signing_key.sign(data).to_bytes().to_vec()
    }

    /// Returns the 32-byte Ed25519 seed backing this key pair.
    pub fn seed(&self) -> &[u8; 32] {
        &self.seed.0
    }

    /// Derives the X25519 private key for Diffie-Hellman from the Ed25519 seed.
    pub fn x25519_private_key(&self) -> X25519Secret {
        let hash = Sha512::digest(&self.seed.0);
        let mut scalar = [0u8; 32];
        scalar.copy_from_slice(&hash[..32]);
        scalar[0] &= 248;
        scalar[31] &= 127;
        scalar[31] |= 64;
        let secret = X25519Secret::from(scalar);
        scalar.zeroize();
        secret
    }

    /// Derives the X25519 public key for Diffie-Hellman from the identity key.
    pub fn x25519_public_key(&self) -> X25519Public {
        self.public_key().to_x25519()
    }
}

/// Ed25519 public identity key.
#[derive(Clone, Copy, Eq)]
pub struct IdentityPublicKey(VerifyingKey);

impl IdentityPublicKey {
    /// Parses an Ed25519 public identity key from its 32-byte encoding.
    ///
    /// Returns [`CryptoError::InvalidKey`] if the bytes are not a valid point.
    pub fn from_bytes(bytes: &[u8; 32]) -> Result<Self> {
        let key = VerifyingKey::from_bytes(bytes).map_err(|_| CryptoError::InvalidKey)?;
        Ok(Self(key))
    }

    /// Returns the 32-byte Ed25519 encoding of this public key.
    pub fn as_bytes(&self) -> [u8; 32] {
        self.0.to_bytes()
    }

    /// Verifies a 64-byte Ed25519 signature over `data`.
    ///
    /// Returns [`CryptoError::InvalidSignature`] on a malformed or failing signature.
    pub fn verify(&self, data: &[u8], signature: &[u8]) -> Result<()> {
        let sig_bytes: [u8; 64] = signature
            .try_into()
            .map_err(|_| CryptoError::InvalidSignature)?;
        let sig = Signature::from_bytes(&sig_bytes);
        self.0
            .verify(data, &sig)
            .map_err(|_| CryptoError::InvalidSignature)
    }

    /// Converts this Ed25519 identity key to its X25519 (Montgomery) public key.
    pub fn to_x25519(&self) -> X25519Public {
        let compressed = CompressedEdwardsY(self.0.to_bytes());
        let edwards = compressed
            .decompress()
            .expect("valid Ed25519 public key always decompresses");
        let montgomery = edwards.to_montgomery();
        X25519Public::from(*montgomery.as_bytes())
    }

    /// Returns the underlying Ed25519 [`VerifyingKey`].
    pub fn verifying_key(&self) -> &VerifyingKey {
        &self.0
    }
}

impl std::fmt::Debug for IdentityPublicKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "IdentityPublicKey({:?})", &self.as_bytes()[..8])
    }
}

impl PartialEq for IdentityPublicKey {
    fn eq(&self, other: &Self) -> bool {
        self.as_bytes().ct_eq(&other.as_bytes()).into()
    }
}

impl std::hash::Hash for IdentityPublicKey {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.as_bytes().hash(state);
    }
}

impl Serialize for IdentityPublicKey {
    fn serialize<S: serde::Serializer>(
        &self,
        serializer: S,
    ) -> std::result::Result<S::Ok, S::Error> {
        self.as_bytes().serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for IdentityPublicKey {
    fn deserialize<D: serde::Deserializer<'de>>(
        deserializer: D,
    ) -> std::result::Result<Self, D::Error> {
        let bytes: [u8; 32] = Deserialize::deserialize(deserializer)?;
        Self::from_bytes(&bytes).map_err(serde::de::Error::custom)
    }
}

/// X25519 key pair for ephemeral DH operations.
pub struct EphemeralKeyPair {
    secret: X25519Secret,
    public: X25519Public,
}

impl EphemeralKeyPair {
    /// Generates a new ephemeral X25519 key pair from random bytes.
    pub fn generate() -> Self {
        let mut bytes = [0u8; 32];
        rand::rng().fill(&mut bytes[..]);
        let secret = X25519Secret::from(bytes);
        let public = X25519Public::from(&secret);
        Self { secret, public }
    }

    /// Returns the X25519 public key.
    pub fn public_key(&self) -> &X25519Public {
        &self.public
    }

    /// Computes the X25519 Diffie-Hellman shared secret with `their_public`.
    pub fn diffie_hellman(&self, their_public: &X25519Public) -> SharedSecret {
        let ss = self.secret.diffie_hellman(their_public);
        SharedSecret(*ss.as_bytes())
    }

    /// Returns the 32-byte encoding of the X25519 public key.
    pub fn public_key_bytes(&self) -> [u8; 32] {
        self.public.to_bytes()
    }
}

impl std::fmt::Debug for EphemeralKeyPair {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("EphemeralKeyPair")
            .field("public", &&self.public.as_bytes()[..8])
            .finish_non_exhaustive()
    }
}

/// Shared secret from X25519 DH.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct SharedSecret([u8; 32]);

impl SharedSecret {
    /// Wraps raw 32 bytes as a shared secret.
    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    /// Returns the 32-byte shared secret.
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn identity_keypair_generate_and_sign() {
        let kp = IdentityKeyPair::generate();
        let data = b"hello world";
        let sig = kp.sign(data);
        assert!(kp.public_key().verify(data, &sig).is_ok());
    }

    #[test]
    fn identity_keypair_wrong_data_fails_verify() {
        let kp = IdentityKeyPair::generate();
        let sig = kp.sign(b"correct");
        assert!(kp.public_key().verify(b"wrong", &sig).is_err());
    }

    #[test]
    fn identity_keypair_wrong_key_fails_verify() {
        let kp1 = IdentityKeyPair::generate();
        let kp2 = IdentityKeyPair::generate();
        let sig = kp1.sign(b"data");
        assert!(kp2.public_key().verify(b"data", &sig).is_err());
    }

    #[test]
    fn identity_keypair_invalid_signature_length() {
        let kp = IdentityKeyPair::generate();
        assert!(kp.public_key().verify(b"data", &[0u8; 63]).is_err());
        assert!(kp.public_key().verify(b"data", &[]).is_err());
    }

    #[test]
    fn identity_keypair_from_seed_deterministic() {
        let seed = [42u8; 32];
        let kp1 = IdentityKeyPair::from_seed(&seed);
        let kp2 = IdentityKeyPair::from_seed(&seed);
        assert_eq!(kp1.public_key(), kp2.public_key());
        let sig = kp1.sign(b"test");
        assert!(kp2.public_key().verify(b"test", &sig).is_ok());
    }

    #[test]
    fn identity_public_key_serialization_roundtrip() {
        let kp = IdentityKeyPair::generate();
        let pk = kp.public_key();
        let bytes = pk.as_bytes();
        let restored = IdentityPublicKey::from_bytes(&bytes).unwrap();
        assert_eq!(pk, restored);
    }

    #[test]
    fn identity_public_key_serde_roundtrip() {
        let kp = IdentityKeyPair::generate();
        let pk = kp.public_key();
        let serialized = postcard::to_allocvec(&pk).unwrap();
        let deserialized: IdentityPublicKey = postcard::from_bytes(&serialized).unwrap();
        assert_eq!(pk, deserialized);
    }

    #[test]
    fn ed25519_to_x25519_public_key_conversion() {
        let kp = IdentityKeyPair::generate();
        let x_pub = kp.public_key().to_x25519();
        // The X25519 public key derived from the identity key should
        // match the one derived from the X25519 private key.
        let x_priv = kp.x25519_private_key();
        let x_pub_from_priv = X25519Public::from(&x_priv);
        assert_eq!(x_pub.as_bytes(), x_pub_from_priv.as_bytes());
    }

    #[test]
    fn x25519_dh_agreement() {
        let kp_a = IdentityKeyPair::generate();
        let kp_b = IdentityKeyPair::generate();

        let a_priv = kp_a.x25519_private_key();
        let b_pub = kp_b.x25519_public_key();
        let ss_a = a_priv.diffie_hellman(&b_pub);

        let b_priv = kp_b.x25519_private_key();
        let a_pub = kp_a.x25519_public_key();
        let ss_b = b_priv.diffie_hellman(&a_pub);

        assert_eq!(ss_a.as_bytes(), ss_b.as_bytes());
    }

    #[test]
    fn ephemeral_keypair_dh() {
        let alice = EphemeralKeyPair::generate();
        let bob = EphemeralKeyPair::generate();

        let ss_a = alice.diffie_hellman(bob.public_key());
        let ss_b = bob.diffie_hellman(alice.public_key());

        assert_eq!(ss_a.as_bytes(), ss_b.as_bytes());
    }

    #[test]
    fn identity_public_key_equality_is_constant_time() {
        let kp = IdentityKeyPair::generate();
        let pk1 = kp.public_key();
        let pk2 = kp.public_key();
        assert_eq!(pk1, pk2);

        let other = IdentityKeyPair::generate().public_key();
        assert_ne!(pk1, other);
    }

    #[test]
    fn shared_secret_from_bytes() {
        let bytes = [99u8; 32];
        let ss = SharedSecret::from_bytes(bytes);
        assert_eq!(*ss.as_bytes(), bytes);
    }

    #[test]
    fn identity_public_key_hash_consistent() {
        use std::collections::HashSet;
        let kp = IdentityKeyPair::generate();
        let pk = kp.public_key();

        let mut set = HashSet::new();
        set.insert(pk);
        assert!(set.contains(&pk));

        let other = IdentityKeyPair::generate().public_key();
        assert!(!set.contains(&other));
    }

    #[test]
    fn identity_public_key_verifying_key() {
        let kp = IdentityKeyPair::generate();
        let pk = kp.public_key();
        let vk = pk.verifying_key();
        assert_eq!(vk.to_bytes(), pk.as_bytes());
    }

    #[test]
    fn shared_secret_zeroize_on_drop() {
        use std::mem::ManuallyDrop;

        let kp1 = EphemeralKeyPair::generate();
        let kp2 = EphemeralKeyPair::generate();
        let mut ss = ManuallyDrop::new(Box::new(kp1.diffie_hellman(kp2.public_key())));

        assert_ne!(ss.0, [0u8; 32]);

        let ptr: *mut SharedSecret = &mut **ss;
        unsafe {
            std::ptr::drop_in_place(ptr);
            assert_eq!((*ptr).0, [0u8; 32], "shared secret not zeroized after drop");
            drop(Box::from_raw(ptr));
        }
    }
}
