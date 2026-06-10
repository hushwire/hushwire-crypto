//! Convenience re-exports for downstream consumers.
//!
//! `use hushwire_crypto::prelude::*;` pulls in the crate's most commonly used
//! types: errors, core newtypes, identity keys, the session/handshake entry
//! points, the storage traits, and the principal application-layer types. It
//! mirrors the curated set re-exported at the crate root.

pub use crate::{
    ChainIteration, ChainKey, Ciphertext, CryptoError, DeviceId, DhPublicKey, Direction,
    Ed25519Signature, Ed25519TrustRoot, EncryptedOutput, EnvelopeVerificationInput,
    EphemeralKeyPair, GroupId, IdentityKeyPair, IdentityKeyStore, IdentityPublicKey,
    KyberCiphertext, KyberPreKeyRecord, KyberPreKeyStore, KyberPublicKey, MessageKey,
    MessageNumber, MetadataKeyEnvelope, MockTrustRoot, PqxdhInitialMessage, PreKeyBundle,
    PreKeyRecord, PreKeyStore, ProtocolAddress, RecoveryKey, RegistrationId, Result, RootKey,
    SenderKeyRecord, SenderKeyStore, SenderUuid, ServerKeyId, SesameStore, SesameUserRecord,
    SessionRecord, SessionStore, SharedSecret, SignedPreKeyRecord, SignedPreKeyStore,
    SigningKeypair, SigningPrivateKey, SigningPublicKey, SymmetricMetadataKeyEnvelope, Timestamp,
    TrustRoot, verify_envelope,
};
