//! Clean-room, Rust-native implementation of the [Signal Protocol], plus the
//! standalone cryptographic primitives Hushwire builds on top of it.
//!
//! The crate exposes raw-byte APIs and carries no dependency on Hushwire's
//! wire/protocol types, so it can be audited and reused in isolation. All secret
//! key material is zeroized on drop and secret comparisons are constant-time.
//!
//! # Layout
//!
//! The crate is organized into three layers, plus the foundational vocabulary
//! ([`error`], [`types`], [`address`], [`serialization`]) every layer shares:
//!
//! - [`primitives`] — low-level cryptographic building blocks: authenticated
//!   encryption, KDFs, identity/ephemeral keys, and message padding.
//! - [`protocol`] — the clean-room Signal Protocol: post-quantum key agreement
//!   ([`protocol::pqxdh`]), the forward-secret Double Ratchet ([`protocol::ratchet`])
//!   and the ML-KEM Braid / SPQR ([`protocol::braid`]) that feeds it, group
//!   [`protocol::sender_key`] messaging, [`protocol::sealed_sender`] server-blind
//!   delivery, [`protocol::sesame`] multi-device session management, and the
//!   storage traits in [`protocol::stores`].
//! - [`hushwire`] — application crypto built on top of the protocol: the server
//!   [`hushwire::trust_root`], organization [`hushwire::org`] metadata and signing,
//!   device [`hushwire::provisioning`], BIP39 [`hushwire::recovery`], Argon2id
//!   [`hushwire::storage_key`] derivation, and [`hushwire::envelope`] verification.
//!
//! The most commonly used items are re-exported at the crate root and collected
//! in [`prelude`] for glob import (`use hushwire_crypto::prelude::*;`).
//!
//! Storage is abstracted behind the async traits in [`protocol::stores`]; the
//! caller supplies the persistence layer.
//!
//! # Divergences from the Signal specification
//!
//! This implementation is clean-room from the published specs. Every deliberate
//! deviation is catalogued and justified in the crate's `docs/signal-spec-divergence.md`.
//!
//! [Signal Protocol]: https://signal.org/docs/

#![deny(missing_docs)]

// -- Foundational shared vocabulary (used by every layer) --
pub mod address;
pub mod error;
pub mod serialization;
pub mod types;

// -- The three layers --
pub mod hushwire;
pub mod primitives;
pub mod protocol;

pub mod prelude;

// -- Curated root re-exports: the principal type of each area, surfaced flat. --

pub use address::ProtocolAddress;
pub use error::{CryptoError, Result};
pub use types::{
    ChainIteration, ChainKey, Ciphertext, DeviceId, DhPublicKey, Ed25519Signature, GroupId,
    KyberCiphertext, KyberPublicKey, MessageKey, MessageNumber, RegistrationId, RootKey,
    SenderUuid, ServerKeyId, SigningPrivateKey, SigningPublicKey, Timestamp,
};

// primitives
pub use primitives::keys::{EphemeralKeyPair, IdentityKeyPair, IdentityPublicKey, SharedSecret};

// protocol
pub use protocol::prekey::{PqxdhInitialMessage, PreKeyBundle};
pub use protocol::ratchet::EncryptedOutput;
pub use protocol::stores::{
    Direction, IdentityKeyStore, KyberPreKeyRecord, KyberPreKeyStore, PreKeyRecord, PreKeyStore,
    SenderKeyRecord, SenderKeyStore, SesameStore, SesameUserRecord, SessionRecord, SessionStore,
    SignedPreKeyRecord, SignedPreKeyStore,
};

// hushwire application layer
pub use hushwire::envelope::{EnvelopeVerificationInput, verify_envelope};
pub use hushwire::org::metadata::{MetadataKeyEnvelope, SymmetricMetadataKeyEnvelope};
pub use hushwire::org::signing::SigningKeypair;
pub use hushwire::recovery::RecoveryKey;
pub use hushwire::trust_root::{Ed25519TrustRoot, MockTrustRoot, TrustRoot};
