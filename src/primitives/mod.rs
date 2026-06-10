//! Low-level cryptographic building blocks.
//!
//! These are the primitives the protocol and application layers compose:
//! authenticated encryption ([`aead`]), key-derivation functions ([`kdf`]),
//! identity and ephemeral key material ([`keys`]), and message [`padding`].
//! Nothing here knows about sessions, ratchets, or organizations -- they are
//! the smallest auditable units the rest of the crate is built from.

pub mod aead;
pub mod kdf;
pub mod keys;
pub mod padding;
