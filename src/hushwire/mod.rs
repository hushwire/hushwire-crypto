//! Hushwire application crypto, built on top of the Signal Protocol.
//!
//! Where [`crate::protocol`] is a faithful Signal Protocol implementation, these
//! modules are the application-specific primitives Hushwire layers on top of it:
//! the server [`trust_root`] key abstraction, organization metadata encryption
//! and signing identities ([`org`]), device [`provisioning`], BIP39 account
//! [`recovery`], Argon2id [`storage_key`] derivation, and sealed-sender
//! [`envelope`] verification. They share the crate's primitives but are
//! independent of the Signal session machinery.

pub mod envelope;
pub mod org;
pub mod provisioning;
pub mod recovery;
pub mod storage_key;
pub mod trust_root;
