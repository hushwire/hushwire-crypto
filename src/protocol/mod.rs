//! The clean-room Signal Protocol.
//!
//! This is the heart of the crate: post-quantum key agreement ([`pqxdh`] with
//! [`prekey`] bundles), the forward-secret [`ratchet`] for 1:1 sessions, the
//! [`braid`] post-quantum ratchet that feeds it, [`sender_key`] group messaging,
//! [`sealed_sender`] server-blind delivery, and [`sesame`] multi-device session
//! management. Persistence is abstracted behind the async traits in [`stores`];
//! the caller supplies the backing store.

pub mod braid;
pub mod pqxdh;
pub mod prekey;
pub mod ratchet;
pub mod sealed_sender;
pub mod sender_key;
pub mod sesame;
pub mod stores;
