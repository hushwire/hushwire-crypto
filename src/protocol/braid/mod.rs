//! ML-KEM Braid (SPQR) -- Signal's sparse post-quantum ratchet.
//!
//! This is the continuous post-quantum key-agreement primitive that *feeds* the
//! Double Ratchet; it is not part of the ratchet itself (the ratchet depends on
//! this module, never the reverse). It replaces the novel D-13 continuous PQ
//! ratchet with a faithful implementation of Signal's formally-modeled ML-KEM
//! Braid protocol.
//!
//! The module is layered: [`erasure`] is the Reed-Solomon chunk-stream wrapper
//! that fragments each ML-KEM ciphertext/public key across many small messages,
//! [`kem`] wraps the underlying ML-KEM-768 incremental API, [`auth`] binds braid
//! payloads to the session, and [`state_machine`] drives the SCKA epochs. The
//! Double Ratchet consumes the resulting [`EpochSecret`]s; see
//! [`crate::protocol::ratchet`].

pub mod auth;
pub mod erasure;
pub mod kem;
pub mod state_machine;

pub use state_machine::{BraidState, EpochSecret, Message, MsgType, SckaReceive, SckaSend};
