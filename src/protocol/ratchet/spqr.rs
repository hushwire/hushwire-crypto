//! The Sparse Post-Quantum Ratchet (SPQR) -- the post-quantum half of Signal's
//! Triple Ratchet. This is `spqr_state` from the Double Ratchet spec section 5,
//! a clean-room translation: an ML-KEM braid (the SCKA) plus per-epoch symmetric
//! KDF chains whose per-message keys are combined with the EC Double Ratchet's
//! message key via `KDF_HYBRID` (in [`super`]).
//!
//! The braid ([`BraidState`]) is the SCKA: `ratchet_send_key` / `ratchet_receive_key`
//! wrap `SCKASend` / `SCKAReceive` and maintain the spec's `kdfchains`, `MKSKIPPED`,
//! root key, and epoch counter. One fresh KEM secret completes roughly every ~74
//! messages and reseeds the chains via `KDF_SCKA_RK`; between completions each chain
//! advances per message via `KDF_SCKA_CK`.
//!
//! Two spec-errata are handled here (both confirmed against the reference structure,
//! no code copied): the section 7.2 `KDF_SCKA_CK` table is a copy-paste of
//! `KDF_SCKA_INIT` (we follow the normative section 5.2 definition, see [`crate::primitives::kdf`]);
//! and section 5.6 `SCKARatchetReceiveKey` calls `SkipMessageKeys(..., header.n)` where
//! the trailing advance then over-advances -- the correct skip bound is `header.n - 1`
//! (skip the gap, then one trailing advance yields the message's key). See
//! [`SpqrState::ratchet_receive_key`].

use std::collections::BTreeMap;

use rand_core::CryptoRng;
use serde::{Deserialize, Serialize};

use crate::error::{CryptoError, Result};
use crate::primitives::kdf::{hkdf_sha256, kdf_scka_ck, kdf_scka_init, kdf_scka_rk};
use crate::protocol::braid::{BraidState, Message, SckaReceive, SckaSend};
use crate::types::{ChainKey, MessageKey, RootKey};

// Maximum skipped per-message PQ keys per chain (spec `MAX_SKIP`). Shared with the
// classical EC ratchet's bound (divergence D-12) via a single constant so the two
// skip limits cannot drift apart.
use super::skipped::MAX_SKIP;

/// The participant's role in the braid (spec `direction`). Determines which of the
/// two reseed chain keys is the send chain vs the receive chain, so that one peer's
/// send chain pairs with the other's receive chain.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Serialize, Deserialize)]
enum Direction {
    A2B,
    B2A,
}

/// One SPQR KDF chain (spec `KDFChain`): a chain key and a message counter `N`.
///
/// This intentionally does *not* reuse [`super::chain::ChainState`]: that type's
/// `advance` calls `KDF_CK(ck)` (single-input), whereas an SPQR step is
/// counter-bound via `KDF_SCKA_CK(ck, ctr)`. A future "dedup" that collapsed the
/// two would silently drop the counter binding, so the two chain types stay
/// separate by design.
#[derive(Clone, Serialize, Deserialize)]
struct SckaChain {
    ck: ChainKey,
    n: u32,
}

impl SckaChain {
    fn new(ck: ChainKey) -> Self {
        Self { ck, n: 0 }
    }

    /// Advance one step (spec `N += 1; CK, mk = KDF_SCKA_CK(CK, N)`), returning the
    /// new counter and this step's message key.
    fn advance(&mut self) -> (u32, MessageKey) {
        self.n += 1;
        let out = kdf_scka_ck(&self.ck, self.n);
        self.ck = out.chain_key;
        (self.n, out.message_key)
    }
}

/// The send/receive chains for one epoch (spec `kdfchains[epoch]`).
///
/// In practice `send` is the field individually dropped (`None`) for forward
/// secrecy, once the sender advances past this epoch (`ratchet_send_key`). `recv`
/// is effectively always `Some` while the entry lives; whole `EpochChains` entries
/// are freed wholesale by `ClearOldEpochs` two epochs back. The `Option` on `recv`
/// is kept for symmetry with the spec's `kdfchains` shape.
#[derive(Clone, Serialize, Deserialize)]
struct EpochChains {
    send: Option<SckaChain>,
    recv: Option<SckaChain>,
}

/// Derive the SPQR session key (`SKscka`) from the X3DH/PQXDH shared secret. Both
/// peers feed the same secret, so both derive the same key; it seeds both the braid
/// (the SCKA authenticator) and `KDF_SCKA_INIT`'s root key and bootstrap chains.
pub fn braid_auth_seed(shared_secret: &[u8; 32]) -> [u8; 32] {
    let okm = hkdf_sha256(shared_secret, None, b"HushwireBraid:auth_seed", 32);
    let mut seed = [0u8; 32];
    seed.copy_from_slice(&okm);
    seed
}

/// The Sparse Post-Quantum Ratchet state (`spqr_state`, spec section 5.3).
#[derive(Clone, Serialize, Deserialize)]
pub struct SpqrState {
    /// `scka_state`: the ML-KEM braid.
    braid: BraidState,
    /// `RK`: the SPQR root key (separate from the EC Double Ratchet root key).
    rk: RootKey,
    /// The latest epoch whose SCKA key has been incorporated (init 0 = bootstrap).
    epoch: u64,
    /// `kdfchains`: per-epoch send/receive KDF chains.
    kdfchains: BTreeMap<u64, EpochChains>,
    /// `MKSKIPPED`: per-epoch maps of skipped message numbers to their keys.
    mkskipped: BTreeMap<u64, BTreeMap<u32, MessageKey>>,
    /// `direction`: A2B / B2A role.
    direction: Direction,
}

impl SpqrState {
    /// Initialize the A2B party (the session initiator, Alice), spec
    /// `RatchetInitAliceSCKA`.
    pub fn new_sender(shared_secret: &[u8; 32]) -> Self {
        Self::init(shared_secret, Direction::A2B)
    }

    /// Initialize the B2A party (the responder, Bob), spec `RatchetInitBobSCKA`.
    pub fn new_receiver(shared_secret: &[u8; 32]) -> Self {
        Self::init(shared_secret, Direction::B2A)
    }

    /// The latest epoch whose SCKA key has been incorporated (0 = bootstrap, before
    /// the braid completes its first KEM key agreement).
    #[cfg(test)]
    pub(crate) fn current_epoch(&self) -> u64 {
        self.epoch
    }

    fn init(shared_secret: &[u8; 32], direction: Direction) -> Self {
        let sk = braid_auth_seed(shared_secret);
        let braid = match direction {
            Direction::A2B => BraidState::init_sender(&sk),
            Direction::B2A => BraidState::init_receiver(&sk),
        };
        let chains = kdf_scka_init(&sk);
        let (send_ck, recv_ck) = Self::assign(direction, chains.chain_key_0, chains.chain_key_1);
        let mut kdfchains = BTreeMap::new();
        kdfchains.insert(
            0,
            EpochChains {
                send: Some(SckaChain::new(send_ck)),
                recv: Some(SckaChain::new(recv_ck)),
            },
        );
        Self {
            braid,
            rk: chains.root_key,
            epoch: 0,
            kdfchains,
            mkskipped: BTreeMap::new(),
            direction,
        }
    }

    /// Map the spec's `(CKs, CKr)` reseed output to this party's (send, receive)
    /// chains. A2B uses `(CK0, CK1)`; B2A swaps, so Alice's send pairs with Bob's
    /// receive (and vice versa).
    fn assign(direction: Direction, ck0: ChainKey, ck1: ChainKey) -> (ChainKey, ChainKey) {
        match direction {
            Direction::A2B => (ck0, ck1),
            Direction::B2A => (ck1, ck0),
        }
    }

    /// Incorporate a completed braid epoch secret (spec: `KDF_SCKA_RK` reseed +
    /// a fresh `kdfchains[key_epoch]`). Fails closed if epochs are not consecutive.
    fn add_epoch(&mut self, key_epoch: u64, epoch_secret: &[u8; 32]) -> Result<()> {
        if self.epoch + 1 != key_epoch {
            return Err(CryptoError::BraidKem(format!(
                "non-consecutive SPQR epoch: have {}, got {key_epoch}",
                self.epoch
            )));
        }
        let chains = kdf_scka_rk(&self.rk, epoch_secret);
        self.rk = chains.root_key;
        let (send_ck, recv_ck) =
            Self::assign(self.direction, chains.chain_key_0, chains.chain_key_1);
        self.kdfchains.insert(
            key_epoch,
            EpochChains {
                send: Some(SckaChain::new(send_ck)),
                recv: Some(SckaChain::new(recv_ck)),
            },
        );
        self.epoch = key_epoch;
        Ok(())
    }

    /// `SCKARatchetSendKey`: advance the braid and the sending PQ chain, returning
    /// the braid message to piggyback, this message's PQ counter (`pqN`), and the
    /// per-message PQ key `pq_mk` to combine with the EC message key.
    pub fn ratchet_send_key<R: CryptoRng>(
        &mut self,
        rng: &mut R,
    ) -> Result<(Message, u32, MessageKey)> {
        let SckaSend {
            msg,
            sending_epoch,
            output_key,
        } = self.braid.send(rng)?;
        if let Some(es) = output_key {
            self.add_epoch(es.epoch, &es.secret)?;
            self.clear_old_epochs(sending_epoch);
        }
        // Drop the previous epoch's send chain for forward secrecy (spec:
        // `kdfchains[sending_epoch - 1].send = None`).
        if let Some(prev) = sending_epoch.checked_sub(1)
            && let Some(c) = self.kdfchains.get_mut(&prev)
        {
            c.send = None;
        }
        let chain = self
            .kdfchains
            .get_mut(&sending_epoch)
            .and_then(|c| c.send.as_mut())
            .ok_or_else(|| {
                CryptoError::BraidKem(format!("no SPQR send chain for epoch {sending_epoch}"))
            })?;
        let (pq_n, pq_mk) = chain.advance();
        Ok((msg, pq_n, pq_mk))
    }

    /// `SCKARatchetReceiveKey`: advance the braid with the carried codeword and the
    /// receiving PQ chain to produce `pq_mk` for the message numbered `pq_n`.
    ///
    /// Spec section 5.6, with the section-5.6 off-by-one corrected: skip-and-store
    /// the gap up through `pq_n - 1`, then a single trailing advance yields this
    /// message's key at `pq_n` (the rendered spec skips through `pq_n`, which would
    /// return the `pq_n + 1` key). Confirmed against the reference structure.
    ///
    /// `receiving_epoch` and `pq_n` come from the message header, which the caller
    /// MUST have bound into the AEAD associated data: this routine derives a key for
    /// whatever `(epoch, pq_n)` it is handed (constrained only by chain membership and
    /// the replay guard), so a header value the legitimate sender did not stamp is
    /// caught by the carrying message's AEAD tag, not here. Deriving `pq_mk` before or
    /// independently of that AEAD check would reintroduce a forgeable-epoch oracle.
    pub fn ratchet_receive_key(&mut self, msg: &Message, pq_n: u32) -> Result<MessageKey> {
        let SckaReceive {
            receiving_epoch,
            output_key,
        } = self.braid.receive(msg)?;
        if let Some(es) = output_key {
            self.add_epoch(es.epoch, &es.secret)?;
        }
        if let Some(mk) = self.try_skipped(receiving_epoch, pq_n) {
            return Ok(mk);
        }
        // The chain must not already be at or past this message (replay / duplicate).
        let cur = self
            .kdfchains
            .get(&receiving_epoch)
            .and_then(|c| c.recv.as_ref())
            .map(|c| c.n);
        if let Some(cur) = cur
            && pq_n <= cur
        {
            return Err(CryptoError::BraidKem(format!(
                "SPQR replay or duplicate: epoch {receiving_epoch} message {pq_n} <= current {cur}"
            )));
        }
        // Skip-and-store the gap [.. pq_n - 1].
        self.skip_message_keys(receiving_epoch, pq_n.saturating_sub(1))?;
        // Trailing advance yields this message's key.
        let chain = self
            .kdfchains
            .get_mut(&receiving_epoch)
            .and_then(|c| c.recv.as_mut())
            .ok_or_else(|| {
                CryptoError::BraidKem(format!("no SPQR recv chain for epoch {receiving_epoch}"))
            })?;
        let (n, mk) = chain.advance();
        // The trailing advance must land exactly on the requested counter. This is an
        // invariant of the skip-bound arithmetic above; promote it to a runtime
        // fail-closed (not just a debug_assert) so any future regression returns an
        // error rather than silently handing back a key for the wrong counter.
        if n != pq_n {
            return Err(CryptoError::BraidKem(format!(
                "SPQR counter mismatch: advanced to {n}, expected {pq_n}"
            )));
        }
        Ok(mk)
    }

    /// `TrySkippedMessageKeys`: take a previously stored skipped key, if present.
    fn try_skipped(&mut self, epoch: u64, n: u32) -> Option<MessageKey> {
        let inner = self.mkskipped.get_mut(&epoch)?;
        let mk = inner.remove(&n)?;
        if inner.is_empty() {
            self.mkskipped.remove(&epoch);
        }
        Some(mk)
    }

    /// `SkipMessageKeys`: advance the receive chain of `epoch` up to `until`,
    /// storing each skipped message key. No-op if that chain is gone.
    fn skip_message_keys(&mut self, epoch: u64, until: u32) -> Result<()> {
        let Some(chain) = self.kdfchains.get_mut(&epoch).and_then(|c| c.recv.as_mut()) else {
            return Ok(());
        };
        if chain.n + MAX_SKIP < until {
            return Err(CryptoError::MaxSkipExceeded(until - chain.n, MAX_SKIP));
        }
        let mut skipped = Vec::new();
        while chain.n < until {
            skipped.push(chain.advance());
        }
        if !skipped.is_empty() {
            let inner = self.mkskipped.entry(epoch).or_default();
            for (n, mk) in skipped {
                inner.insert(n, mk);
            }
        }
        Ok(())
    }

    /// `ClearOldEpochs`: drop chains and skipped keys two epochs behind the sender
    /// (they can no longer be referenced).
    ///
    /// Epoch pruning is intentionally **send-path only**: this is called from
    /// `ratchet_send_key`, never from `ratchet_receive_key`. We believe this matches
    /// Signal's design, where epoch eviction is keyed off the sending epoch advancing
    /// rather than the receiving one. The retained set is therefore bounded by the
    /// gap between the current (highest braid) epoch and the local sending epoch, not
    /// by message volume: a new epoch cannot be minted without a complete bidirectional
    /// braid round-trip (`add_epoch` requires consecutive epochs and the braid only
    /// emits an `output_key` after a full KEM exchange), so a party cannot run its
    /// current epoch arbitrarily far ahead of its own send participation. A peer that
    /// sends at all prunes on each send; a peer that sends nothing transmits no braid
    /// chunks and so cannot advance the epoch past what is already in flight. The one
    /// degenerate case is a peer that legitimately receives across many epochs while
    /// never sending — its retained epochs grow with that send/receive gap until it
    /// next sends. This is an inherent property of send-driven pruning, not a leak.
    fn clear_old_epochs(&mut self, sending_epoch: u64) {
        if let Some(old) = sending_epoch.checked_sub(2) {
            self.kdfchains.remove(&old);
            self.mkskipped.remove(&old);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand_chacha::ChaCha20Rng;
    use rand_chacha::rand_core::SeedableRng;

    fn pair() -> (SpqrState, SpqrState) {
        let ss = [0x21u8; 32];
        (SpqrState::new_sender(&ss), SpqrState::new_receiver(&ss))
    }

    #[test]
    fn auth_seed_is_deterministic_and_secret_dependent() {
        assert_eq!(braid_auth_seed(&[1u8; 32]), braid_auth_seed(&[1u8; 32]));
        assert_ne!(braid_auth_seed(&[1u8; 32]), braid_auth_seed(&[2u8; 32]));
    }

    #[test]
    fn bootstrap_first_message_pairs() {
        // Before any braid epoch completes, the epoch-0 (KDF_SCKA_INIT) chains must
        // already yield a peer-identical pq_mk from message 1.
        let (mut alice, mut bob) = pair();
        let mut ra = ChaCha20Rng::seed_from_u64(1);
        let (msg, pqn, mk_a) = alice.ratchet_send_key(&mut ra).unwrap();
        let mk_b = bob.ratchet_receive_key(&msg, pqn).unwrap();
        assert_eq!(pqn, 1, "first PQ message number is 1");
        assert_eq!(mk_a, mk_b, "bootstrap pq_mk must pair across peers");
    }

    /// Drive a full duplex ping-pong, asserting every message's pq_mk pairs across
    /// peers. Long enough to cross multiple braid epoch completions (reseeds), so it
    /// exercises bootstrap, KDF_SCKA_RK reseed, and the role swap each epoch.
    #[test]
    fn in_order_pairs_across_many_epochs() {
        let (mut alice, mut bob) = pair();
        let mut ra = ChaCha20Rng::seed_from_u64(1);
        let mut rb = ChaCha20Rng::seed_from_u64(2);
        let mut max_epoch = 0u64;
        for _ in 0..300 {
            let (msg, pqn, mk_a) = alice.ratchet_send_key(&mut ra).unwrap();
            let mk_b = bob.ratchet_receive_key(&msg, pqn).unwrap();
            assert_eq!(mk_a, mk_b, "alice->bob pq_mk must pair");

            let (msg, pqn, mk_b) = bob.ratchet_send_key(&mut rb).unwrap();
            let mk_a = alice.ratchet_receive_key(&msg, pqn).unwrap();
            assert_eq!(mk_b, mk_a, "bob->alice pq_mk must pair");
            max_epoch = max_epoch.max(alice.epoch).max(bob.epoch);
        }
        assert!(
            max_epoch >= 2,
            "test must cross at least two braid epoch reseeds, reached {max_epoch}"
        );
    }

    /// Out-of-order delivery within a chain: the receiver buffers skipped keys and
    /// recovers the right pq_mk when the delayed messages arrive.
    #[test]
    fn out_of_order_within_chain_pairs() {
        let (mut alice, mut bob) = pair();
        let mut ra = ChaCha20Rng::seed_from_u64(7);

        // Alice sends three in a row; capture (msg, pqn, mk).
        let m1 = alice.ratchet_send_key(&mut ra).unwrap();
        let m2 = alice.ratchet_send_key(&mut ra).unwrap();
        let m3 = alice.ratchet_send_key(&mut ra).unwrap();

        // Bob receives 2, then 1, then 3.
        let b2 = bob.ratchet_receive_key(&m2.0, m2.1).unwrap();
        assert_eq!(b2, m2.2, "out-of-order m2 must pair");
        let b1 = bob.ratchet_receive_key(&m1.0, m1.1).unwrap();
        assert_eq!(b1, m1.2, "delayed m1 must pair (from MKSKIPPED)");
        let b3 = bob.ratchet_receive_key(&m3.0, m3.1).unwrap();
        assert_eq!(b3, m3.2, "m3 must pair");
    }

    /// Out-of-order delivery that straddles a braid epoch reseed: a message held
    /// back from epoch e and delivered after the receiver has reseeded into a later
    /// epoch must still pair. This is the case that requires `receiving_epoch` to be
    /// read from the message (`msg.epoch - 1`), not the receiver's advanced state.
    #[test]
    fn out_of_order_across_epoch_reseed_pairs() {
        let (mut alice, mut bob) = pair();
        let mut ra = ChaCha20Rng::seed_from_u64(11);
        let mut rb = ChaCha20Rng::seed_from_u64(12);

        let mut held: Option<(Message, u32, MessageKey, u64)> = None;
        let mut done = false;
        for _ in 0..400 {
            let (msg, pqn, mk_a) = alice.ratchet_send_key(&mut ra).unwrap();
            let msg_epoch = msg.epoch.saturating_sub(1);
            // Hold back the first message that keys under a completed epoch (>= 1),
            // so there is a real reseed boundary to straddle.
            if held.is_none() && msg_epoch >= 1 {
                held = Some((msg, pqn, mk_a, msg_epoch));
            } else {
                let mk_b = bob.ratchet_receive_key(&msg, pqn).unwrap();
                assert_eq!(mk_a, mk_b);
            }

            let (msg, pqn, mk_b) = bob.ratchet_send_key(&mut rb).unwrap();
            let mk_a = alice.ratchet_receive_key(&msg, pqn).unwrap();
            assert_eq!(mk_b, mk_a);

            // Deliver the held message only once bob has reseeded past its epoch.
            if let Some((ref hmsg, hpqn, ref hmk, hepoch)) = held
                && bob.current_epoch() > hepoch
            {
                let got = bob.ratchet_receive_key(hmsg, hpqn).unwrap();
                assert_eq!(
                    *hmk, got,
                    "a message delayed across an epoch reseed must still pair"
                );
                done = true;
                break;
            }
        }
        assert!(
            done,
            "test must hold a message and deliver it after bob reseeds past its epoch"
        );
    }

    /// A replayed / duplicate message number fails closed rather than returning a
    /// wrong key.
    #[test]
    fn replay_fails_closed() {
        let (mut alice, mut bob) = pair();
        let mut ra = ChaCha20Rng::seed_from_u64(9);
        let (msg, pqn, _) = alice.ratchet_send_key(&mut ra).unwrap();
        bob.ratchet_receive_key(&msg, pqn).unwrap();
        // Re-presenting the same (msg, pqn): the recv chain is already past it.
        assert!(
            bob.ratchet_receive_key(&msg, pqn).is_err(),
            "a replayed PQ message number must fail closed"
        );
    }

    /// Replay of an *older* message whose key was already delivered out of order
    /// (consumed from MKSKIPPED) must also fail closed -- not just the immediate
    /// re-presentation covered by `replay_fails_closed`.
    #[test]
    fn replay_of_consumed_skipped_message_fails_closed() {
        let (mut alice, mut bob) = pair();
        let mut ra = ChaCha20Rng::seed_from_u64(5);
        let m1 = alice.ratchet_send_key(&mut ra).unwrap();
        let m2 = alice.ratchet_send_key(&mut ra).unwrap();
        // Receive #2 first (skips and stores #1), then #1 (consumes the stored key).
        bob.ratchet_receive_key(&m2.0, m2.1).unwrap();
        bob.ratchet_receive_key(&m1.0, m1.1).unwrap();
        // Replaying #1 now: it is gone from MKSKIPPED and pq_n(1) <= cur(2).
        assert!(
            bob.ratchet_receive_key(&m1.0, m1.1).is_err(),
            "replay of an already-consumed skipped message must fail closed"
        );
    }

    /// The SPQR per-chain `MAX_SKIP` bound. The EC-level `max_skip_exceeded` test
    /// (ratchet/mod.rs) trips the classical chain's bound first in the full decrypt
    /// path, so this branch is otherwise never exercised. Drive it directly with an
    /// `Idle` codeword (keys under epoch 0) and a PQ counter just over / just under
    /// the bound.
    #[test]
    fn pq_chain_max_skip_bound() {
        // Just over: pq_n - 1 = MAX_SKIP + 1 > chain.n(0) + MAX_SKIP -> fail closed.
        let (_a, mut over) = pair();
        assert!(matches!(
            over.ratchet_receive_key(&Message::idle(1), MAX_SKIP + 2),
            Err(CryptoError::MaxSkipExceeded(_, _))
        ));
        // Just under: pq_n - 1 = MAX_SKIP is exactly the inclusive bound -> accepted.
        let (_b, mut at) = pair();
        assert!(
            at.ratchet_receive_key(&Message::idle(1), MAX_SKIP + 1)
                .is_ok(),
            "skipping exactly MAX_SKIP keys must be accepted"
        );
    }

    /// `add_epoch` must reject a non-consecutive epoch rather than silently skipping
    /// a `KDF_SCKA_RK` reseed (which would desync the SPQR root key across peers).
    #[test]
    fn add_epoch_non_consecutive_fails_closed() {
        let mut s = SpqrState::new_sender(&[1u8; 32]);
        // epoch starts at 0; jumping straight to 2 skips epoch 1's reseed.
        assert!(matches!(
            s.add_epoch(2, &[9u8; 32]),
            Err(CryptoError::BraidKem(_))
        ));
        // The consecutive epoch is accepted.
        assert!(s.add_epoch(1, &[9u8; 32]).is_ok());
    }

    /// A message delayed beyond the two-epoch `ClearOldEpochs` window: once its
    /// epoch's recv chain and skipped keys are evicted it is unrecoverable, but it
    /// must fail closed (clean `Err`), never panic or return a wrong key. This is the
    /// availability cliff that interacts with durable/offline delivery (tracked as a
    /// P2 issue); the contract verified here is "fails closed, recoverable by rekey,"
    /// not "still decrypts."
    ///
    /// The eviction is driven explicitly via `clear_old_epochs` because the receiver
    /// role completes epochs on the *receive* path, where pruning does not currently
    /// run -- exactly the receive-side-growth gap filed as P2. This test pins the
    /// fail-closed contract a sender-role `clear_old_epochs(hepoch + 2)` would create.
    #[test]
    fn delayed_beyond_clear_window_fails_closed() {
        let (mut alice, mut bob) = pair();
        let mut ra = ChaCha20Rng::seed_from_u64(21);
        let mut rb = ChaCha20Rng::seed_from_u64(22);

        // Hold back the first message that keys under a completed epoch (>= 1), and
        // drive the duplex past that epoch so the held epoch is genuinely old.
        let mut held: Option<(Message, u32, u64)> = None;
        for _ in 0..600 {
            let (msg, pqn, _) = alice.ratchet_send_key(&mut ra).unwrap();
            let msg_epoch = msg.epoch.saturating_sub(1);
            if held.is_none() && msg_epoch >= 1 {
                held = Some((msg, pqn, msg_epoch));
            } else {
                bob.ratchet_receive_key(&msg, pqn).unwrap();
            }
            let (msg, pqn, _) = bob.ratchet_send_key(&mut rb).unwrap();
            alice.ratchet_receive_key(&msg, pqn).unwrap();
            if let Some((_, _, hepoch)) = held
                && bob.current_epoch() >= hepoch + 2
            {
                break;
            }
        }
        let (hmsg, hpqn, hepoch) = held.expect("a message must be held");
        assert!(
            bob.current_epoch() >= hepoch + 2,
            "bob must advance at least two epochs past the held message"
        );

        // Evict the held epoch (as a sender-role ClearOldEpochs would), then confirm
        // the delayed message fails closed rather than panicking or returning a key.
        bob.clear_old_epochs(hepoch + 2);
        assert!(
            !bob.kdfchains.contains_key(&hepoch),
            "the held epoch's chain must be evicted"
        );
        assert!(
            bob.ratchet_receive_key(&hmsg, hpqn).is_err(),
            "a message whose epoch chain was cleared must fail closed"
        );
    }

    /// Receive-heavy bound: `ClearOldEpochs` runs only on the send path, so
    /// a peer that receives far more than it sends prunes infrequently. This must NOT
    /// translate into unbounded `kdfchains` growth: a new epoch cannot be minted
    /// without a full bidirectional braid round-trip, so the retained set is bounded by
    /// the send/receive epoch gap (the handshake pipeline depth, a small constant), not
    /// by received-message volume. Drive a heavily asymmetric stream (Bob receives a
    /// burst for every single reply) and assert Bob's retained epoch chains stay small
    /// while the braid still makes epoch progress and every message pairs.
    #[test]
    fn receive_heavy_peer_retained_epochs_stay_bounded() {
        let (mut alice, mut bob) = pair();
        let mut ra = ChaCha20Rng::seed_from_u64(31);
        let mut rb = ChaCha20Rng::seed_from_u64(32);

        // Alice sends this many messages to Bob for each single Bob -> Alice reply.
        const BURST: usize = 8;
        let mut bob_max_chains = 0usize;
        let mut max_epoch = 0u64;

        for _ in 0..80 {
            for _ in 0..BURST {
                let (msg, pqn, mk_a) = alice.ratchet_send_key(&mut ra).unwrap();
                let mk_b = bob.ratchet_receive_key(&msg, pqn).unwrap();
                assert_eq!(
                    mk_a, mk_b,
                    "alice->bob pq_mk must pair under receive-heavy load"
                );
                bob_max_chains = bob_max_chains.max(bob.kdfchains.len());
            }
            // Bob's sole reply per burst -- this is the only place Bob's chains prune.
            let (msg, pqn, mk_b) = bob.ratchet_send_key(&mut rb).unwrap();
            let mk_a = alice.ratchet_receive_key(&msg, pqn).unwrap();
            assert_eq!(mk_b, mk_a, "bob->alice reply pq_mk must pair");
            bob_max_chains = bob_max_chains.max(bob.kdfchains.len());
            max_epoch = max_epoch.max(bob.epoch);
        }

        assert!(
            max_epoch >= 1,
            "the braid must complete at least one epoch for this bound to be meaningful, reached {max_epoch}"
        );
        // The send/receive gap is bounded by the braid handshake depth, independent of
        // the ~640 messages Bob received. A handful of epochs (current + a small lead +
        // the two-behind retention window) is the structural ceiling; a regression that
        // pruned on neither path, or grew per-message, would blow far past this.
        assert!(
            bob_max_chains <= 5,
            "receive-heavy peer retained {bob_max_chains} epoch chains across {} received messages; \
             send-driven pruning must keep this bounded by the epoch gap, not message volume",
            80 * BURST
        );
    }

    // ── Property-based replay / epoch coverage (bolero) ──────────────────────
    //
    // These run as fast `cargo test` unit tests (bolero's ~1s default budget per
    // property) and as libfuzzer targets under `cargo bolero test <name>
    // --engine libfuzzer` (later, Kani under `--engine kani`). Unlike the
    // ratchet-level properties, the SPQR API takes an explicit RNG, so these are
    // seeded deterministically from the input and fully reproducible.
    use bolero::check;

    /// P5: a replayed (already-received) `(epoch, pq_n)` fails closed for any send
    /// sequence — generalizes `replay_fails_closed`.
    #[test]
    fn prop_replay_fails_closed() {
        check!()
            .with_type::<(u64, u8)>()
            .for_each(|(seed, count_raw)| {
                let ss = [0x21u8; 32];
                let mut alice = SpqrState::new_sender(&ss);
                let mut bob = SpqrState::new_receiver(&ss);
                let mut ra = ChaCha20Rng::seed_from_u64(*seed);
                let k = 1 + (*count_raw % 16) as usize;
                let mut sent = Vec::new();
                for _ in 0..k {
                    let (msg, pqn, mk) = alice.ratchet_send_key(&mut ra).unwrap();
                    assert_eq!(bob.ratchet_receive_key(&msg, pqn).unwrap(), mk);
                    sent.push((msg, pqn));
                }
                for (msg, pqn) in &sent {
                    assert!(
                        bob.ratchet_receive_key(msg, *pqn).is_err(),
                        "replay of a consumed PQ message must fail closed"
                    );
                }
            });
    }

    /// P6: out-of-order delivery within a chain pairs every message via the
    /// skipped-key store, for an arbitrary delivery permutation.
    #[test]
    fn prop_out_of_order_pairs() {
        check!()
            .with_type::<(u64, Vec<u8>)>()
            .for_each(|(seed, order)| {
                let ss = [0x37u8; 32];
                let mut alice = SpqrState::new_sender(&ss);
                let mut bob = SpqrState::new_receiver(&ss);
                let mut ra = ChaCha20Rng::seed_from_u64(*seed);
                let k = 2 + (order.len() % 8); // within MAX_SKIP, single epoch
                let msgs: Vec<(Message, u32, MessageKey)> = (0..k)
                    .map(|_| alice.ratchet_send_key(&mut ra).unwrap())
                    .collect();
                let mut idx: Vec<usize> = (0..k).collect();
                for (i, b) in order.iter().enumerate() {
                    idx.swap(i % k, (*b as usize) % k);
                }
                for &i in &idx {
                    assert_eq!(
                        bob.ratchet_receive_key(&msgs[i].0, msgs[i].1).unwrap(),
                        msgs[i].2,
                        "out-of-order delivery must pair"
                    );
                }
            });
    }

    /// P7: a receive-heavy duplex keeps the retained epoch-chain set bounded by
    /// the braid handshake depth, NOT by message volume — generalizes
    /// `receive_heavy_peer_retained_epochs_stay_bounded` to arbitrary burst
    /// schedules. The `<= 8` ceiling (current epoch + a small handshake lead +
    /// the two-behind retention window) is the structural bound; per-message
    /// growth would blow far past it.
    #[test]
    fn prop_retained_epochs_bounded() {
        check!()
            .with_type::<(u64, u64, Vec<u8>)>()
            .for_each(|(sa, sb, sched)| {
                let ss = [0x55u8; 32];
                let mut alice = SpqrState::new_sender(&ss);
                let mut bob = SpqrState::new_receiver(&ss);
                let mut ra = ChaCha20Rng::seed_from_u64(*sa);
                let mut rb = ChaCha20Rng::seed_from_u64(*sb);
                let mut bob_max = 0usize;
                for b in sched.iter().take(48) {
                    let burst = 1 + (*b % 8) as usize;
                    for _ in 0..burst {
                        let (msg, pqn, mk_a) = alice.ratchet_send_key(&mut ra).unwrap();
                        assert_eq!(bob.ratchet_receive_key(&msg, pqn).unwrap(), mk_a);
                        bob_max = bob_max.max(bob.kdfchains.len());
                    }
                    // Bob's single reply per burst is the only place his chains prune.
                    let (msg, pqn, mk_b) = bob.ratchet_send_key(&mut rb).unwrap();
                    assert_eq!(alice.ratchet_receive_key(&msg, pqn).unwrap(), mk_b);
                    bob_max = bob_max.max(bob.kdfchains.len());
                }
                assert!(
                    bob_max <= 8,
                    "retained epoch chains must stay bounded by handshake depth, got {bob_max}"
                );
            });
    }
}
