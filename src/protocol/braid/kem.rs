//! Incremental ML-KEM-768 KEM layer for the Braid.
//!
//! Thin wrapper over `libcrux-ml-kem`'s incremental API (Apache-2.0, pure Rust,
//! formally verified with hax/F*). That API was built by Cryspen at Signal's
//! request specifically for the ML-KEM Braid; it is the same primitive Signal's
//! own SPQR uses. We do NOT fork RustCrypto `ml-kem` or hand-roll K-PKE.
//!
//! The incremental shape maps 1:1 to the `mlkembraid` spec:
//!
//! ```text
//!  Alice (keypair owner)                 Bob (encapsulator)
//!  ─────────────────────                 ──────────────────
//!  kp = generate_keypair(seed)
//!  pk1 = header part  ───────────────▶   (ct1, st, ss) = encapsulate1(pk1, r)
//!  pk2 = ek_vector    ───────────────▶   ct2 = encapsulate2(st, pk2)
//!  ss = decapsulate(kp, ct1, ct2)  ◀───  ct1, ct2
//!  // ss (Alice) == ss (Bob)
//! ```
//!
//! `pk1` carries the seed/header part, so Bob can compute `ct1` (and learn the
//! shared secret) before the full key `pk2` (ek_vector) has finished streaming.
//! All randomness is passed in explicitly, so KAT determinism is free here.

use libcrux_ml_kem::mlkem768::incremental as inc;

use crate::error::{CryptoError, Result};

/// Key-generation seed length (ML-KEM `d || z`).
pub const SEED_LEN: usize = libcrux_ml_kem::KEY_GENERATION_SEED_SIZE;
/// Encapsulation randomness length.
pub const ENCAPS_RANDOMNESS_LEN: usize = 32;
/// Shared-secret length.
pub const SHARED_SECRET_LEN: usize = 32;

const KP_LEN: usize = inc::key_pair_len();
const PK2_LEN: usize = inc::pk2_len();
const STATE_LEN: usize = inc::encaps_state_len();
const CT1_LEN: usize = inc::Ciphertext1::len();
const CT2_LEN: usize = inc::Ciphertext2::len();

fn kem_err(e: impl core::fmt::Debug) -> CryptoError {
    CryptoError::BraidKem(format!("{e:?}"))
}

fn size_err(what: &str) -> CryptoError {
    CryptoError::BraidKem(format!("wrong byte length for {what}"))
}

/// Byte length of `pk1` (the header / ek_seed part).
pub const fn pk1_len() -> usize {
    inc::pk1_len()
}
/// Byte length of `pk2` (the ek_vector part).
pub const fn pk2_len() -> usize {
    PK2_LEN
}
/// Byte length of `ct1` (the early ciphertext part).
pub const fn ct1_len() -> usize {
    CT1_LEN
}
/// Byte length of `ct2` (the late ciphertext part).
pub const fn ct2_len() -> usize {
    CT2_LEN
}

/// Generate Alice's incremental keypair, deterministically, from a 64-byte seed.
/// Returns the serialized keypair bytes (private material) the braid persists.
pub fn generate_keypair(seed: &[u8; SEED_LEN]) -> Vec<u8> {
    inc::KeyPairBytes::from_seed(*seed).to_bytes().to_vec()
}

/// Split a keypair's public material into `pk1` (header part) and `pk2`
/// (ek_vector). `pk1` is sufficient for Bob to produce `ct1`.
pub fn public_key_parts(keypair: &[u8]) -> Result<(Vec<u8>, Vec<u8>)> {
    let kp = <&[u8; KP_LEN]>::try_from(keypair).map_err(|_| size_err("keypair"))?;
    Ok((inc::pk1(kp).to_vec(), inc::pk2(kp).to_vec()))
}

/// Validate that `pk1` and `pk2` are a consistent pair (binds the header to the
/// ek_vector, fail-closed against a transplanted/forged ek_vector).
pub fn validate_public_key(pk1: &[u8], pk2: &[u8]) -> Result<()> {
    inc::validate_pk_bytes(pk1, pk2).map_err(kem_err)
}

/// Bob, phase 1: from `pk1` alone plus 32 bytes of randomness, produce the early
/// ciphertext `ct1`, the carried-forward encapsulation `state`, and the shared
/// secret. Bob learns the shared secret here, before `pk2` arrives.
pub fn encapsulate1(
    pk1: &[u8],
    randomness: &[u8; ENCAPS_RANDOMNESS_LEN],
) -> Result<(Vec<u8>, Vec<u8>, [u8; SHARED_SECRET_LEN])> {
    let mut state = vec![0u8; STATE_LEN];
    let mut shared_secret = [0u8; SHARED_SECRET_LEN];
    let ct1 =
        inc::encapsulate1(pk1, *randomness, &mut state, &mut shared_secret).map_err(kem_err)?;
    Ok((ct1.value.to_vec(), state, shared_secret))
}

/// Bob, phase 2: from the carried `state` and `pk2` (ek_vector), produce the
/// late ciphertext `ct2`.
pub fn encapsulate2(state: &[u8], pk2: &[u8]) -> Result<Vec<u8>> {
    let state = <&[u8; STATE_LEN]>::try_from(state).map_err(|_| size_err("encaps state"))?;
    let pk2 = <&[u8; PK2_LEN]>::try_from(pk2).map_err(|_| size_err("pk2"))?;
    Ok(inc::encapsulate2(state, pk2).value.to_vec())
}

/// Alice: decapsulate the shared secret from her keypair and both ciphertext
/// parts. ML-KEM implicit rejection means a corrupted ciphertext yields a
/// pseudorandom (mismatching) secret rather than an error.
pub fn decapsulate(keypair: &[u8], ct1: &[u8], ct2: &[u8]) -> Result<[u8; SHARED_SECRET_LEN]> {
    let c1 = inc::Ciphertext1 {
        value: <[u8; CT1_LEN]>::try_from(ct1).map_err(|_| size_err("ct1"))?,
    };
    let c2 = inc::Ciphertext2 {
        value: <[u8; CT2_LEN]>::try_from(ct2).map_err(|_| size_err("ct2"))?,
    };
    inc::decapsulate_incremental_key(keypair, &c1, &c2).map_err(kem_err)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn seed() -> [u8; SEED_LEN] {
        let mut s = [0u8; SEED_LEN];
        for (i, b) in s.iter_mut().enumerate() {
            *b = (i as u8).wrapping_mul(7).wrapping_add(1);
        }
        s
    }

    fn randomness() -> [u8; ENCAPS_RANDOMNESS_LEN] {
        [0xAB; ENCAPS_RANDOMNESS_LEN]
    }

    /// The full two-phase braid exchange: both parties derive the same secret.
    #[test]
    fn incremental_roundtrip_agrees() {
        let kp = generate_keypair(&seed());
        let (pk1, pk2) = public_key_parts(&kp).unwrap();
        validate_public_key(&pk1, &pk2).unwrap();

        let (ct1, state, ss_bob) = encapsulate1(&pk1, &randomness()).unwrap();
        let ct2 = encapsulate2(&state, &pk2).unwrap();
        let ss_alice = decapsulate(&kp, &ct1, &ct2).unwrap();

        assert_eq!(ss_alice, ss_bob, "both parties must derive the same secret");
        assert_eq!(ss_alice.len(), SHARED_SECRET_LEN);
    }

    /// Same seed + randomness must reproduce identical bytes (KAT determinism).
    #[test]
    fn deterministic_given_seed_and_randomness() {
        let (pk1a, pk2a) = public_key_parts(&generate_keypair(&seed())).unwrap();
        let (pk1b, pk2b) = public_key_parts(&generate_keypair(&seed())).unwrap();
        assert_eq!(pk1a, pk1b);
        assert_eq!(pk2a, pk2b);

        let (ct1a, _, ssa) = encapsulate1(&pk1a, &randomness()).unwrap();
        let (ct1b, _, ssb) = encapsulate1(&pk1b, &randomness()).unwrap();
        assert_eq!(
            ct1a, ct1b,
            "encapsulate1 must be deterministic in its inputs"
        );
        assert_eq!(ssa, ssb);
    }

    /// ct1 can be produced from pk1 alone (before pk2/ek_vector is available) --
    /// the timing property the whole braid depends on.
    #[test]
    fn ct1_needs_only_pk1() {
        let kp = generate_keypair(&seed());
        let (pk1, _pk2) = public_key_parts(&kp).unwrap();
        // No pk2 used here.
        let (ct1, _state, _ss) = encapsulate1(&pk1, &randomness()).unwrap();
        assert_eq!(ct1.len(), ct1_len());
    }

    /// Sizes match the spec's ML-KEM-768 braid constants (ct1 ~960, ct2 ~128).
    #[test]
    fn component_sizes() {
        let kp = generate_keypair(&seed());
        let (pk1, pk2) = public_key_parts(&kp).unwrap();
        let (ct1, _, _) = encapsulate1(&pk1, &randomness()).unwrap();
        let ct2 = encapsulate2(&encapsulate1(&pk1, &randomness()).unwrap().1, &pk2).unwrap();
        assert_eq!(pk1.len(), pk1_len());
        assert_eq!(pk2.len(), pk2_len());
        assert_eq!(ct1.len(), 960, "ct1 == ML-KEM-768 c1");
        assert_eq!(ct2.len(), 128, "ct2 == ML-KEM-768 c2");
    }

    /// A corrupted ct2 must not yield the genuine secret (implicit rejection).
    #[test]
    fn corrupted_ciphertext_does_not_match() {
        let kp = generate_keypair(&seed());
        let (pk1, pk2) = public_key_parts(&kp).unwrap();
        let (ct1, state, ss_bob) = encapsulate1(&pk1, &randomness()).unwrap();
        let mut ct2 = encapsulate2(&state, &pk2).unwrap();
        ct2[0] ^= 0xFF;
        let ss_alice = decapsulate(&kp, &ct1, &ct2).unwrap();
        assert_ne!(
            ss_alice, ss_bob,
            "tampered ct2 must not decapsulate to the real secret"
        );
    }

    /// Wrong-length inputs are rejected, not panicked.
    #[test]
    fn wrong_lengths_error() {
        assert!(matches!(
            public_key_parts(&[0u8; 8]),
            Err(CryptoError::BraidKem(_))
        ));
        assert!(matches!(
            encapsulate2(&[0u8; 8], &[0u8; 8]),
            Err(CryptoError::BraidKem(_))
        ));
        let kp = generate_keypair(&seed());
        assert!(matches!(
            decapsulate(&kp, &[0u8; 8], &[0u8; 8]),
            Err(CryptoError::BraidKem(_))
        ));
    }
}
