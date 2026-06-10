//! Key derivation functions for the Double Ratchet and the Sparse Post-Quantum
//! Ratchet (SPQR) / Triple Ratchet hybrid combiner.
//!
//! All KDFs are HKDF-SHA256 or HMAC-SHA256 instantiations of the Signal Double
//! Ratchet spec. The SPQR/Triple Ratchet `info` strings are frozen
//! domain-separation inputs pinned by known-answer tests.

use hkdf::Hkdf;
use hmac::{Hmac, Mac};
use sha2::Sha256;
use zeroize::Zeroize;

use crate::types::{ChainKey, MessageKey, RootKey};

/// Output of KDF_RK: new root key and chain key.
pub struct RootKeyOutput {
    /// New root key for the next ratchet step.
    pub root_key: RootKey,
    /// New sending or receiving chain key.
    pub chain_key: ChainKey,
}

/// Output of KDF_CK: new chain key and message key.
pub struct ChainKeyOutput {
    /// Advanced chain key for the next message.
    pub chain_key: ChainKey,
    /// Per-message key for this step.
    pub message_key: MessageKey,
}

/// KDF_RK: Root key derivation function.
///
/// Takes the current root key and DH output, produces a new root key
/// and chain key via HKDF-SHA256.
///
/// `dh_output` may be 32 bytes (X25519 only) or 64 bytes (X25519 || ML-KEM)
/// when the continuous PQ ratchet is active. HKDF's extraction step handles
/// variable-length inputs safely.
pub fn kdf_rk(root_key: &RootKey, dh_output: &[u8]) -> RootKeyOutput {
    let hk = Hkdf::<Sha256>::new(Some(root_key.as_bytes()), dh_output);

    let mut okm = [0u8; 64];
    hk.expand(b"HushwireRatchet", &mut okm)
        .expect("64 bytes is valid HKDF-SHA256 output");

    let mut root = [0u8; 32];
    let mut chain = [0u8; 32];
    root.copy_from_slice(&okm[..32]);
    chain.copy_from_slice(&okm[32..64]);
    okm.zeroize();

    RootKeyOutput {
        root_key: RootKey(root),
        chain_key: ChainKey(chain),
    }
}

/// KDF_CK: Chain key derivation function.
///
/// Uses HMAC-SHA256 to derive a message key and advance the chain.
/// - Message key = HMAC-SHA256(ck, 0x01)
/// - New chain key = HMAC-SHA256(ck, 0x02)
pub fn kdf_ck(chain_key: &ChainKey) -> ChainKeyOutput {
    let mut mac_msg =
        Hmac::<Sha256>::new_from_slice(chain_key.as_bytes()).expect("HMAC accepts any key length");
    mac_msg.update(&[0x01]);
    let message_key: [u8; 32] = mac_msg.finalize().into_bytes().into();

    let mut mac_chain =
        Hmac::<Sha256>::new_from_slice(chain_key.as_bytes()).expect("HMAC accepts any key length");
    mac_chain.update(&[0x02]);
    let new_chain_key: [u8; 32] = mac_chain.finalize().into_bytes().into();

    ChainKeyOutput {
        chain_key: ChainKey(new_chain_key),
        message_key: MessageKey(message_key),
    }
}

/// General-purpose HKDF-SHA256 expand.
///
/// # Panics
///
/// Panics if `output_len > 255 * 32` (8160 bytes), the maximum for HKDF-SHA256.
pub fn hkdf_sha256(ikm: &[u8], salt: Option<&[u8]>, info: &[u8], output_len: usize) -> Vec<u8> {
    let hk = Hkdf::<Sha256>::new(salt, ikm);
    let mut okm = vec![0u8; output_len];
    hk.expand(info, &mut okm)
        .expect("requested HKDF output length is valid");
    okm
}

// ── SPQR / Triple Ratchet KDFs (Signal Double Ratchet spec §5.2, §6.3, §7.2) ──
//
// These instantiate the spec's application-defined KDFs for the Sparse Post-Quantum
// Ratchet (SPQR) and the Triple Ratchet hybrid combiner. `SPQR_PROTOCOL_INFO` and
// `TR_PROTOCOL_INFO` are the spec's "unique constant specifying the protocol in use";
// Hushwire picks its own values (it never wire-interoperates with Signal's deployment).

/// Spec `SPQR_PROTOCOL_INFO` (application-defined).
const SPQR_PROTOCOL_INFO: &[u8] = b"HushwireSPQR";
/// Spec `TR_PROTOCOL_INFO` (application-defined).
const TR_PROTOCOL_INFO: &[u8] = b"HushwireTripleRatchet";

/// Output of `KDF_SCKA_INIT` / `KDF_SCKA_RK`: a root key and the two chain keys.
///
/// The chain keys are returned in spec order `(CKs, CKr)` from the A2B party's
/// perspective. The caller assigns send/receive by `direction`: A2B uses
/// `(send, receive) = (chain_key_0, chain_key_1)`; B2A swaps to
/// `(chain_key_1, chain_key_0)`. This pairs Alice's send chain with Bob's receive
/// chain (and vice versa).
pub struct SckaChains {
    /// SPQR root key for the current epoch.
    pub root_key: RootKey,
    /// First chain key in spec order (`CKs` from the A2B perspective).
    pub chain_key_0: ChainKey,
    /// Second chain key in spec order (`CKr` from the A2B perspective).
    pub chain_key_1: ChainKey,
}

fn split_scka_chains(okm: &[u8]) -> SckaChains {
    let mut rk = [0u8; 32];
    let mut ck0 = [0u8; 32];
    let mut ck1 = [0u8; 32];
    rk.copy_from_slice(&okm[..32]);
    ck0.copy_from_slice(&okm[32..64]);
    ck1.copy_from_slice(&okm[64..96]);
    SckaChains {
        root_key: RootKey(rk),
        chain_key_0: ChainKey(ck0),
        chain_key_1: ChainKey(ck1),
    }
}

/// `KDF_SCKA_INIT(sk)` (spec §7.2): bootstrap the SPQR root key and the epoch-0
/// send/receive chains from the SPQR session key.
///
/// HKDF: `salt = zero-filled 32 bytes`, `ikm = sk`,
/// `info = SPQR_PROTOCOL_INFO || "Chain Start"`, `length = 96`.
pub fn kdf_scka_init(sk: &[u8; 32]) -> SckaChains {
    let mut info = Vec::with_capacity(SPQR_PROTOCOL_INFO.len() + 11);
    info.extend_from_slice(SPQR_PROTOCOL_INFO);
    info.extend_from_slice(b"Chain Start");
    let mut okm = hkdf_sha256(sk, Some(&[0u8; 32]), &info, 96);
    let out = split_scka_chains(&okm);
    okm.zeroize();
    out
}

/// `KDF_SCKA_RK(rk, scka_output)` (spec §5.2, §7.2): reseed the SPQR root key and
/// mint fresh send/receive chains when a braid epoch completes.
///
/// HKDF: `salt = rk`, `ikm = scka_output`,
/// `info = SPQR_PROTOCOL_INFO || "Chain Add Epoch"`, `length = 96`.
pub fn kdf_scka_rk(rk: &RootKey, scka_output: &[u8; 32]) -> SckaChains {
    let mut info = Vec::with_capacity(SPQR_PROTOCOL_INFO.len() + 15);
    info.extend_from_slice(SPQR_PROTOCOL_INFO);
    info.extend_from_slice(b"Chain Add Epoch");
    let mut okm = hkdf_sha256(scka_output, Some(rk.as_bytes()), &info, 96);
    let out = split_scka_chains(&okm);
    okm.zeroize();
    out
}

/// `KDF_SCKA_CK(ck, ctr)`: advance one SPQR per-message chain, returning the next chain
/// key and this message's key.
///
/// We follow the spec's **normative §5.2 definition** — "keyed by the chain key `ck` to
/// `ctr` concatenated with some unique constant" → `(chain_key, message_key)` — instantiated
/// as HKDF `salt = ck`, `ikm = ctr` (big-endian u32),
/// `info = SPQR_PROTOCOL_INFO || ":Chain Step"`, `length = 64`. This mirrors the exact
/// keyed-by/applied-to → salt/ikm mapping the spec uses for `KDF_SCKA_RK`.
///
/// NOTE: the spec's §7.2 *recommended* HKDF parameters for `KDF_SCKA_CK` are an apparent
/// editorial error — they are copied verbatim from `KDF_SCKA_INIT` (`salt = zero32`,
/// `ikm = sk`, `info = ... "Chain Start"`), which references `sk` (not a parameter here) and
/// ignores both `ck` and `ctr`. Taken literally that is not a forward-secure chain step, so
/// we deviate from the §7.2 typo and implement the §5.2 definition instead. (Tracked in
/// `docs/signal-spec-divergence.md`.)
///
/// The `info` tag `":Chain Step"` deliberately carries a leading colon where
/// `KDF_SCKA_INIT`/`KDF_SCKA_RK` use `"Chain Start"`/`"Chain Add Epoch"` without one.
/// These exact bytes are frozen domain-separation inputs (pinned by the KAT tests
/// below); do NOT "normalize" the punctuation — changing any byte changes every
/// derived key.
pub fn kdf_scka_ck(ck: &ChainKey, ctr: u32) -> ChainKeyOutput {
    let mut info = Vec::with_capacity(SPQR_PROTOCOL_INFO.len() + 11);
    info.extend_from_slice(SPQR_PROTOCOL_INFO);
    info.extend_from_slice(b":Chain Step");
    let mut okm = hkdf_sha256(&ctr.to_be_bytes(), Some(ck.as_bytes()), &info, 64);
    let mut chain = [0u8; 32];
    let mut msg = [0u8; 32];
    chain.copy_from_slice(&okm[..32]);
    msg.copy_from_slice(&okm[32..64]);
    okm.zeroize();
    ChainKeyOutput {
        chain_key: ChainKey(chain),
        message_key: MessageKey(msg),
    }
}

/// `KDF_HYBRID(ec_mk, pq_mk)` (spec §6.3, §7.2): combine the EC Double Ratchet message
/// key with the SPQR per-message key into the AEAD message key, for every message.
///
/// HKDF: `salt = pq_mk`, `ikm = ec_mk`, `info = TR_PROTOCOL_INFO`, `length = 32`.
pub fn kdf_hybrid(ec_mk: &MessageKey, pq_mk: &[u8; 32]) -> MessageKey {
    let mut okm = hkdf_sha256(ec_mk.as_bytes(), Some(pq_mk), TR_PROTOCOL_INFO, 32);
    let mut out = [0u8; 32];
    out.copy_from_slice(&okm);
    okm.zeroize();
    MessageKey(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn kdf_rk_produces_distinct_outputs() {
        let rk = RootKey::from([1u8; 32]);
        let dh = [2u8; 32];
        let out = kdf_rk(&rk, &dh);

        assert_ne!(*out.root_key.as_bytes(), *out.chain_key.as_bytes());
    }

    #[test]
    fn kdf_rk_deterministic() {
        let rk = RootKey::from([1u8; 32]);
        let dh = [2u8; 32];
        let out1 = kdf_rk(&rk, &dh);
        let out2 = kdf_rk(&rk, &dh);

        assert_eq!(out1.root_key, out2.root_key);
        assert_eq!(out1.chain_key, out2.chain_key);
    }

    #[test]
    fn kdf_rk_different_inputs_different_outputs() {
        let rk = RootKey::from([1u8; 32]);
        let out1 = kdf_rk(&rk, &[2u8; 32]);
        let out2 = kdf_rk(&rk, &[3u8; 32]);

        assert_ne!(out1.root_key, out2.root_key);
        assert_ne!(out1.chain_key, out2.chain_key);
    }

    #[test]
    fn kdf_rk_accepts_64_byte_input() {
        let rk = RootKey::from([1u8; 32]);
        let combined = [2u8; 64]; // X25519 (32) + ML-KEM (32)
        let out = kdf_rk(&rk, &combined);
        assert_ne!(*out.root_key.as_bytes(), [0u8; 32]);
    }

    #[test]
    fn kdf_ck_produces_distinct_keys() {
        let ck = ChainKey::from([1u8; 32]);
        let out = kdf_ck(&ck);

        assert_ne!(*out.chain_key.as_bytes(), *out.message_key.as_bytes());
        assert_ne!(out.chain_key, ck);
    }

    #[test]
    fn kdf_ck_deterministic() {
        let ck = ChainKey::from([1u8; 32]);
        let out1 = kdf_ck(&ck);
        let out2 = kdf_ck(&ck);

        assert_eq!(out1.chain_key, out2.chain_key);
        assert_eq!(out1.message_key, out2.message_key);
    }

    #[test]
    fn kdf_ck_chain_advances() {
        let ck = ChainKey::from([1u8; 32]);
        let step1 = kdf_ck(&ck);
        let step2 = kdf_ck(&step1.chain_key);

        assert_ne!(step1.message_key, step2.message_key);
        assert_ne!(step1.chain_key, step2.chain_key);
    }

    #[test]
    fn hkdf_sha256_basic() {
        let ikm = [1u8; 32];
        let out = hkdf_sha256(&ikm, None, b"test", 64);
        assert_eq!(out.len(), 64);
        assert_ne!(&out[..32], &out[32..]);
    }

    #[test]
    fn hkdf_sha256_with_salt() {
        let ikm = [1u8; 32];
        let salt = [2u8; 32];
        let out1 = hkdf_sha256(&ikm, Some(&salt), b"test", 32);
        let out2 = hkdf_sha256(&ikm, None, b"test", 32);
        assert_ne!(out1, out2);
    }

    // ── SPQR / Triple Ratchet KDFs ──

    #[test]
    fn kdf_scka_init_deterministic_and_distinct() {
        let sk = [7u8; 32];
        let a = kdf_scka_init(&sk);
        let b = kdf_scka_init(&sk);
        assert_eq!(a.root_key, b.root_key);
        assert_eq!(a.chain_key_0, b.chain_key_0);
        assert_eq!(a.chain_key_1, b.chain_key_1);
        // root key and the two chain keys are mutually distinct.
        assert_ne!(*a.root_key.as_bytes(), *a.chain_key_0.as_bytes());
        assert_ne!(*a.root_key.as_bytes(), *a.chain_key_1.as_bytes());
        assert_ne!(a.chain_key_0, a.chain_key_1);
        // different session key -> different chains.
        let c = kdf_scka_init(&[8u8; 32]);
        assert_ne!(a.chain_key_0, c.chain_key_0);
    }

    #[test]
    fn init_direction_convention_pairs_send_and_receive() {
        // Both peers derive the same (ck0, ck1) from the shared SPQR key. Under the
        // A2B/B2A swap, Alice's send chain equals Bob's receive chain and vice versa.
        let sk = [0x21u8; 32];
        let c = kdf_scka_init(&sk);
        // A2B (Alice): send = ck0, recv = ck1. B2A (Bob): send = ck1, recv = ck0.
        let (alice_send, alice_recv) = (&c.chain_key_0, &c.chain_key_1);
        let (bob_send, bob_recv) = (&c.chain_key_1, &c.chain_key_0);
        assert_eq!(
            alice_send, bob_recv,
            "Alice send must pair with Bob receive"
        );
        assert_eq!(
            alice_recv, bob_send,
            "Alice receive must pair with Bob send"
        );
    }

    #[test]
    fn kdf_scka_rk_deterministic_and_input_dependent() {
        let rk = RootKey::from([1u8; 32]);
        let key = [2u8; 32];
        let a = kdf_scka_rk(&rk, &key);
        let b = kdf_scka_rk(&rk, &key);
        assert_eq!(a.root_key, b.root_key);
        assert_eq!(a.chain_key_0, b.chain_key_0);
        // depends on both the root key and the epoch secret.
        assert_ne!(
            a.root_key,
            kdf_scka_rk(&RootKey::from([9u8; 32]), &key).root_key
        );
        assert_ne!(a.chain_key_0, kdf_scka_rk(&rk, &[3u8; 32]).chain_key_0);
    }

    #[test]
    fn kdf_scka_ck_advances_and_binds_counter() {
        let ck = ChainKey::from([5u8; 32]);
        let s1 = kdf_scka_ck(&ck, 1);
        let s1b = kdf_scka_ck(&ck, 1);
        assert_eq!(s1.chain_key, s1b.chain_key);
        assert_eq!(s1.message_key, s1b.message_key);
        // chain key and message key are distinct; counter is bound into the KDF.
        assert_ne!(*s1.chain_key.as_bytes(), *s1.message_key.as_bytes());
        let s2 = kdf_scka_ck(&ck, 2);
        assert_ne!(
            s1.message_key, s2.message_key,
            "different ctr -> different mk"
        );
        assert_ne!(s1.chain_key, s2.chain_key);
    }

    #[test]
    fn kdf_hybrid_deterministic_depends_on_both_and_is_ordered() {
        let ec = MessageKey::from([1u8; 32]);
        let pq = [2u8; 32];
        let h = kdf_hybrid(&ec, &pq);
        assert_eq!(h, kdf_hybrid(&ec, &pq));
        // depends on both inputs.
        assert_ne!(h, kdf_hybrid(&MessageKey::from([9u8; 32]), &pq));
        assert_ne!(h, kdf_hybrid(&ec, &[9u8; 32]));
        // ec_mk (ikm) and pq_mk (salt) are not interchangeable.
        let swapped = kdf_hybrid(&MessageKey::from(pq), ec.as_bytes());
        assert_ne!(h, swapped, "ec/pq orientation must matter");
    }

    fn hx(b: &[u8]) -> String {
        b.iter().map(|x| format!("{x:02x}")).collect()
    }

    /// Known-answer tests pinning the exact derived bytes for fixed inputs. Self-
    /// consistency tests above prove the KDFs are deterministic and input-dependent;
    /// these freeze the precise output so a silent change to an `info` string, the
    /// salt/ikm orientation, or the HKDF output length is caught (it would otherwise
    /// pass every self-consistency test while breaking interop and stored sessions).
    /// Regenerate ONLY with an intentional, version-bumped wire/KDF change.
    #[test]
    fn kdf_scka_init_known_answer() {
        let c = kdf_scka_init(&[7u8; 32]);
        assert_eq!(
            hx(c.root_key.as_bytes()),
            "2f9ca0469f15057ab84d67ef49ffc9b078c1743cca1738693ced4e61c8cd2832"
        );
        assert_eq!(
            hx(c.chain_key_0.as_bytes()),
            "739d16ad7acc088f7032547a71f7095e355944d6902c7e4212c1e15f17125cd1"
        );
        assert_eq!(
            hx(c.chain_key_1.as_bytes()),
            "4e775e707607ea7fe642828bf9a4dc09c0d8391d4edb28308c988bfa559a904d"
        );
    }

    #[test]
    fn kdf_scka_rk_known_answer() {
        let c = kdf_scka_rk(&RootKey::from([1u8; 32]), &[2u8; 32]);
        assert_eq!(
            hx(c.root_key.as_bytes()),
            "5628edb2d1a480393b7b1d22e978506cb4f13ea91c6e81dce5a60ef5d54c0ddd"
        );
        assert_eq!(
            hx(c.chain_key_0.as_bytes()),
            "31b371e7f1055177a95c15aa1c6d798ebbe0d4abc429e295ba4f4edaefe09139"
        );
        assert_eq!(
            hx(c.chain_key_1.as_bytes()),
            "19ffc5bce519c19038e8c4b566007fbd92322cb3e891c551e6d1f3e464ce1b24"
        );
    }

    #[test]
    fn kdf_scka_ck_known_answer() {
        let out = kdf_scka_ck(&ChainKey::from([5u8; 32]), 1);
        assert_eq!(
            hx(out.chain_key.as_bytes()),
            "d5be4741d53a1cd5b8615c7b481d5c18df293767d4b61867af5ecf7919e5c857"
        );
        assert_eq!(
            hx(out.message_key.as_bytes()),
            "3deb71e6c21caad1d916c2adb00178e8ffdffa7b374d06709c98ff0730005112"
        );
    }

    #[test]
    fn kdf_hybrid_known_answer() {
        let h = kdf_hybrid(&MessageKey::from([1u8; 32]), &[2u8; 32]);
        assert_eq!(
            hx(h.as_bytes()),
            "d54d1bc81af8b93b3dde9fca7ba71050d49279ff879cfba2350a45a4993a4508"
        );
    }
}
