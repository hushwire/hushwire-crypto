//! PQXDH (post-quantum X3DH) key agreement.
//!
//! Combines three or four Curve25519 Diffie-Hellman exchanges with an
//! ML-KEM-1024 encapsulation against the responder's Kyber prekey, then derives
//! a shared secret via HKDF-SHA256. The initiator side processes a published
//! [`PreKeyBundle`]; the responder side processes the resulting
//! [`PqxdhInitialMessage`] to arrive at the same secret.

use ml_kem::{
    Kem, MlKem1024,
    kem::{Decapsulate, Encapsulate, KeyExport},
};
use x25519_dalek::{PublicKey as X25519Public, StaticSecret as X25519Secret};
use zeroize::Zeroize;

use crate::error::{CryptoError, Result};
use crate::primitives::kdf::hkdf_sha256;
use crate::primitives::keys::{EphemeralKeyPair, IdentityKeyPair};
use crate::protocol::prekey::{PqxdhInitialMessage, PreKeyBundle};
use crate::types::{DhPublicKey, RegistrationId};

const PQXDH_INFO: &[u8] = b"HushwireProtocol";

/// Output of PQXDH key agreement: shared secret and initial message for the responder.
pub struct PqxdhOutput {
    /// Derived 32-byte shared secret seeding the session's root key.
    pub shared_secret: [u8; 32],
    /// Message the initiator sends so the responder can derive the same secret.
    pub initial_message: PqxdhInitialMessage,
}

/// Process a prekey bundle as the initiator (Alice).
///
/// Performs the full PQXDH key agreement:
/// 1. Verify Ed25519 signature on signed prekey
/// 2. Verify Ed25519 signature on Kyber prekey
/// 3. DH1 = DH(IKa, SPKb)
/// 4. DH2 = DH(EKa, IKb)
/// 5. DH3 = DH(EKa, SPKb)
/// 6. DH4 = DH(EKa, OPKb) (if present)
/// 7. SS = ML-KEM-1024 encapsulate against Kyber prekey
/// 8. SK = HKDF(0xFF*32 || DH1 || DH2 || DH3 [|| DH4] || SS)
pub fn process_prekey_bundle(
    our_identity: &IdentityKeyPair,
    their_bundle: &PreKeyBundle,
) -> Result<PqxdhOutput> {
    // Verify signed prekey signature
    their_bundle.identity_key.verify(
        their_bundle.signed_pre_key_public.as_bytes(),
        &their_bundle.signed_pre_key_signature,
    )?;

    // Verify Kyber prekey signature
    their_bundle.identity_key.verify(
        &their_bundle.kyber_pre_key.public_key,
        &their_bundle.kyber_pre_key.signature,
    )?;

    let ephemeral = EphemeralKeyPair::generate();
    let our_x25519 = our_identity.x25519_private_key();
    let their_x25519 = their_bundle.identity_key.to_x25519();
    let spk_x25519 = X25519Public::from(their_bundle.signed_pre_key_public.0);

    // DH1 = DH(IKa_x25519, SPKb)
    let dh1 = our_x25519.diffie_hellman(&spk_x25519);

    // DH2 = DH(EKa, IKb_x25519)
    let dh2 = ephemeral.diffie_hellman(&their_x25519);

    // DH3 = DH(EKa, SPKb)
    let dh3 = ephemeral.diffie_hellman(&spk_x25519);

    let mut dh_material = Vec::with_capacity(32 + 32 + 32 + 32 + 32);
    dh_material.extend_from_slice(&[0xFF; 32]); // padding
    dh_material.extend_from_slice(dh1.as_bytes());
    dh_material.extend_from_slice(dh2.as_bytes());
    dh_material.extend_from_slice(dh3.as_bytes());

    // DH4 = DH(EKa, OPKb) if present
    let opk_id = if let Some(ref opk) = their_bundle.one_time_pre_key {
        let opk_x25519 = X25519Public::from(opk.public_key.0);
        let dh4 = ephemeral.diffie_hellman(&opk_x25519);
        dh_material.extend_from_slice(dh4.as_bytes());
        Some(opk.id)
    } else {
        None
    };

    // SS = ML-KEM-1024 encapsulate against Bob's Kyber prekey
    let ek = ek_from_bytes(&their_bundle.kyber_pre_key.public_key)?;
    let (ct, ss) = ek.encapsulate();
    let ct_bytes: Vec<u8> = AsRef::<[u8]>::as_ref(&ct).to_vec();
    dh_material.extend_from_slice(ss.as_ref());

    let salt = [0u8; 32];
    let mut sk_vec = hkdf_sha256(&dh_material, Some(&salt), PQXDH_INFO, 32);
    dh_material.zeroize();

    let mut shared_secret = [0u8; 32];
    shared_secret.copy_from_slice(&sk_vec);
    sk_vec.zeroize();

    let initial_message = PqxdhInitialMessage {
        registration_id: RegistrationId(0), // set by caller
        ephemeral_public_key: DhPublicKey::from(ephemeral.public_key_bytes()),
        signed_pre_key_id: their_bundle.signed_pre_key_id,
        one_time_pre_key_id: opk_id,
        kyber_pre_key_id: their_bundle.kyber_pre_key.id,
        kyber_ciphertext: ct_bytes,
        identity_key: our_identity.public_key(),
    };

    Ok(PqxdhOutput {
        shared_secret,
        initial_message,
    })
}

/// Process an initial message as the responder (Bob).
///
/// Takes Bob's keys and Alice's initial message, produces the same shared secret.
pub fn process_initial_message(
    our_identity: &IdentityKeyPair,
    signed_pre_key_private: &[u8; 32],
    one_time_pre_key_private: Option<&[u8; 32]>,
    kyber_decapsulation_key: &ml_kem::DecapsulationKey<MlKem1024>,
    initial_message: &PqxdhInitialMessage,
) -> Result<[u8; 32]> {
    let our_x25519 = our_identity.x25519_private_key();
    let their_x25519 = initial_message.identity_key.to_x25519();
    let ek_x25519 = X25519Public::from(initial_message.ephemeral_public_key.0);
    let spk_secret = X25519Secret::from(*signed_pre_key_private);

    // DH1 = DH(SPKb, IKa_x25519)
    let dh1 = spk_secret.diffie_hellman(&their_x25519);

    // DH2 = DH(IKb_x25519, EKa)
    let dh2 = our_x25519.diffie_hellman(&ek_x25519);

    // DH3 = DH(SPKb, EKa)
    let dh3 = spk_secret.diffie_hellman(&ek_x25519);

    let mut dh_material = Vec::with_capacity(32 + 32 + 32 + 32 + 32);
    dh_material.extend_from_slice(&[0xFF; 32]);
    dh_material.extend_from_slice(dh1.as_bytes());
    dh_material.extend_from_slice(dh2.as_bytes());
    dh_material.extend_from_slice(dh3.as_bytes());

    // DH4 = DH(OPKb, EKa) if OPK was used
    if initial_message.one_time_pre_key_id.is_some() {
        let opk_private = one_time_pre_key_private.ok_or_else(|| {
            CryptoError::InvalidPrekeyBundle("missing one-time prekey private".into())
        })?;
        let opk_secret = X25519Secret::from(*opk_private);
        let dh4 = opk_secret.diffie_hellman(&ek_x25519);
        dh_material.extend_from_slice(dh4.as_bytes());
    }

    // ML-KEM-1024 decapsulation
    let ct = ml_kem::Ciphertext::<MlKem1024>::try_from(initial_message.kyber_ciphertext.as_slice())
        .map_err(|_| CryptoError::InvalidCiphertext)?;

    let ss = kyber_decapsulation_key.decapsulate(&ct);
    dh_material.extend_from_slice(ss.as_ref());

    let salt = [0u8; 32];
    let mut sk_vec = hkdf_sha256(&dh_material, Some(&salt), PQXDH_INFO, 32);
    dh_material.zeroize();

    let mut shared_secret = [0u8; 32];
    shared_secret.copy_from_slice(&sk_vec);
    sk_vec.zeroize();

    Ok(shared_secret)
}

/// Deserialize an ML-KEM-1024 encapsulation key from bytes.
fn ek_from_bytes(bytes: &[u8]) -> Result<ml_kem::EncapsulationKey<MlKem1024>> {
    use ml_kem::kem::Key;
    type EK = ml_kem::EncapsulationKey<MlKem1024>;
    let key_array: &Key<EK> = <&Key<EK>>::try_from(bytes)
        .map_err(|_| CryptoError::InvalidPrekeyBundle("wrong ML-KEM-1024 key length".into()))?;
    EK::new(key_array)
        .map_err(|_| CryptoError::InvalidPrekeyBundle("invalid ML-KEM-1024 public key".into()))
}

/// Generate an ML-KEM-1024 keypair for PQXDH prekeys.
pub fn generate_kyber_keypair() -> (ml_kem::DecapsulationKey<MlKem1024>, Vec<u8>) {
    let (dk, ek) = MlKem1024::generate_keypair();
    let ek_bytes: Vec<u8> = ek.to_bytes().to_vec();
    (dk, ek_bytes)
}

/// Extract the 64-byte seed from an ML-KEM-1024 decapsulation key for storage.
pub fn dk_to_seed_bytes(dk: &ml_kem::DecapsulationKey<MlKem1024>) -> [u8; 64] {
    let seed = dk.to_seed().expect("ML-KEM-1024 key generated from seed");
    let mut out = [0u8; 64];
    out.copy_from_slice(seed.as_slice());
    out
}

/// Reconstruct an ML-KEM-1024 decapsulation key from its 64-byte seed.
pub fn dk_from_seed_bytes(seed_bytes: &[u8; 64]) -> ml_kem::DecapsulationKey<MlKem1024> {
    let seed = ml_kem::Seed::from(*seed_bytes);
    ml_kem::DecapsulationKey::<MlKem1024>::from_seed(seed)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::primitives::keys::IdentityKeyPair;
    use crate::protocol::prekey::{KyberPreKey, OneTimePreKey, PreKeyBundle};
    use crate::types::{DeviceId, KyberPreKeyId, PreKeyId, SignedPreKeyId};
    use rand::RngExt as _;

    fn make_signed_prekey(identity: &IdentityKeyPair) -> ([u8; 32], [u8; 32], Vec<u8>) {
        let mut private_bytes = [0u8; 32];
        rand::rng().fill(&mut private_bytes[..]);
        let secret = X25519Secret::from(private_bytes);
        let public = X25519Public::from(&secret);
        let public_bytes = public.to_bytes();
        let signature = identity.sign(&public_bytes);
        (private_bytes, public_bytes, signature)
    }

    fn make_one_time_prekey() -> ([u8; 32], [u8; 32]) {
        let mut private_bytes = [0u8; 32];
        rand::rng().fill(&mut private_bytes[..]);
        let secret = X25519Secret::from(private_bytes);
        let public = X25519Public::from(&secret);
        (private_bytes, public.to_bytes())
    }

    fn make_bundle(
        bob_identity: &IdentityKeyPair,
        with_opk: bool,
    ) -> (
        PreKeyBundle,
        [u8; 32],
        Option<[u8; 32]>,
        ml_kem::DecapsulationKey<MlKem1024>,
    ) {
        let (spk_private, spk_public, spk_sig) = make_signed_prekey(bob_identity);

        let (opk_private, opk) = if with_opk {
            let (priv_bytes, pub_bytes) = make_one_time_prekey();
            (
                Some(priv_bytes),
                Some(OneTimePreKey {
                    id: PreKeyId::from(1),
                    public_key: DhPublicKey::from(pub_bytes),
                }),
            )
        } else {
            (None, None)
        };

        let (dk, ek_bytes) = generate_kyber_keypair();
        let kyber_sig = bob_identity.sign(&ek_bytes);

        let bundle = PreKeyBundle {
            registration_id: RegistrationId::from(100),
            device_id: DeviceId::from(1),
            identity_key: bob_identity.public_key(),
            signed_pre_key_id: SignedPreKeyId::from(5),
            signed_pre_key_public: DhPublicKey::from(spk_public),
            signed_pre_key_signature: spk_sig,
            one_time_pre_key: opk,
            kyber_pre_key: KyberPreKey {
                id: KyberPreKeyId::from(10),
                public_key: ek_bytes,
                signature: kyber_sig,
                is_last_resort: !with_opk,
            },
        };

        (bundle, spk_private, opk_private, dk)
    }

    #[test]
    fn pqxdh_handshake_with_opk() {
        let alice = IdentityKeyPair::generate();
        let bob = IdentityKeyPair::generate();

        let (bundle, spk_private, opk_private, dk) = make_bundle(&bob, true);

        let output = process_prekey_bundle(&alice, &bundle).unwrap();

        let bob_secret = process_initial_message(
            &bob,
            &spk_private,
            opk_private.as_ref(),
            &dk,
            &output.initial_message,
        )
        .unwrap();

        assert_eq!(output.shared_secret, bob_secret);
    }

    #[test]
    fn pqxdh_handshake_without_opk() {
        let alice = IdentityKeyPair::generate();
        let bob = IdentityKeyPair::generate();

        let (bundle, spk_private, _, dk) = make_bundle(&bob, false);

        let output = process_prekey_bundle(&alice, &bundle).unwrap();

        let bob_secret =
            process_initial_message(&bob, &spk_private, None, &dk, &output.initial_message)
                .unwrap();

        assert_eq!(output.shared_secret, bob_secret);
    }

    #[test]
    fn pqxdh_different_sessions_different_secrets() {
        let alice = IdentityKeyPair::generate();
        let bob = IdentityKeyPair::generate();

        let (bundle1, _, _, _) = make_bundle(&bob, true);
        let (bundle2, _, _, _) = make_bundle(&bob, true);

        let out1 = process_prekey_bundle(&alice, &bundle1).unwrap();
        let out2 = process_prekey_bundle(&alice, &bundle2).unwrap();

        assert_ne!(out1.shared_secret, out2.shared_secret);
    }

    #[test]
    fn pqxdh_invalid_spk_signature_rejected() {
        let alice = IdentityKeyPair::generate();
        let bob = IdentityKeyPair::generate();

        let (mut bundle, _, _, _) = make_bundle(&bob, true);
        bundle.signed_pre_key_signature = vec![0u8; 64];

        assert!(process_prekey_bundle(&alice, &bundle).is_err());
    }

    #[test]
    fn pqxdh_invalid_kyber_signature_rejected() {
        let alice = IdentityKeyPair::generate();
        let bob = IdentityKeyPair::generate();

        let (mut bundle, _, _, _) = make_bundle(&bob, true);
        bundle.kyber_pre_key.signature = vec![0u8; 64];

        assert!(process_prekey_bundle(&alice, &bundle).is_err());
    }

    #[test]
    fn pqxdh_wrong_identity_key_rejected() {
        let alice = IdentityKeyPair::generate();
        let bob = IdentityKeyPair::generate();
        let eve = IdentityKeyPair::generate();

        let (mut bundle, _, _, _) = make_bundle(&bob, true);
        bundle.identity_key = eve.public_key();

        assert!(process_prekey_bundle(&alice, &bundle).is_err());
    }

    #[test]
    fn pqxdh_initial_message_contains_alice_identity() {
        let alice = IdentityKeyPair::generate();
        let bob = IdentityKeyPair::generate();

        let (bundle, _, _, _) = make_bundle(&bob, true);
        let output = process_prekey_bundle(&alice, &bundle).unwrap();

        assert_eq!(output.initial_message.identity_key, alice.public_key());
    }

    #[test]
    fn pqxdh_initial_message_references_correct_prekey_ids() {
        let alice = IdentityKeyPair::generate();
        let bob = IdentityKeyPair::generate();

        let (bundle, _, _, _) = make_bundle(&bob, true);
        let output = process_prekey_bundle(&alice, &bundle).unwrap();

        assert_eq!(
            output.initial_message.signed_pre_key_id,
            SignedPreKeyId::from(5)
        );
        assert_eq!(
            output.initial_message.one_time_pre_key_id,
            Some(PreKeyId::from(1))
        );
        assert_eq!(
            output.initial_message.kyber_pre_key_id,
            KyberPreKeyId::from(10)
        );
    }

    #[test]
    fn generate_kyber_keypair_produces_valid_keys() {
        let (dk, ek_bytes) = generate_kyber_keypair();
        assert_eq!(ek_bytes.len(), 1568); // ML-KEM-1024 encapsulation key size

        let ek = ek_from_bytes(&ek_bytes).unwrap();
        let (ct, k_send) = ek.encapsulate();
        let k_recv = dk.decapsulate(&ct);
        assert_eq!(k_send, k_recv);
    }
}
