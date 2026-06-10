//! Group messaging via Signal sender keys.
//!
//! Each member maintains a `SenderKeyState` (a hash-ratcheted chain key) and
//! shares it once through a [`SenderKeyDistributionMessage`] over an
//! authenticated pairwise channel. Group messages then encrypt under
//! per-message keys derived from the chain key. Per-message authentication is
//! either Ed25519 signatures ([`SenderKeyAuth::Signed`], text/group, unforgeable
//! within the group) or HMAC-SHA256 ([`SenderKeyAuth::Hmac`], voice frames).

pub mod distribution;

use hmac::{Hmac, Mac};
use rand::RngExt as _;
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use subtle::ConstantTimeEq;

use crate::error::{CryptoError, Result};
use crate::primitives::keys::{IdentityKeyPair, IdentityPublicKey};

use self::distribution::SenderKeyDistributionMessage;

/// Per-message authentication mode for a sender key chain.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum SenderKeyAuth {
    /// HMAC-SHA256 authentication. The auth key is derived from the chain key,
    /// so any group member holding the chain key can forge messages. Deniable
    /// but forgeable within the group. Retained **only** for voice frames,
    /// where a per-frame Ed25519 signature (64 bytes + a sign/verify at ~50 fps)
    /// would be prohibitively expensive and the voice transport layer already
    /// authenticates the source. Transitional, pending the dedicated voice-frame
    /// crypto scheme.
    Hmac,
    /// Ed25519 per-message signatures, mirroring Signal. Each message is signed
    /// with a per-sender-key private signing key that never leaves the sender,
    /// so **no group member can forge another member's messages**. Used for
    /// text/group messages.
    Signed,
}

/// Sender key state for a group member.
///
/// Authentication depends on `auth_mode`:
/// - `Signed` (text/group): each message carries an Ed25519 signature produced
///   with the per-sender-key signing key in `signing_private`. Receivers verify
///   with `signing_public`, distributed in the `SenderKeyDistributionMessage`.
///   No group member can forge another member's messages. Mirrors Signal.
/// - `Hmac` (voice): each message carries an HMAC-SHA256 tag derived from the
///   chain key. Forgeable within the group; see [`SenderKeyAuth::Hmac`].
#[derive(Clone, Serialize, Deserialize)]
pub struct SenderKeyState {
    chain_key: [u8; 32],
    iteration: u32,
    is_sender: bool,
    // Fail-closed defaults so any state persisted before per-message signatures
    // existed deserializes as `Signed` with no keys -- it cannot sign or verify,
    // so it routes through rekey rather than silently degrading to forgeable HMAC.
    #[serde(default = "default_auth_mode")]
    auth_mode: SenderKeyAuth,
    /// Ed25519 public signing key (`Signed` mode). Held by senders and receivers.
    #[serde(default)]
    signing_public: Option<[u8; 32]>,
    /// Ed25519 private signing seed (`Signed` mode, sender only).
    #[serde(default)]
    signing_private: Option<[u8; 32]>,
    #[serde(default)]
    skipped_message_keys: Vec<(u32, [u8; 32])>,
}

fn default_auth_mode() -> SenderKeyAuth {
    SenderKeyAuth::Signed
}

impl SenderKeyState {
    /// Build a receiver-side state from a distribution message. The auth mode
    /// is inferred from whether the message carries a signing key; no private
    /// signing key is stored, so the resulting state can verify but not send.
    pub fn from_distribution(msg: &SenderKeyDistributionMessage) -> Self {
        let auth_mode = if msg.signing_key.is_some() {
            SenderKeyAuth::Signed
        } else {
            SenderKeyAuth::Hmac
        };
        Self {
            chain_key: msg.chain_key,
            iteration: msg.iteration,
            is_sender: false,
            auth_mode,
            signing_public: msg.signing_key,
            signing_private: None,
            skipped_message_keys: Vec::new(),
        }
    }

    fn derive_message_key(&self, at_iteration: u32) -> Result<(Vec<[u8; 32]>, [u8; 32])> {
        if at_iteration < self.iteration {
            return Err(CryptoError::DuplicateMessage);
        }
        let gap = at_iteration - self.iteration;
        if gap > 2000 {
            return Err(CryptoError::MaxSkipExceeded(gap, 2000));
        }
        let mut ck = self.chain_key;
        let mut skipped = Vec::new();
        for _ in self.iteration..at_iteration {
            let mk = hmac_derive(&ck, 0x01);
            skipped.push(mk);
            ck = hmac_derive(&ck, 0x02);
        }
        let mk = hmac_derive(&ck, 0x01);
        Ok((skipped, mk))
    }

    /// The current chain iteration (number of messages advanced past).
    pub fn iteration(&self) -> u32 {
        self.iteration
    }
}

fn hmac_derive(key: &[u8; 32], byte: u8) -> [u8; 32] {
    let mut mac = Hmac::<Sha256>::new_from_slice(key).expect("HMAC accepts any key length");
    mac.update(&[byte]);
    mac.finalize().into_bytes().into()
}

fn hmac_authenticate(key: &[u8; 32], data: &[u8]) -> [u8; 32] {
    let mut mac = Hmac::<Sha256>::new_from_slice(key).expect("HMAC accepts any key length");
    mac.update(data);
    mac.finalize().into_bytes().into()
}

/// Verify an HMAC-SHA256 tag for a `Hmac`-mode chain (voice). The auth key is
/// derived from the chain key advanced to `iteration`. Comparison is
/// constant-time. Out-of-window iterations are rejected before any decryption.
fn verify_hmac(state: &SenderKeyState, iteration: u32, auth_data: &[u8], mac: &[u8]) -> Result<()> {
    let auth_key = if iteration == state.iteration {
        hmac_derive(&state.chain_key, 0x03)
    } else if iteration > state.iteration {
        let gap = iteration - state.iteration;
        if gap > 2000 {
            return Err(CryptoError::MaxSkipExceeded(gap, 2000));
        }
        let mut ck = state.chain_key;
        for _ in state.iteration..iteration {
            ck = hmac_derive(&ck, 0x02);
        }
        hmac_derive(&ck, 0x03)
    } else {
        return Err(CryptoError::DuplicateMessage);
    };

    let expected = hmac_authenticate(&auth_key, auth_data);
    let mac_bytes: [u8; 32] = mac.try_into().map_err(|_| CryptoError::InvalidSignature)?;

    if expected.ct_eq(&mac_bytes).into() {
        Ok(())
    } else {
        Err(CryptoError::InvalidSignature)
    }
}

/// Per-message authentication carried by a [`SenderKeyMessage`].
///
/// The variant must match the receiving state's [`SenderKeyAuth`] mode;
/// `group_decrypt` rejects a mismatch, closing a downgrade attack where an
/// attacker strips a signature and substitutes a (forgeable) HMAC.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum MessageAuth {
    /// HMAC-SHA256 tag (32 bytes). See [`SenderKeyAuth::Hmac`].
    Hmac(Vec<u8>),
    /// Ed25519 signature (64 bytes). See [`SenderKeyAuth::Signed`].
    Signature(Vec<u8>),
}

/// Sender key message (encrypted group message).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SenderKeyMessage {
    /// Identifier of the group this message belongs to.
    pub group_id: Vec<u8>,
    /// Chain iteration whose message key encrypted this message.
    pub iteration: u32,
    /// AEAD ciphertext of the plaintext, with `group_id` as associated data.
    pub ciphertext: Vec<u8>,
    /// Per-message authentication (Ed25519 signature or HMAC tag).
    pub auth: MessageAuth,
}

/// Create a sender key distribution message for a group.
///
/// `auth` selects per-message authentication: `Signed` (Ed25519, text/group) or
/// `Hmac` (voice). For `Signed`, a fresh per-sender-key Ed25519 keypair is
/// generated; its public half is placed in the distribution message and both
/// halves are stored in the returned state.
pub fn create_sender_key_distribution_message(
    group_id: &[u8],
    auth: SenderKeyAuth,
) -> (SenderKeyState, SenderKeyDistributionMessage) {
    let mut chain_key = [0u8; 32];
    rand::rng().fill(&mut chain_key[..]);

    let (signing_private, signing_public) = match auth {
        SenderKeyAuth::Signed => {
            let keypair = IdentityKeyPair::generate();
            (Some(*keypair.seed()), Some(keypair.public_key().as_bytes()))
        }
        SenderKeyAuth::Hmac => (None, None),
    };

    let state = SenderKeyState {
        chain_key,
        iteration: 0,
        is_sender: true,
        auth_mode: auth,
        signing_public,
        signing_private,
        skipped_message_keys: Vec::new(),
    };

    let dist_msg = SenderKeyDistributionMessage {
        group_id: group_id.to_vec(),
        chain_key,
        iteration: 0,
        signing_key: signing_public,
    };

    (state, dist_msg)
}

/// Create a distribution message from an existing sender key state.
///
/// Unlike `create_sender_key_distribution_message`, this does NOT generate a
/// new key. It snapshots the current chain key and iteration so recipients
/// can sync to the sender's current state. Use this when re-distributing
/// an existing key (e.g., to a reconnecting peer).
pub fn distribution_message_for_existing(
    state: &SenderKeyState,
    group_id: &[u8],
) -> SenderKeyDistributionMessage {
    SenderKeyDistributionMessage {
        group_id: group_id.to_vec(),
        chain_key: state.chain_key,
        iteration: state.iteration,
        signing_key: state.signing_public,
    }
}

/// Process a received sender key distribution message from a group member.
pub fn process_sender_key_distribution_message(
    _sender: &crate::address::ProtocolAddress,
    msg: &SenderKeyDistributionMessage,
) -> SenderKeyState {
    SenderKeyState::from_distribution(msg)
}

/// Encrypt a message for the group using sender keys.
pub fn group_encrypt(
    state: &mut SenderKeyState,
    group_id: &[u8],
    plaintext: &[u8],
) -> Result<SenderKeyMessage> {
    if !state.is_sender {
        return Err(CryptoError::MissingSenderKey);
    }

    let mk = hmac_derive(&state.chain_key, 0x01);
    let ciphertext = crate::primitives::aead::encrypt(&mk, plaintext, group_id)?;

    let iteration = state.iteration;

    let auth_data = authenticated_data(group_id, iteration, &ciphertext);

    let auth = match state.auth_mode {
        SenderKeyAuth::Signed => {
            let seed = state.signing_private.ok_or(CryptoError::MissingSenderKey)?;
            let signature = IdentityKeyPair::from_seed(&seed).sign(&auth_data);
            MessageAuth::Signature(signature)
        }
        SenderKeyAuth::Hmac => {
            let auth_key = hmac_derive(&state.chain_key, 0x03);
            MessageAuth::Hmac(hmac_authenticate(&auth_key, &auth_data).to_vec())
        }
    };

    state.chain_key = hmac_derive(&state.chain_key, 0x02);
    state.iteration += 1;

    Ok(SenderKeyMessage {
        group_id: group_id.to_vec(),
        iteration,
        ciphertext,
        auth,
    })
}

/// Bytes authenticated by the per-message signature or HMAC:
/// `group_id || iteration(big-endian u32) || ciphertext`.
fn authenticated_data(group_id: &[u8], iteration: u32, ciphertext: &[u8]) -> Vec<u8> {
    let mut data = Vec::with_capacity(group_id.len() + 4 + ciphertext.len());
    data.extend_from_slice(group_id);
    data.extend_from_slice(&iteration.to_be_bytes());
    data.extend_from_slice(ciphertext);
    data
}

/// Decrypt a group message using sender keys.
pub fn group_decrypt(state: &mut SenderKeyState, message: &SenderKeyMessage) -> Result<Vec<u8>> {
    // Authenticate before any decryption. The message's auth variant must match
    // the chain's mode -- a mismatch (e.g. an HMAC tag presented to a Signed
    // chain) is a downgrade attempt and is rejected.
    let auth_data = authenticated_data(&message.group_id, message.iteration, &message.ciphertext);
    match (state.auth_mode, &message.auth) {
        (SenderKeyAuth::Signed, MessageAuth::Signature(signature)) => {
            let public = state.signing_public.ok_or(CryptoError::InvalidSignature)?;
            IdentityPublicKey::from_bytes(&public)?.verify(&auth_data, signature)?;
        }
        (SenderKeyAuth::Hmac, MessageAuth::Hmac(mac)) => {
            verify_hmac(state, message.iteration, &auth_data, mac)?;
        }
        _ => return Err(CryptoError::InvalidSignature),
    }

    if let Some(pos) = state
        .skipped_message_keys
        .iter()
        .position(|(iter, _)| *iter == message.iteration)
    {
        let (_, mk) = state.skipped_message_keys.remove(pos);
        return crate::primitives::aead::decrypt(&mk, &message.ciphertext, &message.group_id);
    }

    let (skipped, mk) = state.derive_message_key(message.iteration)?;

    let plaintext = crate::primitives::aead::decrypt(&mk, &message.ciphertext, &message.group_id)?;

    for (i, skipped_mk) in skipped.into_iter().enumerate() {
        let iter = state.iteration + i as u32;
        if state.skipped_message_keys.len() < 2000 {
            state.skipped_message_keys.push((iter, skipped_mk));
        }
    }

    for _ in state.iteration..=message.iteration {
        state.chain_key = hmac_derive(&state.chain_key, 0x02);
        state.iteration += 1;
    }

    Ok(plaintext)
}

#[cfg(test)]
mod tests {
    use super::*;

    const MODES: [SenderKeyAuth; 2] = [SenderKeyAuth::Signed, SenderKeyAuth::Hmac];

    #[test]
    fn encrypt_decrypt_roundtrip() {
        for mode in MODES {
            let group_id = b"test-group";
            let (mut sender_state, dist_msg) =
                create_sender_key_distribution_message(group_id, mode);
            let mut receiver_state = SenderKeyState::from_distribution(&dist_msg);

            let msg = group_encrypt(&mut sender_state, group_id, b"hello group").unwrap();
            let plaintext = group_decrypt(&mut receiver_state, &msg).unwrap();
            assert_eq!(plaintext, b"hello group");
        }
    }

    #[test]
    fn multiple_messages() {
        for mode in MODES {
            let group_id = b"group-1";
            let (mut sender, dist) = create_sender_key_distribution_message(group_id, mode);
            let mut receiver = SenderKeyState::from_distribution(&dist);

            for i in 0..10 {
                let msg =
                    group_encrypt(&mut sender, group_id, format!("msg {i}").as_bytes()).unwrap();
                let pt = group_decrypt(&mut receiver, &msg).unwrap();
                assert_eq!(pt, format!("msg {i}").as_bytes());
            }
        }
    }

    #[test]
    fn multiple_senders() {
        let group_id = b"group-multi";

        let (mut alice_state, alice_dist) =
            create_sender_key_distribution_message(group_id, SenderKeyAuth::Signed);
        let (mut bob_state, bob_dist) =
            create_sender_key_distribution_message(group_id, SenderKeyAuth::Signed);

        let mut alice_receives_bob = SenderKeyState::from_distribution(&bob_dist);
        let mut bob_receives_alice = SenderKeyState::from_distribution(&alice_dist);

        let msg_a = group_encrypt(&mut alice_state, group_id, b"from alice").unwrap();
        let msg_b = group_encrypt(&mut bob_state, group_id, b"from bob").unwrap();

        assert_eq!(
            group_decrypt(&mut bob_receives_alice, &msg_a).unwrap(),
            b"from alice"
        );
        assert_eq!(
            group_decrypt(&mut alice_receives_bob, &msg_b).unwrap(),
            b"from bob"
        );
    }

    #[test]
    fn tampered_auth_rejected() {
        for mode in MODES {
            let group_id = b"group";
            let (mut sender, dist) = create_sender_key_distribution_message(group_id, mode);
            let mut receiver = SenderKeyState::from_distribution(&dist);

            let mut msg = group_encrypt(&mut sender, group_id, b"data").unwrap();
            msg.auth = match msg.auth {
                MessageAuth::Hmac(t) => MessageAuth::Hmac(vec![0u8; t.len()]),
                MessageAuth::Signature(s) => MessageAuth::Signature(vec![0u8; s.len()]),
            };
            assert!(group_decrypt(&mut receiver, &msg).is_err());
        }
    }

    #[test]
    fn tampered_ciphertext_rejected() {
        for mode in MODES {
            let group_id = b"group";
            let (mut sender, dist) = create_sender_key_distribution_message(group_id, mode);
            let mut receiver = SenderKeyState::from_distribution(&dist);

            let mut msg = group_encrypt(&mut sender, group_id, b"data").unwrap();
            let len = msg.ciphertext.len();
            msg.ciphertext[len - 1] ^= 0xFF;
            assert!(group_decrypt(&mut receiver, &msg).is_err());
        }
    }

    #[test]
    fn cannot_encrypt_without_sender_flag() {
        let group_id = b"group";
        let (_, dist) = create_sender_key_distribution_message(group_id, SenderKeyAuth::Signed);
        let mut receiver = SenderKeyState::from_distribution(&dist);
        assert!(!receiver.is_sender);
        assert!(group_encrypt(&mut receiver, group_id, b"data").is_err());
    }

    #[test]
    fn distribution_message_roundtrip() {
        let group_id = b"test-group-dist";
        let (_, dist) = create_sender_key_distribution_message(group_id, SenderKeyAuth::Signed);
        let bytes = postcard::to_allocvec(&dist).unwrap();
        let restored: SenderKeyDistributionMessage = postcard::from_bytes(&bytes).unwrap();
        assert_eq!(restored.group_id, group_id);
        assert_eq!(restored.iteration, 0);
        assert!(restored.signing_key.is_some());
    }

    #[test]
    fn rekeying() {
        let group_id = b"rekey-group";
        let (mut sender1, dist1) =
            create_sender_key_distribution_message(group_id, SenderKeyAuth::Signed);
        let mut receiver1 = SenderKeyState::from_distribution(&dist1);

        let msg1 = group_encrypt(&mut sender1, group_id, b"before rekey").unwrap();
        assert_eq!(
            group_decrypt(&mut receiver1, &msg1).unwrap(),
            b"before rekey"
        );

        let (mut sender2, dist2) =
            create_sender_key_distribution_message(group_id, SenderKeyAuth::Signed);
        let mut receiver2 = SenderKeyState::from_distribution(&dist2);

        let msg2 = group_encrypt(&mut sender2, group_id, b"after rekey").unwrap();
        assert_eq!(
            group_decrypt(&mut receiver2, &msg2).unwrap(),
            b"after rekey"
        );

        // Old receiver can't decrypt new messages (different chain)
        assert!(group_decrypt(&mut receiver1, &msg2).is_err());
    }

    #[test]
    fn decrypt_with_wrong_distribution_fails() {
        let group_id = b"wrong-dist";
        let (mut sender, _dist) =
            create_sender_key_distribution_message(group_id, SenderKeyAuth::Signed);
        let msg = group_encrypt(&mut sender, group_id, b"secret").unwrap();

        let (_, wrong_dist) =
            create_sender_key_distribution_message(group_id, SenderKeyAuth::Signed);
        let mut wrong_receiver = SenderKeyState::from_distribution(&wrong_dist);
        assert!(group_decrypt(&mut wrong_receiver, &msg).is_err());
    }

    #[test]
    fn process_distribution_message_creates_state() {
        let group_id = b"proc-test";
        let (_, dist) = create_sender_key_distribution_message(group_id, SenderKeyAuth::Signed);
        let addr = crate::address::ProtocolAddress::new(uuid::Uuid::new_v4(), 1u32);
        let state = process_sender_key_distribution_message(&addr, &dist);
        assert_eq!(state.iteration(), 0);
    }

    #[test]
    fn truncated_hmac_rejected() {
        let group_id = b"group";
        let (mut sender, dist) =
            create_sender_key_distribution_message(group_id, SenderKeyAuth::Hmac);
        let mut receiver = SenderKeyState::from_distribution(&dist);

        let mut msg = group_encrypt(&mut sender, group_id, b"data").unwrap();
        msg.auth = MessageAuth::Hmac(vec![0u8; 16]);
        assert!(group_decrypt(&mut receiver, &msg).is_err());
    }

    #[test]
    fn signed_mode_uses_signature_hmac_mode_uses_hmac() {
        let group_id = b"group";

        let (mut signed, _) =
            create_sender_key_distribution_message(group_id, SenderKeyAuth::Signed);
        let signed_msg = group_encrypt(&mut signed, group_id, b"data").unwrap();
        match signed_msg.auth {
            MessageAuth::Signature(s) => assert_eq!(s.len(), 64),
            MessageAuth::Hmac(_) => panic!("signed chain produced an HMAC"),
        }

        let (mut hmac, _) = create_sender_key_distribution_message(group_id, SenderKeyAuth::Hmac);
        let hmac_msg = group_encrypt(&mut hmac, group_id, b"data").unwrap();
        match hmac_msg.auth {
            MessageAuth::Hmac(t) => assert_eq!(t.len(), 32),
            MessageAuth::Signature(_) => panic!("hmac chain produced a signature"),
        }
    }

    /// The core property this change restores: a group member who holds the
    /// chain key (a receiver) cannot forge a message that verifies against the
    /// sender's distributed Ed25519 public key. Under the old HMAC scheme this
    /// forgery succeeded.
    #[test]
    fn chain_key_holder_cannot_forge_signed_message() {
        let group_id = b"no-forge";
        let (mut sender, dist) =
            create_sender_key_distribution_message(group_id, SenderKeyAuth::Signed);

        // The receiver holds the full chain key (via the distribution message)
        // and can derive every message key, but lacks the private signing key.
        let mut receiver = SenderKeyState::from_distribution(&dist);
        assert!(receiver.signing_private.is_none());
        assert!(receiver.signing_public.is_some());

        // A genuine message from the real sender verifies.
        let genuine = group_encrypt(&mut sender, group_id, b"real").unwrap();
        assert_eq!(group_decrypt(&mut receiver, &genuine).unwrap(), b"real");

        // The receiver forges: it can produce a valid ciphertext for the next
        // iteration (it knows the chain key) but cannot produce a valid
        // signature. The forgery is rejected.
        receiver.is_sender = true; // pretend to be able to send
        let iteration = receiver.iteration;
        let mk = hmac_derive(&receiver.chain_key, 0x01);
        let ciphertext = crate::primitives::aead::encrypt(&mk, b"forged", group_id).unwrap();
        let auth_data = authenticated_data(group_id, iteration, &ciphertext);
        // Best the forger can do: sign with a key of its own choosing.
        let forger_key = IdentityKeyPair::generate();
        let forged = SenderKeyMessage {
            group_id: group_id.to_vec(),
            iteration,
            ciphertext,
            auth: MessageAuth::Signature(forger_key.sign(&auth_data)),
        };

        let mut victim = SenderKeyState::from_distribution(&dist);
        assert!(matches!(
            group_decrypt(&mut victim, &forged),
            Err(CryptoError::InvalidSignature)
        ));
    }

    /// A `SenderKeyState` persisted before per-message signatures existed (no
    /// `auth_mode` / `signing_*` fields) must deserialize fail-closed: `Signed`
    /// mode with no keys, so it can neither sign nor verify and is forced to
    /// rekey rather than silently degrading to forgeable HMAC.
    #[test]
    fn legacy_state_deserializes_fail_closed() {
        let legacy = serde_json::json!({
            "chain_key": vec![7u8; 32],
            "iteration": 3,
            "is_sender": true,
        });
        let state: SenderKeyState = serde_json::from_value(legacy).unwrap();
        assert_eq!(state.auth_mode, SenderKeyAuth::Signed);
        assert!(state.signing_public.is_none());
        assert!(state.signing_private.is_none());
        assert_eq!(state.iteration, 3);
    }

    /// A `Hmac`-variant message presented to a `Signed` chain (signature
    /// stripped, forgeable HMAC substituted) must be rejected.
    #[test]
    fn downgrade_to_hmac_rejected() {
        let group_id = b"downgrade";
        let (mut sender, dist) =
            create_sender_key_distribution_message(group_id, SenderKeyAuth::Signed);
        let mut receiver = SenderKeyState::from_distribution(&dist);

        let mut msg = group_encrypt(&mut sender, group_id, b"data").unwrap();
        // Forge an HMAC the way any chain-key holder could.
        let auth_key = hmac_derive(&dist.chain_key, 0x03);
        let auth_data = authenticated_data(group_id, msg.iteration, &msg.ciphertext);
        msg.auth = MessageAuth::Hmac(hmac_authenticate(&auth_key, &auth_data).to_vec());

        assert!(matches!(
            group_decrypt(&mut receiver, &msg),
            Err(CryptoError::InvalidSignature)
        ));
    }
}
