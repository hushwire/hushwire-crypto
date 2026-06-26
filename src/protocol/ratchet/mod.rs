//! Double Ratchet session.
//!
//! Implements Signal's Double Ratchet over the EC (X25519) ratchet, extended
//! into a Triple Ratchet: each message key is `KDF_HYBRID(ec_mk, pq_mk)`, where
//! the post-quantum half (`pq_mk`) comes from the Sparse Post-Quantum Ratchet
//! ([`spqr`]) carried in the message header. The EC root key remains classical
//! DH-only (`KDF_RK(rk, dh_out)`).
//!
//! [`RatchetSession`] is the per-conversation state: a root key, a sending and a
//! receiving symmetric [`chain`], the skipped-message-key store ([`skipped`]),
//! and the SPQR braid. It encrypts and decrypts [`RatchetMessage`]s, advancing
//! the symmetric chains per message and performing a DH ratchet step whenever the
//! peer's ratchet public key changes. The first message of a new session is wrapped
//! as a [`PreKeyRatchetMessage`] carrying the PQXDH establishment data.

pub mod chain;
pub mod header;
pub mod skipped;
pub mod spqr;

use rand::RngExt as _;
use serde::{Deserialize, Serialize};
use x25519_dalek::{PublicKey as X25519Public, StaticSecret as X25519Secret};
use zeroize::Zeroize;

use crate::error::{CryptoError, Result};
use crate::primitives::kdf;
use crate::primitives::keys::IdentityPublicKey;
use crate::types::{DhPublicKey, RootKey};

use self::chain::ChainState;
use self::header::MessageHeader;
use self::skipped::{MAX_SKIP, SkippedKeys};
use self::spqr::SpqrState;

/// Double Ratchet message (wire format).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RatchetMessage {
    /// Serialized [`MessageHeader`]; also bound into the AEAD associated data.
    pub header: Vec<u8>,
    /// AEAD ciphertext of the padded plaintext under the hybrid message key.
    pub ciphertext: Vec<u8>,
}

/// Pre-key message wrapping a ratchet message with session establishment data.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PreKeyRatchetMessage {
    /// Sender's registration id.
    pub registration_id: crate::types::RegistrationId,
    /// Id of the recipient's one-time pre-key consumed by PQXDH, if one was used.
    pub pre_key_id: Option<crate::types::PreKeyId>,
    /// Id of the recipient's signed pre-key used by PQXDH.
    pub signed_pre_key_id: crate::types::SignedPreKeyId,
    /// Id of the recipient's Kyber (ML-KEM) pre-key used by PQXDH.
    pub kyber_pre_key_id: crate::types::KyberPreKeyId,
    /// Sender's ephemeral X25519 public key for the PQXDH handshake.
    pub ephemeral_dh_key: DhPublicKey,
    /// Kyber (ML-KEM) ciphertext encapsulating the post-quantum shared secret.
    pub kyber_ciphertext: Vec<u8>,
    /// Sender's long-term identity public key.
    pub identity_key: crate::primitives::keys::IdentityPublicKey,
    /// The wrapped ratchet message (the first encrypted payload of the session).
    pub message: RatchetMessage,
}

/// Output of [`RatchetSession::encrypt_message`]: either a normal ratchet message
/// or a pre-key message (first message in a new session).
#[derive(Debug)]
pub enum EncryptedOutput {
    /// A normal ratchet message (the session is already established).
    Message(RatchetMessage),
    /// A pre-key message wrapping the first message of a new session.
    PreKeyMessage(Box<PreKeyRatchetMessage>),
}

/// Double Ratchet session state.
pub struct RatchetSession {
    dh_self: X25519Secret,
    dh_self_public: DhPublicKey,
    dh_remote: Option<DhPublicKey>,
    root_key: RootKey,
    sending_chain: Option<ChainState>,
    receiving_chain: Option<ChainState>,
    previous_sending_chain_length: u32,
    skipped: SkippedKeys,
    pending_prekey: Option<crate::protocol::prekey::PqxdhInitialMessage>,
    /// The post-quantum half of the Triple Ratchet: the Sparse Post-Quantum Ratchet
    /// (SPQR). Each message's AEAD key is `KDF_HYBRID(ec_mk, pq_mk)` where `pq_mk`
    /// comes from this ratchet; the EC root key is classical DH-only.
    spqr: SpqrState,
    /// Stable id of the X3DH/PQXDH shared secret this session was initialized
    /// from, captured BEFORE any root-key ratchet so it is IDENTICAL on both
    /// peers. Used as a deterministic dual-init convergence tie-breaker.
    /// Runtime-only (not in `SerializedState`); meaningful only right after
    /// construction (0 after deserialize), so callers persist it into the
    /// session's `convergence_priority`.
    initial_root_id: u64,
}

/// Derive a stable 64-bit id from an X3DH/PQXDH shared secret (first 8 bytes).
fn shared_secret_id(shared_secret: &[u8; 32]) -> u64 {
    let mut id = [0u8; 8];
    id.copy_from_slice(&shared_secret[..8]);
    u64::from_be_bytes(id)
}

impl RatchetSession {
    /// Initialize as Alice (initiator) after PQXDH.
    pub fn initialize_alice(shared_secret: &[u8; 32], bob_dh_public: &[u8; 32]) -> Result<Self> {
        let ss = RootKey::from(*shared_secret);

        let mut dh_private_bytes = [0u8; 32];
        rand::rng().fill(&mut dh_private_bytes);
        let dh_self = X25519Secret::from(dh_private_bytes);
        dh_private_bytes.zeroize();
        let dh_self_public = DhPublicKey::from(X25519Public::from(&dh_self).to_bytes());

        let bob_x25519 = X25519Public::from(*bob_dh_public);
        let dh_out = dh_self.diffie_hellman(&bob_x25519);

        // The EC Double Ratchet root key is classical DH-only (`KDF_RK(rk, dh_out)`);
        // the post-quantum contribution enters at the message-key layer via
        // `KDF_HYBRID(ec_mk, pq_mk)`, not the root key (Signal's Triple Ratchet).
        let rk_out = kdf::kdf_rk(&ss, dh_out.as_bytes());

        Ok(Self {
            dh_self,
            dh_self_public,
            dh_remote: Some(DhPublicKey::from(*bob_dh_public)),
            root_key: rk_out.root_key,
            sending_chain: Some(ChainState::new(rk_out.chain_key)),
            receiving_chain: None,
            previous_sending_chain_length: 0,
            skipped: SkippedKeys::new(),
            pending_prekey: None,
            spqr: SpqrState::new_sender(shared_secret),
            initial_root_id: shared_secret_id(shared_secret),
        })
    }

    /// Initialize as Alice (initiator) with a pending pre-key message.
    ///
    /// The `initial_message` is stored so that [`Self::encrypt_message`] automatically
    /// produces a [`PreKeyRatchetMessage`] on the first call, mirroring how
    /// Signal's session internally tracks whether it's a pre-key session.
    pub fn initialize_alice_with_prekey(
        shared_secret: &[u8; 32],
        bob_dh_public: &[u8; 32],
        initial_message: crate::protocol::prekey::PqxdhInitialMessage,
    ) -> Result<Self> {
        let mut session = Self::initialize_alice(shared_secret, bob_dh_public)?;
        session.pending_prekey = Some(initial_message);
        Ok(session)
    }

    /// Initialize as Bob (responder) after PQXDH.
    pub fn initialize_bob(shared_secret: &[u8; 32], bob_dh_keypair: ([u8; 32], [u8; 32])) -> Self {
        let (dh_private_bytes, dh_public_bytes) = bob_dh_keypair;
        let dh_self = X25519Secret::from(dh_private_bytes);

        Self {
            dh_self,
            dh_self_public: DhPublicKey::from(dh_public_bytes),
            dh_remote: None,
            root_key: RootKey::from(*shared_secret),
            sending_chain: None,
            receiving_chain: None,
            previous_sending_chain_length: 0,
            skipped: SkippedKeys::new(),
            pending_prekey: None,
            spqr: SpqrState::new_receiver(shared_secret),
            initial_root_id: shared_secret_id(shared_secret),
        }
    }

    /// Encrypt a plaintext message.
    ///
    /// AD is constructed internally as `sender_x25519 (32) || recipient_x25519 (32) || header`,
    /// providing KCI (key-compromise impersonation) resistance by binding both identity keys.
    ///
    /// Returns an error if the session has a pending pre-key message. Use
    /// [`Self::encrypt_message`] instead, which auto-detects pre-key sessions.
    pub fn encrypt(
        &mut self,
        plaintext: &[u8],
        sender_identity: &IdentityPublicKey,
        recipient_identity: &IdentityPublicKey,
    ) -> Result<RatchetMessage> {
        if self.pending_prekey.is_some() {
            return Err(CryptoError::InvalidSessionState);
        }
        self.encrypt_raw(plaintext, sender_identity, recipient_identity)
    }

    fn encrypt_raw(
        &mut self,
        plaintext: &[u8],
        sender_identity: &IdentityPublicKey,
        recipient_identity: &IdentityPublicKey,
    ) -> Result<RatchetMessage> {
        // SCKARatchetSendKey: advance the braid and the sending PQ chain, yielding
        // the codeword to piggyback, this message's PQ counter, and the PQ key.
        let (braid_msg, pq_message_number, pq_mk) = self.spqr.ratchet_send_key(&mut rand::rng())?;

        let (ec_mk, message_number) = {
            let chain = self
                .sending_chain
                .as_mut()
                .ok_or(CryptoError::InvalidSessionState)?;
            let mk = chain.advance();
            (mk, chain.message_number - 1)
        };

        let header = MessageHeader {
            dh_public_key: self.dh_self_public.clone(),
            previous_chain_length: self.previous_sending_chain_length,
            message_number,
            braid_msg,
            pq_message_number,
        };

        let header_bytes = header.serialize();
        let ad = build_ad(sender_identity, recipient_identity, &header_bytes);

        // The AEAD message key is the Triple Ratchet hybrid of the EC and PQ keys.
        let mk = crate::primitives::kdf::kdf_hybrid(&ec_mk, pq_mk.as_bytes());
        let padded = crate::primitives::padding::pad(plaintext);
        let ciphertext = crate::primitives::aead::encrypt(mk.as_bytes(), &padded, &ad)?;

        Ok(RatchetMessage {
            header: header_bytes,
            ciphertext,
        })
    }

    /// Encrypt a message, auto-detecting whether this is a pre-key session.
    ///
    /// If [`Self::initialize_alice_with_prekey`] was used and this is the first encrypt,
    /// returns [`EncryptedOutput::PreKeyMessage`]. Otherwise returns
    /// [`EncryptedOutput::Message`]. The pending pre-key data is consumed on first use.
    pub fn encrypt_message(
        &mut self,
        plaintext: &[u8],
        sender_identity: &IdentityPublicKey,
        recipient_identity: &IdentityPublicKey,
    ) -> Result<EncryptedOutput> {
        let ratchet_msg = self.encrypt_raw(plaintext, sender_identity, recipient_identity)?;

        if let Some(initial) = self.pending_prekey.take() {
            Ok(EncryptedOutput::PreKeyMessage(Box::new(
                PreKeyRatchetMessage {
                    registration_id: initial.registration_id,
                    pre_key_id: initial.one_time_pre_key_id,
                    signed_pre_key_id: initial.signed_pre_key_id,
                    kyber_pre_key_id: initial.kyber_pre_key_id,
                    ephemeral_dh_key: initial.ephemeral_public_key,
                    kyber_ciphertext: initial.kyber_ciphertext,
                    identity_key: *sender_identity,
                    message: ratchet_msg,
                },
            )))
        } else {
            Ok(EncryptedOutput::Message(ratchet_msg))
        }
    }

    /// Decrypt a received message.
    ///
    /// Try order: (1) skipped message keys, (2) same chain advance,
    /// (3) new DH key triggering a ratchet step.
    pub fn decrypt(
        &mut self,
        message: &RatchetMessage,
        sender_identity: &IdentityPublicKey,
        recipient_identity: &IdentityPublicKey,
    ) -> Result<Vec<u8>> {
        let header = MessageHeader::deserialize(&message.header)?;

        let ad = build_ad(sender_identity, recipient_identity, &message.header);

        // Resolve the EC Double Ratchet message key: from the skipped-key store for
        // an out-of-order message, otherwise by advancing the receiving chain after
        // any DH ratchet step.
        let ec_mk = if let Some(mk) = self
            .skipped
            .try_remove_by_dh(&header.dh_public_key.0, header.message_number)
        {
            mk
        } else {
            let needs_ratchet = self
                .dh_remote
                .as_ref()
                .is_none_or(|r| r.0 != header.dh_public_key.0);
            if needs_ratchet {
                self.skip_receiving_messages(header.previous_chain_length)?;
                self.perform_dh_ratchet_step(&header)?;
            }
            self.skip_receiving_messages(header.message_number)?;
            self.receiving_chain
                .as_mut()
                .ok_or(CryptoError::InvalidSessionState)?
                .advance()
        };

        // SCKARatchetReceiveKey: advance the braid with the carried codeword and the
        // receiving PQ chain to obtain `pq_mk`. The PQ ratchet advances during key
        // derivation (as the EC ratchet does); the braid authenticates its own
        // codewords, and the whole header (codeword + PQ counter) is bound into the
        // AEAD associated data, so a stripped or forged codeword/counter fails closed
        // at the AEAD tag rather than silently downgrading to classical-only.
        let pq_mk = self
            .spqr
            .ratchet_receive_key(&header.braid_msg, header.pq_message_number)?;

        let mk = crate::primitives::kdf::kdf_hybrid(&ec_mk, pq_mk.as_bytes());
        let padded = crate::primitives::aead::decrypt(mk.as_bytes(), &message.ciphertext, &ad)?;
        let plaintext = crate::primitives::padding::unpad(&padded).map(|s| s.to_vec())?;
        Ok(plaintext)
    }

    fn skip_receiving_messages(&mut self, until: u32) -> Result<()> {
        let chain_dh = self.dh_remote.as_ref().map(|d| d.0).unwrap_or([0u8; 32]);
        let chain = match self.receiving_chain.as_mut() {
            Some(c) => c,
            None => return Ok(()),
        };
        if chain.message_number > until {
            return Ok(());
        }
        let gap = until - chain.message_number;
        if gap > MAX_SKIP {
            return Err(CryptoError::MaxSkipExceeded(gap, MAX_SKIP));
        }
        while chain.message_number < until {
            let mk = chain.advance();
            let n = chain.message_number - 1;
            self.skipped.insert(n, chain_dh, mk);
        }
        Ok(())
    }

    fn perform_dh_ratchet_step(&mut self, header: &MessageHeader) -> Result<()> {
        self.previous_sending_chain_length = self
            .sending_chain
            .as_ref()
            .map(|c| c.message_number)
            .unwrap_or(0);

        self.dh_remote = Some(header.dh_public_key.clone());

        // DH ratchet step (receiving half): classical DH-only `KDF_RK(rk, dh_out)`.
        // The post-quantum contribution enters at the message-key layer (KDF_HYBRID),
        // not the root key, so the braid secret never touches `KDF_RK`.
        let dh_remote = X25519Public::from(header.dh_public_key.0);
        let dh_out = self.dh_self.diffie_hellman(&dh_remote);
        let rk_out = kdf::kdf_rk(&self.root_key, dh_out.as_bytes());
        self.root_key = rk_out.root_key;
        self.receiving_chain = Some(ChainState::new(rk_out.chain_key));

        // DH ratchet step (sending half): fresh DH keypair.
        let mut new_dh_bytes = [0u8; 32];
        rand::rng().fill(&mut new_dh_bytes);
        self.dh_self = X25519Secret::from(new_dh_bytes);
        new_dh_bytes.zeroize();
        self.dh_self_public = DhPublicKey::from(X25519Public::from(&self.dh_self).to_bytes());

        let dh_out2 = self.dh_self.diffie_hellman(&dh_remote);
        let rk_out2 = kdf::kdf_rk(&self.root_key, dh_out2.as_bytes());
        self.root_key = rk_out2.root_key;
        self.sending_chain = Some(ChainState::new(rk_out2.chain_key));

        Ok(())
    }

    /// Diagnostic-only: a short fingerprint of the current root key. Two
    /// in-sync sides of the same session share the root key after processing
    /// the same DH steps, so this is useful for tracing session divergence.
    pub fn root_key_fingerprint(&self) -> u32 {
        self.root_key
            .as_bytes()
            .iter()
            .fold(0u32, |a, &x| a.wrapping_mul(31).wrapping_add(x as u32))
    }

    /// Stable id derived from this session's X3DH/PQXDH shared secret, captured
    /// at construction (identical on both peers). Deterministic dual-init
    /// convergence tie-breaker; only meaningful right after construction.
    pub fn root_key_id(&self) -> u64 {
        self.initial_root_id
    }

    /// Wrap the first encrypted message with PQXDH establishment data.
    pub fn encrypt_prekey_message(
        &mut self,
        plaintext: &[u8],
        sender_identity: &IdentityPublicKey,
        recipient_identity: &IdentityPublicKey,
        pqxdh_initial: &crate::protocol::prekey::PqxdhInitialMessage,
    ) -> Result<PreKeyRatchetMessage> {
        let ratchet_msg = self.encrypt(plaintext, sender_identity, recipient_identity)?;
        Ok(PreKeyRatchetMessage {
            registration_id: pqxdh_initial.registration_id,
            pre_key_id: pqxdh_initial.one_time_pre_key_id,
            signed_pre_key_id: pqxdh_initial.signed_pre_key_id,
            kyber_pre_key_id: pqxdh_initial.kyber_pre_key_id,
            ephemeral_dh_key: pqxdh_initial.ephemeral_public_key.clone(),
            kyber_ciphertext: pqxdh_initial.kyber_ciphertext.clone(),
            identity_key: *sender_identity,
            message: ratchet_msg,
        })
    }

    /// Process a PreKeyRatchetMessage as the responder.
    ///
    /// Performs PQXDH, initializes the session, and decrypts the first message.
    /// `kyber_dk_seed` is the 64-byte seed used to reconstruct the ML-KEM-1024
    /// decapsulation key (see [`crate::protocol::pqxdh::dk_to_seed_bytes`]).
    pub fn decrypt_prekey_message(
        msg: &PreKeyRatchetMessage,
        our_identity: &crate::primitives::keys::IdentityKeyPair,
        signed_pre_key_private: &[u8; 32],
        signed_pre_key_public: &[u8; 32],
        one_time_pre_key_private: Option<&[u8; 32]>,
        kyber_dk_seed: &[u8; 64],
    ) -> Result<(Self, Vec<u8>)> {
        let dk = crate::protocol::pqxdh::dk_from_seed_bytes(kyber_dk_seed);

        let initial_message = crate::protocol::prekey::PqxdhInitialMessage {
            registration_id: msg.registration_id,
            ephemeral_public_key: msg.ephemeral_dh_key.clone(),
            signed_pre_key_id: msg.signed_pre_key_id,
            one_time_pre_key_id: msg.pre_key_id,
            kyber_pre_key_id: msg.kyber_pre_key_id,
            kyber_ciphertext: msg.kyber_ciphertext.clone(),
            identity_key: msg.identity_key,
        };

        let shared_secret = crate::protocol::pqxdh::process_initial_message(
            our_identity,
            signed_pre_key_private,
            one_time_pre_key_private,
            &dk,
            &initial_message,
        )?;

        let bob_dh_keypair = (*signed_pre_key_private, *signed_pre_key_public);
        let mut session = Self::initialize_bob(&shared_secret, bob_dh_keypair);

        let plaintext =
            session.decrypt(&msg.message, &msg.identity_key, &our_identity.public_key())?;

        Ok((session, plaintext))
    }

    /// Test-only: the highest SPQR epoch whose KEM secret this session has
    /// incorporated, or `None` while still in the bootstrap epoch (epoch 0, before
    /// the braid completes its first key agreement).
    #[cfg(test)]
    fn braid_completed_epochs(&self) -> Option<u64> {
        match self.spqr.current_epoch() {
            0 => None,
            e => Some(e),
        }
    }

    /// Serialize the session state for storage.
    pub fn serialize(&self) -> Result<Vec<u8>> {
        let state = SerializedState {
            session_version: SESSION_VERSION,
            dh_self_bytes: self.dh_self.to_bytes(),
            dh_self_public: self.dh_self_public.clone(),
            dh_remote: self.dh_remote.clone(),
            root_key: self.root_key.clone(),
            sending_chain: self.sending_chain.clone(),
            receiving_chain: self.receiving_chain.clone(),
            previous_sending_chain_length: self.previous_sending_chain_length,
            skipped: self.skipped.clone(),
            pending_prekey: self.pending_prekey.clone(),
            spqr: self.spqr.clone(),
        };
        crate::serialization::serialize(&state)
    }

    /// Deserialize a session from bytes produced by [`Self::serialize`].
    ///
    /// Fail-closed on version mismatch: any session not at the current
    /// `SESSION_VERSION` (e.g. a pre-braid v3 D-13 session) is rejected so the
    /// caller re-establishes the session rather than loading incompatible state.
    pub fn deserialize(data: &[u8]) -> Result<Self> {
        let state: SerializedState = crate::serialization::deserialize(data)?;
        if state.session_version != SESSION_VERSION {
            return Err(CryptoError::Serialization(format!(
                "session version {} is not the supported version {}",
                state.session_version, SESSION_VERSION
            )));
        }
        Ok(Self {
            dh_self: X25519Secret::from(state.dh_self_bytes),
            dh_self_public: state.dh_self_public,
            dh_remote: state.dh_remote,
            root_key: state.root_key,
            sending_chain: state.sending_chain,
            receiving_chain: state.receiving_chain,
            previous_sending_chain_length: state.previous_sending_chain_length,
            skipped: state.skipped,
            pending_prekey: state.pending_prekey,
            spqr: state.spqr,
            // Runtime-only; only read right after construction.
            initial_root_id: 0,
        })
    }
}

fn build_ad(
    sender_identity: &IdentityPublicKey,
    recipient_identity: &IdentityPublicKey,
    header: &[u8],
) -> Vec<u8> {
    let sender_x25519 = sender_identity.to_x25519();
    let recipient_x25519 = recipient_identity.to_x25519();
    let mut ad = Vec::with_capacity(32 + 32 + header.len());
    ad.extend_from_slice(sender_x25519.as_bytes());
    ad.extend_from_slice(recipient_x25519.as_bytes());
    ad.extend_from_slice(header);
    ad
}

/// Session record version. v6 is the SPQR combiner shape: per-message
/// `KDF_HYBRID`, per-epoch KDF chains plus an `(epoch, n)` skipped-key store, and a
/// header carrying the PQ counter. v5 (and earlier) sessions are rejected by
/// `deserialize` and must rekey.
const SESSION_VERSION: u32 = 6;

fn default_session_version() -> u32 {
    SESSION_VERSION
}

#[derive(Serialize, Deserialize)]
struct SerializedState {
    #[serde(default = "default_session_version")]
    session_version: u32,
    dh_self_bytes: [u8; 32],
    dh_self_public: DhPublicKey,
    dh_remote: Option<DhPublicKey>,
    root_key: RootKey,
    sending_chain: Option<ChainState>,
    receiving_chain: Option<ChainState>,
    previous_sending_chain_length: u32,
    skipped: SkippedKeys,
    #[serde(default)]
    pending_prekey: Option<crate::protocol::prekey::PqxdhInitialMessage>,
    spqr: SpqrState,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::primitives::keys::IdentityKeyPair;

    fn make_shared_secret() -> [u8; 32] {
        let mut ss = [0u8; 32];
        rand::rng().fill(&mut ss);
        ss
    }

    fn make_dh_keypair() -> ([u8; 32], [u8; 32]) {
        let mut priv_bytes = [0u8; 32];
        rand::rng().fill(&mut priv_bytes);
        let secret = X25519Secret::from(priv_bytes);
        let public = X25519Public::from(&secret).to_bytes();
        (priv_bytes, public)
    }

    struct TestContext {
        alice_session: RatchetSession,
        bob_session: RatchetSession,
        alice_id: IdentityPublicKey,
        bob_id: IdentityPublicKey,
    }

    fn setup() -> TestContext {
        let ss = make_shared_secret();
        let bob_dh = make_dh_keypair();
        let alice_identity = IdentityKeyPair::generate();
        let bob_identity = IdentityKeyPair::generate();

        TestContext {
            alice_session: RatchetSession::initialize_alice(&ss, &bob_dh.1).unwrap(),
            bob_session: RatchetSession::initialize_bob(&ss, bob_dh),
            alice_id: alice_identity.public_key(),
            bob_id: bob_identity.public_key(),
        }
    }

    #[test]
    fn out_of_order_within_chain() {
        let ss = make_shared_secret();
        let bob_dh = make_dh_keypair();
        let a_id = IdentityKeyPair::generate().public_key();
        let b_id = IdentityKeyPair::generate().public_key();
        let mut alice = RatchetSession::initialize_alice(&ss, &bob_dh.1).unwrap();
        let mut bob = RatchetSession::initialize_bob(&ss, bob_dh);

        let m = alice.encrypt(b"prime", &a_id, &b_id).unwrap();
        bob.decrypt(&m, &a_id, &b_id).unwrap();

        let m0 = alice.encrypt(b"m0", &a_id, &b_id).unwrap();
        let m1 = alice.encrypt(b"m1", &a_id, &b_id).unwrap();
        let m2 = alice.encrypt(b"m2", &a_id, &b_id).unwrap();

        assert_eq!(bob.decrypt(&m1, &a_id, &b_id).unwrap(), b"m1");
        assert_eq!(bob.decrypt(&m0, &a_id, &b_id).unwrap(), b"m0");
        assert_eq!(bob.decrypt(&m2, &a_id, &b_id).unwrap(), b"m2");
    }

    #[test]
    fn alice_sends_first_message() {
        let TestContext {
            mut alice_session,
            mut bob_session,
            alice_id,
            bob_id,
        } = setup();

        let msg = alice_session
            .encrypt(b"hello bob", &alice_id, &bob_id)
            .unwrap();
        let pt = bob_session.decrypt(&msg, &alice_id, &bob_id).unwrap();
        assert_eq!(pt, b"hello bob");
    }

    #[test]
    fn bidirectional_conversation() {
        let TestContext {
            mut alice_session,
            mut bob_session,
            alice_id,
            bob_id,
        } = setup();

        let msg1 = alice_session.encrypt(b"hello", &alice_id, &bob_id).unwrap();
        assert_eq!(
            bob_session.decrypt(&msg1, &alice_id, &bob_id).unwrap(),
            b"hello"
        );

        let msg2 = bob_session
            .encrypt(b"hi alice", &bob_id, &alice_id)
            .unwrap();
        assert_eq!(
            alice_session.decrypt(&msg2, &bob_id, &alice_id).unwrap(),
            b"hi alice"
        );

        let msg3 = alice_session
            .encrypt(b"how are you?", &alice_id, &bob_id)
            .unwrap();
        assert_eq!(
            bob_session.decrypt(&msg3, &alice_id, &bob_id).unwrap(),
            b"how are you?"
        );
    }

    #[test]
    fn multiple_messages_same_direction() {
        let TestContext {
            mut alice_session,
            mut bob_session,
            alice_id,
            bob_id,
        } = setup();

        let msg1 = alice_session.encrypt(b"one", &alice_id, &bob_id).unwrap();
        let msg2 = alice_session.encrypt(b"two", &alice_id, &bob_id).unwrap();
        let msg3 = alice_session.encrypt(b"three", &alice_id, &bob_id).unwrap();

        assert_eq!(
            bob_session.decrypt(&msg1, &alice_id, &bob_id).unwrap(),
            b"one"
        );
        assert_eq!(
            bob_session.decrypt(&msg2, &alice_id, &bob_id).unwrap(),
            b"two"
        );
        assert_eq!(
            bob_session.decrypt(&msg3, &alice_id, &bob_id).unwrap(),
            b"three"
        );
    }

    #[test]
    fn out_of_order_delivery() {
        let TestContext {
            mut alice_session,
            mut bob_session,
            alice_id,
            bob_id,
        } = setup();

        let msg1 = alice_session.encrypt(b"first", &alice_id, &bob_id).unwrap();
        let msg2 = alice_session
            .encrypt(b"second", &alice_id, &bob_id)
            .unwrap();
        let msg3 = alice_session.encrypt(b"third", &alice_id, &bob_id).unwrap();

        assert_eq!(
            bob_session.decrypt(&msg3, &alice_id, &bob_id).unwrap(),
            b"third"
        );
        assert_eq!(
            bob_session.decrypt(&msg1, &alice_id, &bob_id).unwrap(),
            b"first"
        );
        assert_eq!(
            bob_session.decrypt(&msg2, &alice_id, &bob_id).unwrap(),
            b"second"
        );
    }

    #[test]
    fn wrong_identity_fails_decrypt() {
        let TestContext {
            mut alice_session,
            mut bob_session,
            alice_id,
            bob_id,
        } = setup();
        let eve_id = IdentityKeyPair::generate().public_key();

        let msg = alice_session
            .encrypt(b"secret", &alice_id, &bob_id)
            .unwrap();
        assert!(bob_session.decrypt(&msg, &eve_id, &bob_id).is_err());
    }

    #[test]
    fn tampered_ciphertext_fails() {
        let TestContext {
            mut alice_session,
            mut bob_session,
            alice_id,
            bob_id,
        } = setup();

        let mut msg = alice_session
            .encrypt(b"secret", &alice_id, &bob_id)
            .unwrap();
        let len = msg.ciphertext.len();
        msg.ciphertext[len - 1] ^= 0xFF;
        assert!(bob_session.decrypt(&msg, &alice_id, &bob_id).is_err());
    }

    #[test]
    fn session_serialization_roundtrip() {
        let TestContext {
            mut alice_session,
            mut bob_session,
            alice_id,
            bob_id,
        } = setup();

        // Exchange a message first so both sides have state
        let msg1 = alice_session
            .encrypt(b"before serialize", &alice_id, &bob_id)
            .unwrap();
        bob_session.decrypt(&msg1, &alice_id, &bob_id).unwrap();

        // Serialize and deserialize Alice
        let serialized = alice_session.serialize().unwrap();
        assert_eq!(&serialized[..4], b"HWCR");
        let mut restored = RatchetSession::deserialize(&serialized).unwrap();

        // Verify restored session can still communicate
        let msg2 = restored
            .encrypt(b"after deserialize", &alice_id, &bob_id)
            .unwrap();
        let pt = bob_session.decrypt(&msg2, &alice_id, &bob_id).unwrap();
        assert_eq!(pt, b"after deserialize");
    }

    #[test]
    fn many_messages_conversation() {
        let TestContext {
            mut alice_session,
            mut bob_session,
            alice_id,
            bob_id,
        } = setup();

        for i in 0..50 {
            let msg = alice_session
                .encrypt(format!("msg {i}").as_bytes(), &alice_id, &bob_id)
                .unwrap();
            assert_eq!(
                bob_session.decrypt(&msg, &alice_id, &bob_id).unwrap(),
                format!("msg {i}").as_bytes()
            );

            let reply = bob_session
                .encrypt(format!("reply {i}").as_bytes(), &bob_id, &alice_id)
                .unwrap();
            assert_eq!(
                alice_session.decrypt(&reply, &bob_id, &alice_id).unwrap(),
                format!("reply {i}").as_bytes()
            );
        }
    }

    #[test]
    fn empty_message() {
        let TestContext {
            mut alice_session,
            mut bob_session,
            alice_id,
            bob_id,
        } = setup();

        let msg = alice_session.encrypt(b"", &alice_id, &bob_id).unwrap();
        let pt = bob_session.decrypt(&msg, &alice_id, &bob_id).unwrap();
        assert!(pt.is_empty());
    }

    #[test]
    fn max_skip_exceeded_returns_error() {
        let TestContext {
            mut alice_session,
            mut bob_session,
            alice_id,
            bob_id,
        } = setup();

        for _ in 0..=MAX_SKIP {
            alice_session.encrypt(b"skip", &alice_id, &bob_id).unwrap();
        }
        let msg = alice_session
            .encrypt(b"too far", &alice_id, &bob_id)
            .unwrap();
        let result = bob_session.decrypt(&msg, &alice_id, &bob_id);
        assert!(matches!(result, Err(CryptoError::MaxSkipExceeded(_, _))));
    }

    fn make_bundle(
        bob_identity: &IdentityKeyPair,
        with_opk: bool,
    ) -> (
        crate::protocol::prekey::PreKeyBundle,
        [u8; 32],
        Option<[u8; 32]>,
        [u8; 64],
    ) {
        use crate::types::{DeviceId, KyberPreKeyId, PreKeyId, RegistrationId, SignedPreKeyId};
        use x25519_dalek::PublicKey as X25519Public;
        let mut spk_private = [0u8; 32];
        rand::rng().fill(&mut spk_private);
        let spk_secret = X25519Secret::from(spk_private);
        let spk_public = X25519Public::from(&spk_secret).to_bytes();
        let spk_sig = bob_identity.sign(&spk_public);

        let (opk_private, opk) = if with_opk {
            let mut opk_priv = [0u8; 32];
            rand::rng().fill(&mut opk_priv);
            let opk_secret = X25519Secret::from(opk_priv);
            let opk_pub = X25519Public::from(&opk_secret).to_bytes();
            (
                Some(opk_priv),
                Some(crate::protocol::prekey::OneTimePreKey {
                    id: PreKeyId::from(1),
                    public_key: DhPublicKey::from(opk_pub),
                }),
            )
        } else {
            (None, None)
        };

        let (dk, ek_bytes) = crate::protocol::pqxdh::generate_kyber_keypair();
        let kyber_sig = bob_identity.sign(&ek_bytes);

        let bundle = crate::protocol::prekey::PreKeyBundle {
            registration_id: RegistrationId::from(100),
            device_id: DeviceId::from(1),
            identity_key: bob_identity.public_key(),
            signed_pre_key_id: SignedPreKeyId::from(5),
            signed_pre_key_public: DhPublicKey::from(spk_public),
            signed_pre_key_signature: spk_sig,
            one_time_pre_key: opk,
            kyber_pre_key: crate::protocol::prekey::KyberPreKey {
                id: KyberPreKeyId::from(10),
                public_key: ek_bytes,
                signature: kyber_sig,
                is_last_resort: !with_opk,
            },
        };

        let dk_seed = crate::protocol::pqxdh::dk_to_seed_bytes(&dk);
        (bundle, spk_private, opk_private, dk_seed)
    }

    #[test]
    fn prekey_message_roundtrip_with_opk() {
        let alice_identity = IdentityKeyPair::generate();
        let bob_identity = IdentityKeyPair::generate();
        let alice_id = alice_identity.public_key();
        let bob_id = bob_identity.public_key();

        let (bundle, spk_private, opk_private, dk_seed) = make_bundle(&bob_identity, true);

        let mut pqxdh_output =
            crate::protocol::pqxdh::process_prekey_bundle(&alice_identity, &bundle).unwrap();
        pqxdh_output.initial_message.registration_id = crate::types::RegistrationId(100);
        let mut alice_session = RatchetSession::initialize_alice(
            &pqxdh_output.shared_secret,
            bundle.signed_pre_key_public.as_bytes(),
        )
        .unwrap();

        let prekey_msg = alice_session
            .encrypt_prekey_message(
                b"first contact",
                &alice_id,
                &bob_id,
                &pqxdh_output.initial_message,
            )
            .unwrap();

        assert_eq!(
            prekey_msg.registration_id,
            crate::types::RegistrationId(100)
        );
        assert_eq!(
            prekey_msg.signed_pre_key_id,
            crate::types::SignedPreKeyId(5)
        );
        assert_eq!(prekey_msg.pre_key_id, Some(crate::types::PreKeyId(1)));
        assert_eq!(prekey_msg.kyber_pre_key_id, crate::types::KyberPreKeyId(10));
        assert_eq!(prekey_msg.identity_key, alice_id);

        let (mut bob_session, plaintext) = RatchetSession::decrypt_prekey_message(
            &prekey_msg,
            &bob_identity,
            &spk_private,
            bundle.signed_pre_key_public.as_bytes(),
            opk_private.as_ref(),
            &dk_seed,
        )
        .unwrap();

        assert_eq!(plaintext, b"first contact");

        let reply = bob_session.encrypt(b"got it", &bob_id, &alice_id).unwrap();
        let reply_pt = alice_session.decrypt(&reply, &bob_id, &alice_id).unwrap();
        assert_eq!(reply_pt, b"got it");
    }

    #[test]
    fn prekey_message_roundtrip_without_opk() {
        let alice_identity = IdentityKeyPair::generate();
        let bob_identity = IdentityKeyPair::generate();
        let alice_id = alice_identity.public_key();
        let bob_id = bob_identity.public_key();

        let (bundle, spk_private, _, dk_seed) = make_bundle(&bob_identity, false);

        let pqxdh_output =
            crate::protocol::pqxdh::process_prekey_bundle(&alice_identity, &bundle).unwrap();
        let mut alice_session = RatchetSession::initialize_alice(
            &pqxdh_output.shared_secret,
            bundle.signed_pre_key_public.as_bytes(),
        )
        .unwrap();

        let prekey_msg = alice_session
            .encrypt_prekey_message(
                b"hello no opk",
                &alice_id,
                &bob_id,
                &pqxdh_output.initial_message,
            )
            .unwrap();

        assert!(prekey_msg.pre_key_id.is_none());

        let (mut bob_session, plaintext) = RatchetSession::decrypt_prekey_message(
            &prekey_msg,
            &bob_identity,
            &spk_private,
            bundle.signed_pre_key_public.as_bytes(),
            None,
            &dk_seed,
        )
        .unwrap();

        assert_eq!(plaintext, b"hello no opk");

        let msg2 = alice_session
            .encrypt(b"followup", &alice_id, &bob_id)
            .unwrap();
        assert_eq!(
            bob_session.decrypt(&msg2, &alice_id, &bob_id).unwrap(),
            b"followup"
        );

        let msg3 = bob_session.encrypt(b"reply", &bob_id, &alice_id).unwrap();
        assert_eq!(
            alice_session.decrypt(&msg3, &bob_id, &alice_id).unwrap(),
            b"reply"
        );
    }

    #[test]
    fn prekey_message_bidirectional_conversation() {
        let alice_identity = IdentityKeyPair::generate();
        let bob_identity = IdentityKeyPair::generate();
        let alice_id = alice_identity.public_key();
        let bob_id = bob_identity.public_key();

        let (bundle, spk_private, opk_private, dk_seed) = make_bundle(&bob_identity, true);

        let pqxdh_output =
            crate::protocol::pqxdh::process_prekey_bundle(&alice_identity, &bundle).unwrap();
        let mut alice = RatchetSession::initialize_alice(
            &pqxdh_output.shared_secret,
            bundle.signed_pre_key_public.as_bytes(),
        )
        .unwrap();

        let prekey_msg = alice
            .encrypt_prekey_message(b"init", &alice_id, &bob_id, &pqxdh_output.initial_message)
            .unwrap();

        let (mut bob, pt) = RatchetSession::decrypt_prekey_message(
            &prekey_msg,
            &bob_identity,
            &spk_private,
            bundle.signed_pre_key_public.as_bytes(),
            opk_private.as_ref(),
            &dk_seed,
        )
        .unwrap();
        assert_eq!(pt, b"init");

        for i in 0..10 {
            let m = alice
                .encrypt(format!("a-{i}").as_bytes(), &alice_id, &bob_id)
                .unwrap();
            assert_eq!(
                bob.decrypt(&m, &alice_id, &bob_id).unwrap(),
                format!("a-{i}").as_bytes()
            );

            let r = bob
                .encrypt(format!("b-{i}").as_bytes(), &bob_id, &alice_id)
                .unwrap();
            assert_eq!(
                alice.decrypt(&r, &bob_id, &alice_id).unwrap(),
                format!("b-{i}").as_bytes()
            );
        }
    }

    #[test]
    fn pending_prekey_auto_detect() {
        let alice_identity = IdentityKeyPair::generate();
        let bob_identity = IdentityKeyPair::generate();
        let alice_id = alice_identity.public_key();
        let bob_id = bob_identity.public_key();

        let (bundle, spk_private, opk_private, dk_seed) = make_bundle(&bob_identity, true);

        let pqxdh_output =
            crate::protocol::pqxdh::process_prekey_bundle(&alice_identity, &bundle).unwrap();
        let mut alice = RatchetSession::initialize_alice_with_prekey(
            &pqxdh_output.shared_secret,
            bundle.signed_pre_key_public.as_bytes(),
            pqxdh_output.initial_message,
        )
        .unwrap();

        // First encrypt_message should produce a PreKeyMessage
        let output1 = alice.encrypt_message(b"first", &alice_id, &bob_id).unwrap();
        let prekey_msg = match output1 {
            EncryptedOutput::PreKeyMessage(msg) => msg,
            EncryptedOutput::Message(_) => panic!("expected PreKeyMessage on first encrypt"),
        };

        // Second encrypt_message should produce a normal Message
        let output2 = alice
            .encrypt_message(b"second", &alice_id, &bob_id)
            .unwrap();
        assert!(
            matches!(output2, EncryptedOutput::Message(_)),
            "expected Message on second encrypt"
        );

        // Bob can decrypt the prekey message
        let (mut bob, pt) = RatchetSession::decrypt_prekey_message(
            &prekey_msg,
            &bob_identity,
            &spk_private,
            bundle.signed_pre_key_public.as_bytes(),
            opk_private.as_ref(),
            &dk_seed,
        )
        .unwrap();
        assert_eq!(pt, b"first");

        // Bob can also decrypt the second message
        let second_msg = match output2 {
            EncryptedOutput::Message(m) => m,
            _ => unreachable!(),
        };
        assert_eq!(
            bob.decrypt(&second_msg, &alice_id, &bob_id).unwrap(),
            b"second"
        );

        // Verify pending_prekey survives serialization and Bob can decrypt
        let alice_identity2 = IdentityKeyPair::generate();
        let bob_identity2 = IdentityKeyPair::generate();
        let (bundle2, spk_private2, opk_private2, dk_seed2) = make_bundle(&bob_identity2, true);
        let pqxdh2 =
            crate::protocol::pqxdh::process_prekey_bundle(&alice_identity2, &bundle2).unwrap();
        let session = RatchetSession::initialize_alice_with_prekey(
            &pqxdh2.shared_secret,
            bundle2.signed_pre_key_public.as_bytes(),
            pqxdh2.initial_message,
        )
        .unwrap();
        let serialized = session.serialize().unwrap();
        let mut restored = RatchetSession::deserialize(&serialized).unwrap();
        let output = restored
            .encrypt_message(
                b"after restore",
                &alice_identity2.public_key(),
                &bob_identity2.public_key(),
            )
            .unwrap();
        let prekey_msg2 = match output {
            EncryptedOutput::PreKeyMessage(msg) => msg,
            EncryptedOutput::Message(_) => {
                panic!("pending_prekey should survive serialization")
            }
        };

        let (_bob2, pt2) = RatchetSession::decrypt_prekey_message(
            &prekey_msg2,
            &bob_identity2,
            &spk_private2,
            bundle2.signed_pre_key_public.as_bytes(),
            opk_private2.as_ref(),
            &dk_seed2,
        )
        .unwrap();
        assert_eq!(pt2, b"after restore");
    }

    // ── Triple Ratchet (SPQR braid) integration ─────────────────────────────

    /// Run a full duplex ping-pong, asserting every message decrypts and the
    /// braid actually completes (and folds) epochs. Continued correct decryption
    /// *past* an epoch completion is the both-peers-identical-secret guarantee:
    /// the folded braid secret enters the root key, so a desync would fail AEAD.
    #[test]
    fn triple_ratchet_folds_epochs_and_stays_in_sync() {
        let TestContext {
            mut alice_session,
            mut bob_session,
            alice_id,
            bob_id,
        } = setup();

        let mut folded_after_completion = false;
        for i in 0..400u32 {
            let m = alice_session
                .encrypt(format!("a-{i}").as_bytes(), &alice_id, &bob_id)
                .unwrap();
            assert_eq!(
                bob_session.decrypt(&m, &alice_id, &bob_id).unwrap(),
                format!("a-{i}").as_bytes(),
                "alice->bob message {i} must decrypt"
            );

            let r = bob_session
                .encrypt(format!("b-{i}").as_bytes(), &bob_id, &alice_id)
                .unwrap();
            assert_eq!(
                alice_session.decrypt(&r, &bob_id, &alice_id).unwrap(),
                format!("b-{i}").as_bytes(),
                "bob->alice message {i} must decrypt"
            );

            // Once both have completed an epoch, exchanges keep succeeding, which
            // can only happen if both folded the identical braid secret.
            if alice_session.braid_completed_epochs().is_some()
                && bob_session.braid_completed_epochs().is_some()
            {
                folded_after_completion = true;
            }
        }

        assert!(
            folded_after_completion,
            "the braid must complete and fold at least one epoch over the run"
        );
        assert!(
            alice_session.braid_completed_epochs().is_some(),
            "alice must have completed a braid epoch"
        );
        assert!(
            bob_session.braid_completed_epochs().is_some(),
            "bob must have completed a braid epoch"
        );
    }

    /// CRITICAL: stripping the braid codeword from an otherwise-valid message must
    /// break that message at the AEAD layer (the header is authenticated AD),
    /// never silently downgrade to a classical-only decrypt.
    #[test]
    fn fail_closed_when_braid_codeword_stripped() {
        let TestContext {
            mut alice_session,
            mut bob_session,
            alice_id,
            bob_id,
        } = setup();

        // Warm up so a real braid codeword is being streamed.
        for i in 0..20 {
            let m = alice_session
                .encrypt(format!("warm {i}").as_bytes(), &alice_id, &bob_id)
                .unwrap();
            bob_session.decrypt(&m, &alice_id, &bob_id).unwrap();
            let r = bob_session.encrypt(b"ok", &bob_id, &alice_id).unwrap();
            alice_session.decrypt(&r, &bob_id, &alice_id).unwrap();
        }

        let mut msg = alice_session
            .encrypt(b"secret", &alice_id, &bob_id)
            .unwrap();

        // Strip the braid codeword: replace it with an idle step of the same epoch.
        let mut header = MessageHeader::deserialize(&msg.header).unwrap();
        assert!(
            header.braid_msg.chunk.is_some(),
            "warm-up should have a real codeword to strip"
        );
        header.braid_msg = crate::protocol::braid::Message::idle(header.braid_msg.epoch);
        msg.header = header.serialize();

        assert!(
            bob_session.decrypt(&msg, &alice_id, &bob_id).is_err(),
            "a stripped braid codeword must fail closed, not decrypt classical-only"
        );
    }

    /// The PQ counter `pq_message_number` is bound into the AEAD associated data, so
    /// a tampered counter must fail closed at the AEAD tag -- the same guarantee the
    /// decrypt path documents for the braid codeword, but for the PQ field that is
    /// NOT braid-authenticated and is the new attack surface this rework introduced.
    #[test]
    fn fail_closed_when_pq_message_number_tampered() {
        let TestContext {
            mut alice_session,
            mut bob_session,
            alice_id,
            bob_id,
        } = setup();

        // Warm up so the PQ chain is advancing past the bootstrap counter.
        for i in 0..20 {
            let m = alice_session
                .encrypt(format!("warm {i}").as_bytes(), &alice_id, &bob_id)
                .unwrap();
            bob_session.decrypt(&m, &alice_id, &bob_id).unwrap();
            let r = bob_session.encrypt(b"ok", &bob_id, &alice_id).unwrap();
            alice_session.decrypt(&r, &bob_id, &alice_id).unwrap();
        }

        let mut msg = alice_session
            .encrypt(b"secret", &alice_id, &bob_id)
            .unwrap();

        // Tamper only the PQ counter; the braid codeword and everything else stay
        // authentic.
        let mut header = MessageHeader::deserialize(&msg.header).unwrap();
        header.pq_message_number = header.pq_message_number.wrapping_add(1);
        msg.header = header.serialize();

        assert!(
            bob_session.decrypt(&msg, &alice_id, &bob_id).is_err(),
            "a tampered pq_message_number must fail closed at the AEAD tag"
        );
    }

    /// CRITICAL: an active MITM injecting a garbage braid codeword must not brick a
    /// wired session -- the forged message is rejected (AEAD), and the next honest
    /// message still decrypts.
    #[test]
    fn injected_garbage_codeword_does_not_brick_session() {
        let TestContext {
            mut alice_session,
            mut bob_session,
            alice_id,
            bob_id,
        } = setup();

        for i in 0..20 {
            let m = alice_session
                .encrypt(format!("warm {i}").as_bytes(), &alice_id, &bob_id)
                .unwrap();
            bob_session.decrypt(&m, &alice_id, &bob_id).unwrap();
            let r = bob_session.encrypt(b"ok", &bob_id, &alice_id).unwrap();
            alice_session.decrypt(&r, &bob_id, &alice_id).unwrap();
        }

        // Forge a message whose braid codeword bytes are garbled.
        let mut forged = alice_session
            .encrypt(b"forged", &alice_id, &bob_id)
            .unwrap();
        let mut header = MessageHeader::deserialize(&forged.header).unwrap();
        if let Some(chunk) = header.braid_msg.chunk.as_mut() {
            for b in chunk.data.iter_mut() {
                *b ^= 0xFF;
            }
        }
        forged.header = header.serialize();
        assert!(
            bob_session.decrypt(&forged, &alice_id, &bob_id).is_err(),
            "garbled codeword (and thus header AD) must be rejected"
        );

        // The session is not bricked: the next honest message still flows. (Note
        // the forged message consumed a sending-chain key on alice's side, so we
        // simply continue the conversation from a fresh message.)
        let good = alice_session
            .encrypt(b"still here", &alice_id, &bob_id)
            .unwrap();
        // bob skips the forged message's number and decrypts the next one.
        assert_eq!(
            bob_session.decrypt(&good, &alice_id, &bob_id).unwrap(),
            b"still here",
            "an honest message after injected garbage must still decrypt"
        );
    }

    /// CRITICAL: losing braid-codeword-bearing messages must not permanently wedge
    /// the session. Reed-Solomon re-streaming recovers, the braid still completes
    /// epochs, and all *delivered* messages decrypt.
    #[test]
    fn message_loss_does_not_wedge_braid() {
        let TestContext {
            mut alice_session,
            mut bob_session,
            alice_id,
            bob_id,
        } = setup();

        let mut delivered = 0u32;
        for i in 0..400u32 {
            // Drop one in three alice->bob messages (their codewords are lost).
            // The first message is always delivered: bob's sending chain is only
            // established once he has received from alice (standard Double Ratchet).
            let m = alice_session
                .encrypt(format!("a-{i}").as_bytes(), &alice_id, &bob_id)
                .unwrap();
            if i == 0 || i % 3 != 0 {
                assert_eq!(
                    bob_session.decrypt(&m, &alice_id, &bob_id).unwrap(),
                    format!("a-{i}").as_bytes(),
                    "delivered alice->bob message {i} must decrypt"
                );
                delivered += 1;
            }

            // Bob always replies (delivered) so the braid can ping-pong.
            let r = bob_session
                .encrypt(format!("b-{i}").as_bytes(), &bob_id, &alice_id)
                .unwrap();
            assert_eq!(
                alice_session.decrypt(&r, &bob_id, &alice_id).unwrap(),
                format!("b-{i}").as_bytes(),
                "bob->alice message {i} must decrypt despite upstream loss"
            );
        }

        assert!(delivered > 0);
        assert!(
            bob_session.braid_completed_epochs().is_some(),
            "the braid must still complete an epoch despite codeword loss"
        );
    }

    /// The mirror of `message_loss_does_not_wedge_braid`: losing bob->alice
    /// codeword-bearing messages must also recover via re-streaming. Exercises the
    /// receive-side reassembly in alice's role, which the forward-only test never
    /// touches.
    #[test]
    fn reverse_message_loss_does_not_wedge_braid() {
        let TestContext {
            mut alice_session,
            mut bob_session,
            alice_id,
            bob_id,
        } = setup();

        let mut delivered = 0u32;
        for i in 0..400u32 {
            // Alice always reaches bob, so bob's sending chain stays established.
            let m = alice_session
                .encrypt(format!("a-{i}").as_bytes(), &alice_id, &bob_id)
                .unwrap();
            assert_eq!(
                bob_session.decrypt(&m, &alice_id, &bob_id).unwrap(),
                format!("a-{i}").as_bytes(),
                "alice->bob message {i} must decrypt"
            );

            // Drop one in three bob->alice messages (their codewords are lost).
            // The first reply is always delivered so alice ratchets onto bob's key.
            let r = bob_session
                .encrypt(format!("b-{i}").as_bytes(), &bob_id, &alice_id)
                .unwrap();
            if i == 0 || i % 3 != 0 {
                assert_eq!(
                    alice_session.decrypt(&r, &bob_id, &alice_id).unwrap(),
                    format!("b-{i}").as_bytes(),
                    "delivered bob->alice message {i} must decrypt despite loss"
                );
                delivered += 1;
            }
        }

        assert!(delivered > 0);
        assert!(
            alice_session.braid_completed_epochs().is_some(),
            "the braid must still complete an epoch despite reverse-direction loss"
        );
    }

    /// Mid-stream serialize/deserialize of both peers resumes the braid (its
    /// in-flight reassembly is persisted) and the session keeps converging.
    #[test]
    fn braid_resumes_across_serialization_midstream() {
        let TestContext {
            mut alice_session,
            mut bob_session,
            alice_id,
            bob_id,
        } = setup();

        // Get mid-braid (a header/ek/ct is partway through streaming).
        for i in 0..10 {
            let m = alice_session
                .encrypt(format!("pre {i}").as_bytes(), &alice_id, &bob_id)
                .unwrap();
            bob_session.decrypt(&m, &alice_id, &bob_id).unwrap();
            let r = bob_session.encrypt(b"pre-r", &bob_id, &alice_id).unwrap();
            alice_session.decrypt(&r, &bob_id, &alice_id).unwrap();
        }

        let mut alice = RatchetSession::deserialize(&alice_session.serialize().unwrap()).unwrap();
        let mut bob = RatchetSession::deserialize(&bob_session.serialize().unwrap()).unwrap();

        // Resume and run long enough to complete an epoch post-restore.
        for i in 0..400u32 {
            let m = alice
                .encrypt(format!("post {i}").as_bytes(), &alice_id, &bob_id)
                .unwrap();
            assert_eq!(
                bob.decrypt(&m, &alice_id, &bob_id).unwrap(),
                format!("post {i}").as_bytes()
            );
            let r = bob
                .encrypt(format!("post-r {i}").as_bytes(), &bob_id, &alice_id)
                .unwrap();
            assert_eq!(
                alice.decrypt(&r, &bob_id, &alice_id).unwrap(),
                format!("post-r {i}").as_bytes()
            );
        }
        assert!(
            bob.braid_completed_epochs().is_some(),
            "the braid must complete an epoch after a mid-stream restore"
        );
    }

    // ── Property-based fail-closed coverage (bolero) ─────────────────────────
    //
    // One body per property. Each runs as a fast unit test under `cargo test`
    // (bolero's default ~1s time budget per property) AND as a libfuzzer target
    // under `cargo bolero test <name> --engine libfuzzer` (and, later, a Kani
    // harness under `--engine kani`). Every closure builds a FRESH session pair
    // per input (`fresh_pair`) so ratchet state never bleeds between iterations
    // and the skipped-key store cannot grow unbounded across a fuzz campaign.
    //
    // The session/AEAD layer draws from the thread RNG internally (DH keypairs,
    // SPQR send), so these bodies are not fully input-deterministic; full
    // determinism (needed for the Kani engine) is part of the later
    // pure-core-extraction track, not Tier 1.
    use bolero::check;

    fn fresh_pair() -> (RatchetSession, RatchetSession) {
        let ss = make_shared_secret();
        let bob_dh = make_dh_keypair();
        (
            RatchetSession::initialize_alice(&ss, &bob_dh.1).unwrap(),
            RatchetSession::initialize_bob(&ss, bob_dh),
        )
    }

    /// P1: arbitrary plaintext round-trips through the real encrypt/decrypt path
    /// (also exercises pad/unpad over every length).
    #[test]
    fn prop_roundtrip() {
        let alice_id = IdentityKeyPair::generate().public_key();
        let bob_id = IdentityKeyPair::generate().public_key();
        check!().with_type::<Vec<u8>>().for_each(|pt| {
            let (mut alice, mut bob) = fresh_pair();
            let msg = alice.encrypt(pt, &alice_id, &bob_id).unwrap();
            assert_eq!(&bob.decrypt(&msg, &alice_id, &bob_id).unwrap(), pt);
        });
    }

    /// P1b: a multi-message, bidirectional interleaving round-trips, exercising
    /// the DH ratchet step (on each direction change) and chain advance — not
    /// just a single message.
    #[test]
    fn prop_multi_message_dh_ratchet_roundtrip() {
        let alice_id = IdentityKeyPair::generate().public_key();
        let bob_id = IdentityKeyPair::generate().public_key();
        check!()
            .with_type::<Vec<(bool, Vec<u8>)>>()
            .for_each(|sched| {
                let (mut alice, mut bob) = fresh_pair();
                let mut bob_can_send = false;
                for (to_bob, pt) in sched.iter().take(24) {
                    // Bob has no sending chain until he has received from Alice,
                    // so force Alice->Bob until then (standard Double Ratchet).
                    if *to_bob || !bob_can_send {
                        let m = alice.encrypt(pt, &alice_id, &bob_id).unwrap();
                        assert_eq!(&bob.decrypt(&m, &alice_id, &bob_id).unwrap(), pt);
                        bob_can_send = true;
                    } else {
                        let m = bob.encrypt(pt, &bob_id, &alice_id).unwrap();
                        assert_eq!(&alice.decrypt(&m, &bob_id, &alice_id).unwrap(), pt);
                    }
                }
            });
    }

    /// P2: any mutation of the ciphertext fails closed — never `Ok` with altered
    /// plaintext.
    #[test]
    fn prop_ciphertext_mutation_fails_closed() {
        let alice_id = IdentityKeyPair::generate().public_key();
        let bob_id = IdentityKeyPair::generate().public_key();
        check!()
            .with_type::<(Vec<u8>, usize, u8)>()
            .for_each(|(pt, idx, mask)| {
                let (mut alice, mut bob) = fresh_pair();
                let mut msg = alice.encrypt(pt, &alice_id, &bob_id).unwrap();
                if msg.ciphertext.is_empty() {
                    return;
                }
                let i = *idx % msg.ciphertext.len();
                msg.ciphertext[i] ^= *mask | 1; // `| 1` guarantees a real change
                assert!(
                    bob.decrypt(&msg, &alice_id, &bob_id).is_err(),
                    "mutated ciphertext must fail closed"
                );
            });
    }

    /// P3: AD binding — any header mutation, or a swapped sender identity, fails
    /// closed (the whole header + both identities are bound into the AEAD AD).
    #[test]
    fn prop_ad_binding_fails_closed() {
        let alice_id = IdentityKeyPair::generate().public_key();
        let bob_id = IdentityKeyPair::generate().public_key();
        let eve_id = IdentityKeyPair::generate().public_key();
        check!()
            .with_type::<(Vec<u8>, usize, u8, bool)>()
            .for_each(|(pt, idx, mask, swap_id)| {
                let (mut alice, mut bob) = fresh_pair();
                let mut msg = alice.encrypt(pt, &alice_id, &bob_id).unwrap();
                if *swap_id {
                    // Authentic bytes, wrong bound identity -> AD mismatch.
                    assert!(
                        bob.decrypt(&msg, &eve_id, &bob_id).is_err(),
                        "wrong sender identity must fail closed"
                    );
                } else {
                    if msg.header.is_empty() {
                        return;
                    }
                    let i = *idx % msg.header.len();
                    msg.header[i] ^= *mask | 1;
                    assert!(
                        bob.decrypt(&msg, &alice_id, &bob_id).is_err(),
                        "mutated header must fail closed"
                    );
                }
            });
    }

    /// P4: stripping (idle-swap) or garbling the braid codeword fails closed —
    /// never a silent downgrade to classical-only. Warms up so a real codeword is
    /// streaming; skips iterations where this message carries no chunk.
    #[test]
    fn prop_codeword_strip_or_garble_fails_closed() {
        let alice_id = IdentityKeyPair::generate().public_key();
        let bob_id = IdentityKeyPair::generate().public_key();
        check!()
            .with_type::<(Vec<u8>, bool)>()
            .for_each(|(pt, garble)| {
                let (mut alice, mut bob) = fresh_pair();
                for i in 0..12u32 {
                    let m = alice
                        .encrypt(format!("warm{i}").as_bytes(), &alice_id, &bob_id)
                        .unwrap();
                    bob.decrypt(&m, &alice_id, &bob_id).unwrap();
                    let r = bob.encrypt(b"ok", &bob_id, &alice_id).unwrap();
                    alice.decrypt(&r, &bob_id, &alice_id).unwrap();
                }
                let mut msg = alice.encrypt(pt, &alice_id, &bob_id).unwrap();
                let mut header = MessageHeader::deserialize(&msg.header).unwrap();
                if header.braid_msg.chunk.is_none() {
                    return; // no codeword to strip this round
                }
                if *garble {
                    for b in header.braid_msg.chunk.as_mut().unwrap().data.iter_mut() {
                        *b ^= 0xFF;
                    }
                } else {
                    header.braid_msg =
                        crate::protocol::braid::Message::idle(header.braid_msg.epoch);
                }
                msg.header = header.serialize();
                assert!(
                    bob.decrypt(&msg, &alice_id, &bob_id).is_err(),
                    "stripped/garbled codeword must fail closed"
                );
            });
    }

    /// P4b: out-of-order EC delivery within `MAX_SKIP` resolves via the
    /// skipped-key store; every delivered message decrypts to its own plaintext.
    /// (Beyond-`MAX_SKIP` rejection is pinned by `max_skip_exceeded_returns_error`.)
    #[test]
    fn prop_out_of_order_within_chain() {
        let alice_id = IdentityKeyPair::generate().public_key();
        let bob_id = IdentityKeyPair::generate().public_key();
        check!().with_type::<Vec<u8>>().for_each(|order_seed| {
            let (mut alice, mut bob) = fresh_pair();
            // Establish bob's receiving chain.
            let prime = alice.encrypt(b"prime", &alice_id, &bob_id).unwrap();
            bob.decrypt(&prime, &alice_id, &bob_id).unwrap();
            let k = 2 + (order_seed.len() % 8); // 2..=9, well within MAX_SKIP
            let msgs: Vec<RatchetMessage> = (0..k)
                .map(|i| {
                    alice
                        .encrypt(format!("m{i}").as_bytes(), &alice_id, &bob_id)
                        .unwrap()
                })
                .collect();
            // Permute the delivery order by the input (stays a permutation).
            let mut idx: Vec<usize> = (0..k).collect();
            for (i, b) in order_seed.iter().enumerate() {
                idx.swap(i % k, (*b as usize) % k);
            }
            for &i in &idx {
                assert_eq!(
                    bob.decrypt(&msgs[i], &alice_id, &bob_id).unwrap(),
                    format!("m{i}").as_bytes(),
                    "out-of-order message {i} must decrypt to its own plaintext"
                );
            }
        });
    }

    /// P4d: the PQXDH first-message (prekey) decrypt path round-trips, and any
    /// tampering of the wrapped message fails closed. The bundle/identities (the
    /// expensive ML-KEM keygen) are built once; each input gets a fresh session.
    #[test]
    fn prop_prekey_path_fail_closed() {
        let alice_identity = IdentityKeyPair::generate();
        let bob_identity = IdentityKeyPair::generate();
        let alice_id = alice_identity.public_key();
        let bob_id = bob_identity.public_key();
        let (bundle, spk_private, opk_private, dk_seed) = make_bundle(&bob_identity, true);
        let spk_public = *bundle.signed_pre_key_public.as_bytes();
        check!()
            .with_type::<(Vec<u8>, bool)>()
            .for_each(|(pt, tamper)| {
                let pqxdh = crate::protocol::pqxdh::process_prekey_bundle(&alice_identity, &bundle)
                    .unwrap();
                let mut alice =
                    RatchetSession::initialize_alice(&pqxdh.shared_secret, &spk_public).unwrap();
                let mut prekey_msg = alice
                    .encrypt_prekey_message(pt, &alice_id, &bob_id, &pqxdh.initial_message)
                    .unwrap();
                if *tamper {
                    if prekey_msg.message.ciphertext.is_empty() {
                        return;
                    }
                    let last = prekey_msg.message.ciphertext.len() - 1;
                    prekey_msg.message.ciphertext[last] ^= 0xFF;
                    let r = RatchetSession::decrypt_prekey_message(
                        &prekey_msg,
                        &bob_identity,
                        &spk_private,
                        &spk_public,
                        opk_private.as_ref(),
                        &dk_seed,
                    );
                    assert!(r.is_err(), "tampered prekey message must fail closed");
                } else {
                    let (_bob, plaintext) = RatchetSession::decrypt_prekey_message(
                        &prekey_msg,
                        &bob_identity,
                        &spk_private,
                        &spk_public,
                        opk_private.as_ref(),
                        &dk_seed,
                    )
                    .unwrap();
                    assert_eq!(&plaintext, pt);
                }
            });
    }
}
