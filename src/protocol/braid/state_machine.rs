//! The ML-KEM Braid state machine (`mlkembraid` spec).
//!
//! A faithful translation of the spec's 11-state machine. Each party runs one
//! [`BraidState`]; per epoch one party sends the encapsulation-key header and
//! the other encapsulates, and the roles swap each epoch. The braid emits one
//! [`EpochSecret`] per epoch (the encapsulator early, in `HeaderReceived` send;
//! the keypair owner after the full ciphertext arrives, in `EkSentCt1Received`
//! receive); both parties derive the same secret.
//!
//! Large objects (header, ek_vector, ct1, ct2) are streamed as erasure
//! codewords (see [`super::erasure`]); the KEM is the incremental ML-KEM-768
//! primitive (see [`super::kem`]); per-epoch authentication is the
//! [`Authenticator`] ratchet (see [`super::auth`]).

use rand_core::CryptoRng;
use serde::{Deserialize, Serialize};

use crate::error::{CryptoError, Result};

use super::auth::{Authenticator, kdf_ok};
use super::erasure::{Chunk, Decoder, Encoder};
use super::kem;

/// MAC length appended to the header and to ct2 (HMAC-SHA256).
const MAC_SIZE: usize = 32;

/// The braid's initial epoch, per the ML-KEM Braid spec (`InitAlice`/`InitBob`:
/// `epoch = 1`). The first completed KEM key agreement therefore yields epoch 1;
/// epoch 0 is the bootstrap epoch the SPQR layer covers with its `KDF_SCKA_INIT`
/// chains before any braid secret completes. With `sending_epoch = epoch - 1`
/// (the spec's one-epoch lag), the first messages are sent under epoch 0.
const INITIAL_EPOCH: u64 = 1;

fn proto_err(msg: &str) -> CryptoError {
    CryptoError::BraidKem(msg.into())
}

/// The type of a braid wire message.
///
/// These match the ML-KEM Braid spec's message-type enum and its `Send`/`Receive`
/// pseudocode. The spec also lists a `Ct1Ack` variant (a bare ack with no payload),
/// but its braid `Send` pseudocode never emits it and no `Receive` handler matches
/// it -- the keypair owner always acknowledges ct1 by sending `EkCt1Ack` (an
/// ek_vector codeword carrying the ack), and re-streams ek (the encoder cycles)
/// while waiting. We therefore omit the unused `Ct1Ack`; this set is 1:1 with the
/// spec's actual braid flow. (`Idle` is the spec's `None`.)
#[derive(Clone, Copy, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub enum MsgType {
    /// No payload this step (the party has nothing to send yet). Spec `None`.
    Idle,
    /// An encapsulation-key header codeword (`header || mac`).
    Hdr,
    /// An ek_vector codeword.
    Ek,
    /// An ek_vector codeword that also acknowledges ct1 receipt.
    EkCt1Ack,
    /// A ct1 codeword.
    Ct1,
    /// A ct2 codeword (`ct2 || mac`).
    Ct2,
}

/// One braid wire message: an epoch, a type, and at most one codeword.
#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub struct Message {
    /// The braid epoch this message belongs to.
    pub epoch: u64,
    /// What the message carries.
    pub mtype: MsgType,
    /// The erasure codeword, if any.
    pub chunk: Option<Chunk>,
}

impl Message {
    /// A no-payload step for `epoch` (the party has nothing to stream this turn).
    pub fn idle(epoch: u64) -> Self {
        Self {
            epoch,
            mtype: MsgType::Idle,
            chunk: None,
        }
    }
    fn carrying(epoch: u64, mtype: MsgType, chunk: Chunk) -> Self {
        Self {
            epoch,
            mtype,
            chunk: Some(chunk),
        }
    }
}

/// A completed per-epoch shared secret, ready for the Double Ratchet to mix in.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub struct EpochSecret {
    /// The epoch this secret belongs to.
    pub epoch: u64,
    /// The 32-byte secret (already `KDF_OK`-derived).
    pub secret: [u8; 32],
}

/// Output of [`BraidState::send`] -- the spec's `SCKASend(state) -> (msg,
/// sending_epoch, output_key)`.
#[derive(Debug)]
pub struct SckaSend {
    /// The codeword to hand to the peer.
    pub msg: Message,
    /// The latest epoch guaranteed known to the peer once it processes `msg`
    /// (`state.epoch - 1`) -- the epoch whose SPQR chain keys this message.
    pub sending_epoch: u64,
    /// A completed epoch secret, if one finished this step.
    pub output_key: Option<EpochSecret>,
}

/// Output of [`BraidState::receive`] -- the spec's `SCKAReceive(state, msg) ->
/// (receiving_epoch, output_key)`.
#[derive(Debug)]
pub struct SckaReceive {
    /// The epoch whose SPQR chain decrypts this message (by epoch agreement, equal
    /// to the `sending_epoch` the peer used).
    pub receiving_epoch: u64,
    /// A completed epoch secret, if one finished this step.
    pub output_key: Option<EpochSecret>,
}

/// The 11 protocol states. `header` is the libcrux `pk1` (`ek_seed || hek`);
/// `ek_vector` is `pk2`; `dk` is the serialized keypair; `encaps_secret` is the
/// incremental encapsulation state.
#[derive(Clone, Serialize, Deserialize)]
enum State {
    KeysUnsampled {
        epoch: u64,
        auth: Authenticator,
    },
    KeysSampled {
        epoch: u64,
        auth: Authenticator,
        dk: Vec<u8>,
        ek_vector: Vec<u8>,
        header_enc: Encoder,
    },
    HeaderSent {
        epoch: u64,
        auth: Authenticator,
        dk: Vec<u8>,
        ct1_dec: Decoder,
        ek_enc: Encoder,
    },
    Ct1Received {
        epoch: u64,
        auth: Authenticator,
        dk: Vec<u8>,
        ct1: Vec<u8>,
        ek_enc: Encoder,
    },
    EkSentCt1Received {
        epoch: u64,
        auth: Authenticator,
        dk: Vec<u8>,
        ct1: Vec<u8>,
        ct2_dec: Decoder,
    },
    NoHeaderReceived {
        epoch: u64,
        auth: Authenticator,
        hdr_dec: Decoder,
    },
    HeaderReceived {
        epoch: u64,
        auth: Authenticator,
        header: Vec<u8>,
        ek_dec: Decoder,
    },
    Ct1Sampled {
        epoch: u64,
        auth: Authenticator,
        header: Vec<u8>,
        encaps_secret: Vec<u8>,
        ct1: Vec<u8>,
        ct1_enc: Encoder,
        ek_dec: Decoder,
    },
    EkReceivedCt1Sampled {
        epoch: u64,
        auth: Authenticator,
        encaps_secret: Vec<u8>,
        ct1: Vec<u8>,
        ek_vector: Vec<u8>,
        ct1_enc: Encoder,
    },
    Ct1Acknowledged {
        epoch: u64,
        auth: Authenticator,
        encaps_secret: Vec<u8>,
        header: Vec<u8>,
        ct1: Vec<u8>,
        ek_dec: Decoder,
    },
    Ct2Sampled {
        epoch: u64,
        auth: Authenticator,
        ct2_enc: Encoder,
    },
    /// Transient placeholder while a transition takes ownership of the state.
    Poisoned,
}

/// Encapsulate ct2 and build the `ct2 || mac`-carrying encoder, the shared tail
/// of three receiver transitions.
fn build_ct2_encoder(
    auth: &Authenticator,
    epoch: u64,
    encaps_secret: &[u8],
    ek_vector: &[u8],
    ct1: &[u8],
) -> Result<Encoder> {
    let ct2 = kem::encapsulate2(encaps_secret, ek_vector)?;
    let mut ct = Vec::with_capacity(ct1.len() + ct2.len());
    ct.extend_from_slice(ct1);
    ct.extend_from_slice(&ct2);
    let mac = auth.mac_ct(epoch, &ct);
    let mut payload = ct2;
    payload.extend_from_slice(&mac);
    Encoder::new(&payload)
}

type Transition = Result<(State, Option<EpochSecret>)>;

impl State {
    /// The epoch this state is currently negotiating (`state.epoch` in the spec).
    /// `Poisoned` is transient and never queried on the live paths; it reports 0.
    fn epoch(&self) -> u64 {
        match self {
            State::KeysUnsampled { epoch, .. }
            | State::KeysSampled { epoch, .. }
            | State::HeaderSent { epoch, .. }
            | State::Ct1Received { epoch, .. }
            | State::EkSentCt1Received { epoch, .. }
            | State::NoHeaderReceived { epoch, .. }
            | State::HeaderReceived { epoch, .. }
            | State::Ct1Sampled { epoch, .. }
            | State::EkReceivedCt1Sampled { epoch, .. }
            | State::Ct1Acknowledged { epoch, .. }
            | State::Ct2Sampled { epoch, .. } => *epoch,
            State::Poisoned => 0,
        }
    }

    fn send<R: CryptoRng>(self, rng: &mut R) -> Result<(State, Message, Option<EpochSecret>)> {
        match self {
            State::KeysUnsampled { epoch, auth } => {
                // KeyGen, build header || mac, start streaming the header.
                let mut seed = [0u8; kem::SEED_LEN];
                rng.fill_bytes(&mut seed);
                let dk = kem::generate_keypair(&seed);
                let (header, ek_vector) = kem::public_key_parts(&dk)?;
                let mac = auth.mac_hdr(epoch, &header);
                let mut header_with_mac = header;
                header_with_mac.extend_from_slice(&mac);
                let mut header_enc = Encoder::new(&header_with_mac)?;
                let chunk = header_enc.next_chunk();
                Ok((
                    State::KeysSampled {
                        epoch,
                        auth,
                        dk,
                        ek_vector,
                        header_enc,
                    },
                    Message::carrying(epoch, MsgType::Hdr, chunk),
                    None,
                ))
            }
            State::KeysSampled {
                epoch,
                auth,
                dk,
                ek_vector,
                mut header_enc,
            } => {
                let chunk = header_enc.next_chunk();
                Ok((
                    State::KeysSampled {
                        epoch,
                        auth,
                        dk,
                        ek_vector,
                        header_enc,
                    },
                    Message::carrying(epoch, MsgType::Hdr, chunk),
                    None,
                ))
            }
            State::HeaderSent {
                epoch,
                auth,
                dk,
                ct1_dec,
                mut ek_enc,
            } => {
                let chunk = ek_enc.next_chunk();
                Ok((
                    State::HeaderSent {
                        epoch,
                        auth,
                        dk,
                        ct1_dec,
                        ek_enc,
                    },
                    Message::carrying(epoch, MsgType::Ek, chunk),
                    None,
                ))
            }
            State::Ct1Received {
                epoch,
                auth,
                dk,
                ct1,
                mut ek_enc,
            } => {
                let chunk = ek_enc.next_chunk();
                Ok((
                    State::Ct1Received {
                        epoch,
                        auth,
                        dk,
                        ct1,
                        ek_enc,
                    },
                    Message::carrying(epoch, MsgType::EkCt1Ack, chunk),
                    None,
                ))
            }
            State::EkSentCt1Received {
                epoch,
                auth,
                dk,
                ct1,
                ct2_dec,
            } => Ok((
                State::EkSentCt1Received {
                    epoch,
                    auth,
                    dk,
                    ct1,
                    ct2_dec,
                },
                Message::idle(epoch),
                None,
            )),
            State::NoHeaderReceived {
                epoch,
                auth,
                hdr_dec,
            } => Ok((
                State::NoHeaderReceived {
                    epoch,
                    auth,
                    hdr_dec,
                },
                Message::idle(epoch),
                None,
            )),
            State::HeaderReceived {
                epoch,
                mut auth,
                header,
                ek_dec,
            } => {
                // Encapsulate ct1 from the header alone, learn (and output) the
                // epoch secret, and ratchet the authenticator forward.
                let mut randomness = [0u8; kem::ENCAPS_RANDOMNESS_LEN];
                rng.fill_bytes(&mut randomness);
                let (ct1, encaps_secret, raw_ss) = kem::encapsulate1(&header, &randomness)?;
                let ss = kdf_ok(&raw_ss, epoch);
                auth.update(epoch, &ss);
                let mut ct1_enc = Encoder::new(&ct1)?;
                let chunk = ct1_enc.next_chunk();
                Ok((
                    State::Ct1Sampled {
                        epoch,
                        auth,
                        header,
                        encaps_secret,
                        ct1,
                        ct1_enc,
                        ek_dec,
                    },
                    Message::carrying(epoch, MsgType::Ct1, chunk),
                    Some(EpochSecret { epoch, secret: ss }),
                ))
            }
            State::Ct1Sampled {
                epoch,
                auth,
                header,
                encaps_secret,
                ct1,
                mut ct1_enc,
                ek_dec,
            } => {
                let chunk = ct1_enc.next_chunk();
                Ok((
                    State::Ct1Sampled {
                        epoch,
                        auth,
                        header,
                        encaps_secret,
                        ct1,
                        ct1_enc,
                        ek_dec,
                    },
                    Message::carrying(epoch, MsgType::Ct1, chunk),
                    None,
                ))
            }
            State::EkReceivedCt1Sampled {
                epoch,
                auth,
                encaps_secret,
                ct1,
                ek_vector,
                mut ct1_enc,
            } => {
                let chunk = ct1_enc.next_chunk();
                Ok((
                    State::EkReceivedCt1Sampled {
                        epoch,
                        auth,
                        encaps_secret,
                        ct1,
                        ek_vector,
                        ct1_enc,
                    },
                    Message::carrying(epoch, MsgType::Ct1, chunk),
                    None,
                ))
            }
            State::Ct1Acknowledged {
                epoch,
                auth,
                encaps_secret,
                header,
                ct1,
                ek_dec,
            } => Ok((
                State::Ct1Acknowledged {
                    epoch,
                    auth,
                    encaps_secret,
                    header,
                    ct1,
                    ek_dec,
                },
                Message::idle(epoch),
                None,
            )),
            State::Ct2Sampled {
                epoch,
                auth,
                mut ct2_enc,
            } => {
                let chunk = ct2_enc.next_chunk();
                Ok((
                    State::Ct2Sampled {
                        epoch,
                        auth,
                        ct2_enc,
                    },
                    Message::carrying(epoch, MsgType::Ct2, chunk),
                    None,
                ))
            }
            State::Poisoned => Err(proto_err("braid state poisoned")),
        }
    }

    /// Dispatch an incoming message to the current state's handler. Each handler
    /// is a small free function so this stays a thin dispatcher.
    fn receive(self, msg: &Message) -> Transition {
        match self {
            State::KeysSampled {
                epoch,
                auth,
                dk,
                ek_vector,
                header_enc,
            } => recv_keys_sampled(msg, epoch, auth, dk, ek_vector, header_enc),
            State::HeaderSent {
                epoch,
                auth,
                dk,
                ct1_dec,
                ek_enc,
            } => recv_header_sent(msg, epoch, auth, dk, ct1_dec, ek_enc),
            State::Ct1Received {
                epoch,
                auth,
                dk,
                ct1,
                ek_enc,
            } => recv_ct1_received(msg, epoch, auth, dk, ct1, ek_enc),
            State::EkSentCt1Received {
                epoch,
                auth,
                dk,
                ct1,
                ct2_dec,
            } => recv_ek_sent_ct1_received(msg, epoch, auth, dk, ct1, ct2_dec),
            State::NoHeaderReceived {
                epoch,
                auth,
                hdr_dec,
            } => recv_no_header_received(msg, epoch, auth, hdr_dec),
            State::Ct1Sampled {
                epoch,
                auth,
                header,
                encaps_secret,
                ct1,
                ct1_enc,
                ek_dec,
            } => recv_ct1_sampled(
                msg,
                epoch,
                auth,
                header,
                encaps_secret,
                ct1,
                ct1_enc,
                ek_dec,
            ),
            State::EkReceivedCt1Sampled {
                epoch,
                auth,
                encaps_secret,
                ct1,
                ek_vector,
                ct1_enc,
            } => recv_ek_received_ct1_sampled(
                msg,
                epoch,
                auth,
                encaps_secret,
                ct1,
                ek_vector,
                ct1_enc,
            ),
            State::Ct1Acknowledged {
                epoch,
                auth,
                encaps_secret,
                header,
                ct1,
                ek_dec,
            } => recv_ct1_acknowledged(msg, epoch, auth, encaps_secret, header, ct1, ek_dec),
            State::Ct2Sampled {
                epoch,
                auth,
                ct2_enc,
            } => recv_ct2_sampled(msg, epoch, auth, ct2_enc),
            // KeysUnsampled, HeaderReceived, Poisoned: Receive is a no-op.
            other => Ok((other, None)),
        }
    }
}

#[allow(clippy::too_many_arguments)]
fn recv_keys_sampled(
    msg: &Message,
    epoch: u64,
    auth: Authenticator,
    dk: Vec<u8>,
    ek_vector: Vec<u8>,
    header_enc: Encoder,
) -> Transition {
    if msg.epoch == epoch && msg.mtype == MsgType::Ct1 {
        let mut ct1_dec = Decoder::new(kem::ct1_len());
        add_chunk(&mut ct1_dec, msg)?;
        let ek_enc = Encoder::new(&ek_vector)?;
        return Ok((
            State::HeaderSent {
                epoch,
                auth,
                dk,
                ct1_dec,
                ek_enc,
            },
            None,
        ));
    }
    Ok((
        State::KeysSampled {
            epoch,
            auth,
            dk,
            ek_vector,
            header_enc,
        },
        None,
    ))
}

fn recv_header_sent(
    msg: &Message,
    epoch: u64,
    auth: Authenticator,
    dk: Vec<u8>,
    mut ct1_dec: Decoder,
    ek_enc: Encoder,
) -> Transition {
    if msg.epoch == epoch && msg.mtype == MsgType::Ct1 {
        add_chunk(&mut ct1_dec, msg)?;
        if let Some(ct1) = ct1_dec.message()? {
            return Ok((
                State::Ct1Received {
                    epoch,
                    auth,
                    dk,
                    ct1,
                    ek_enc,
                },
                None,
            ));
        }
    }
    Ok((
        State::HeaderSent {
            epoch,
            auth,
            dk,
            ct1_dec,
            ek_enc,
        },
        None,
    ))
}

fn recv_ct1_received(
    msg: &Message,
    epoch: u64,
    auth: Authenticator,
    dk: Vec<u8>,
    ct1: Vec<u8>,
    ek_enc: Encoder,
) -> Transition {
    if msg.epoch == epoch && msg.mtype == MsgType::Ct2 {
        let mut ct2_dec = Decoder::new(kem::ct2_len() + MAC_SIZE);
        add_chunk(&mut ct2_dec, msg)?;
        return Ok((
            State::EkSentCt1Received {
                epoch,
                auth,
                dk,
                ct1,
                ct2_dec,
            },
            None,
        ));
    }
    Ok((
        State::Ct1Received {
            epoch,
            auth,
            dk,
            ct1,
            ek_enc,
        },
        None,
    ))
}

fn recv_ek_sent_ct1_received(
    msg: &Message,
    epoch: u64,
    auth: Authenticator,
    dk: Vec<u8>,
    ct1: Vec<u8>,
    mut ct2_dec: Decoder,
) -> Transition {
    if msg.epoch == epoch && msg.mtype == MsgType::Ct2 {
        add_chunk(&mut ct2_dec, msg)?;
        if let Some(ct2_with_mac) = ct2_dec.message()? {
            let (ct2, mac) = ct2_with_mac.split_at(kem::ct2_len());
            let raw_ss = kem::decapsulate(&dk, &ct1, ct2)?;
            let ss = kdf_ok(&raw_ss, epoch);
            // The ciphertext MAC is computed by the sender over the post-update
            // authenticator, so verify against a candidate update; only commit it
            // (and emit the epoch secret) once the MAC checks out.
            let mut next_auth = auth.clone();
            next_auth.update(epoch, &ss);
            let mut ct = ct1.clone();
            ct.extend_from_slice(ct2);
            if next_auth.vfy_ct(epoch, &ct, mac).is_ok() {
                let hdr_dec = Decoder::new(kem::pk1_len() + MAC_SIZE);
                return Ok((
                    State::NoHeaderReceived {
                        epoch: epoch + 1,
                        auth: next_auth,
                        hdr_dec,
                    },
                    Some(EpochSecret { epoch, secret: ss }),
                ));
            }
            // The reconstructed ciphertext failed its MAC: discard the candidate
            // secret and clear the decoder so honest codewords rebuild it (P1 #2).
            ct2_dec.reset();
        }
    }
    Ok((
        State::EkSentCt1Received {
            epoch,
            auth,
            dk,
            ct1,
            ct2_dec,
        },
        None,
    ))
}

fn recv_no_header_received(
    msg: &Message,
    epoch: u64,
    auth: Authenticator,
    mut hdr_dec: Decoder,
) -> Transition {
    if msg.epoch == epoch && msg.mtype == MsgType::Hdr {
        add_chunk(&mut hdr_dec, msg)?;
        if let Some(header_with_mac) = hdr_dec.message()? {
            let (header, mac) = header_with_mac.split_at(kem::pk1_len());
            if auth.vfy_hdr(epoch, header, mac).is_ok() {
                let ek_dec = Decoder::new(kem::pk2_len());
                return Ok((
                    State::HeaderReceived {
                        epoch,
                        auth,
                        header: header.to_vec(),
                        ek_dec,
                    },
                    None,
                ));
            }
            // The reconstructed header failed its MAC: it is not authentic. Clear
            // the decoder so honest re-streamed codewords rebuild it rather than
            // the session staying wedged on committed garbage (P1 #2 fix).
            hdr_dec.reset();
        }
    }
    Ok((
        State::NoHeaderReceived {
            epoch,
            auth,
            hdr_dec,
        },
        None,
    ))
}

#[allow(clippy::too_many_arguments)]
fn recv_ct1_sampled(
    msg: &Message,
    epoch: u64,
    auth: Authenticator,
    header: Vec<u8>,
    encaps_secret: Vec<u8>,
    ct1: Vec<u8>,
    ct1_enc: Encoder,
    mut ek_dec: Decoder,
) -> Transition {
    let is_ek = msg.epoch == epoch && msg.mtype == MsgType::Ek;
    let is_ack = msg.epoch == epoch && msg.mtype == MsgType::EkCt1Ack;
    if is_ek || is_ack {
        add_chunk(&mut ek_dec, msg)?;
        if let Some(ek_vector) = ek_dec.message()? {
            kem::validate_public_key(&header, &ek_vector)?;
            if is_ack {
                let ct2_enc = build_ct2_encoder(&auth, epoch, &encaps_secret, &ek_vector, &ct1)?;
                return Ok((
                    State::Ct2Sampled {
                        epoch,
                        auth,
                        ct2_enc,
                    },
                    None,
                ));
            }
            return Ok((
                State::EkReceivedCt1Sampled {
                    epoch,
                    auth,
                    encaps_secret,
                    ct1,
                    ek_vector,
                    ct1_enc,
                },
                None,
            ));
        }
        if is_ack {
            // ek not yet complete but ct1 is acknowledged.
            return Ok((
                State::Ct1Acknowledged {
                    epoch,
                    auth,
                    encaps_secret,
                    header,
                    ct1,
                    ek_dec,
                },
                None,
            ));
        }
    }
    Ok((
        State::Ct1Sampled {
            epoch,
            auth,
            header,
            encaps_secret,
            ct1,
            ct1_enc,
            ek_dec,
        },
        None,
    ))
}

fn recv_ek_received_ct1_sampled(
    msg: &Message,
    epoch: u64,
    auth: Authenticator,
    encaps_secret: Vec<u8>,
    ct1: Vec<u8>,
    ek_vector: Vec<u8>,
    ct1_enc: Encoder,
) -> Transition {
    if msg.epoch == epoch && msg.mtype == MsgType::EkCt1Ack {
        let ct2_enc = build_ct2_encoder(&auth, epoch, &encaps_secret, &ek_vector, &ct1)?;
        return Ok((
            State::Ct2Sampled {
                epoch,
                auth,
                ct2_enc,
            },
            None,
        ));
    }
    Ok((
        State::EkReceivedCt1Sampled {
            epoch,
            auth,
            encaps_secret,
            ct1,
            ek_vector,
            ct1_enc,
        },
        None,
    ))
}

fn recv_ct1_acknowledged(
    msg: &Message,
    epoch: u64,
    auth: Authenticator,
    encaps_secret: Vec<u8>,
    header: Vec<u8>,
    ct1: Vec<u8>,
    mut ek_dec: Decoder,
) -> Transition {
    if msg.epoch == epoch && msg.mtype == MsgType::EkCt1Ack {
        add_chunk(&mut ek_dec, msg)?;
        if let Some(ek_vector) = ek_dec.message()? {
            kem::validate_public_key(&header, &ek_vector)?;
            let ct2_enc = build_ct2_encoder(&auth, epoch, &encaps_secret, &ek_vector, &ct1)?;
            return Ok((
                State::Ct2Sampled {
                    epoch,
                    auth,
                    ct2_enc,
                },
                None,
            ));
        }
    }
    Ok((
        State::Ct1Acknowledged {
            epoch,
            auth,
            encaps_secret,
            header,
            ct1,
            ek_dec,
        },
        None,
    ))
}

fn recv_ct2_sampled(
    msg: &Message,
    epoch: u64,
    auth: Authenticator,
    ct2_enc: Encoder,
) -> Transition {
    if msg.epoch == epoch + 1 {
        return Ok((
            State::KeysUnsampled {
                epoch: epoch + 1,
                auth,
            },
            None,
        ));
    }
    Ok((
        State::Ct2Sampled {
            epoch,
            auth,
            ct2_enc,
        },
        None,
    ))
}

fn add_chunk(dec: &mut Decoder, msg: &Message) -> Result<()> {
    let chunk = msg
        .chunk
        .clone()
        .ok_or_else(|| proto_err("message missing codeword"))?;
    dec.add_chunk(chunk)
}

/// One party's view of an ML-KEM Braid session.
#[derive(Clone, Serialize, Deserialize)]
pub struct BraidState {
    state: State,
}

impl BraidState {
    /// The party that sends the first epoch's encapsulation-key header (spec
    /// `InitAlice`). Both parties seed the authenticator with the same `auth_seed`
    /// (e.g. derived from the PQXDH handshake) and start at the initial epoch.
    pub fn init_sender(auth_seed: &[u8; 32]) -> Self {
        Self {
            state: State::KeysUnsampled {
                epoch: INITIAL_EPOCH,
                auth: Authenticator::init(INITIAL_EPOCH, auth_seed),
            },
        }
    }

    /// The party that receives the first epoch's header (spec `InitBob`).
    pub fn init_receiver(auth_seed: &[u8; 32]) -> Self {
        Self {
            state: State::NoHeaderReceived {
                epoch: INITIAL_EPOCH,
                auth: Authenticator::init(INITIAL_EPOCH, auth_seed),
                hdr_dec: Decoder::new(kem::pk1_len() + MAC_SIZE),
            },
        }
    }

    /// Run a fallible state transition transactionally: commit the new state on
    /// success; on a recoverable error restore the prior state and propagate the
    /// error, never leaving [`State::Poisoned`] behind. `Poisoned` is held only for
    /// the duration of the transition (so a panic mid-transition is observable).
    fn transition<T>(&mut self, f: impl FnOnce(State) -> Result<(State, T)>) -> Result<T> {
        let snapshot = self.state.clone();
        let state = std::mem::replace(&mut self.state, State::Poisoned);
        match f(state) {
            Ok((next, out)) => {
                self.state = next;
                Ok(out)
            }
            Err(e) => {
                self.state = snapshot;
                Err(e)
            }
        }
    }

    /// `SCKASend(state) -> (msg, sending_epoch, output_key)`: produce the next
    /// outgoing codeword, the epoch its SPQR chain keys under, and an [`EpochSecret`]
    /// if one completed this step.
    ///
    /// A recoverable error (a transient KEM/encode failure) restores the prior state
    /// rather than leaving it poisoned.
    pub fn send<R: CryptoRng>(&mut self, rng: &mut R) -> Result<SckaSend> {
        let (msg, output_key) = self.transition(|state| {
            state
                .send(rng)
                .map(|(next, msg, secret)| (next, (msg, secret)))
        })?;
        // Epoch is invariant across a Send transition, so the post-state epoch
        // equals the pre-state epoch; sending_epoch = epoch - 1.
        let sending_epoch = self.state.epoch().saturating_sub(1);
        Ok(SckaSend {
            msg,
            sending_epoch,
            output_key,
        })
    }

    /// `SCKAReceive(state, msg) -> (receiving_epoch, output_key)`: consume an incoming
    /// codeword, returning the epoch it decrypts under and an [`EpochSecret`] if one
    /// completed this step.
    ///
    /// `receiving_epoch` is read from the message itself (`msg.epoch - 1`), not the
    /// receiver's `state.epoch - 1`: for an in-order message the two are equal (epoch
    /// agreement), but a message delayed across an epoch boundary carries its own
    /// (older) epoch while the receiver's state has advanced -- deriving it from the
    /// message keeps out-of-order delivery across a reseed correct.
    ///
    /// Fail-closed without bricking the session: a recoverable validation error
    /// restores the prior state. Combined with the decoder reset on MAC failure (the
    /// `recv_*` handlers), a single injected garbage codeword cannot wedge a live
    /// session -- honest re-streamed codewords rebuild the object.
    pub fn receive(&mut self, msg: &Message) -> Result<SckaReceive> {
        let receiving_epoch = msg.epoch.saturating_sub(1);
        let output_key = self.transition(|state| state.receive(msg))?;
        Ok(SckaReceive {
            receiving_epoch,
            output_key,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand_chacha::ChaCha20Rng;
    use rand_chacha::rand_core::SeedableRng;

    /// Pump two parties over a (possibly lossy) channel until both have emitted
    /// a secret for `target_epochs` epochs. Returns the per-epoch secrets each
    /// party emitted. `drop` decides whether to drop the message on a given step.
    fn run(target_epochs: u64, drop: impl Fn(u64) -> bool) -> (Vec<EpochSecret>, Vec<EpochSecret>) {
        let seed = [0x42u8; 32];
        let mut alice = BraidState::init_sender(&seed);
        let mut bob = BraidState::init_receiver(&seed);
        let mut rng_a = ChaCha20Rng::seed_from_u64(1);
        let mut rng_b = ChaCha20Rng::seed_from_u64(2);
        let mut a_secrets = Vec::new();
        let mut b_secrets = Vec::new();

        let mut step = 0u64;
        while a_secrets.len() < target_epochs as usize || b_secrets.len() < target_epochs as usize {
            step += 1;
            assert!(step < 100_000, "braid did not converge");

            let send_a = alice.send(&mut rng_a).unwrap();
            if let Some(s) = send_a.output_key {
                a_secrets.push(s);
            }
            if !drop(step)
                && let Some(s) = bob.receive(&send_a.msg).unwrap().output_key
            {
                b_secrets.push(s);
            }

            let send_b = bob.send(&mut rng_b).unwrap();
            if let Some(s) = send_b.output_key {
                b_secrets.push(s);
            }
            if !drop(step + 1)
                && let Some(s) = alice.receive(&send_b.msg).unwrap().output_key
            {
                a_secrets.push(s);
            }
        }
        (a_secrets, b_secrets)
    }

    #[test]
    fn single_epoch_both_parties_agree() {
        let (a, b) = run(1, |_| false);
        // The braid's first completed KEM epoch is epoch 1 (spec InitAlice/InitBob
        // start at epoch 1); epoch 0 is the SPQR bootstrap epoch, not a braid secret.
        assert_eq!(a[0].epoch, 1);
        assert_eq!(b[0].epoch, 1);
        assert_eq!(
            a[0].secret, b[0].secret,
            "both parties must derive the same epoch-1 secret"
        );
    }

    #[test]
    fn multi_epoch_roles_alternate_and_agree() {
        let (a, b) = run(3, |_| false);
        for epoch in 0..3usize {
            // Completed braid epochs are 1-based (epoch 0 is the SPQR bootstrap).
            assert_eq!(a[epoch].epoch, epoch as u64 + 1);
            assert_eq!(b[epoch].epoch, epoch as u64 + 1);
            assert_eq!(
                a[epoch].secret, b[epoch].secret,
                "epoch {epoch} secrets must match"
            );
        }
        assert_ne!(a[0].secret, a[1].secret);
        assert_ne!(a[1].secret, a[2].secret);
    }

    #[test]
    fn completes_over_lossy_channel() {
        let (a, b) = run(2, |step| step % 3 == 0);
        for epoch in 0..2usize {
            assert_eq!(
                a[epoch].secret, b[epoch].secret,
                "epoch {epoch} must agree despite loss"
            );
        }
    }

    #[test]
    fn state_survives_serialization() {
        let seed = [0x7u8; 32];
        let mut alice = BraidState::init_sender(&seed);
        let mut rng = ChaCha20Rng::seed_from_u64(9);
        alice.send(&mut rng).unwrap();
        let bytes = postcard::to_allocvec(&alice).unwrap();
        let restored: BraidState = postcard::from_bytes(&bytes).unwrap();
        let mut clone = restored;
        let msg = clone.send(&mut rng).unwrap().msg;
        assert_eq!(msg.mtype, MsgType::Hdr);
    }

    #[test]
    fn ek_received_via_plain_ek_before_ack() {
        // Force the EkReceivedCt1Sampled path: the encapsulator completes
        // ek_vector from plain Ek chunks before any EkCt1Ack arrives. We let the
        // header-sender into HeaderSent (one ct1 chunk) then withhold her
        // remaining ct1 so she keeps emitting Ek; once the encapsulator has the
        // full ek we resume delivery so the ack flows and the epoch finishes.
        let seed = [0x55u8; 32];
        let mut alice = BraidState::init_sender(&seed);
        let mut bob = BraidState::init_receiver(&seed);
        let mut ra = ChaCha20Rng::seed_from_u64(11);
        let mut rb = ChaCha20Rng::seed_from_u64(12);
        let mut a_sec: Option<EpochSecret> = None;
        let mut b_sec: Option<EpochSecret> = None;
        for step in 1..5000u64 {
            let send_a = alice.send(&mut ra).unwrap();
            if send_a.output_key.is_some() {
                a_sec = send_a.output_key;
            }
            if let Some(s) = bob.receive(&send_a.msg).unwrap().output_key {
                b_sec = Some(s);
            }

            let send_b = bob.send(&mut rb).unwrap();
            if send_b.output_key.is_some() {
                b_sec = send_b.output_key;
            }
            // Deliver bob->alice only for the first ct1 chunk and after the
            // encapsulator has had time to complete ek via Ek (steps >= 50).
            let deliver = step <= 4 || step >= 50;
            if deliver && let Some(s) = alice.receive(&send_b.msg).unwrap().output_key {
                a_sec = Some(s);
            }
            if a_sec.is_some() && b_sec.is_some() {
                break;
            }
        }
        assert_eq!(
            a_sec.expect("alice secret").secret,
            b_sec.expect("bob secret").secret,
            "both parties agree via the EkReceived path"
        );
    }

    #[test]
    fn forged_header_mac_rejected() {
        // Mismatched auth seeds: bob can never authenticate alice's header, so he
        // must never accept it -- he never advances past the header wait and never
        // emits an epoch secret -- yet the session is not bricked (the MAC failure
        // resets the decoder and recovers rather than poisoning, P1 #1/#2).
        let mut alice = BraidState::init_sender(&[1u8; 32]);
        let mut bob = BraidState::init_receiver(&[2u8; 32]); // wrong seed
        let mut rng = ChaCha20Rng::seed_from_u64(3);
        for _ in 0..50 {
            let msg = alice.send(&mut rng).unwrap().msg;
            let recv = bob
                .receive(&msg)
                .expect("a forged header must not brick bob");
            assert!(
                recv.output_key.is_none(),
                "a header that fails its MAC must never yield an epoch secret"
            );
        }
        assert!(
            matches!(bob.state, State::NoHeaderReceived { .. }),
            "bob must stay waiting for an authentic header, not advance or poison"
        );
    }

    #[test]
    fn malformed_codeword_does_not_poison() {
        // A genuinely malformed codeword (out-of-range index) is a hard receive
        // error, but it must restore the prior state -- never leave it Poisoned --
        // so an honest run still completes afterwards (P1 #1 regression).
        let seed = [0x33u8; 32];
        let mut alice = BraidState::init_sender(&seed);
        let mut bob = BraidState::init_receiver(&seed);
        let mut ra = ChaCha20Rng::seed_from_u64(7);

        // Feed bob a poison chunk: a Hdr message whose codeword index is out of
        // range for the header decoder. add_chunk rejects it. The message must be
        // tagged with bob's current epoch (INITIAL_EPOCH) so it reaches add_chunk.
        let bad = Message::carrying(
            INITIAL_EPOCH,
            MsgType::Hdr,
            crate::protocol::braid::erasure::Chunk {
                index: u16::MAX,
                data: vec![0u8; crate::protocol::braid::erasure::CHUNK_BYTES],
            },
        );
        assert!(
            bob.receive(&bad).is_err(),
            "out-of-range codeword must error"
        );
        assert!(
            matches!(bob.state, State::NoHeaderReceived { .. }),
            "a recoverable error must restore the prior state, not poison it"
        );

        // The session is intact: an honest exchange still converges.
        let mut rb = ChaCha20Rng::seed_from_u64(8);
        let mut a_sec = None;
        let mut b_sec = None;
        for _ in 0..3000 {
            let send_a = alice.send(&mut ra).unwrap();
            if let Some(s) = bob.receive(&send_a.msg).unwrap().output_key {
                b_sec = Some(s);
            }
            if send_a.output_key.is_some() {
                a_sec = send_a.output_key;
            }
            let send_b = bob.send(&mut rb).unwrap();
            if let Some(s) = alice.receive(&send_b.msg).unwrap().output_key {
                a_sec = Some(s);
            }
            if send_b.output_key.is_some() {
                b_sec = send_b.output_key;
            }
            if a_sec.is_some() && b_sec.is_some() {
                break;
            }
        }
        assert_eq!(
            a_sec.expect("alice secret").secret,
            b_sec.expect("bob secret").secret,
            "session must still converge after a recoverable error"
        );
    }
}
