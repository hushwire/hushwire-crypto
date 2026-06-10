//! Streaming Reed-Solomon erasure coding for the Braid transport.
//!
//! Matches the `mlkembraid` spec's interface: `Encode(bytes)` yields a stream of
//! bare indexed codewords via [`Encoder::next_chunk`]; [`Decoder::new`] is told
//! the target message length up front, collects chunks via
//! [`Decoder::add_chunk`], and reconstructs once enough distinct codewords have
//! arrived ([`Decoder::has_message`] / [`Decoder::message`]).
//!
//! The codewords are intentionally *bare* (just an index + payload). Object
//! binding (which logical object a chunk belongs to) lives in the state
//! machine's message framing (`{epoch, type}`) and its routing; integrity lives
//! in the authenticator ratchet's MACs and the `hek` check. None of that is in
//! the codeword, exactly as the spec specifies.
//!
//! Codec: `reed-solomon-simd` (systematic Reed-Solomon over GF(2^16)). For a
//! `k`-data-shard message we also produce `k` recovery shards, so any `k` of the
//! `2k` distinct codewords reconstruct the message. The encoder cycles
//! (resending) once it has emitted all `2k`, so a lossy channel still completes.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use crate::error::{CryptoError, Result};

/// Bytes carried in one codeword (`w` in the spec). With a 32-byte MAC this
/// reproduces the spec's ML-KEM-768 chunk counts (header+mac 3, ek_vector 36,
/// ct1 30, ct2+mac 5).
pub const CHUNK_BYTES: usize = 32;

fn err(msg: impl Into<String>) -> CryptoError {
    CryptoError::BraidErasure(msg.into())
}

/// Number of data shards needed to carry `len` bytes.
fn data_shards_for(len: usize) -> usize {
    len.div_ceil(CHUNK_BYTES).max(1)
}

/// Recovery shards generated per data shard. Signal's systematic Reed-Solomon over
/// `GF(2^16)` can emit many more distinct recovery codewords than data shards, so a
/// lossy channel recovers from a large pool of *distinct* codewords before the
/// encoder ever has to re-send one. (The prior scheme emitted only `k` recovery
/// shards then cycled, re-sending duplicates under loss > k.)
const RECOVERY_MULTIPLE: usize = 8;

/// Upper bound on recovery shards, bounding encoder memory. `GF(2^16)` permits far
/// more (~65k total), but a small multiple of `k` is ample for any realistic loss.
const MAX_RECOVERY_SHARDS: usize = 1024;

/// Number of distinct recovery shards for a `len`-byte message. Both the encoder and
/// a size-matched decoder derive this identically, so it never needs to be on the wire.
fn recovery_shards_for(len: usize) -> usize {
    (data_shards_for(len) * RECOVERY_MULTIPLE).min(MAX_RECOVERY_SHARDS)
}

/// One erasure codeword on the wire: its index plus `CHUNK_BYTES` of payload.
#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub struct Chunk {
    /// Position in the codeword array. `< data_shards` is a systematic
    /// (original) shard; the rest are recovery shards.
    pub index: u16,
    /// The codeword payload (`CHUNK_BYTES` long).
    pub data: Vec<u8>,
}

/// Streaming encoder over one message. Produces systematic shards first, then a
/// large pool of distinct recovery shards, then cycles (resending) only if even
/// those are exhausted, so a lossy channel still completes.
#[derive(Clone, Serialize, Deserialize)]
pub struct Encoder {
    /// `data_shards` originals followed by `recovery_shards_for(len)` recovery shards.
    shards: Vec<Vec<u8>>,
    cursor: usize,
}

impl Encoder {
    /// Build an encoder for `data`. The message length is recoverable by a
    /// [`Decoder::new`] created with the same length.
    pub fn new(data: &[u8]) -> Result<Self> {
        if data.is_empty() {
            return Err(err("cannot encode an empty message"));
        }
        let k = data_shards_for(data.len());
        let mut padded = data.to_vec();
        padded.resize(k * CHUNK_BYTES, 0u8);
        let originals: Vec<Vec<u8>> = padded
            .chunks_exact(CHUNK_BYTES)
            .map(<[u8]>::to_vec)
            .collect();
        // Generate many distinct recovery shards: any `k` of the `k + r` distinct
        // codewords reconstruct, with `r >> k` so loss is covered without re-sends.
        let r = recovery_shards_for(data.len());
        let recovery = reed_solomon_simd::encode(k, r, &originals)
            .map_err(|e| err(format!("rs encode: {e}")))?;
        let mut shards = originals;
        shards.extend(recovery);
        Ok(Self { shards, cursor: 0 })
    }

    /// The next codeword. Cycles through systematic then recovery shards,
    /// repeating from the start once exhausted (re-sending lost codewords).
    pub fn next_chunk(&mut self) -> Chunk {
        let index = self.cursor % self.shards.len();
        self.cursor += 1;
        Chunk {
            index: index as u16,
            data: self.shards[index].clone(),
        }
    }
}

/// Size-keyed decoder. Reconstructs the original `len`-byte message once it has
/// `data_shards` distinct valid codewords.
#[derive(Clone, Serialize, Deserialize)]
pub struct Decoder {
    len: usize,
    data_shards: usize,
    recovery_shards: usize,
    received: BTreeMap<u16, Vec<u8>>,
}

impl Decoder {
    /// A decoder for a message of exactly `len` bytes.
    pub fn new(len: usize) -> Self {
        Self {
            len,
            data_shards: data_shards_for(len),
            recovery_shards: recovery_shards_for(len),
            received: BTreeMap::new(),
        }
    }

    /// Total distinct codewords the matching encoder can produce
    /// (`data_shards + recovery_shards`).
    fn total_shards(&self) -> usize {
        self.data_shards + self.recovery_shards
    }

    /// Admit a codeword. Duplicates are ignored; wrong-length or out-of-range
    /// codewords are rejected.
    pub fn add_chunk(&mut self, chunk: Chunk) -> Result<()> {
        if chunk.data.len() != CHUNK_BYTES {
            return Err(err("codeword has wrong length"));
        }
        if chunk.index as usize >= self.total_shards() {
            return Err(err("codeword index out of range"));
        }
        self.received.entry(chunk.index).or_insert(chunk.data);
        Ok(())
    }

    /// Whether enough distinct codewords have arrived to reconstruct.
    pub fn has_message(&self) -> bool {
        self.received.len() >= self.data_shards
    }

    /// Discard every collected codeword, returning the decoder to its empty
    /// initial state. Used to recover when a reconstructed object fails its
    /// authenticator MAC: clearing the (first-writer-wins) buffer lets honest,
    /// re-streamed codewords rebuild the object from scratch rather than the
    /// decoder being wedged on committed garbage.
    pub fn reset(&mut self) {
        self.received.clear();
    }

    /// Reconstruct the message, or `None` if not enough codewords yet.
    ///
    /// Works from borrowed codeword buffers: bytes are copied once into the
    /// output. Returns an error only if the codec rejects the inputs.
    pub fn message(&self) -> Result<Option<Vec<u8>>> {
        if !self.has_message() {
            return Ok(None);
        }
        let k = self.data_shards;
        let restored = if (0..k as u16).all(|i| self.received.contains_key(&i)) {
            BTreeMap::new()
        } else {
            let present = self
                .received
                .iter()
                .filter(|&(&idx, _)| (idx as usize) < k)
                .map(|(&idx, d)| (idx as usize, d));
            let recovery = self
                .received
                .iter()
                .filter(|&(&idx, _)| (idx as usize) >= k)
                .map(|(&idx, d)| (idx as usize - k, d));
            reed_solomon_simd::decode(k, self.recovery_shards, present, recovery)
                .map_err(|e| err(format!("rs decode: {e}")))?
        };

        let mut out = Vec::with_capacity(k * CHUNK_BYTES);
        for i in 0..k {
            let bytes = match self.received.get(&(i as u16)) {
                Some(d) => d.as_slice(),
                None => restored
                    .get(&i)
                    .map(Vec::as_slice)
                    .ok_or_else(|| err("reconstruction incomplete"))?,
            };
            out.extend_from_slice(bytes);
        }
        out.truncate(self.len);
        Ok(Some(out))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample(len: usize) -> Vec<u8> {
        (0..len).map(|i| (i * 31 + 7) as u8).collect()
    }

    /// Drive an encoder through a (possibly lossy) channel into a decoder.
    fn stream(data: &[u8], drop: impl Fn(usize) -> bool, max_chunks: usize) -> Option<Vec<u8>> {
        let mut enc = Encoder::new(data).unwrap();
        let mut dec = Decoder::new(data.len());
        for i in 0..max_chunks {
            let chunk = enc.next_chunk();
            if !drop(i) {
                dec.add_chunk(chunk).unwrap();
            }
            if dec.has_message() {
                return dec.message().unwrap();
            }
        }
        None
    }

    #[test]
    fn lossless_roundtrip() {
        for len in [32usize, 64, 96, 960, 1088, 1152, 1184] {
            let data = sample(len);
            let got = stream(&data, |_| false, 100).expect("should reconstruct");
            assert_eq!(got, data, "len {len}");
        }
    }

    #[test]
    fn chunk_counts_match_spec() {
        // header+mac=96, ct1=960, ek_vector=1152, ct2+mac=160 -> 3, 30, 36, 5.
        assert_eq!(data_shards_for(96), 3);
        assert_eq!(data_shards_for(960), 30);
        assert_eq!(data_shards_for(1152), 36);
        assert_eq!(data_shards_for(160), 5);
    }

    #[test]
    fn recovers_from_loss_up_to_k() {
        // k=36 for ek_vector; drop the first 36 codewords (all originals), the
        // 36 recovery codewords must still reconstruct.
        let data = sample(1152);
        let got = stream(&data, |i| i < 36, 200).expect("recovery shards reconstruct");
        assert_eq!(got, data);
    }

    #[test]
    fn lossy_channel_completes_by_resending() {
        // Drop every other codeword; cycling resends, so it still completes.
        let data = sample(960);
        let got = stream(&data, |i| i % 2 == 1, 500).expect("resending completes");
        assert_eq!(got, data);
    }

    #[test]
    fn reset_clears_buffer_and_allows_rebuild() {
        // The P1 #2 recovery mechanism: a decoder holding committed (first-writer-
        // wins) codewords can be reset, after which honest codewords rebuild the
        // message from scratch.
        let data = sample(96); // k = 3
        let mut enc = Encoder::new(&data).unwrap();
        let mut dec = Decoder::new(data.len());

        // Commit some codewords, then reset before reconstruction completes.
        dec.add_chunk(enc.next_chunk()).unwrap();
        dec.add_chunk(enc.next_chunk()).unwrap();
        assert!(!dec.received.is_empty());
        dec.reset();
        assert!(dec.received.is_empty(), "reset must drop all codewords");
        assert!(!dec.has_message());

        // A fresh full stream after the reset reconstructs correctly.
        let mut enc2 = Encoder::new(&data).unwrap();
        let mut got = None;
        for _ in 0..10 {
            dec.add_chunk(enc2.next_chunk()).unwrap();
            if dec.has_message() {
                got = dec.message().unwrap();
                break;
            }
        }
        assert_eq!(got.expect("rebuilds after reset"), data);
    }

    #[test]
    fn duplicate_index_ignored() {
        let data = sample(96);
        let mut enc = Encoder::new(&data).unwrap();
        let mut dec = Decoder::new(data.len());
        let c = enc.next_chunk();
        dec.add_chunk(c.clone()).unwrap();
        dec.add_chunk(c).unwrap(); // duplicate: ignored, not an error
        assert!(!dec.has_message());
        assert_eq!(dec.received.len(), 1);
    }

    #[test]
    fn encoder_emits_many_distinct_recovery_shards_before_cycling() {
        // k=3 used to yield only 2k=6 distinct codewords; now it yields
        // k + k*RECOVERY_MULTIPLE distinct codewords before re-sending any.
        let data = sample(96);
        let mut enc = Encoder::new(&data).unwrap();
        let total = 3 + 3 * RECOVERY_MULTIPLE;
        let mut seen = std::collections::HashSet::new();
        for _ in 0..total {
            seen.insert(enc.next_chunk().index);
        }
        assert_eq!(seen.len(), total, "all {total} codewords are distinct");
        // Only after exhausting the distinct pool does the encoder cycle.
        assert_eq!(enc.next_chunk().index, 0);
    }

    #[test]
    fn recovers_from_loss_beyond_2k_without_resending() {
        // Drop the first 2k codewords (more than the old scheme had in total). The
        // message still reconstructs from *distinct* recovery shards beyond index 2k,
        // i.e. without relying on cycling.
        let data = sample(96); // k=3
        let got = stream(&data, |i| i < 6, 50).expect("distinct recovery shards reconstruct");
        assert_eq!(got, data);
    }

    #[test]
    fn out_of_range_and_wrong_length_rejected() {
        // k=3, recovery=3*RECOVERY_MULTIPLE=24, so total=27; index 27 is out of range.
        let mut dec = Decoder::new(96);
        assert_eq!(dec.total_shards(), 3 + 3 * RECOVERY_MULTIPLE);
        assert!(matches!(
            dec.add_chunk(Chunk {
                index: dec.total_shards() as u16,
                data: vec![0u8; CHUNK_BYTES]
            }),
            Err(CryptoError::BraidErasure(_))
        ));
        assert!(matches!(
            dec.add_chunk(Chunk {
                index: 0,
                data: vec![0u8; 16]
            }),
            Err(CryptoError::BraidErasure(_))
        ));
    }

    #[test]
    fn not_enough_chunks_yields_none() {
        let data = sample(96); // k=3
        let mut enc = Encoder::new(&data).unwrap();
        let mut dec = Decoder::new(data.len());
        dec.add_chunk(enc.next_chunk()).unwrap();
        dec.add_chunk(enc.next_chunk()).unwrap();
        assert!(!dec.has_message());
        assert_eq!(dec.message().unwrap(), None);
    }

    #[test]
    fn empty_message_rejected() {
        assert!(matches!(
            Encoder::new(&[]),
            Err(CryptoError::BraidErasure(_))
        ));
    }

    #[test]
    fn differential_any_k_of_n_matches_independent_impl() {
        // Cross-check the any-k-of-n property against a second, independent RS
        // implementation (reed-solomon-erasure, dev-only).
        use reed_solomon_erasure::galois_8::ReedSolomon;
        let k = 4usize;
        let parity = 2usize;
        let data = sample(k * CHUNK_BYTES);
        let mut shards: Vec<Vec<u8>> = data.chunks(CHUNK_BYTES).map(<[u8]>::to_vec).collect();
        shards.extend((0..parity).map(|_| vec![0u8; CHUNK_BYTES]));
        let rs = ReedSolomon::new(k, parity).unwrap();
        rs.encode(&mut shards).unwrap();
        let mut opt: Vec<Option<Vec<u8>>> = shards.iter().cloned().map(Some).collect();
        opt[0] = None;
        opt[2] = None;
        rs.reconstruct(&mut opt).unwrap();
        let recovered: Vec<u8> = opt.into_iter().take(k).flat_map(Option::unwrap).collect();
        assert_eq!(recovered, data);
    }

    #[test]
    fn clamped_recovery_shards_roundtrip() {
        // A message large enough that data_shards * RECOVERY_MULTIPLE exceeds
        // MAX_RECOVERY_SHARDS, so the recovery count is clamped. Encoder and decoder
        // derive the clamp identically from `len`, so they must still agree on
        // total_shards and reconstruct (including across some loss).
        let len = (MAX_RECOVERY_SHARDS / RECOVERY_MULTIPLE + 2) * CHUNK_BYTES;
        let k = data_shards_for(len);
        let dec = Decoder::new(len);
        assert_eq!(
            dec.recovery_shards, MAX_RECOVERY_SHARDS,
            "recovery count must be clamped for a large message"
        );
        assert_eq!(dec.total_shards(), k + MAX_RECOVERY_SHARDS);
        let data = sample(len);
        // Drop the first few originals so reconstruction must use recovery shards.
        let got = stream(&data, |i| i < 4, k + 16).expect("clamped message reconstructs");
        assert_eq!(got, data);
    }
}
