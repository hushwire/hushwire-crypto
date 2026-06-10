//! ISO/IEC 7816-4 message padding.
//!
//! Pads plaintext to a multiple of a fixed block size before encryption so that
//! ciphertext length does not reveal exact plaintext length, frustrating
//! content-type inference from message size.

use crate::error::{CryptoError, Result};

const BLOCK_SIZE: usize = 160;

/// Pad plaintext using ISO/IEC 7816-4 padding to a multiple of 160 bytes.
///
/// Append 0x80, then zero-fill to the next block boundary. This hides
/// plaintext length from ciphertext length, preventing content-type inference
/// from message size.
pub fn pad(plaintext: &[u8]) -> Vec<u8> {
    let padded_len = (plaintext.len() + 1).div_ceil(BLOCK_SIZE) * BLOCK_SIZE;
    let mut out = Vec::with_capacity(padded_len);
    out.extend_from_slice(plaintext);
    out.push(0x80);
    out.resize(padded_len, 0x00);
    out
}

/// Strip ISO/IEC 7816-4 padding, returning the original plaintext.
pub fn unpad(padded: &[u8]) -> Result<&[u8]> {
    for i in (0..padded.len()).rev() {
        match padded[i] {
            0x80 => return Ok(&padded[..i]),
            0x00 => continue,
            _ => return Err(CryptoError::InvalidPadding),
        }
    }
    Err(CryptoError::InvalidPadding)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pad_unpad_roundtrip() {
        let msg = b"hello world";
        let padded = pad(msg);
        assert_eq!(padded.len() % BLOCK_SIZE, 0);
        assert_eq!(unpad(&padded).unwrap(), msg);
    }

    #[test]
    fn empty_message() {
        let padded = pad(b"");
        assert_eq!(padded.len(), BLOCK_SIZE);
        assert_eq!(unpad(&padded).unwrap(), b"");
    }

    #[test]
    fn exact_block_minus_one() {
        let msg = vec![0x41u8; BLOCK_SIZE - 1];
        let padded = pad(&msg);
        assert_eq!(padded.len(), BLOCK_SIZE);
        assert_eq!(unpad(&padded).unwrap(), msg.as_slice());
    }

    #[test]
    fn exact_block_size_rounds_up() {
        let msg = vec![0x41u8; BLOCK_SIZE];
        let padded = pad(&msg);
        assert_eq!(padded.len(), BLOCK_SIZE * 2);
        assert_eq!(unpad(&padded).unwrap(), msg.as_slice());
    }

    #[test]
    fn large_message() {
        let msg = vec![0xABu8; 1000];
        let padded = pad(&msg);
        assert_eq!(padded.len() % BLOCK_SIZE, 0);
        assert!(padded.len() > msg.len());
        assert_eq!(unpad(&padded).unwrap(), msg.as_slice());
    }

    #[test]
    fn invalid_padding_no_marker() {
        let bad = vec![0x00u8; BLOCK_SIZE];
        assert!(matches!(unpad(&bad), Err(CryptoError::InvalidPadding)));
    }

    #[test]
    fn invalid_padding_trailing_nonzero() {
        let mut bad = pad(b"test");
        let len = bad.len();
        bad[len - 1] = 0x42;
        assert!(matches!(unpad(&bad), Err(CryptoError::InvalidPadding)));
    }

    #[test]
    fn same_length_messages_same_padded_size() {
        let a = pad(b"hello");
        let b = pad(b"world");
        assert_eq!(a.len(), b.len());
    }

    #[test]
    fn plaintext_with_zero_bytes() {
        let msg = b"\x00\x00\x00test\x00\x00";
        let padded = pad(msg);
        assert_eq!(unpad(&padded).unwrap(), msg);
    }

    #[test]
    fn plaintext_ending_with_0x80() {
        let msg = b"data\x80";
        let padded = pad(msg);
        assert_eq!(unpad(&padded).unwrap(), msg);
    }
}
