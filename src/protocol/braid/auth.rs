//! Braid key derivation (`KDF_OK`) and the authenticator ratchet (`KDF_AUTH` +
//! per-epoch MACs), per the `mlkembraid` spec.
//!
//! - [`kdf_ok`] turns a raw KEM shared secret into the per-epoch session key the
//!   Double Ratchet consumes.
//! - [`Authenticator`] ratchets a `(root_key, mac_key)` pair forward each epoch
//!   (`update`) and MACs/verifies the header and ciphertext (`mac_hdr`/`mac_ct`,
//!   `vfy_hdr`/`vfy_ct`). The MAC is HMAC-SHA256; verification is constant-time.
//!
//! `PROTOCOL_INFO` is Hushwire's domain-separation tag (the spec leaves it
//! application-defined); it never interoperates with Signal's own deployment.

use hmac::{Hmac, Mac};
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use subtle::ConstantTimeEq;

use crate::error::{CryptoError, Result};
use crate::primitives::kdf::hkdf_sha256;

/// Domain-separation tag for all braid KDF/MAC inputs. Per the ML-KEM Braid spec,
/// `PROTOCOL_INFO` binds the protocol name and KEM/hash parameters (e.g.
/// `"<Name>_MLKEM768_SHA-256"`); Hushwire picks its own value and never
/// wire-interoperates with Signal's deployment.
const PROTOCOL_INFO: &[u8] = b"HushwireBraid_MLKEM768_SHA-256";

const KEY_LEN: usize = 32;

/// Encode an epoch as the spec's `ToBytes(epoch)` (big-endian u64).
fn epoch_bytes(epoch: u64) -> [u8; 8] {
    epoch.to_be_bytes()
}

/// `KDF_OK(shared_secret, epoch)`: derive the per-epoch session key.
///
/// `HKDF(ikm = shared_secret, salt = zeros, info = PROTOCOL_INFO || ":SCKA Key"
/// || epoch, len = 32)`.
pub fn kdf_ok(shared_secret: &[u8; KEY_LEN], epoch: u64) -> [u8; KEY_LEN] {
    let salt = [0u8; KEY_LEN];
    let mut info = Vec::with_capacity(PROTOCOL_INFO.len() + 9 + 8);
    info.extend_from_slice(PROTOCOL_INFO);
    info.extend_from_slice(b":SCKA Key");
    info.extend_from_slice(&epoch_bytes(epoch));
    let okm = hkdf_sha256(shared_secret, Some(&salt), &info, KEY_LEN);
    let mut out = [0u8; KEY_LEN];
    out.copy_from_slice(&okm);
    out
}

/// `KDF_AUTH(root_key, update_key, epoch)` -> `(new_root_key, mac_key)`.
///
/// `HKDF(ikm = update_key, salt = root_key, info = PROTOCOL_INFO ||
/// ":Authenticator Update" || epoch, len = 64)`, split 32/32.
fn kdf_auth(
    root_key: &[u8; KEY_LEN],
    update_key: &[u8; KEY_LEN],
    epoch: u64,
) -> ([u8; KEY_LEN], [u8; KEY_LEN]) {
    let mut info = Vec::with_capacity(PROTOCOL_INFO.len() + 21 + 8);
    info.extend_from_slice(PROTOCOL_INFO);
    info.extend_from_slice(b":Authenticator Update");
    info.extend_from_slice(&epoch_bytes(epoch));
    let okm = hkdf_sha256(update_key, Some(root_key), &info, 2 * KEY_LEN);
    let mut root = [0u8; KEY_LEN];
    let mut mac = [0u8; KEY_LEN];
    root.copy_from_slice(&okm[..KEY_LEN]);
    mac.copy_from_slice(&okm[KEY_LEN..]);
    (root, mac)
}

/// The braid authenticator: a ratcheting `(root_key, mac_key)` that
/// authenticates each epoch's header and ciphertext.
#[derive(Clone, Serialize, Deserialize)]
pub struct Authenticator {
    root_key: [u8; KEY_LEN],
    mac_key: [u8; KEY_LEN],
}

impl Authenticator {
    /// Initialize from the first epoch's key (`root_key` starts zero-filled,
    /// then one `update`), per `Authenticator.Init`.
    pub fn init(epoch: u64, key: &[u8; KEY_LEN]) -> Self {
        let mut auth = Self {
            root_key: [0u8; KEY_LEN],
            mac_key: [0u8; KEY_LEN],
        };
        auth.update(epoch, key);
        auth
    }

    /// Ratchet the authenticator forward with an epoch's shared secret.
    pub fn update(&mut self, epoch: u64, key: &[u8; KEY_LEN]) {
        let (root, mac) = kdf_auth(&self.root_key, key, epoch);
        self.root_key = root;
        self.mac_key = mac;
    }

    fn mac(&self, label: &[u8], epoch: u64, data: &[u8]) -> [u8; 32] {
        let mut mac = Hmac::<Sha256>::new_from_slice(&self.mac_key).expect("HMAC accepts any key");
        mac.update(PROTOCOL_INFO);
        mac.update(label);
        mac.update(&epoch_bytes(epoch));
        mac.update(data);
        mac.finalize().into_bytes().into()
    }

    /// MAC over an encapsulation-key header.
    pub fn mac_hdr(&self, epoch: u64, hdr: &[u8]) -> [u8; 32] {
        self.mac(b":ekheader", epoch, hdr)
    }

    /// MAC over a ciphertext (`ct1 || ct2`).
    pub fn mac_ct(&self, epoch: u64, ct: &[u8]) -> [u8; 32] {
        self.mac(b":ciphertext", epoch, ct)
    }

    /// Verify a header MAC in constant time.
    pub fn vfy_hdr(&self, epoch: u64, hdr: &[u8], expected: &[u8]) -> Result<()> {
        verify(&self.mac_hdr(epoch, hdr), expected)
    }

    /// Verify a ciphertext MAC in constant time.
    pub fn vfy_ct(&self, epoch: u64, ct: &[u8], expected: &[u8]) -> Result<()> {
        verify(&self.mac_ct(epoch, ct), expected)
    }
}

/// Constant-time MAC comparison.
fn verify(computed: &[u8; 32], expected: &[u8]) -> Result<()> {
    let expected: &[u8; 32] = expected
        .try_into()
        .map_err(|_| CryptoError::BraidKem("MAC has wrong length".into()))?;
    if computed.ct_eq(expected).into() {
        Ok(())
    } else {
        Err(CryptoError::InvalidSignature)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn kdf_ok_deterministic_and_epoch_separated() {
        let ss = [7u8; KEY_LEN];
        assert_eq!(kdf_ok(&ss, 1), kdf_ok(&ss, 1));
        assert_ne!(kdf_ok(&ss, 1), kdf_ok(&ss, 2), "epoch must separate keys");
        assert_ne!(kdf_ok(&ss, 1), kdf_ok(&[8u8; KEY_LEN], 1));
    }

    #[test]
    fn auth_ratchet_advances() {
        let a = Authenticator::init(0, &[1u8; KEY_LEN]);
        let mut b = a.clone();
        b.update(1, &[2u8; KEY_LEN]);
        // After a further update the mac key changes, so the same input MACs
        // differently across epochs.
        assert_ne!(a.mac_hdr(0, b"hdr"), b.mac_hdr(0, b"hdr"));
    }

    #[test]
    fn mac_roundtrip_verifies() {
        let auth = Authenticator::init(5, &[3u8; KEY_LEN]);
        let hdr = b"ek_seed||hek";
        let ct = b"ct1||ct2";
        let hmac = auth.mac_hdr(5, hdr);
        let cmac = auth.mac_ct(5, ct);
        auth.vfy_hdr(5, hdr, &hmac).unwrap();
        auth.vfy_ct(5, ct, &cmac).unwrap();
    }

    #[test]
    fn tampered_mac_rejected() {
        let auth = Authenticator::init(5, &[3u8; KEY_LEN]);
        let hdr = b"header";
        let mut mac = auth.mac_hdr(5, hdr);
        mac[0] ^= 0xFF;
        assert!(matches!(
            auth.vfy_hdr(5, hdr, &mac),
            Err(CryptoError::InvalidSignature)
        ));
    }

    #[test]
    fn hdr_and_ct_macs_are_domain_separated() {
        let auth = Authenticator::init(1, &[9u8; KEY_LEN]);
        // Same epoch + same bytes, different label -> different MAC.
        assert_ne!(auth.mac_hdr(1, b"x"), auth.mac_ct(1, b"x"));
    }

    #[test]
    fn wrong_epoch_fails_verification() {
        let auth = Authenticator::init(1, &[4u8; KEY_LEN]);
        let hdr = b"header";
        let mac = auth.mac_hdr(1, hdr);
        assert!(auth.vfy_hdr(2, hdr, &mac).is_err());
    }

    #[test]
    fn wrong_length_mac_rejected() {
        let auth = Authenticator::init(1, &[4u8; KEY_LEN]);
        assert!(auth.vfy_hdr(1, b"h", &[0u8; 16]).is_err());
    }
}
