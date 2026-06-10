//! Signed envelope verification.
//!
//! Verifies the chain of trust on sealed sender envelopes:
//! 1. Server Ed25519 signature on the sender certificate
//! 2. Certificate expiry (optional, skipped for history)
//! 3. Certificate user_id matches envelope sender_id
//! 4. Sender signature over the envelope payload

use crate::error::{CryptoError, Result};
use ed25519_dalek::{Signature, Verifier, VerifyingKey};

/// Raw byte inputs for envelope verification.
///
/// Callers extract these fields from their domain-specific envelope type
/// and pass them as raw bytes. This keeps the verification logic
/// independent of any wire format or protocol types.
pub struct EnvelopeVerificationInput<'a> {
    /// The certificate bytes covered by the server's signature.
    pub cert_signing_bytes: &'a [u8],
    /// The server's Ed25519 signature over `cert_signing_bytes`.
    pub cert_server_signature: &'a [u8],
    /// Certificate expiry as a Unix epoch timestamp in seconds.
    pub cert_expires_at_epoch_secs: i64,
    /// The user ID asserted by the certificate.
    pub cert_user_id: &'a [u8],
    /// The sender ID claimed by the envelope; must match `cert_user_id`.
    pub envelope_sender_id: &'a [u8],
    /// The envelope payload bytes covered by the sender's signature.
    pub envelope_signing_bytes: &'a [u8],
    /// The sender's identity key used to verify `sender_signature`.
    pub sender_identity_key: &'a [u8],
    /// The sender's signature over `envelope_signing_bytes`.
    pub sender_signature: &'a [u8],
}

/// Verify the chain of trust on an envelope.
///
/// `verify_sender_sig` is a callback that verifies the sender's signature:
/// `(identity_key_bytes, data, signature_bytes) -> bool`.
///
/// Server certificate signatures are always verified with Ed25519.
pub fn verify_envelope(
    input: &EnvelopeVerificationInput<'_>,
    server_verifying_key: &VerifyingKey,
    verify_sender_sig: impl Fn(&[u8], &[u8], &[u8]) -> bool,
    check_expiry: bool,
) -> Result<()> {
    let cert_sig: [u8; 64] = input
        .cert_server_signature
        .try_into()
        .map_err(|_| CryptoError::InvalidSignature)?;
    server_verifying_key
        .verify(input.cert_signing_bytes, &Signature::from_bytes(&cert_sig))
        .map_err(|_| CryptoError::InvalidCertificate("invalid server signature".to_string()))?;

    if check_expiry {
        let now = chrono::Utc::now().timestamp();
        if input.cert_expires_at_epoch_secs <= now {
            return Err(CryptoError::ExpiredCertificate);
        }
    }

    if input.cert_user_id != input.envelope_sender_id {
        return Err(CryptoError::InvalidCertificate(
            "certificate user_id does not match sender_id".to_string(),
        ));
    }

    if !verify_sender_sig(
        input.sender_identity_key,
        input.envelope_signing_bytes,
        input.sender_signature,
    ) {
        return Err(CryptoError::InvalidSignature);
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use chacha20poly1305::aead::{OsRng, rand_core::RngCore};
    use ed25519_dalek::{Signer, SigningKey};

    fn gen_identity() -> ([u8; 32], [u8; 32]) {
        let mut secret_bytes = [0u8; 32];
        OsRng.fill_bytes(&mut secret_bytes);
        let signing_key = SigningKey::from_bytes(&secret_bytes);
        let verifying_key = signing_key.verifying_key();
        (verifying_key.to_bytes(), signing_key.to_bytes())
    }

    fn ed25519_verify(identity_key: &[u8], data: &[u8], signature: &[u8]) -> bool {
        let key_bytes: [u8; 32] = match identity_key.try_into() {
            Ok(b) => b,
            Err(_) => return false,
        };
        let Ok(vk) = VerifyingKey::from_bytes(&key_bytes) else {
            return false;
        };
        let sig_bytes: [u8; 64] = match signature.try_into() {
            Ok(b) => b,
            Err(_) => return false,
        };
        vk.verify(data, &Signature::from_bytes(&sig_bytes)).is_ok()
    }

    struct TestEnvelope {
        cert_signing_bytes: Vec<u8>,
        cert_server_signature: Vec<u8>,
        expires: i64,
        sender_id: Vec<u8>,
        envelope_data: Vec<u8>,
        sender_public: Vec<u8>,
        sender_sig: Vec<u8>,
    }

    fn make_test_envelope(
        server_secret: &[u8; 32],
        sender_secret: &[u8; 32],
        sender_public: &[u8; 32],
        expired: bool,
    ) -> TestEnvelope {
        let cert_signing_bytes = [sender_public.as_slice(), &[0u8; 16]].concat();
        let server_signing_key = SigningKey::from_bytes(server_secret);
        let cert_sig = server_signing_key.sign(&cert_signing_bytes);

        let expires = if expired {
            chrono::Utc::now().timestamp() - 3600
        } else {
            chrono::Utc::now().timestamp() + 86400
        };

        let sender_id = vec![42u8; 16];
        let envelope_data = b"test envelope data";
        let sender_signing_key = SigningKey::from_bytes(sender_secret);
        let sender_sig = sender_signing_key.sign(envelope_data);

        TestEnvelope {
            cert_signing_bytes,
            cert_server_signature: cert_sig.to_bytes().to_vec(),
            expires,
            sender_id,
            envelope_data: envelope_data.to_vec(),
            sender_public: sender_public.to_vec(),
            sender_sig: sender_sig.to_bytes().to_vec(),
        }
    }

    impl TestEnvelope {
        fn as_input(&self) -> EnvelopeVerificationInput<'_> {
            EnvelopeVerificationInput {
                cert_signing_bytes: &self.cert_signing_bytes,
                cert_server_signature: &self.cert_server_signature,
                cert_expires_at_epoch_secs: self.expires,
                cert_user_id: &self.sender_id,
                envelope_sender_id: &self.sender_id,
                envelope_signing_bytes: &self.envelope_data,
                sender_identity_key: &self.sender_public,
                sender_signature: &self.sender_sig,
            }
        }
    }

    #[test]
    fn test_valid_envelope() {
        let (sender_public, sender_secret) = gen_identity();
        let (server_public, server_secret) = gen_identity();
        let te = make_test_envelope(&server_secret, &sender_secret, &sender_public, false);
        let vk = VerifyingKey::from_bytes(&server_public).unwrap();
        assert!(verify_envelope(&te.as_input(), &vk, ed25519_verify, true).is_ok());
    }

    #[test]
    fn test_expired_cert_rejected() {
        let (sender_public, sender_secret) = gen_identity();
        let (server_public, server_secret) = gen_identity();
        let te = make_test_envelope(&server_secret, &sender_secret, &sender_public, true);
        let vk = VerifyingKey::from_bytes(&server_public).unwrap();
        let result = verify_envelope(&te.as_input(), &vk, ed25519_verify, true);
        assert!(matches!(result, Err(CryptoError::ExpiredCertificate)));
    }

    #[test]
    fn test_expired_cert_accepted_for_history() {
        let (sender_public, sender_secret) = gen_identity();
        let (server_public, server_secret) = gen_identity();
        let te = make_test_envelope(&server_secret, &sender_secret, &sender_public, true);
        let vk = VerifyingKey::from_bytes(&server_public).unwrap();
        assert!(verify_envelope(&te.as_input(), &vk, ed25519_verify, false).is_ok());
    }

    #[test]
    fn test_wrong_server_key_rejected() {
        let (sender_public, sender_secret) = gen_identity();
        let (_server_public, server_secret) = gen_identity();
        let (wrong_server_public, _) = gen_identity();
        let te = make_test_envelope(&server_secret, &sender_secret, &sender_public, false);
        let vk = VerifyingKey::from_bytes(&wrong_server_public).unwrap();
        let result = verify_envelope(&te.as_input(), &vk, ed25519_verify, true);
        assert!(matches!(result, Err(CryptoError::InvalidCertificate(_))));
    }
}
