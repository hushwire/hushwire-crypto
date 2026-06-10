//! Ed25519 signing-identity key generation for an organization.
//!
//! An organization has a dedicated Ed25519 signing keypair. The private key
//! stays on the client; only the public key is published to the server (and
//! embedded in invites) so peers can verify the organization's signatures.

use rand::RngExt as _;

/// Result of generating an Ed25519 signing keypair for an organization.
pub struct SigningKeypair {
    /// 32-byte Ed25519 private key (never leaves client storage).
    pub private_key: [u8; 32],
    /// 32-byte Ed25519 public key (sent to server, embedded in invites).
    pub public_key: [u8; 32],
}

/// Generate a new Ed25519 signing keypair for an organization.
///
/// Uses the system CSPRNG. The private key must be stored in the client's
/// encrypted local storage and never sent to the server.
pub fn generate_signing_keypair() -> SigningKeypair {
    use ed25519_dalek::SigningKey;

    let mut key_bytes = [0u8; 32];
    rand::rng().fill(&mut key_bytes[..]);
    let signing_key = SigningKey::from_bytes(&key_bytes);
    let verifying_key = signing_key.verifying_key();

    SigningKeypair {
        private_key: signing_key.to_bytes(),
        public_key: verifying_key.to_bytes(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn signing_keypair_generation() {
        let kp = generate_signing_keypair();
        assert_ne!(kp.private_key, [0u8; 32]);
        assert_ne!(kp.public_key, [0u8; 32]);
        // Verify the public key corresponds to the private key.
        let signing = ed25519_dalek::SigningKey::from_bytes(&kp.private_key);
        assert_eq!(signing.verifying_key().to_bytes(), kp.public_key);
    }

    #[test]
    fn signing_keypairs_are_unique() {
        let kp1 = generate_signing_keypair();
        let kp2 = generate_signing_keypair();
        assert_ne!(kp1.private_key, kp2.private_key);
        assert_ne!(kp1.public_key, kp2.public_key);
    }
}
