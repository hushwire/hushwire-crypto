//! Organization crypto: metadata encryption and a signing identity.
//!
//! An *organization* is a collection of users who want to share encrypted data
//! among themselves. It is the cryptographic backing for whatever a higher layer
//! calls a "group", "team", "server", or "guild": a named container that a set of
//! members can read and write while the relaying server stays blind to its
//! contents. The server only ever holds opaque ciphertext and forwards opaque
//! key-distribution blobs.
//!
//! An organization owns two pieces of crypto material:
//!
//! - A shared **metadata key** -- a 32-byte ChaCha20-Poly1305 key held by every
//!   member. It encrypts the org's human-readable metadata (its name, channel
//!   names, and so on). A caller-supplied context identifier (e.g. the org's id)
//!   is bound in as AAD so ciphertext cannot be transplanted between orgs. See
//!   [`metadata`].
//! - A **signing identity** -- an Ed25519 keypair. The public half is published so
//!   members can verify signatures attributed to the org; the private half never
//!   leaves the creator's client. See [`signing`].
//!
//! New members are admitted *server-blind*: the shared metadata key is wrapped for
//! each member's X25519 public key with [`metadata::encrypt_metadata_key`], so the
//! server relays only an opaque envelope and never learns the key.
//!
//! # Example
//!
//! One user creates an organization and encrypts its name, then shares the key with
//! a second user, who decrypts the name -- all without the server seeing plaintext:
//!
//! ```
//! use hushwire_crypto::hushwire::org::{metadata, signing};
//! use hushwire_crypto::hushwire::provisioning::generate_provisioning_keypair;
//!
//! // -- Creator: mint the org's signing identity and its shared metadata key --
//! let identity = signing::generate_signing_keypair();
//! let _org_public_key = identity.public_key; // published so members can verify
//! let metadata_key = metadata::generate_metadata_key();
//!
//! // The org's id doubles as the AAD binding this ciphertext to this org.
//! let org_id = [7u8; 16];
//! let name_ct = metadata::encrypt_metadata(&metadata_key, b"Acme Team", &org_id)?;
//!
//! // -- A second user joins; they already have an X25519 keypair --
//! let (member_private, member_public) = generate_provisioning_keypair();
//!
//! // -- Creator wraps the shared key for that member; the server stays blind --
//! let envelope = metadata::encrypt_metadata_key(&metadata_key, &member_public)?;
//!
//! // -- Member unwraps the shared key and reads the org's name --
//! let member_key = metadata::decrypt_metadata_key(&envelope, &member_private)?;
//! let name = metadata::decrypt_metadata(&member_key, &name_ct, &org_id)?;
//! assert_eq!(name, b"Acme Team".as_slice());
//! # Ok::<(), hushwire_crypto::CryptoError>(())
//! ```

pub mod metadata;
pub mod signing;
