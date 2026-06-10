# Signal Specification Divergence Register

hushwire-crypto is a clean-room implementation of the Signal Protocol, written
in Rust from Signal's published specifications. It is not a fork of libsignal.

This document catalogs every place where hushwire-crypto intentionally diverges
from those specifications. Each divergence includes the relevant source file, what
Signal specifies, what Hushwire does instead, why, and what the security impact
is.

**Audience:** Hushwire developers, security researchers, potential auditors.

**Scope:** Only the `hushwire-crypto` crate. SDK-level decisions (session
management orchestration, key distribution strategy, epoch keys) are out of
scope.

**Living document.** Any change to hushwire-crypto's algorithms or constants
must update this register. If you find a divergence not listed here, that is a
documentation bug.


## Specification coverage

| Signal specification | Reference | hushwire-crypto module | Status |
|---|---|---|---|
| PQXDH | [signal.org/docs/specifications/pqxdh](https://signal.org/docs/specifications/pqxdh/) | `src/pqxdh.rs`, `src/prekey.rs` | Implemented with divergences |
| Double Ratchet | [signal.org/docs/specifications/doubleratchet](https://signal.org/docs/specifications/doubleratchet/) | `src/ratchet/` | Implemented with divergences |
| Sesame | [signal.org/docs/specifications/sesame](https://signal.org/docs/specifications/sesame/) | `src/sesame/` | Implemented with divergences |
| XEdDSA | [signal.org/docs/specifications/xeddsa](https://signal.org/docs/specifications/xeddsa/) | N/A | **Not implemented.** Eliminated by D-01 |
| ML-KEM Braid | [signal.org/docs/specifications/mlkem-braid](https://signal.org/docs/specifications/mlkem-braid/) | `src/braid/`, `src/ratchet/` | Implemented (the Triple Ratchet; see D-13) |
| Sender Keys | Unpublished (inferred from libsignal source) | `src/sender_key/` | Implemented with divergences |
| Sealed Sender | Unpublished (inferred from libsignal source) | `src/sealed_sender/` | Implemented with divergences |


## Divergence classification

Each divergence below is assigned one of these classifications:

- **Equivalent** -- Different implementation, cryptographically identical output.
  No change to security properties.
- **Substitution** -- Different cryptographic primitive with equivalent or better
  security properties. Signal's specification explicitly permits most of these
  substitutions.
- **Enhancement** -- Provides additional security mechanisms not present in
  Signal's approach. These have not been formally proven to be strictly
  stronger; "enhancement" means the construction includes more data or more
  steps, which is plausible-but-not-proven to improve security.
- **Novel** -- New construction with no published security proof. Requires
  independent cryptographic analysis.
- **Domain Separation** -- Different HKDF info strings or constants. Intentional;
  prevents cross-protocol attacks. No security impact beyond non-interoperability.
- **Compliant** -- Matches Signal's specification. Included for completeness
  where an auditor might expect to find a divergence.


## Divergence register

### D-01: Identity key format (Ed25519 canonical)

| | |
|---|---|
| **Classification** | Substitution |
| **Source** | `src/keys.rs` -- `IdentityKeyPair`, `IdentityPublicKey` |
| **Signal** | Curve25519 is the canonical key format. Signing operations use XEdDSA, which constructs an Ed25519 key from a Curve25519 private key, signs, and discards the Ed25519 key. |
| **Hushwire** | Ed25519 is the canonical key format. X25519 keys are derived on-the-fly for DH operations via `SHA-512(seed)` clamping and Edwards-to-Montgomery point conversion. |

**Rationale.** Ed25519 has broader library support and more extensive audit
coverage than XEdDSA. The Ed25519-to-X25519 conversion is well-defined: the
private key conversion follows RFC 8032 Section 5.1.5 (SHA-512 hash of seed,
clamp low 32 bytes), and the public key conversion uses the standard
Edwards-to-Montgomery map (RFC 7748 Section 4.1). Both approaches produce valid
Curve25519 keys for DH agreement.

**Security impact.** Equivalent. The `ed25519_to_x25519_public_key_conversion`
and `x25519_dh_agreement` tests verify the conversion produces matching
public keys and correct shared secrets. Public key equality uses constant-time
comparison (`subtle::ConstantTimeEq`).

**What this eliminates.** XEdDSA is not implemented anywhere in hushwire-crypto.
Identity keys are stored as Ed25519 seeds (32 bytes) and never as Curve25519
scalars.


### D-02: AEAD cipher (XChaCha20-Poly1305)

| | |
|---|---|
| **Classification** | Substitution |
| **Source** | `src/aead.rs` -- `encrypt`, `decrypt`, `derive_enc_key` |
| **Signal** | AES-256-CBC with HMAC-SHA256 (Encrypt-then-MAC). The Double Ratchet specification recommends any AEAD scheme. |
| **Hushwire** | XChaCha20-Poly1305 with HKDF-SHA256 key derivation. The message key is expanded via `HKDF(salt=0, ikm=message_key, info="HushwireMessageKey")` into a 32-byte encryption key. |

**Rationale.** XChaCha20-Poly1305 is a modern AEAD cipher that eliminates
several classes of implementation risk: no padding oracle (stream cipher), safe
random nonce generation (24-byte nonce space makes collisions negligible), and
constant-time on all platforms without hardware AES.

**Wire overhead.** 40 bytes per message (24-byte nonce + 16-byte Poly1305 tag).

**Security impact.** Equivalent or better. The Double Ratchet specification
explicitly permits AEAD substitution.


### D-03: Serialization format (Postcard with HWCR prefix)

| | |
|---|---|
| **Classification** | Substitution |
| **Source** | `src/serialization.rs` |
| **Signal** | Protocol Buffers (protobuf) for all serialized structures. |
| **Hushwire** | Postcard (compact binary serde format). Session state is prefixed with `b"HWCR"` magic bytes and a version integer for forward-compatible format upgrades. |

**Rationale.** Postcard is Rust-native, more compact than protobuf, and
integrates directly with serde. The HWCR prefix enables version-aware
deserialization without external schema management.

**Security impact.** None. Serialization format has no cryptographic
significance.


### D-04: Message padding (ISO/IEC 7816-4)

| | |
|---|---|
| **Classification** | Equivalent |
| **Source** | `src/padding.rs` -- `pad`, `unpad` |
| **Signal** | PKCS#7-style padding to the nearest 160-byte block boundary. |
| **Hushwire** | ISO/IEC 7816-4 padding to 160-byte blocks. Appends `0x80`, then fills with `0x00` bytes to the next block boundary. |

**Block size.** 160 bytes (same as Signal).

**Rationale.** ISO 7816-4 is unambiguous for arbitrary binary data (the `0x80`
marker byte is distinct from zero-filled padding). Both schemes hide plaintext
length to the same 160-byte granularity.

**Security impact.** Equivalent. Same privacy property (ciphertext length
reveals plaintext length only to the nearest 160 bytes).


### D-05: PQXDH HKDF info string

| | |
|---|---|
| **Classification** | Domain Separation |
| **Source** | `src/pqxdh.rs` line 14 -- `PQXDH_INFO = b"HushwireProtocol"` |
| **Signal** | Application-defined. The PQXDH specification states: "applications should define a unique info string." |
| **Hushwire** | `"HushwireProtocol"` |

**Security impact.** None. This is the intended use of the info parameter --
domain separation between different protocols using the same HKDF construction.


### D-06: PQXDH HKDF salt

| | |
|---|---|
| **Classification** | Equivalent |
| **Source** | `src/pqxdh.rs` line 91 -- `let salt = [0u8; 32]` |
| **Signal** | Empty salt (zero-length byte sequence `""`). |
| **Hushwire** | `[0u8; 32]` (32 zero bytes). |

**Rationale.** Per RFC 5869 Section 2.2: "if [the salt] is not provided, it
is set to a string of HashLen zeros." For HKDF-SHA256, HashLen = 32, so
`[0u8; 32]` and an empty salt produce identical HKDF extraction output.

**Security impact.** None. Cryptographically identical.


### D-08: Associated data construction

| | |
|---|---|
| **Classification** | Enhancement |
| **Source** | `src/ratchet/mod.rs` -- `build_ad` |
| **Signal** | `AD = Encode(IKa) \|\| Encode(IKb)`, where `Encode` includes a type byte prefix for the identity key format. |
| **Hushwire** | `AD = sender_x25519_pub(32) \|\| recipient_x25519_pub(32) \|\| header` |

**Two differences from Signal:**

1. Uses X25519 public key representations (the actual DH agreement keys) rather
   than the Ed25519 identity key encodings.
2. Includes the plaintext serialized header in the associated data. This binds
   the header to the ciphertext, preventing header substitution attacks where
   an attacker replaces a message's header with a different valid header.

**Known limitation: Edwards-to-Montgomery is 2-to-1.** The conversion from
Ed25519 to X25519 public keys (`IdentityPublicKey::to_x25519`) discards the
sign bit. Two distinct Ed25519 identity keys can map to the same X25519
public key. This means the AD binds a Montgomery equivalence class, not a
unique Ed25519 identity. Signal's AD uses the identity key encoding directly
(with type prefix), which does not have this ambiguity. The practical risk is
negligible -- an attacker would need to find a second Ed25519 key in the same
equivalence class that also passes identity verification -- but this is a
theoretical weakening relative to Signal's AD construction.

**Security impact.** The header binding is an additional integrity guarantee
not present in Signal's AD construction. The X25519 equivalence class issue is
a theoretical weakening. Net impact is believed to be positive but has not been
formally proven.


### D-10: HKDF info strings (Double Ratchet)

| | |
|---|---|
| **Classification** | Domain Separation |
| **Source** | `src/kdf.rs` -- `kdf_rk` uses `"HushwireRatchet"` |
| **Signal** | The Double Ratchet specification leaves info strings as application-defined. |
| **Hushwire** | `"HushwireRatchet"` for root key derivation. |

**Security impact.** None. Standard domain separation.


### D-11: KDF_CK chain key derivation (compliant)

| | |
|---|---|
| **Classification** | Compliant |
| **Source** | `src/kdf.rs` lines 59-74 -- `kdf_ck` |
| **Signal** | Message key = `HMAC-SHA256(ck, 0x01)`. New chain key = `HMAC-SHA256(ck, 0x02)`. |
| **Hushwire** | Identical. |

**Included for completeness.** An auditor reviewing KDF constants should confirm
this matches the specification.


### D-12: MAX_SKIP threshold (compliant)

| | |
|---|---|
| **Classification** | Compliant |
| **Source** | `src/ratchet/skipped.rs` line 6 -- `MAX_SKIP = 2000` |
| **Signal** | The specification recommends implementations set a maximum number of skipped message keys but does not prescribe a specific value. |
| **Hushwire** | 2000 messages. Also used as the maximum gap in sender key decryption (`src/sender_key/mod.rs`). |

**Security impact.** None. Within the specification's recommendation.


### D-13: Continuous post-quantum ratchet (Signal's ML-KEM Braid / Triple Ratchet)

| | |
|---|---|
| **Classification** | Compliant (construction); clean-room implementation |
| **Source** | `src/braid/` -- `BraidState`, `erasure`, `kem`, `auth`; `src/ratchet/spqr.rs` -- `SpqrState`; `src/ratchet/mod.rs` -- `encrypt_raw`/`decrypt` (the `KDF_HYBRID` combine); `src/kdf.rs` -- the SPQR KDFs |
| **Signal** | ML-KEM is used in the initial PQXDH handshake. For continuous post-quantum key agreement Signal specifies the ML-KEM Braid + the Sparse Post-Quantum Ratchet (the "Triple Ratchet", eprint 2025/078): a sparse, state-machine-based KEM ratchet whose large keys/ciphertexts are streamed via erasure coding, producing a fresh secret roughly every ~74 messages. The SPQR is an independent ratchet that emits a per-message key; for **every** message the AEAD key is `KDF_HYBRID(ec_mk, pq_mk)` (Double Ratchet spec section 6), combined at the message-key layer -- **not** folded into the Double Ratchet root key. |
| **Hushwire** | Implements that construction. The braid (`src/braid/`) runs the 11-state machine (the SCKA); `SpqrState` (`src/ratchet/spqr.rs`) is the spec section 5 `spqr_state` -- per-epoch KDF chains reseeded by `KDF_SCKA_RK` at each completion epoch, bootstrapped by `KDF_SCKA_INIT`, with an `(epoch, n)`-indexed skipped-key store. Every message's AEAD key is `mk = KDF_HYBRID(ec_mk, pq_mk)`; the EC root key is classical DH-only. This **replaces** both the prior novel per-step PQ ratchet (the original D-13) and the interim root-key fold (issue #535 comment, retracted), which mirrored neither Signal's construction nor its proof. |

**Construction is compliant; the implementation is clean-room.** Unlike the
original D-13 (a novel, every-step, full-size PQ mix with no published proof),
this mirrors Signal's formally-modeled Triple Ratchet -- so the *protocol* carries
a published proof (ProVerif/hax/F*, eprint 2025/078). What is **not** proven is
*this Rust implementation*.

**Clean-room status (honest scope).** The implementation is written clean-room from
the published specs. Two *narrow instantiation details* were cross-validated against
the structure of the AGPL reference (`signalapp/SparsePostQuantumRatchet`), because
the spec is erroneous at those points; **no source code or test vectors were copied**,
and the validation returned only a structural yes/no (see "Spec errata" below):
(1) `KDF_SCKA_CK` -- the spec section 7.2 parameter table is a copy-paste of
`KDF_SCKA_INIT`; we follow the normative section 5.2 definition. (2) the receive
skip bound -- spec section 5.6 skips through `header.n` then over-advances; the
correct bound is `header.n - 1`. Both are documented in code. Everything else is
spec-only clean-room.


### D-14: Sender key authentication (Ed25519 signatures for text; HMAC for voice)

| | |
|---|---|
| **Classification** | Compliant (text/group); Substitution (voice, transitional) |
| **Source** | `src/sender_key/mod.rs` -- `SenderKeyAuth`, `MessageAuth`, `group_encrypt`, `group_decrypt` |
| **Signal** | Per-message Ed25519 signatures (64 bytes) produced with a per-sender-key signing keypair distributed in the `SenderKeyDistributionMessage`. Provides non-repudiation: no group member can forge another member's messages. |
| **Hushwire (text/group)** | Identical: each sender key carries a fresh Ed25519 signing keypair; the public half is distributed in the `SenderKeyDistributionMessage` (`signing_key`), each message carries an Ed25519 signature (`MessageAuth::Signature`) over `group_id \|\| iteration(big-endian u32) \|\| ciphertext`. The private signing key never leaves the sender, so no group member can forge another's messages. |
| **Hushwire (voice)** | HMAC-SHA256 (`MessageAuth::Hmac`), auth key `HMAC-SHA256(chain_key, 0x03)`, over the same bytes. |

**Text/group: compliant.** This matches Signal's sender key authentication. The
in-group forgeability of the previous HMAC scheme has been removed: a group
member who holds the chain key can derive every message key but cannot produce
a valid signature without the private signing key. Identity binding comes from
the authenticated pairwise channel (Double Ratchet session) the distribution
message travels over.

**Voice: transitional HMAC.** Voice frames are encrypted per-Opus-frame at
~50 fps. A per-frame Ed25519 signature would add 64 bytes per packet (often a
40-100% size increase on small frames) plus a sign/verify per frame, and the
voice transport layer already authenticates the source. Following Signal's
ringrtc (which does not sign individual frames), voice retains HMAC pending the
dedicated voice-frame crypto scheme. Within the group, voice frames remain
forgeable by a chain-key holder; this is the documented, scoped exception.

**Downgrade resistance.** `MessageAuth` is an enum and the chain's mode is fixed
at creation (and travels in the distribution message). `group_decrypt` rejects a
message whose auth variant does not match the chain mode, so an attacker cannot
strip a signature and substitute a (forgeable) HMAC on a `Signed` chain.


### D-15: Sender key chain derivation (0x03 auth key constant, voice only)

| | |
|---|---|
| **Classification** | Enhancement (voice only) |
| **Source** | `src/sender_key/mod.rs` -- `hmac_derive` with `0x03` |
| **Signal** | Chain key derivation uses `0x01` (message key) and `0x02` (chain key). No `0x03` constant (text/group signatures use a separate signing key, not a derived symmetric key). |
| **Hushwire** | Same `0x01` and `0x02` constants. `0x03` derives the HMAC authentication key used **only** for voice (`SenderKeyAuth::Hmac`); text/group chains use Ed25519 signatures and never derive `0x03`. |

**Security impact.** Safe. HMAC-SHA256 with distinct single-byte inputs produces
cryptographically independent keys. The derived keys (message, chain, and -- for
voice -- auth) are computationally independent given the chain key. Removed when
voice migrates to the dedicated voice-frame crypto scheme.


### D-16: Sealed sender certificate hash binding

| | |
|---|---|
| **Classification** | Enhancement |
| **Source** | `src/sealed_sender/mod.rs` lines 116-124 |
| **Signal v2** | `AD = ephemeral_public \|\| encrypted_static` |
| **Hushwire** | `AD = ephemeral_public \|\| encrypted_static \|\| cert_hash` where `cert_hash = SHA-256(postcard_serialize(sender_certificate))` |

**Rationale.** Including the certificate hash in the AEAD associated data
explicitly binds the sender certificate to the envelope. Without this binding,
an attacker who compromises a recipient's key could potentially replace the
certificate inside a valid envelope (certificate transplant attack). The
cert_hash is also carried unencrypted in the envelope so the recipient can
reconstruct the AD for decryption, then verified against the decrypted
certificate post-decryption.

**Known limitation: metadata leakage.** The cert_hash is carried unencrypted
in the `SealedSenderEnvelope`. A passive observer (including the server, which
sealed sender is designed to hide the sender from) can determine whether two
sealed sender messages use the same sender certificate without decrypting them.
Since sender certificates contain `sender_uuid + device_id + expiration`, the
cert_hash functions as a per-sender pseudonym visible to the server for the
lifetime of that certificate. This partially undermines the sealed sender
property. Signal's approach of not including the cert_hash in the unencrypted
envelope avoids this leak.

**Security impact.** The certificate binding is an additional integrity
guarantee. The metadata leakage is a genuine downside that weakens sender
anonymity. Whether the net effect is positive depends on the threat model:
if the primary concern is certificate transplant attacks, this is stronger;
if the primary concern is sender privacy from the server, this is weaker.


### D-17: Sealed sender HKDF info strings

| | |
|---|---|
| **Classification** | Domain Separation |
| **Source** | `src/sealed_sender/mod.rs` lines 15-16 |
| **Signal** | Info strings reference "Sealed Sender v2". |
| **Hushwire** | `"HushwireSealedSender"` (layer 1) and `"HushwireSealedSenderMessage"` (layer 2). |

**Security impact.** None. Standard domain separation.


### D-18: Sealed sender certificate model (compliant)

| | |
|---|---|
| **Classification** | Compliant |
| **Source** | `src/sealed_sender/certificate.rs` |
| **Signal** | Trust hierarchy: server certificate (self-signed, Ed25519) containing key_id and public key; sender certificate (server-signed) containing sender UUID, device ID, identity key, and expiration. Validation requires a trust root public key. |
| **Hushwire** | Same model. `ServerCertificate` is self-signed with Ed25519. `SenderCertificate` is server-signed and includes sender UUID, device ID, identity key, and expiration. Validation checks: (1) certificate not expired, (2) server certificate self-verification, (3) server key matches trust root, (4) server signature on sender certificate, (5) sender's X25519 key matches certificate identity key. |

**Included for completeness.** The certificate model is compliant.


### D-19: Sesame lifecycle constants (compliant)

| | |
|---|---|
| **Classification** | Compliant |
| **Source** | `src/sesame/lifecycle.rs` |
| **Signal** | The Sesame specification defines MAXSEND, MAXRECV, and MAXLATENCY as implementation-defined constants with the constraint `MAXRECV > MAXSEND + 2 * MAXLATENCY`. |
| **Hushwire** | `MAXSEND = 30 days`, `MAXRECV = 60 days`, `MAXLATENCY = 2 hours`. The constraint is enforced at compile time via `const _: () = assert!(MAXRECV > MAXSEND + 2 * MAXLATENCY)`. |

**Security impact.** None. Within the specification's requirements.


### D-20: Sesame dual-init convergence mechanism (compliant)

| | |
|---|---|
| **Classification** | Compliant |
| **Source** | `src/sesame/state.rs` -- `SessionEntry::convergence_priority`; `src/ratchet/mod.rs` line 588 -- `RatchetSession::root_key_id()` |
| **Signal** | The Sesame specification addresses dual-initialization scenarios but does not prescribe a convergence mechanism. |
| **Hushwire** | Uses a deterministic shared-secret-derived priority (`convergence_priority: u64`, first 8 bytes of the initial shared secret) to select the active session. Both peers converge independently. |

**Included for completeness.** The Sesame specification leaves the dual-init
convergence mechanism as an implementation choice. The `convergence_priority`
is derived deterministically from the shared secret (first 8 bytes as a
big-endian u64), which is identical on both peers by definition. This adds
no new cryptographic assumptions -- it is a tie-breaking rule over existing
session state.


## Continuous post-quantum ratchet: the ML-KEM Braid (D-13)

This section provides the detailed analysis that the continuous post-quantum
ratchet warrants. The *construction* now mirrors Signal's formally-modeled Triple
Ratchet, so it is classified **Compliant** rather than Novel; what remains
unverified is the clean-room Rust *implementation* of it.

### What Signal does

Signal's PQXDH specification adds ML-KEM (formerly CRYSTALS-Kyber) to the
initial key agreement handshake. The KEM shared secret is mixed into the
root key derivation alongside the X25519 DH outputs.

For continuous post-quantum protection Signal specifies the **ML-KEM Braid** plus
the **Sparse Post-Quantum Ratchet (SPQR)** -- the "Triple Ratchet", eprint
2025/078. Because an ML-KEM-768 public key (1184 B) and ciphertext (1088 B) do not
fit in one message, they are erasure-coded and streamed across many messages; one
fresh KEM shared secret completes roughly every ~74 messages. That secret reseeds
the SPQR -- an **independent ratchet that runs in parallel with the EC Double
Ratchet** and emits its own per-message key (`pq_mk`). For **every** message the
AEAD key is `mk = KDF_HYBRID(ec_mk, pq_mk)`, combining the two ratchets' message
keys (Double Ratchet spec section 6). The PQ secret is **not** folded into the EC
root key; the EC root step stays classical DH-only.

### What Hushwire does

Hushwire implements that construction. The braid is a standalone module
(`src/braid/`), independent of the ratchet (the dependency direction is
`ratchet` -> `braid`, never the reverse):

- `braid/kem.rs` -- incremental ML-KEM-768 over `libcrux-ml-kem` (the same
  primitive Signal's SPQR uses; Apache-2.0, hax/F*-verified). All randomness is
  injected, so the path is deterministic for KATs.
- `braid/erasure.rs` -- streaming Reed-Solomon (systematic, GF(2^16)). A `k`-data
  message also emits `k` recovery codewords, so any `k` of `2k` distinct
  codewords reconstruct it; the encoder cycles (re-streams) so a lossy channel
  still completes. Codewords are 32 bytes (`CHUNK_BYTES`).
- `braid/auth.rs` -- the per-epoch authenticator ratchet (`KDF_OK`, `KDF_AUTH`),
  HMAC-SHA256, constant-time verify, domain-separated by `PROTOCOL_INFO =
  "HushwireBraid"` (Hushwire never wire-interoperates with Signal's deployment).
- `braid/state_machine.rs` -- the 11-state machine. One party streams the
  encapsulation-key header, the other encapsulates; both derive the same
  `EpochSecret`, and the roles swap each epoch. `MsgType` is 1:1 with the spec's
  braid `Send`/`Receive` flow. (The spec lists a 7th message type, `Ct1Ack`, but its
  braid pseudocode never sends or matches it -- the keypair owner always
  acknowledges ct1 via `EkCt1Ack` and re-streams ek -- so we omit the unused
  variant rather than carry dead code.)

**The combiner (`src/ratchet/spqr.rs`, `src/ratchet/mod.rs` `encrypt_raw`/`decrypt`,
`src/kdf.rs`).** `SpqrState` is the spec section 5 `spqr_state`: the braid (the
SCKA) plus a separate SPQR root key and per-epoch send/receive KDF chains. Each
braid completion epoch reseeds the chains (`KDF_SCKA_RK`); the epoch-0 bootstrap
chains come from `KDF_SCKA_INIT`. Per message, `SCKARatchetSendKey` /
`ReceiveKey` advance the current epoch's chain (`KDF_SCKA_CK`) to produce `pq_mk`,
and the AEAD key is:

```
mk = KDF_HYBRID(ec_mk, pq_mk)   // every message
```

The EC root step is classical DH-only (`KDF_RK(rk, dh_out)`); the post-quantum
secret enters at the **message-key layer for every message**, not the root key.

**Synchronisation (both peers derive the same `pq_mk`).** The SPQR is an
independent ratchet with its own per-epoch chains and `(epoch, n)`-indexed
skipped-key store. A message carries its PQ counter `pqN` (the spec's
`SCKA_HEADER = (scka_msg, pqN)`); the receiving epoch comes from the braid's
epoch-agreement (`sending_epoch == receiving_epoch`), read from the message's own
epoch so out-of-order delivery across a reseed stays correct. The braid's
one-epoch lag (`sending_epoch = epoch - 1`) guarantees both peers hold the chain a
message keys under by the time they process it. Out-of-order and gap recovery use
the SPQR skipped-key store, exactly as the EC ratchet does.

**Transport is authenticated.** The braid codeword and the PQ counter ride in the
`MessageHeader`, and the entire serialized header is bound into the message's AEAD
associated data (D-08). The SPQR ratchet advances during key derivation (as the EC
ratchet does), but the braid authenticates its own codewords (per-epoch
authenticator MAC), and any tampering with the codeword or counter changes the AD,
so the message fails closed at the AEAD tag. An on-path attacker cannot strip,
forge, or reorder a codeword without breaking decryption -- and a stripped codeword
also changes `pq_mk`, so there is no silent downgrade to classical-only.

### Mixed KEM security levels

| | PQXDH (initial) | Continuous ratchet |
|---|---|---|
| **KEM** | ML-KEM-1024 | ML-KEM-768 |
| **Classical security** | 256 bits | 192 bits |
| **Quantum security** | 233 bits | 179 bits |
| **Ciphertext size** | 1568 bytes | 1088 bytes |
| **Public key size** | 1568 bytes | 1184 bytes |

**Rationale.** The PQXDH shared secret protects the entire session lifetime, so
it uses the strongest available KEM. The braid's epoch key is ephemeral (a fresh
KEM execution roughly every ~74 messages) and balances security against the
bandwidth of streaming a full key/ciphertext. ML-KEM-768 is the parameter
Signal's ML-KEM Braid uses.

### Bandwidth impact

The braid streams one ML-KEM-768 public key (1184 B) and ciphertext (1088 B) per
epoch -- about 2272 B of KEM material -- but **spread across the whole epoch** as
32-byte erasure codewords (plus recovery shards), not in a single 2272-byte
header. Each ratchet message carries one small codeword (plus a few bytes of
epoch bookkeeping). Because a fresh epoch completes only every ~74 messages, the
amortized per-message overhead is small and there is no large single header that
could trigger IP fragmentation -- a deliberate improvement over the prior
per-step 2272-byte mix.

### Informal security argument

The hybrid is **additive**: for every message the AEAD key is
`KDF_HYBRID(ec_mk, pq_mk)` -- HKDF keyed by the EC message key with the PQ message
key as salt. Neither ratchet replaces the other.

- **If ML-KEM-768 is broken** (or `pq_mk` is predictable), the EC `ec_mk`
  contribution alone preserves classical Double-Ratchet security.
- **If X25519 is broken by a quantum computer**, the SPQR `pq_mk` contribution
  provides 192-bit classical / 179-bit quantum security, refreshed by a fresh KEM
  secret roughly every ~74 messages. An attacker must break the KEM at each epoch
  independently, not just at the initial handshake.
- **If both are secure**, the combined HKDF output is at least as strong as either.

**Key assumption.** This relies on the HKDF/PRF property: if either of the two
32-byte inputs (`ec_mk`, `pq_mk`) is uniformly random and independent, the
`KDF_HYBRID` output is pseudorandom regardless of the other. Beyond this combiner
assumption, the *protocol* (when a secret completes, how the two ratchets stay
synchronised, forward secrecy and post-compromise security of the schedule) is
exactly Signal's Triple Ratchet, analysed in eprint 2025/078.

### Failure modes

**Fail-closed downgrade (the central property).** The braid codeword and epoch
bookkeeping are in the header, which is AEAD associated data. If an attacker
strips or garbles the codeword, the header bytes change, the message's AEAD tag
no longer verifies, and the message is rejected. There is no silent fallback to
classical-only: the attack breaks the message rather than degrading it. (An
attacker who persistently drops codeword-bearing messages can deny service, but
cannot weaken the cryptography -- the same property as any MITM who drops
traffic.)

**Bootstrap (no PQ-absent window).** Unlike the prior root-key fold, the hybrid is
active from message 1: the SPQR's epoch-0 chains are seeded by `KDF_SCKA_INIT` from
the session secret, so `pq_mk` -- and therefore `KDF_HYBRID(ec_mk, pq_mk)` -- exists
before the braid completes its first KEM epoch. The bootstrap `pq_mk` is derived
from the PQXDH-bootstrapped session secret (which already carries one-shot
ML-KEM-1024); fresh KEM material then refreshes the SPQR chains as braid epochs
complete. There is no message that is keyed classical-only.

**Message loss recovers, it does not wedge.** Loss of a codeword-bearing message
is exactly what the Reed-Solomon erasure coding is for: any `k` of `2k`
codewords reconstruct the object, and the encoder re-streams, so loss delays an
epoch's completion but never permanently stalls it. The in-flight reassembly
state is persisted in `SerializedState`, so a process restart mid-stream resumes
rather than wedging the session.

**Injected/garbled codeword does not brick the session.** Even setting aside the
AEAD authentication above, the braid is internally robust: a recoverable
validation error restores the prior state rather than poisoning it, and a
reconstructed object that fails its authenticator MAC resets the decoder so
honest re-streamed codewords rebuild it. A single bad codeword cannot
permanently brick a live session.

**ML-KEM implicit rejection.** ML-KEM decapsulation always succeeds, producing a
pseudorandom shared secret for invalid ciphertexts (FIPS 203 implicit rejection).
The braid's authenticator MAC over the ciphertext catches this: a tampered
ciphertext fails `vfy_ct` and is rejected rather than producing a divergent
secret.

**Session state size.** The SPQR persists the braid's current state (at most one
in-flight KEM keypair/encapsulation plus reassembly buffers for the objects
currently streaming), a small window of per-epoch KDF chains (`kdfchains`;
`ClearOldEpochs` drops anything two epochs behind), and the skipped-key store
(`MKSKIPPED`, bounded by `MAX_SKIP = 2000` per chain, as the EC ratchet is). State
growth is bounded and small.

### Spec errata (and how we handle them)

Two errors in the rendered Double Ratchet spec affect a faithful implementation.
We follow the normative definitions / the pairing-correct structure (both
cross-validated against the AGPL reference's structure, no code copied); each is
documented at its call site.

1. **`KDF_SCKA_CK` (spec section 7.2).** The recommended HKDF parameter table for
   `KDF_SCKA_CK(ck, ctr)` is a copy-paste of `KDF_SCKA_INIT`: it lists `ikm = sk`
   (a variable not in scope for this function) and ignores both `ck` and `ctr`,
   which would make every chain step a constant. We follow the **normative section
   5.2 definition** -- keyed by the chain key `ck`, binding the counter `ctr`
   (`src/kdf.rs::kdf_scka_ck`).
2. **Receive skip bound (spec section 5.6).** `SCKARatchetReceiveKey` calls
   `SkipMessageKeys(receiving_epoch, header.n)` and then advances once more, which
   over-advances and returns the `header.n + 1` key for an in-order message. The
   pairing-correct bound is **`header.n - 1`**: skip-and-store the gap, then a
   single trailing advance yields the message's key
   (`src/ratchet/spqr.rs::ratchet_receive_key`).

### What this implementation lacks

**The protocol is proven; this implementation is not.** The Triple Ratchet
construction has a published proof (ProVerif/hax/F*, eprint 2025/078). This Rust
code is written clean-room from the spec and has **not** been independently
verified or audited. The honest claim is "implements Signal's formally-verified
ML-KEM Braid / Triple Ratchet protocol," never "is formally verified." Two narrow
instantiation details were cross-validated against the *structure* of the AGPL
reference (no code or vectors copied) because the published spec is erroneous at
those points -- see "Clean-room status" and "Spec errata".

**Auditors should prioritize the implementation gap:** the Reed-Solomon wrapper's
erasure-interface contract (k-of-n recoverability, fail-closed below threshold),
the 11-state reassembly machine, the SPQR key schedule (`SpqrState`: per-epoch
chains, reseed, `(epoch, n)` skipped-key store), and the combiner (both peers
deriving the identical `pq_mk`, and `KDF_HYBRID(ec_mk, pq_mk)` per message). The
`ml-kem`/`libcrux-ml-kem` primitive itself is out of scope (separately verified
upstream).


## Cryptographic dependencies

All cryptographic operations in hushwire-crypto are performed by these crates:

| Crate | Version | Purpose | Algorithm |
|---|---|---|---|
| `ed25519-dalek` | 2.2 | Identity keys, signing, certificate verification | Ed25519 (RFC 8032) |
| `x25519-dalek` | 2.0 | Ephemeral and identity DH key agreement | X25519 (RFC 7748) |
| `curve25519-dalek` | 4 | Edwards-to-Montgomery point conversion (D-01) | Curve25519 |
| `chacha20poly1305` | 0.10 | Message AEAD encryption | XChaCha20-Poly1305 |
| `hkdf` | 0.12 | Key derivation (root keys, sealed sender) | HKDF-SHA256 (RFC 5869) |
| `sha2` | 0.10 | Certificate hashing, identity key conversion | SHA-256, SHA-512 |
| `hmac` | 0.12 | Chain key derivation, sender key authentication | HMAC-SHA256 (RFC 2104) |
| `ml-kem` | 0.3 | Post-quantum KEM for the PQXDH handshake | ML-KEM-1024 (FIPS 203) |
| `libcrux-ml-kem` | 0.0.9 | Incremental KEM for the ML-KEM Braid (D-13) | ML-KEM-768 (FIPS 203, hax/F*-verified) |
| `reed-solomon-simd` | 3.1 | Erasure coding for the braid's codeword stream (D-13) | Reed-Solomon over GF(2^16) |
| `subtle` | 2 | Constant-time comparison for identity keys and braid MACs | |
| `zeroize` | 1 | Zeroing secret key material on drop | |
| `postcard` | 1.1 | Binary serialization of all crypto structures | |

Versions shown are the minimum semver constraints from the workspace
`Cargo.toml`. Run `cargo tree -p hushwire-crypto` for resolved versions.


## Known limitations

These are cross-cutting concerns that do not map to a single divergence but
affect the overall security posture.

### Timing side channels

The skipped-keys store (`src/ratchet/skipped.rs`) exhibits timing leakage.
`try_remove_by_dh` performs a HashMap lookup for a matching
`(dh_public_key, message_number)` pair. The HashMap lookup is O(1) amortized
but not constant-time in the cryptographic sense.

### PQ coverage

The continuous PQ ratchet (D-13) is fail-closed and applies to **every** message:
the AEAD key is `KDF_HYBRID(ec_mk, pq_mk)` from message 1 onward (the SPQR's
epoch-0 chains are seeded by `KDF_SCKA_INIT` from the session secret, so there is
no classical-only bootstrap window). Fresh KEM material refreshes the SPQR chains
as braid epochs complete.

The braid codeword and PQ counter are carried in the header and bound into the AEAD
associated data. A stripped or garbled codeword changes the header (fails the AEAD
tag) and changes `pq_mk` (fails decryption) -- no silent fallback to classical-only.
Message loss delays an epoch's completion but recovers via erasure re-streaming and
the SPQR skipped-key store, rather than dropping PQ coverage.

### Enhancement claims are unproven

The divergences classified as "Enhancement" (D-08, D-15, D-16)
include additional data or steps in their security mechanisms compared to
Signal. While this is plausible-but-not-proven to improve security,
"enhancement" should not be read as "formally stronger." Additional
complexity can introduce bugs (canonicalization issues, parsing ambiguities,
metadata leakage as in D-16). None of these enhancements have been subjected
to formal security analysis.


## Auditor guidance

Recommended review priority, from highest to lowest:

1. **D-13 (Continuous PQ ratchet / ML-KEM Braid).** The construction is Signal's
   formally-modeled Triple Ratchet, but this clean-room Rust implementation is
   unverified. Review the implementation gap, not the protocol: `src/braid/`
   (the erasure-interface contract in `erasure.rs` -- k-of-n recoverability,
   fail-closed below threshold; the 11-state reassembly machine in
   `state_machine.rs`; the authenticator ratchet in `auth.rs`), the SPQR key
   schedule in `src/ratchet/spqr.rs` (`SpqrState`: per-epoch chains, `KDF_SCKA_RK`
   reseed, `(epoch, n)` skipped-key store, the spec errata), and the combiner in
   `src/ratchet/mod.rs` (`encrypt_raw`/`decrypt`). Verify that both peers derive
   the identical `pq_mk`, that `KDF_HYBRID(ec_mk, pq_mk)` combines them per message,
   and that a broken KEM cannot weaken the classical guarantee (and vice versa).
   The `libcrux-ml-kem` primitive itself is out of scope (verified upstream).

2. **D-08 (AD construction) and D-16 (cert_hash binding).** Non-standard
   associated data constructions. Verify that the enhanced AD cannot introduce
   canonicalization or parsing ambiguities. In D-08, confirm that including the
   plaintext header in the AD does not introduce ambiguities (it does not: the
   header is serialized before inclusion). In D-16, confirm the cert_hash is
   computed over a deterministic serialization.

3. **D-14 (Sender key authentication).** Text/group messages use Ed25519
   signatures (Signal-compliant); voice retains HMAC transitionally. Confirm the
   signature is verified before any decryption, that a chain-key holder cannot
   forge a `Signed` message (the private signing key is never distributed), and
   that the auth variant must match the chain mode (no signature-strip
   downgrade). For voice, confirm the HMAC is verified in constant time
   (`subtle::ConstantTimeEq`) and that `0x03` is independent of `0x01`/`0x02`.

4. **D-01 (Ed25519 canonical identity).** Verify the Ed25519-to-X25519
   private key conversion (`IdentityKeyPair::x25519_private_key`) correctly
   implements the SHA-512 + clamp procedure and cannot produce weak keys.
   Verify the public key conversion (`IdentityPublicKey::to_x25519`) uses
   the standard Edwards-to-Montgomery map and handles all valid Ed25519
   public keys.

5. **D-16 (cert_hash metadata leakage).** Verify whether the unencrypted
   cert_hash in the sealed sender envelope is acceptable for Hushwire's
   threat model. If sender privacy from the server is a priority, this
   construction leaks a per-sender pseudonym.

6. **D-02 (XChaCha20-Poly1305), D-04 (ISO 7816-4 padding).** Standard
   substitutions. Low risk, but confirm the HKDF key derivation in `aead.rs`
   correctly expands the message key before use, and that the padding
   implementation handles edge cases (empty plaintext, plaintext containing
   `0x80` bytes, exact block-size plaintext).

7. **D-05/D-10/D-17 (domain separation), D-06 (equivalent salt), D-03
   (serialization), D-11/D-12/D-18/D-19 (compliant items).** Lowest priority.
   These are either cosmetic, equivalent, or specification-compliant.


## Summary

| ID | Area | Divergence | Class | Security impact |
|---|---|---|---|---|
| D-01 | Identity keys | Ed25519 canonical, no XEdDSA | Substitution | Equivalent |
| D-02 | AEAD | XChaCha20-Poly1305 | Substitution | Equivalent or better |
| D-03 | Serialization | Postcard + HWCR prefix | Substitution | None |
| D-04 | Padding | ISO/IEC 7816-4 (160-byte blocks) | Equivalent | None |
| D-05 | PQXDH | `"HushwireProtocol"` info string | Domain Separation | None |
| D-06 | PQXDH | `[0u8; 32]` salt (equivalent to empty) | Equivalent | None |
| D-08 | Double Ratchet | AD includes plaintext header | Enhancement | Mixed (see D-08) |
| D-10 | Double Ratchet | `"HushwireRatchet"` | Domain Separation | None |
| D-11 | Double Ratchet | KDF_CK uses 0x01/0x02 | Compliant | N/A |
| D-12 | Double Ratchet | MAX_SKIP = 2000 | Compliant | N/A |
| D-13 | Ratchet | ML-KEM Braid / Triple Ratchet (continuous ML-KEM-768; per-message `KDF_HYBRID(ec_mk, pq_mk)`) | Compliant (construction); clean-room impl | Protocol proven (eprint 2025/078); implementation unaudited |
| D-14 | Sender Keys | Ed25519 signatures (text); HMAC (voice, transitional) | Compliant / Substitution | No in-group forgery for text; voice forgeable (see D-14) |
| D-15 | Sender Keys | Auth key via HMAC(ck, 0x03), voice only | Enhancement | Safe |
| D-16 | Sealed Sender | cert_hash in AEAD associated data | Enhancement | Mixed (see D-16) |
| D-17 | Sealed Sender | `"HushwireSealedSender"` info strings | Domain Separation | None |
| D-18 | Sealed Sender | Certificate trust hierarchy | Compliant | N/A |
| D-19 | Sesame | MAXSEND=30d, MAXRECV=60d, MAXLATENCY=2h | Compliant | N/A |
| D-20 | Sesame | Dual-init convergence mechanism | Compliant | None |
