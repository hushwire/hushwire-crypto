# hushwire-crypto

A clean-room, Rust-native implementation of the [Signal Protocol](https://signal.org/docs/),
plus the standalone cryptographic primitives Hushwire builds on top of it. The crate exposes
raw-byte APIs and carries no dependency on Hushwire's wire/protocol types, so it can be
audited and reused in isolation.

## Features

- **PQXDH** — post-quantum-augmented X3DH key agreement (X25519 + ML-KEM-1024).
- **Double Ratchet** — forward-secret, break-in-recovering 1:1 session encryption.
- **ML-KEM Braid (SPQR)** — Signal's sparse post-quantum ratchet, a continuous
  post-quantum key-agreement primitive (ML-KEM-768 with Reed-Solomon erasure coding)
  that feeds the Double Ratchet.
- **Sender Keys** — efficient group messaging with per-message Ed25519 authentication.
- **Sealed Sender** — server-blind delivery with verifiable sender certificates.
- **Sesame** — multi-device session management (dual-init convergence and session lifecycle).
- **Standalone crypto** — server trust-root and organization signing, organization
  metadata encryption, device provisioning, BIP39 recovery keys, Argon2id storage-key
  derivation, sealed-sender envelope verification, and ISO/IEC 7816-4 message padding.

All key material is zeroized on drop and secret comparisons are constant-time.

## Module map

The crate is organized into three layers, over a small foundation of shared
vocabulary (`error`, `types`, `address`, `serialization`). The most commonly
used items are re-exported at the crate root and gathered in `prelude`.

### `primitives` — low-level cryptographic building blocks

| Module | Responsibility |
| --- | --- |
| `primitives::keys` | Identity and ephemeral key types |
| `primitives::kdf` | Protocol KDFs (HKDF-SHA256, HMAC-SHA256) |
| `primitives::aead` | XChaCha20-Poly1305 authenticated encryption |
| `primitives::padding` | ISO/IEC 7816-4 message padding |

### `protocol` — the clean-room Signal Protocol

| Module | Responsibility |
| --- | --- |
| `protocol::pqxdh`, `protocol::prekey` | Post-quantum X3DH handshake and pre-key bundles |
| `protocol::ratchet` | Double Ratchet session (`chain`, `header`, `skipped`, `spqr` submodules) |
| `protocol::braid` | ML-KEM Braid / SPQR SCKA (`erasure`, `kem`, `auth`, `state_machine`) |
| `protocol::sender_key` | Group sender keys and distribution messages |
| `protocol::sealed_sender` | Sealed-sender envelopes and sender certificates |
| `protocol::sesame` | Multi-device session convergence, lifecycle, and state |
| `protocol::stores` | Async storage traits (identity, sessions, pre-keys, sender keys, Sesame) |

### `hushwire` — application crypto built on top of the protocol

| Module | Responsibility |
| --- | --- |
| `hushwire::trust_root` | Server trust-root key abstraction |
| `hushwire::org` | Organization metadata encryption and signing identities |
| `hushwire::provisioning` | Device provisioning (ephemeral ECDH key linking) |
| `hushwire::recovery` | BIP39 recovery keys |
| `hushwire::storage_key` | Argon2id storage-key derivation |
| `hushwire::envelope` | Sealed-sender envelope verification |

### Foundation

| Module | Responsibility |
| --- | --- |
| `types`, `address` | Cryptographic newtypes and protocol addressing |
| `serialization` | Versioned record serde helpers |
| `error` | `CryptoError` and the crate `Result` alias |
| `prelude` | Glob-importable re-exports of the common API |

## Build & test

```bash
cargo build
cargo test                 # or: cargo nextest run
cargo doc --no-deps --open # public API is fully documented
```

## Signal spec divergences

This implementation is clean-room from the published Signal specifications. Every deliberate
deviation is catalogued, classified, and justified in
[`docs/signal-spec-divergence.md`](docs/signal-spec-divergence.md).

## Formal model

A clean-room ProVerif (symbolic) model of the ML-KEM Braid / Triple Ratchet seams —
the per-message hybrid combiner, fold-epoch synchronisation, the braid authenticator,
and the fail-closed codeword binding — lives in [`proofs/`](proofs/). It is an
auditor-facing design-validation artifact, **not** a proof of this Rust and **not** a CI
gate; see [`proofs/README.md`](proofs/README.md) for scope, the term→source map, and the
machine-checked results.

## License

Proprietary — Copyright (c) 2026 Hushwire. All rights reserved. See [`LICENSE`](LICENSE).
No license is granted; unauthorized use, copying, modification, or distribution is prohibited.
