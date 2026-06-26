# ProVerif model of the Hushwire ML-KEM Braid / Triple Ratchet

A clean-room symbolic (Dolev-Yao) model of the seams `hushwire-crypto`'s
implementation of Signal's ML-KEM Braid / Triple Ratchet actually introduces.
It is a **one-time design-validation artifact for an external auditor**.

> **What this is.** Evidence that the *protocol as we built it* — the per-message
> hybrid combiner, the fold-epoch synchronisation, the braid authenticator, and the
> fail-closed codeword binding — holds the expected symbolic security properties.
>
> **What this is NOT.** It is **not** a proof of the Rust. Re-running a static model
> proves nothing about the implementation; it validates spec-reading. It is **not a
> CI gate** and is deliberately not wired into any pipeline. The honest claim remains:
> *"implements Signal's formally-verified protocol,"* never *"is formally verified."*
> See `../docs/signal-spec-divergence.md` (D-13).

## Reproducibility (pinned)

| | |
|---|---|
| **Tool** | ProVerif **2.05** (symbolic model), `opam` package `proverif.2.05` |
| **Install** | `opam install proverif` (pulls OCaml + `lablgtk` deps), then `eval $(opam env)` |
| **Maps to repo commit** | `c303fb5` |
| **Front-end** | `pitype` (typed applied-pi); shared declarations loaded with native `-lib` |

ProVerif results can differ across versions; an auditor reproducing a `proved`
verdict should use the pinned version. The runner echoes `proverif`'s version banner.

## Layout

```
proofs/
├── common.pvl        # single source of truth: types + symbolic primitives (loaded via -lib)
├── combiner.pv       # per-message hybrid combiner: secrecy, hybrid robustness, FS, PCS
├── epoch_sync.pv     # fold-epoch agreement / no-divergence + secrecy of the folded secret
├── braid_machine.pv  # authenticator unforgeability + fail-closed codeword binding (SAFETY)
├── run.sh            # convenience runner (NOT CI)
└── README.md         # this file
```

`common.pvl` is shared by all three models through ProVerif's native `-lib`
mechanism (`proverif -lib common model.pv`). This is the single source of truth for
the primitives — no copy-pasted preamble, and no `m4`/`cpp` preprocessing was needed
(a native include is preferred where one exists; ProVerif's `-lib` is it).

## How to run

```sh
opam install proverif && eval $(opam env)   # one-time
bash proofs/run.sh                           # all three models
# or individually:
proverif -lib proofs/common proofs/combiner.pv
```

## Results (machine-checked, ProVerif 2.05, honest record)

Every valid security query is kept and its **real** result recorded — a failing
security property would be surfaced here, not dropped. As of commit
`c303fb5`, **all security queries are proved** and the non-vacuity sanity checks
confirm the honest paths actually execute (so nothing passes trivially).

### `combiner.pv` — the per-message hybrid combiner
ProVerif prints `not attacker(s) is true` = the attacker cannot recover the secret
protected under the derived key = **key secret**.

| Query | Property | Result |
|---|---|---|
| Q1 `attacker(s_honest)` | message-key secrecy, honest run | **proved** (secret) |
| Q2 `attacker(s_ec)` | hybrid robustness — X25519/EC leaked, ML-KEM still protects | **proved** (secret) |
| Q3 `attacker(s_pq)` | hybrid robustness — ML-KEM leaked, X25519 still protects | **proved** (secret) |
| Q4 `attacker(s_fs)` | forward secrecy — later chain state leaks, earlier key safe | **proved** (secret) |
| Q5 `attacker(s_pcs)` | post-compromise security — fresh KEM reseed heals | **proved** (secret) |

Q2/Q3 are the load-bearing hybrid result: **breaking either primitive alone never
collapses the message key** — no silent classical-only or PQ-only downgrade at the
key-schedule layer.

### `epoch_sync.pv` — fold-epoch synchronisation / no-divergence
| Query | Property | Result |
|---|---|---|
| Q1 `ReceiverFold(e,s) ==> SenderFold(e,s)` | no divergence: receiver never folds a secret the sender did not produce | **proved** |
| Q2 `attacker(probe)` | the folded epoch secret is hidden from the network attacker | **proved** (secret) |
| SN `event(ReceiverFold(e1,s))` | non-vacuity: the honest fold is reachable | **reachable** (as intended) |

### `braid_machine.pv` — authenticator + fail-closed (SAFETY)
| Query | Property | Result |
|---|---|---|
| QA1 `AcceptHeader(e,pk) ==> SentHeader(e,pk)` | header MAC unforgeable | **proved** |
| QA2 `AcceptCt(e,ct) ==> SentCt(e,ct)` | ciphertext MAC unforgeable → epoch secret only after a real round-trip + `vfy_ct` | **proved** |
| QB1 `AcceptedMsg(cw) ==> SentMsg(cw)` | receiver only accepts under the codeword the sender stamped | **proved** |
| QB2 `event(AcceptedMsg(cw_idle))` unreachable | **no silent classical-only downgrade** | **proved** (unreachable) |
| QB3 `attacker(msg_secret)` | message secrecy under the hybrid key | **proved** (secret) |
| SN1/SN2 `AcceptedMsg(cw_real)` / `AcceptCt` | non-vacuity: honest accept + round-trip reachable | **reachable** (as intended) |

QB1/QB2 are the fail-closed core: the braid codeword rides in the AEAD associated
data, so stripping it (`cw_idle`) or garbling it (any `cw != cw_real`) flips the AD,
the AEAD tag fails, and the message is rejected — the attack breaks the session, it
never degrades it to classical-only.

## Term → Rust source map

Each symbolic function/event maps to concrete Rust. The **separate function symbols
are the domain separation**: distinct ProVerif symbols never collide, mirroring the
distinct HKDF `info` strings in the Rust (which the Rust pins with known-answer tests).

| Model symbol (`common.pvl`) | Rust | Notes |
|---|---|---|
| `kdf_hybrid(ec_mk, pq_mk)` | `kdf_hybrid` — `src/primitives/kdf.rs:206` | per-message combiner, info `"HushwireTripleRatchet"` |
| `scka_init_{rk,ck0,ck1}` | `kdf_scka_init` — `src/primitives/kdf.rs:140` | bootstrap, info `…"Chain Start"` |
| `scka_rk_{root,ck0,ck1}` | `kdf_scka_rk` — `src/primitives/kdf.rs:155` | epoch reseed, info `…"Chain Add Epoch"` |
| `scka_ck_{next,mk}` | `kdf_scka_ck` — `src/primitives/kdf.rs:186` | chain step, info `…":Chain Step"` (counter binding abstracted) |
| `kdf_ok(ss, epoch)` | `kdf_ok` — `src/protocol/braid/auth.rs:38` | per-epoch session key, info `…":SCKA Key"` |
| `auth_{root,mackey}` | `kdf_auth` — `src/protocol/braid/auth.rs:54` | authenticator ratchet, info `…":Authenticator Update"` |
| `mac_hdr` / `mac_ct` | `Authenticator::mac_hdr` / `mac_ct` — `auth.rs:108,113` | labels `":ekheader"` / `":ciphertext"` |
| `aead_enc` / `aead_dec` | `encrypt` / `decrypt` + `build_ad` — `src/protocol/ratchet/mod.rs` | AD = identities ‖ header(codeword); fail-closed |
| `kem_pub`/`kem_ct`/`kem_ss`/`kem_decap` | `kem::encapsulate*` / `decapsulate` — `src/protocol/braid/kem.rs` | ML-KEM as IND-CCA black box (internals out of scope) |
| `event SenderFold` / `ReceiverFold` | `SpqrState::add_epoch` — `src/protocol/ratchet/spqr.rs:170` | both peers fold the identical epoch secret |
| `event {Sent,Accept}Header/Ct` | `state_machine.rs` `recv_*` + `vfy_hdr`/`vfy_ct` | epoch-secret completion path |
| `event {Sent,Accepted}Msg(cw)` | codeword in `MessageHeader` bound by `build_ad` — `ratchet/header.rs`, `mod.rs` | fail-closed downgrade |

### Implementation-side anchors (what the symbolic model abstracts)
The model abstracts behaviour the Rust pins concretely; these tests are the
implementation-side evidence an auditor should read alongside the model:
- KDF domain separation + exact bytes: the KAT tests in `src/primitives/kdf.rs`
  (`kdf_*_known_answer`) and `src/protocol/braid/auth.rs`.
- Both-peers-identical-secret: `spqr.rs::bootstrap_first_message_pairs`,
  `in_order_pairs_across_many_epochs`.
- Authenticator fail-closed: `auth.rs::tampered_mac_rejected`,
  `wrong_epoch_fails_verification`.

## Scope and limitations (read before trusting a verdict)

**Modeled:** the per-message hybrid combiner; fold-epoch agreement and secrecy; the
authenticator MAC unforgeability; the fail-closed codeword/AD binding (no downgrade);
forward secrecy and post-compromise security of the combined schedule.

**Explicitly out of scope / abstracted (and why):**
- **ML-KEM-768 internals** — verified upstream (`libcrux-ml-kem`, hax→F\*); modeled as
  an IND-CCA black box (D-13).
- **Reed-Solomon erasure polynomial** — only the k-of-n / fail-closed *contract*
  matters to the proof; the GF(2^16) math is not modeled. A "codeword" is a bitstring
  carried in the AD.
- **Availability / message-loss-resume** — "a dropped codeword does not
  permanently wedge the session; honest re-streamed codewords rebuild via
  `Decoder::reset`" is a **liveness** property a Dolev-Yao attacker (who owns the
  network) can always defeat by dropping delivery. It is **not provable here** and is
  instead evidenced by the Rust tests `spqr.rs::out_of_order_*`,
  `replay_*_fails_closed`, `delayed_beyond_clear_window_fails_closed`,
  `receive_heavy_peer_retained_epochs_stay_bounded`.
- **Unbounded epochs** — the state machine and epoch synchronisation are modeled for a
  **bounded** number of epochs (the current models complete on a single epoch / single
  session). Epoch *monotonicity* — the consecutive-epoch guard (`spqr.rs:171`,
  `self.epoch + 1 == key_epoch`, fail-closed) and the one-epoch lag
  `sending_epoch = epoch - 1` — is anchored by the Rust tests
  `add_epoch_non_consecutive_fails_closed` and `replay_fails_closed` rather than proved
  for unbounded epochs. Bounded ≠ unbounded; this is the honest limit of the artifact.
- **Computational soundness** — ProVerif is symbolic. A computational proof (CryptoVerif,
  as the reference pairs with ProVerif for these protocols) is a separate, larger effort
  and a candidate follow-up.

## Clean-room provenance

Re-derived from the published spec (`signal.org/docs/specifications/mlkembraid`) and
this repository's own Rust. **Not** translated from Signal's AGPL reference
(`signalapp/SparsePostQuantumRatchet`), which was not read, copied, linked, or run.
