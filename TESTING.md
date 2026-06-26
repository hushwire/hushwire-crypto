# Testing

## Unit and integration tests

```sh
cargo test            # full suite, including the property bodies below
cargo test --doc      # doctests
cargo clippy --all-targets --all-features -- -D warnings
cargo fmt --all --check
```

CI runs all of the above as the **blocking** gate (`.github/workflows/verify.yml`).
These exercise the real Rust, so they catch drift between the implementation and
its design.

## Property / fuzz / proof harnesses (bolero)

The fail-closed decrypt path, AD-binding, and the SPQR replay/epoch logic are
covered by `bolero` properties. A single property body runs three ways:

- as a **unit test** under `cargo test` (bolero's ~1s default time budget each),
- as a **fuzz target** under `cargo bolero test <name> --engine libfuzzer`,
- and, on the roadmap, as a **bounded proof** under `--engine kani`.

Property locations:

- `src/protocol/ratchet/mod.rs` — `prop_roundtrip`,
  `prop_multi_message_dh_ratchet_roundtrip`, `prop_ciphertext_mutation_fails_closed`,
  `prop_ad_binding_fails_closed`, `prop_codeword_strip_or_garble_fails_closed`,
  `prop_out_of_order_within_chain`, `prop_prekey_path_fail_closed`
- `src/protocol/ratchet/spqr.rs` — `prop_replay_fails_closed`,
  `prop_out_of_order_pairs`, `prop_retained_epochs_bounded`
- `src/primitives/padding.rs` — `prop_pad_unpad_roundtrip_and_reject`

Run a fuzz smoke locally (nightly toolchain + `cargo install cargo-bolero`):

```sh
cargo bolero test prop_ciphertext_mutation_fails_closed --engine libfuzzer -T 60s
```

### Reproducers are committed by a human; CI never commits

**CI does not commit or push anything** — the `verify.yml` workflow runs with
`permissions: contents: read`. When a fuzz run finds a failure it only *surfaces*
it; a human turns that into a committed regression seed. The loop:

1. A property fails — either the blocking `test` job hits a new random input
   (it prints the failing value and a `BOLERO_RANDOM_SEED=…` line to reproduce),
   or the non-blocking nightly `fuzz-smoke` job finds a crash and writes it to
   `src/**/__fuzz__/<target>/crashes/` on the runner, then uploads it as a
   downloadable CI artifact.
2. **You** reproduce locally, fix the bug, and **manually commit** the reproducer
   file under `src/**/__fuzz__/<target>/crashes/` (downloaded from the artifact,
   or saved from the local `cargo bolero` run).
3. From then on, `cargo test` replays everything under
   `__fuzz__/<target>/{crashes,corpus}` on every run, so the committed reproducer
   is a permanent regression check in the blocking gate.

The `corpus/` exploration inputs are regenerated on every run (and cached in CI),
so they are git-ignored — only the `crashes/` reproducers a human commits are
tracked.

## Symbolic model (separate, offline)

The ProVerif models under `proofs/` validate the protocol *design* and are run
offline by an external auditor. They are deliberately **not** part of CI and are
not a substitute for the tests above, which verify the actual Rust.
