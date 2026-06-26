#!/usr/bin/env bash
# ---------------------------------------------------------------------------
# proofs/run.sh -- machine-check the Hushwire ML-KEM Braid ProVerif models.
#
# This is a DEVELOPER / AUDITOR convenience runner. It is NOT a CI gate:
# re-running a static symbolic model proves nothing about the Rust; it
# validates spec-reading.
#
# Shared declarations live in common.pvl and are loaded with ProVerif's
# native `-lib` (pitype front-end). No m4/cpp preprocessing is needed:
# a native include exists, so it is preferred over m4.
#
# Usage:  bash proofs/run.sh
# Requires `proverif` on PATH (e.g. `eval $(opam env)` after `opam install proverif`).
# ---------------------------------------------------------------------------
set -u

cd "$(dirname "$0")"

if ! command -v proverif >/dev/null 2>&1; then
  echo "ERROR: proverif not on PATH. Install: opam install proverif; then eval \$(opam env)." >&2
  exit 127
fi

echo "=== ProVerif version (pin this in README) ==="
proverif -help 2>&1 | head -1
echo

MODELS=(combiner.pv epoch_sync.pv braid_machine.pv)
fail=0

for m in "${MODELS[@]}"; do
  echo "============================================================"
  echo ">>> $m"
  echo "============================================================"
  out="$(proverif -lib common "$m" 2>&1)"
  echo "$out" | grep -E 'RESULT|Error|error' || echo "$out" | tail -5
  # A model "passes" the runner if every RESULT line reports the proved verdict.
  # Honest reporting: a `false` / `cannot be proved` is recorded in
  # README, not hidden. The runner exit code only flags whether ProVerif ran clean.
  if echo "$out" | grep -qiE 'Error'; then
    echo "  [RUNNER] $m: ProVerif reported an error."
    fail=1
  fi
  echo
done

exit $fail
