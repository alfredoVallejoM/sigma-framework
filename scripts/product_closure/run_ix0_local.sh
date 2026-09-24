#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$ROOT"

OUT_DIR="${IX0_OUTPUT_DIR:-verification/ix0-local}"
mkdir -p "$OUT_DIR"
LOG="$OUT_DIR/ix0-current.log"
GATE_JSON="$OUT_DIR/ix0-gate.json"
LIVE_JSON="$OUT_DIR/ix0-oras-live.json"

exec > >(tee "$LOG") 2>&1

echo "IX0 LOCAL RUNNER"
echo "root=$ROOT"
echo "python=$(python --version 2>&1)"
echo "head=$(git rev-parse HEAD 2>/dev/null || echo unknown)"
echo

echo "[1/5] focused pytest"
python -m pytest -q \
  tests/unit/test_oci_interop_ix0.py \
  tests/unit/test_oci_auth_ix0.py \
  tests/unit/test_oci_layout_ix0.py \
  tests/unit/test_oci_registry_ix0.py \
  tests/integration/test_cli_oci_ix0.py

echo
echo "[2/5] ruff"
ruff check \
  sigma/interop \
  sigma/product_cli.py \
  scripts/product_closure/ix0_fixtures.py \
  scripts/product_closure/ix0_gate.py \
  scripts/product_closure/ix0_oras_diff.py \
  tests/unit/test_oci_interop_ix0.py \
  tests/unit/test_oci_auth_ix0.py \
  tests/unit/test_oci_registry_ix0.py \
  tests/integration/test_cli_oci_ix0.py

echo
echo "[3/5] mypy"
mypy \
  sigma/interop \
  sigma/product_cli.py \
  scripts/product_closure/ix0_fixtures.py \
  scripts/product_closure/ix0_gate.py \
  scripts/product_closure/ix0_oras_diff.py

echo
echo "[4/5] deterministic IX0 gate"
python -m scripts.product_closure.ix0_gate --output "$GATE_JSON"

echo
echo "[5/5] live ORAS differential"
if [[ "${IX0_LIVE:-0}" == "1" ]]; then
  : "${IX0_REGISTRY_URL:?set IX0_REGISTRY_URL}"
  : "${IX0_REPOSITORY:?set IX0_REPOSITORY}"
  : "${IX0_ORAS_TARGET:?set IX0_ORAS_TARGET}"
  : "${IX0_ARTIFACT:?set IX0_ARTIFACT}"
  : "${IX0_SUBJECT_DIGEST:?set IX0_SUBJECT_DIGEST}"
  : "${IX0_SUBJECT_SIZE:?set IX0_SUBJECT_SIZE}"

  live_args=(
    python -m scripts.product_closure.ix0_oras_diff
    --registry-url "$IX0_REGISTRY_URL"
    --repository "$IX0_REPOSITORY"
    --oras-target "$IX0_ORAS_TARGET"
    --artifact "$IX0_ARTIFACT"
    --subject-digest "$IX0_SUBJECT_DIGEST"
    --subject-size "$IX0_SUBJECT_SIZE"
    --output "$LIVE_JSON"
  )

  if [[ -n "${IX0_SUBJECT_MEDIA_TYPE:-}" ]]; then
    live_args+=(--subject-media-type "$IX0_SUBJECT_MEDIA_TYPE")
  fi
  if [[ "${IX0_ORAS_PLAIN_HTTP:-0}" == "1" ]]; then
    live_args+=(--oras-arg=--plain-http)
  fi
  if [[ -n "${IX0_AUTH_HEADER:-}" ]]; then
    live_args+=(--header "$IX0_AUTH_HEADER")
  fi

  "${live_args[@]}"
else
  echo "SKIP: set IX0_LIVE=1 plus registry/subject variables to run live ORAS."
fi

echo
echo "IX0 local runner completed."
echo "log=$LOG"
echo "gate=$GATE_JSON"
if [[ -f "$LIVE_JSON" ]]; then
  echo "live=$LIVE_JSON"
fi
