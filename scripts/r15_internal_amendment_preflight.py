#!/usr/bin/env python3
"""Build and validate the pre-execution R15 internal amendment manifest."""

from __future__ import annotations

import argparse
import hashlib
import json
import subprocess
from pathlib import Path

from experiments.common import canonical_json, sha256_file
from experiments.r15_data import RunKeyV3
from experiments.r15_internal_amendment import (
    AMENDED_ATTACKS,
    AMENDMENT_ID,
    AMENDMENT_TAG,
    BASE_CONFIG_MANIFEST_SHA256,
    BASE_DEPENDENCY_LOCK_SHA256,
    BASE_PREREGISTRATION_SHA256,
    BASE_SOURCE_COMMIT,
    BASE_SOURCE_TREE,
    BASE_TAG,
    EXPECTED_RUN_UNITS,
    FREEZE_ID,
)
from scripts.prepare_r141_confirmatory import prepare_r141_configs

ROOT = Path(__file__).resolve().parents[1]
PREREG = ROOT / "experiments" / "preregistration-v3-r141.md"
LOCK = ROOT / "constraints" / "r14-v3-py313.txt"

ALLOWED_AMENDMENT_PATHS = {
    ".github/workflows/r15-internal-amendment.yml",
    "experiments/r15_confirmatory_internal.py",
    "experiments/r15_internal_amendment.py",
    "experiments/r15_parameter_analysis_fast.py",
    "scripts/r15_internal_amendment_preflight.py",
    "tests/unit/test_r15_internal_amendment.py",
}


def _git(*args: str) -> str:
    result = subprocess.run(
        ["git", *args],
        cwd=ROOT,
        check=False,
        capture_output=True,
        text=True,
    )
    if result.returncode != 0:
        raise RuntimeError(f"git command failed: {' '.join(args)}")
    return result.stdout.strip()


def _tag_target(tag: str) -> str:
    _git("rev-parse", "-q", "--verify", f"refs/tags/{tag}")
    return _git("rev-list", "-n", "1", tag)


def _expected_scope(config_root: Path) -> tuple[int, int, str]:
    allowed = set(AMENDED_ATTACKS)
    cells = 0
    runs = 0
    digest = hashlib.sha256(b"sigma-v3-r15-internal-amendment-runkeys-v1")
    for path in sorted(config_root.glob("*.json")):
        if path.name in {"campaign-index.json", "config-manifest.json"}:
            continue
        config = json.loads(path.read_text(encoding="utf-8"))
        attack_id = config["attack_id"]
        if attack_id not in allowed:
            continue
        for cell in config["cells"]:
            cells += 1
            for replicate_id in range(int(cell["replicates"])):
                runs += 1
                key = RunKeyV3(FREEZE_ID, attack_id, cell["cell_id"], replicate_id)
                encoded = key.stable_id.encode("utf-8")
                digest.update(len(encoded).to_bytes(4, "big"))
                digest.update(encoded)
    if runs != EXPECTED_RUN_UNITS:
        raise RuntimeError(
            f"amendment RunKey cardinality drifted: {runs} != {EXPECTED_RUN_UNITS}"
        )
    return cells, runs, digest.hexdigest()


def build_amendment_manifest(
    *,
    source_commit: str,
    config_root: Path,
    artifact: Path,
) -> dict[str, object]:
    source_commit = _git("rev-parse", f"{source_commit}^{{commit}}")
    source_tree = _git("rev-parse", f"{source_commit}^{{tree}}")

    if _tag_target(BASE_TAG) != BASE_SOURCE_COMMIT:
        raise RuntimeError("base R14.1 tag no longer resolves to frozen source commit")
    if _git("rev-parse", f"{BASE_SOURCE_COMMIT}^{{tree}}") != BASE_SOURCE_TREE:
        raise RuntimeError("base R14.1 source tree drifted")
    if _tag_target(AMENDMENT_TAG) != source_commit:
        raise RuntimeError("amendment tag does not resolve to requested source commit")

    changed = {
        line
        for line in _git("diff", "--name-only", BASE_SOURCE_COMMIT, source_commit).splitlines()
        if line
    }
    unexpected = changed - ALLOWED_AMENDMENT_PATHS
    missing_semantic = {
        "experiments/r15_confirmatory_internal.py",
        "experiments/r15_parameter_analysis_fast.py",
    } - changed
    if unexpected:
        raise RuntimeError(f"unexpected files in amendment: {sorted(unexpected)}")
    if missing_semantic:
        raise RuntimeError(f"required amendment files unchanged: {sorted(missing_semantic)}")

    prepare_r141_configs(config_root, check=True)
    config_manifest = config_root / "config-manifest.json"
    if sha256_file(config_manifest) != BASE_CONFIG_MANIFEST_SHA256:
        raise RuntimeError("amendment config manifest differs from frozen R14.1 config")
    if sha256_file(PREREG) != BASE_PREREGISTRATION_SHA256:
        raise RuntimeError("amendment preregistration differs from frozen R14.1 preregistration")
    if sha256_file(LOCK) != BASE_DEPENDENCY_LOCK_SHA256:
        raise RuntimeError("amendment dependency lock differs from frozen R14.1 lock")

    cells, runs, runkey_root = _expected_scope(config_root)
    artifact_sha256 = sha256_file(artifact)

    return {
        "schema": "sigma-v3-r15-internal-amendment-manifest-v1",
        "amendment_id": AMENDMENT_ID,
        "freeze_id": FREEZE_ID,
        "scope": "internal-amendment",
        "base_tag": BASE_TAG,
        "base_source_commit": BASE_SOURCE_COMMIT,
        "base_source_tree": BASE_SOURCE_TREE,
        "tag": AMENDMENT_TAG,
        "source_commit": source_commit,
        "source_tree": source_tree,
        "artifact_sha256": artifact_sha256,
        "config_manifest_sha256": BASE_CONFIG_MANIFEST_SHA256,
        "preregistration_sha256": BASE_PREREGISTRATION_SHA256,
        "dependency_lock_sha256": BASE_DEPENDENCY_LOCK_SHA256,
        "authorized_attacks": list(AMENDED_ATTACKS),
        "expected_cells": cells,
        "expected_run_units": runs,
        "expected_runkey_sha256": runkey_root,
        "changed_paths": sorted(changed),
        "confirmatory_unlocked": True,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source-commit", required=True)
    parser.add_argument("--configs", type=Path, required=True)
    parser.add_argument("--artifact", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    try:
        result = build_amendment_manifest(
            source_commit=args.source_commit,
            config_root=args.configs,
            artifact=args.artifact,
        )
    except (OSError, RuntimeError, TypeError, ValueError, json.JSONDecodeError) as exc:
        parser.error(str(exc))
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_bytes(canonical_json(result) + b"\n")
    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
