#!/usr/bin/env python3
"""Build and validate the R15 STAT tooling execution manifest."""

from __future__ import annotations

import argparse
import hashlib
import json
import subprocess
from pathlib import Path

from experiments.common import canonical_json, sha256_file
from experiments.r15_data import RunKeyV3
from experiments.r15_stat_adapters import validate_battery_manifest_entry_v3
from experiments.r141_protocol import R141_FREEZE_ID
from scripts.prepare_r141_confirmatory import prepare_r141_configs

ROOT = Path(__file__).resolve().parents[1]
BASE_TAG = "sigma-v3-r14-freeze-v1"
BASE_SOURCE_COMMIT = "80214afde29b3596af83265e18c1e2926e14dd2f"
BASE_SOURCE_TREE = "ca1da75d6409f39a8a1f1b6fa4afea42830781e1"
STAT_TAG = "sigma-v3-r15-stat-tooling-v1"
STAT_TOOLING_ID = "sigma-v3-r15-stat-tooling-20260921-v1"
BASE_CONFIG_MANIFEST_SHA256 = "a8b1b4c9d3a2218e284605a2be02165a2ae36d2a0a8f0aed3223a3b41d6d59e3"
BASE_PREREGISTRATION_SHA256 = "34b256560c74fde95a0d788894d4f27ff4b13b7eadba318321840cf5fe5a7c2a"
BASE_DEPENDENCY_LOCK_SHA256 = "80a64b9564aead53a5a0abe69adae7c431741948c9cd6eeab280544a5a3b3ba2"
EXPECTED_RUN_UNITS = 1_536
MANDATORY_BATTERIES = ("nist-sts", "practrand")

PREREG = ROOT / "experiments" / "preregistration-v3-r141.md"
LOCK = ROOT / "constraints" / "r14-v3-py313.txt"

ALLOWED_STAT_TOOLING_PATHS = {
    ".github/workflows/r15-stat-confirmatory.yml",
    "experiments/r15-stat-tooling-amendment.json",
    "experiments/r15_stat_confirmatory.py",
    "experiments/r15_stat_dataset.py",
    "scripts/r15_stat_tooling_preflight.py",
    "tests/unit/test_r15_stat_confirmatory.py",
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


def _validate_tools_manifest(
    manifest_path: Path,
    *,
    nist_binary: Path,
    practrand_binary: Path,
) -> tuple[dict[str, object], ...]:
    value = json.loads(manifest_path.read_text(encoding="utf-8"))
    if value.get("schema") != "sigma-v3-r15-external-tools-v1":
        raise ValueError("unexpected external-tool manifest schema")
    if value.get("status") != "ready":
        raise ValueError("STAT tool manifest must have status=ready")
    entries = value.get("batteries")
    if not isinstance(entries, list):
        raise ValueError("STAT tool manifest batteries must be a list")

    observed: dict[str, dict[str, object]] = {}
    for raw in entries:
        if not isinstance(raw, dict):
            raise ValueError("STAT tool manifest entry must be an object")
        validate_battery_manifest_entry_v3(raw)
        battery_id = raw["battery_id"]
        assert isinstance(battery_id, str)
        if battery_id in observed:
            raise ValueError("duplicate STAT battery id")
        observed[battery_id] = raw

    if set(observed) != set(MANDATORY_BATTERIES):
        raise ValueError(
            "mandatory STAT manifest must contain exactly nist-sts and practrand"
        )

    binaries = {
        "nist-sts": nist_binary,
        "practrand": practrand_binary,
    }
    for battery_id, binary_path in binaries.items():
        if not binary_path.is_file():
            raise ValueError(f"missing STAT binary: {binary_path}")
        if observed[battery_id]["binary_sha256"] != sha256_file(binary_path):
            raise ValueError(f"{battery_id} binary SHA-256 mismatch")

    return tuple(observed[battery] for battery in MANDATORY_BATTERIES)


def _expected_stat_runkeys(config_root: Path) -> tuple[int, str]:
    config = json.loads((config_root / "stat-01.json").read_text(encoding="utf-8"))
    if config.get("attack_id") != "STAT-01":
        raise ValueError("STAT config attack mismatch")
    if config.get("freeze_id") != R141_FREEZE_ID:
        raise ValueError("STAT config freeze mismatch")

    digest = hashlib.sha256(b"sigma-v3-r15-stat-expected-runkeys-v1")
    count = 0
    for cell in config["cells"]:
        for replicate_id in range(int(cell["replicates"])):
            key = RunKeyV3(
                R141_FREEZE_ID,
                "STAT-01",
                str(cell["cell_id"]),
                replicate_id,
            )
            encoded = key.stable_id.encode("utf-8")
            digest.update(len(encoded).to_bytes(4, "big"))
            digest.update(encoded)
            count += 1
    if count != EXPECTED_RUN_UNITS:
        raise RuntimeError(f"STAT RunKey cardinality drifted: {count}")
    return count, digest.hexdigest()


def build_stat_execution_manifest(
    *,
    source_commit: str,
    config_root: Path,
    artifact: Path,
    tools_manifest: Path,
    nist_binary: Path,
    practrand_binary: Path,
    require_stat_tag: bool = True,
) -> dict[str, object]:
    source_commit = _git("rev-parse", f"{source_commit}^{{commit}}")
    source_tree = _git("rev-parse", f"{source_commit}^{{tree}}")

    if _tag_target(BASE_TAG) != BASE_SOURCE_COMMIT:
        raise RuntimeError("base tag no longer resolves to frozen source")
    if _git("rev-parse", f"{BASE_SOURCE_COMMIT}^{{tree}}") != BASE_SOURCE_TREE:
        raise RuntimeError("base source tree drifted")
    if require_stat_tag and _tag_target(STAT_TAG) != source_commit:
        raise RuntimeError("STAT tooling tag does not resolve to source commit")

    changed = {
        line
        for line in _git("diff", "--name-only", BASE_SOURCE_COMMIT, source_commit).splitlines()
        if line
    }
    unexpected = changed - ALLOWED_STAT_TOOLING_PATHS
    if unexpected:
        raise RuntimeError(f"unexpected files in STAT tooling amendment: {sorted(unexpected)}")

    required = {
        "experiments/r15-stat-tooling-amendment.json",
        "experiments/r15_stat_confirmatory.py",
        "scripts/r15_stat_tooling_preflight.py",
    }
    if not required.issubset(changed):
        raise RuntimeError("required STAT tooling files are missing from amendment")

    prepare_r141_configs(config_root, check=True)
    if sha256_file(config_root / "config-manifest.json") != BASE_CONFIG_MANIFEST_SHA256:
        raise RuntimeError("STAT tooling config manifest differs from frozen R14.1 config")
    if sha256_file(PREREG) != BASE_PREREGISTRATION_SHA256:
        raise RuntimeError("STAT tooling preregistration differs from frozen R14.1 preregistration")
    if sha256_file(LOCK) != BASE_DEPENDENCY_LOCK_SHA256:
        raise RuntimeError("STAT tooling dependency lock differs from frozen R14.1 lock")

    entries = _validate_tools_manifest(
        tools_manifest,
        nist_binary=nist_binary,
        practrand_binary=practrand_binary,
    )
    run_units, runkey_root = _expected_stat_runkeys(config_root)

    return {
        "schema": "sigma-v3-r15-stat-execution-manifest-v1",
        "stat_tooling_id": STAT_TOOLING_ID,
        "freeze_id": R141_FREEZE_ID,
        "scope": "stat-confirmatory",
        "base_tag": BASE_TAG,
        "base_source_commit": BASE_SOURCE_COMMIT,
        "base_source_tree": BASE_SOURCE_TREE,
        "tag": STAT_TAG,
        "source_commit": source_commit,
        "source_tree": source_tree,
        "artifact_sha256": sha256_file(artifact),
        "config_manifest_sha256": BASE_CONFIG_MANIFEST_SHA256,
        "preregistration_sha256": BASE_PREREGISTRATION_SHA256,
        "dependency_lock_sha256": BASE_DEPENDENCY_LOCK_SHA256,
        "external_tools_sha256": sha256_file(tools_manifest),
        "external_batteries": list(MANDATORY_BATTERIES),
        "tool_entries": list(entries),
        "expected_cells": 24,
        "expected_run_units": run_units,
        "expected_runkey_sha256": runkey_root,
        "confirmatory_unlocked": require_stat_tag,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source-commit", required=True)
    parser.add_argument("--configs", type=Path, required=True)
    parser.add_argument("--artifact", type=Path, required=True)
    parser.add_argument("--tools-manifest", type=Path, required=True)
    parser.add_argument("--nist-binary", type=Path, required=True)
    parser.add_argument("--practrand-binary", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--pretag", action="store_true")
    args = parser.parse_args()
    try:
        result = build_stat_execution_manifest(
            source_commit=args.source_commit,
            config_root=args.configs,
            artifact=args.artifact,
            tools_manifest=args.tools_manifest,
            nist_binary=args.nist_binary,
            practrand_binary=args.practrand_binary,
            require_stat_tag=not args.pretag,
        )
    except (OSError, RuntimeError, TypeError, ValueError, json.JSONDecodeError) as exc:
        parser.error(str(exc))

    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_bytes(canonical_json(result) + b"\n")
    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
