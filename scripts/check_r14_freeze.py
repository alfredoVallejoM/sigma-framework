#!/usr/bin/env python3
"""Authoritative R14 protocol-freeze validation."""

from __future__ import annotations

import argparse
import json
import subprocess
from pathlib import Path

from experiments.freeze import preregistration_is_frozen
from experiments.r14_analysis import validate_synthetic_analysis
from experiments.r14_protocol import FREEZE_ID, confirmatory_attack_ids
from scripts.check_r14_baselines import check_baselines
from scripts.prepare_v3_confirmatory import DEFAULT_OUTPUT, prepare

ROOT = Path(__file__).resolve().parents[1]
DEFAULT_MANIFEST = DEFAULT_OUTPUT / "protocol-freeze.json"
PREREGISTRATION = ROOT / "experiments" / "preregistration-v3.md"


def _git_blob(path: Path) -> str:
    result = subprocess.run(
        ["git", "hash-object", str(path)],
        cwd=ROOT,
        check=False,
        capture_output=True,
        text=True,
    )
    if result.returncode != 0:
        raise RuntimeError(f"git hash-object failed for {path}")
    return result.stdout.strip()


def _verify_manifest(path: Path) -> dict[str, object]:
    data = json.loads(path.read_text(encoding="utf-8"))
    required = {
        "schema",
        "freeze_id",
        "r12_5_baseline",
        "r13_baseline",
        "confirmatory_executed",
        "files",
    }
    if not isinstance(data, dict) or set(data) != required:
        raise ValueError("invalid R14 protocol-freeze fields")
    if data["schema"] != "sigma-v3-r14-protocol-freeze-v1":
        raise ValueError("unexpected R14 protocol-freeze schema")
    if data["freeze_id"] != FREEZE_ID:
        raise ValueError("protocol-freeze uses wrong freeze_id")
    if data["confirmatory_executed"] is not False:
        raise ValueError("R14 freeze cannot contain executed confirmatory data")
    files = data["files"]
    if not isinstance(files, dict) or not files:
        raise ValueError("R14 protocol-freeze has no bound files")
    for relative, expected in files.items():
        if not isinstance(relative, str) or not isinstance(expected, str):
            raise ValueError("invalid manifest file entry")
        candidate = ROOT / relative
        if not candidate.is_file():
            raise ValueError(f"frozen file is missing: {relative}")
        if _git_blob(candidate) != expected:
            raise ValueError(f"frozen file changed: {relative}")
    return data


def _reject_premature_results() -> None:
    forbidden_roots = (
        ROOT / "experiments" / "v3-confirmatory-results",
        ROOT / "results" / "v3-confirmatory",
    )
    for root in forbidden_roots:
        if root.exists() and any(path.is_file() for path in root.rglob("*")):
            raise RuntimeError(f"confirmatory results exist before R14 closure: {root}")

    index = json.loads((DEFAULT_OUTPUT / "campaign-index.json").read_text(encoding="utf-8"))
    if index.get("confirmatory_executed") is not False:
        raise RuntimeError("campaign index claims confirmatory execution before R14 PASS")


def validate_r14_freeze(manifest: Path = DEFAULT_MANIFEST) -> dict[str, object]:
    baselines = check_baselines()
    prepare(DEFAULT_OUTPUT, check=True)
    text = PREREGISTRATION.read_text(encoding="utf-8")
    if not preregistration_is_frozen(text):
        raise RuntimeError("v3 preregistration is not frozen")
    manifest_data = _verify_manifest(manifest)
    _reject_premature_results()
    analysis = validate_synthetic_analysis()

    config_files = [
        path
        for path in DEFAULT_OUTPUT.glob("*.json")
        if path.name not in {"campaign-index.json", "protocol-freeze.json"}
    ]
    expected = set(confirmatory_attack_ids())
    actual = {
        json.loads(path.read_text(encoding="utf-8"))["attack_id"]
        for path in config_files
    }
    if actual != expected:
        raise RuntimeError("frozen config attack set differs from protocol")

    return {
        "schema": "sigma-v3-r14-freeze-gate-v1",
        "freeze_id": FREEZE_ID,
        "passed": True,
        "baselines": baselines,
        "manifest_files": len(manifest_data["files"]),
        "confirmatory_configs": len(config_files),
        "confirmatory_attacks": len(expected),
        "synthetic_analysis": analysis,
        "confirmatory_executed": False,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--manifest", type=Path, default=DEFAULT_MANIFEST)
    parser.add_argument("--report", type=Path)
    args = parser.parse_args()
    try:
        report = validate_r14_freeze(args.manifest)
    except (OSError, RuntimeError, TypeError, ValueError, json.JSONDecodeError) as exc:
        parser.error(str(exc))
    if args.report:
        args.report.write_text(
            json.dumps(report, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )
    print(json.dumps(report, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
