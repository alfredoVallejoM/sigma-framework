#!/usr/bin/env python3
"""Verify immutable R12.5/R13 baselines required by R14."""

from __future__ import annotations

import argparse
import json
import subprocess
from pathlib import Path

from experiments.r14_protocol import R12_5_BASELINE, R13_BASELINE

ROOT = Path(__file__).resolve().parents[1]

R12_5_PROTECTED = (
    "sigma/spec/ids_v3.py",
    "sigma/suites/registry_v3.py",
    "sigma/binding/history.py",
    "sigma/layout/history.py",
    "sigma/rounds/history_framing_v3.py",
    "sigma/rounds/history_v3.py",
    "sigma/outputs/digest_v3.py",
    "reference/independent_v3.py",
    "specification/sigma-v3-r12-5-history.md",
    "specification/test-vectors/conformance-v3-r12-5.json.gz.b64",
)

R13_PROTECTED = (
    "specification/security-analysis-v3-r13.md",
    "docs/claims-evidence-v3-r13.md",
    "experiments/r13_attack_registry.py",
    "experiments/r13_schema.py",
    "experiments/history_reduced.py",
    "experiments/history_attackers_v3.py",
    "experiments/trajectory_attacks_v3.py",
    "experiments/parameter_grinding_v3.py",
    "experiments/tmto_v3.py",
    "experiments/branch_failures_v3.py",
    "experiments/r13_pilots.py",
    "scripts/check_r13_design.py",
)


def _git(*args: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        ["git", *args],
        cwd=ROOT,
        check=False,
        capture_output=True,
        text=True,
    )


def _require_commit(commit: str) -> None:
    result = _git("cat-file", "-e", f"{commit}^{{commit}}")
    if result.returncode != 0:
        raise RuntimeError(f"required baseline commit is unavailable: {commit}")


def _require_unchanged(commit: str, paths: tuple[str, ...], label: str) -> None:
    result = _git("diff", "--quiet", commit, "--", *paths)
    if result.returncode == 1:
        changed = _git("diff", "--name-only", commit, "--", *paths).stdout.splitlines()
        raise RuntimeError(f"{label} baseline changed after PASS: {changed}")
    if result.returncode != 0:
        raise RuntimeError(f"git diff failed while checking {label}")


def check_baselines() -> dict[str, object]:
    _require_commit(R12_5_BASELINE)
    _require_commit(R13_BASELINE)
    _require_unchanged(R12_5_BASELINE, R12_5_PROTECTED, "R12.5")
    _require_unchanged(R13_BASELINE, R13_PROTECTED, "R13")
    return {
        "schema": "sigma-v3-r14-baseline-lock-v1",
        "r12_5": R12_5_BASELINE,
        "r13": R13_BASELINE,
        "r12_5_paths": len(R12_5_PROTECTED),
        "r13_paths": len(R13_PROTECTED),
        "passed": True,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--report", type=Path)
    args = parser.parse_args()
    try:
        report = check_baselines()
    except RuntimeError as exc:
        parser.error(str(exc))
    if args.report:
        args.report.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps(report, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
