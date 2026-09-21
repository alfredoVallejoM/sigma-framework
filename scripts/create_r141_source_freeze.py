#!/usr/bin/env python3
"""Create the R14.1 source-freeze manifest from one exact Git commit."""

from __future__ import annotations

import argparse
import json
import subprocess
from pathlib import Path

from experiments.common import canonical_json
from experiments.r141_protocol import R141_FREEZE_ID, R141_TAG, R12_5_BASELINE, R13_BASELINE

ROOT = Path(__file__).resolve().parents[1]

FROZEN_PATHS = (
    ".gitattributes",
    "MANIFEST.in",
    "pyproject.toml",
    "sigma/version.py",
    "scripts/release_artifacts.py",
    "scripts/check_v22_baseline.py",
    "scripts/check_r14_baselines.py",
    "scripts/generate_v3_r12_corpus.py",
    "scripts/generate_v3_r125_corpus.py",
    "constraints/r14-v3-py313.txt",
    "specification/sigma-v3-r12-5-history.md",
    "specification/test-vectors/conformance-v3-r12-5.json.gz.b64",
    "reference/independent_v3.py",
    "experiments/r13_attack_registry.py",
    "experiments/r13_schema.py",
    "experiments/preregistration-v3-r141.md",
    "experiments/r15-publication-scale-plan.json",
    "experiments/r15-data-policy.json",
    "experiments/r141_protocol.py",
    "experiments/r141_schema.py",
    "experiments/r141_analysis.py",
    "experiments/r15_estimators.py",
    "experiments/r15_history_games.py",
    "experiments/r15_layout_ablation.py",
    "experiments/r15_parameter_analysis.py",
    "experiments/r15_branch_dependency.py",
    "experiments/r15_application_campaigns.py",
    "experiments/r15_stat_adapters.py",
    "experiments/r15_attack_bindings.py",
    "experiments/r15_endpoint_wrappers.py",
    "experiments/r15_data.py",
    "scripts/check_r15_plan.py",
    "scripts/check_r15_execution_closure.py",
    "scripts/check_r15_data_closure.py",
    "scripts/prepare_r141_confirmatory.py",
    "scripts/check_r141_protocol.py",
    "scripts/create_r141_source_freeze.py",
    "scripts/build_r141_runtime_manifest.py",
    "scripts/check_r141_freeze.py",
    "scripts/verify_r141_tag.py",
    "scripts/r15_preflight.py",
    "scripts/validate_project.py",
    ".github/workflows/ci.yml",
    ".gitignore",
    "experiments/r15-host-manifest-template.json",
)


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


def render_r141_source_freeze(source_commit: str) -> bytes:
    commit = _git("rev-parse", f"{source_commit}^{{commit}}")
    tree = _git("rev-parse", f"{commit}^{{tree}}")
    files: dict[str, str] = {}
    for relative in FROZEN_PATHS:
        try:
            files[relative] = _git("rev-parse", f"{commit}:{relative}")
        except RuntimeError as exc:
            raise ValueError(f"frozen path missing at source commit: {relative}") from exc
    record = {
        "schema": "sigma-v3-r14-1-source-freeze-v1",
        "freeze_id": R141_FREEZE_ID,
        "required_tag": R141_TAG,
        "source_commit": commit,
        "source_tree": tree,
        "r12_5_baseline": R12_5_BASELINE,
        "r13_baseline": R13_BASELINE,
        "confirmatory_executed": False,
        "files": files,
    }
    return canonical_json(record) + b"\n"


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source-commit", required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    try:
        data = render_r141_source_freeze(args.source_commit)
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_bytes(data)
    except (OSError, RuntimeError, ValueError) as exc:
        parser.error(str(exc))
    print(json.dumps({"source_freeze": str(args.output)}, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
