#!/usr/bin/env python3
"""Create the deterministic R14 protocol-freeze manifest from Git blobs."""

from __future__ import annotations

import argparse
import json
import subprocess
from pathlib import Path

from experiments.common import canonical_json
from experiments.r14_protocol import FREEZE_ID, R12_5_BASELINE, R13_BASELINE

ROOT = Path(__file__).resolve().parents[1]
DEFAULT_OUTPUT = (
    ROOT / "experiments" / "configs" / "v3-confirmatory-frozen" / "protocol-freeze.json"
)

CONFIG_NAMES = (
    "hist-01.json",
    "hist-02.json",
    "hist-03.json",
    "hist-05.json",
    "hist-06.json",
    "red-02.json",
    "red-03.json",
    "red-04.json",
    "red-05.json",
    "tmto-01.json",
    "tmto-02.json",
    "param-01.json",
    "param-02.json",
    "param-03.json",
    "param-04.json",
    "param-05.json",
    "param-06.json",
    "layout-04.json",
    "branch-05.json",
    "branch-06.json",
    "stat-01.json",
    "campaign-index.json",
)

FROZEN_PATHS = (
    "experiments/preregistration-v3.md",
    "experiments/r14_protocol.py",
    "experiments/r14_schema.py",
    "experiments/r14_analysis.py",
    "experiments/r14-budget-decision-record.json",
    "constraints/r14-v3-py313.txt",
    "scripts/prepare_v3_confirmatory.py",
    "scripts/check_r14_baselines.py",
    "scripts/check_r14_freeze.py",
    "scripts/build_r14_runtime_manifest.py",
    "scripts/create_r14_protocol_freeze.py",
    "experiments/r13_attack_registry.py",
    "experiments/r13_schema.py",
    "specification/sigma-v3-r12-5-history.md",
    "specification/test-vectors/conformance-v3-r12-5.json.gz.b64",
    "reference/independent_v3.py",
    *tuple(f"experiments/configs/v3-confirmatory-frozen/{name}" for name in CONFIG_NAMES),
)


def _git_blob(relative: str) -> str:
    path = ROOT / relative
    if not path.is_file():
        raise ValueError(f"frozen path is missing: {relative}")
    result = subprocess.run(
        ["git", "hash-object", relative],
        cwd=ROOT,
        check=False,
        capture_output=True,
        text=True,
    )
    if result.returncode != 0:
        raise RuntimeError(f"git hash-object failed: {relative}")
    return result.stdout.strip()


def render_manifest() -> bytes:
    files = {relative: _git_blob(relative) for relative in FROZEN_PATHS}
    record = {
        "schema": "sigma-v3-r14-protocol-freeze-v1",
        "freeze_id": FREEZE_ID,
        "r12_5_baseline": R12_5_BASELINE,
        "r13_baseline": R13_BASELINE,
        "confirmatory_executed": False,
        "files": files,
    }
    return canonical_json(record) + b"\n"


def create_manifest(output: Path = DEFAULT_OUTPUT, *, check: bool = False) -> Path:
    expected = render_manifest()
    if check:
        if not output.is_file() or output.read_bytes() != expected:
            raise ValueError("R14 protocol-freeze manifest is stale")
        return output
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_bytes(expected)
    return output


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT)
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args()
    try:
        path = create_manifest(args.output, check=args.check)
    except (OSError, RuntimeError, ValueError) as exc:
        parser.error(str(exc))
    print(json.dumps({"manifest": str(path)}, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
