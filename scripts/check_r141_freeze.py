#!/usr/bin/env python3
"""Authoritative pre-tag R14.1 freeze gate."""

from __future__ import annotations

import argparse
import json
import subprocess
import tempfile
from pathlib import Path

from experiments.r141_analysis import validate_r141_analysis
from experiments.r141_protocol import R141_FREEZE_ID
from scripts.check_r14_baselines import check_baselines
from scripts.check_r141_protocol import check_r141_protocol
from scripts.create_r141_source_freeze import render_r141_source_freeze

ROOT = Path(__file__).resolve().parents[1]
PREREG = ROOT / "experiments" / "preregistration-v3-r141.md"


def _head() -> str:
    result = subprocess.run(
        ["git", "rev-parse", "HEAD"],
        cwd=ROOT,
        check=True,
        capture_output=True,
        text=True,
    )
    return result.stdout.strip()


def _prereg_frozen() -> None:
    lines = PREREG.read_text(encoding="utf-8").splitlines()
    statuses = [line for line in lines[:8] if line.startswith("Status:")]
    if statuses != ["Status: **frozen-r14.1-candidate**"]:
        raise RuntimeError("R14.1 preregistration status is not frozen-candidate")


def _reject_confirmatory_results() -> None:
    roots = (
        ROOT / "experiments" / "v3-confirmatory-results",
        ROOT / "results" / "v3-confirmatory",
        ROOT / "results" / "r15",
    )
    for root in roots:
        if root.exists() and any(path.is_file() for path in root.rglob("*")):
            raise RuntimeError(f"confirmatory results exist before R14.1 tag: {root}")


def check_r141_freeze(source_commit: str | None = None) -> dict[str, object]:
    commit = source_commit or _head()
    baselines = check_baselines()
    protocol = check_r141_protocol()
    analysis = validate_r141_analysis()
    _prereg_frozen()
    _reject_confirmatory_results()

    with tempfile.TemporaryDirectory(prefix="sigma-r141-freeze-") as temporary:
        path = Path(temporary) / "source-freeze.json"
        data = render_r141_source_freeze(commit)
        path.write_bytes(data)
        source = json.loads(data)
    if source.get("freeze_id") != R141_FREEZE_ID:
        raise RuntimeError("source freeze id mismatch")
    if source.get("confirmatory_executed") is not False:
        raise RuntimeError("source freeze contains confirmatory execution")

    files = source.get("files")
    if not isinstance(files, dict) or len(files) < 30:
        raise RuntimeError("R14.1 source freeze is unexpectedly incomplete")

    return {
        "schema": "sigma-v3-r14-1-freeze-gate-v1",
        "freeze_id": R141_FREEZE_ID,
        "source_commit": source["source_commit"],
        "source_tree": source["source_tree"],
        "source_files": len(files),
        "confirmatory_executed": False,
        "baselines": baselines,
        "protocol": protocol,
        "analysis": analysis,
        "passed": True,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source-commit")
    parser.add_argument("--report", type=Path)
    args = parser.parse_args()
    try:
        report = check_r141_freeze(args.source_commit)
    except (OSError, RuntimeError, TypeError, ValueError, subprocess.SubprocessError) as exc:
        parser.error(str(exc))
    if args.report is not None:
        args.report.write_text(
            json.dumps(report, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )
    print(json.dumps(report, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
