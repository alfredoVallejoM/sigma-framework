#!/usr/bin/env python3
"""Verify the exact Git tag required to close Sigma v3 R14."""

from __future__ import annotations

import argparse
import json
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
R14_TAG = "sigma-v3-r14-freeze-v1"
R14_CANDIDATE = "b6ebc780cc0b201fd27562c85c64c90df37c1075"


def _git(*args: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        ["git", *args],
        cwd=ROOT,
        check=False,
        capture_output=True,
        text=True,
    )


def verify_r14_tag() -> dict[str, object]:
    tag = _git("rev-parse", "-q", "--verify", f"refs/tags/{R14_TAG}")
    if tag.returncode != 0:
        raise RuntimeError(f"required R14 tag is missing: {R14_TAG}")

    peeled = _git("rev-list", "-n", "1", R14_TAG)
    if peeled.returncode != 0:
        raise RuntimeError("failed to resolve R14 tag target")
    target = peeled.stdout.strip()
    if target != R14_CANDIDATE:
        raise RuntimeError(f"R14 tag points to {target}, expected {R14_CANDIDATE}")

    candidate = _git("cat-file", "-e", f"{R14_CANDIDATE}^{{commit}}")
    if candidate.returncode != 0:
        raise RuntimeError("R14 candidate commit is unavailable")

    return {
        "schema": "sigma-v3-r14-tag-check-v1",
        "tag": R14_TAG,
        "candidate": R14_CANDIDATE,
        "resolved": target,
        "passed": True,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--report", type=Path)
    args = parser.parse_args()
    try:
        report = verify_r14_tag()
    except RuntimeError as exc:
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
