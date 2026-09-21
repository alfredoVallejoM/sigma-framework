#!/usr/bin/env python3
"""Verify that the final R14.1 tag points to the runtime-manifest source commit."""

from __future__ import annotations

import argparse
import json
import subprocess
from pathlib import Path

from experiments.r141_protocol import R141_FREEZE_ID, R141_TAG

ROOT = Path(__file__).resolve().parents[1]


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


def verify_r141_tag(runtime_manifest: Path) -> dict[str, object]:
    manifest = json.loads(runtime_manifest.read_text(encoding="utf-8"))
    if manifest.get("schema") != "sigma-v3-r14-1-runtime-manifest-v1":
        raise ValueError("unexpected R14.1 runtime manifest schema")
    if manifest.get("freeze_id") != R141_FREEZE_ID:
        raise ValueError("runtime manifest freeze id mismatch")
    source_commit = manifest.get("source_commit")
    if not isinstance(source_commit, str) or len(source_commit) != 40:
        raise ValueError("runtime manifest has invalid source commit")

    _git("rev-parse", "-q", "--verify", f"refs/tags/{R141_TAG}")
    target = _git("rev-list", "-n", "1", R141_TAG)
    if target != source_commit:
        raise RuntimeError(
            f"{R141_TAG} resolves to {target}, expected runtime source {source_commit}"
        )
    tagged_tree = _git("rev-parse", f"{target}^{{tree}}")
    if tagged_tree != manifest.get("source_tree"):
        raise RuntimeError("tagged source tree differs from runtime manifest")

    return {
        "schema": "sigma-v3-r14-1-tag-check-v1",
        "tag": R141_TAG,
        "source_commit": source_commit,
        "source_tree": tagged_tree,
        "passed": True,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--runtime-manifest", type=Path, required=True)
    args = parser.parse_args()
    try:
        report = verify_r141_tag(args.runtime_manifest)
    except (OSError, RuntimeError, ValueError, json.JSONDecodeError) as exc:
        parser.error(str(exc))
    print(json.dumps(report, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
