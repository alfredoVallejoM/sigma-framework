#!/usr/bin/env python3
"""Build the runtime identity manifest that binds R14 to release artifacts."""

from __future__ import annotations

import argparse
import json
import subprocess
from pathlib import Path

from experiments.common import canonical_json, sha256_file
from experiments.r14_protocol import FREEZE_ID

ROOT = Path(__file__).resolve().parents[1]


def _git(*args: str) -> str:
    result = subprocess.run(
        ["git", *args],
        cwd=ROOT,
        check=True,
        capture_output=True,
        text=True,
    )
    return result.stdout.strip()


def build_runtime_manifest(
    distribution: Path,
    protocol_freeze: Path,
    output: Path,
    *,
    require_tag: bool = False,
) -> dict[str, object]:
    artifacts = sorted(
        path
        for path in distribution.iterdir()
        if path.is_file()
        and (
            path.suffix == ".whl"
            or path.name.endswith(".tar.gz")
            or path.name.endswith(".sha256")
            or "sbom" in path.name.lower()
        )
    )
    if not artifacts:
        raise ValueError("no release artifacts found")
    tags = _git("tag", "--points-at", "HEAD")
    tag = _git("describe", "--tags", "--exact-match", "HEAD") if tags else None
    if require_tag and tag is None:
        raise ValueError("R14 final runtime manifest requires an exact tag")

    record: dict[str, object] = {
        "schema": "sigma-v3-r14-runtime-artifact-v1",
        "freeze_id": FREEZE_ID,
        "commit": _git("rev-parse", "HEAD"),
        "tag": tag,
        "protocol_freeze": {
            "path": str(protocol_freeze),
            "sha256": sha256_file(protocol_freeze),
        },
        "artifacts": {
            path.name: {"sha256": sha256_file(path), "size": path.stat().st_size}
            for path in artifacts
        },
    }
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_bytes(canonical_json(record) + b"\n")
    return record


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--distribution", type=Path, required=True)
    parser.add_argument("--protocol-freeze", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--require-tag", action="store_true")
    args = parser.parse_args()
    try:
        result = build_runtime_manifest(
            args.distribution,
            args.protocol_freeze,
            args.output,
            require_tag=args.require_tag,
        )
    except (OSError, subprocess.CalledProcessError, ValueError) as exc:
        parser.error(str(exc))
    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
