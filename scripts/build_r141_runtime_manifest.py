#!/usr/bin/env python3
"""Bind R14.1 source, configs and release artifacts into a runtime manifest."""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from experiments.common import canonical_json, sha256_file
from experiments.r141_protocol import R141_FREEZE_ID


def _sha256_tree_files(root: Path) -> dict[str, str]:
    return {
        str(path.relative_to(root)): sha256_file(path)
        for path in sorted(root.glob("*.json"))
        if path.is_file()
    }


def build_r141_runtime_manifest(
    *,
    distribution: Path,
    source_freeze: Path,
    configs: Path,
    preregistration: Path,
    dependency_lock: Path,
    source_commit: str,
    output: Path,
) -> dict[str, object]:
    source = json.loads(source_freeze.read_text(encoding="utf-8"))
    if source.get("freeze_id") != R141_FREEZE_ID:
        raise ValueError("source freeze id mismatch")
    if source.get("source_commit") != source_commit:
        raise ValueError("runtime source commit differs from source freeze")
    if source.get("confirmatory_executed") is not False:
        raise ValueError("source freeze contains confirmatory execution")

    artifacts = sorted(
        path
        for path in distribution.iterdir()
        if path.is_file()
        and (
            path.suffix == ".whl"
            or path.name.endswith(".tar.gz")
            or path.name == "SHA256SUMS"
            or "sbom" in path.name.lower()
            or path.name.endswith(".cdx.json")
        )
    )
    if not artifacts:
        raise ValueError("release distribution is empty")

    config_manifest = configs / "config-manifest.json"
    if not config_manifest.is_file():
        raise ValueError("generated config manifest is missing")
    config_hashes = _sha256_tree_files(configs)
    record: dict[str, object] = {
        "schema": "sigma-v3-r14-1-runtime-manifest-v1",
        "freeze_id": R141_FREEZE_ID,
        "source_commit": source_commit,
        "source_tree": source["source_tree"],
        "source_freeze_sha256": sha256_file(source_freeze),
        "preregistration_sha256": sha256_file(preregistration),
        "dependency_lock_sha256": sha256_file(dependency_lock),
        "config_manifest_sha256": sha256_file(config_manifest),
        "config_files": config_hashes,
        "artifacts": {
            path.name: {
                "sha256": sha256_file(path),
                "size": path.stat().st_size,
            }
            for path in artifacts
        },
    }
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_bytes(canonical_json(record) + b"\n")
    return record


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--distribution", type=Path, required=True)
    parser.add_argument("--source-freeze", type=Path, required=True)
    parser.add_argument("--configs", type=Path, required=True)
    parser.add_argument("--preregistration", type=Path, required=True)
    parser.add_argument("--dependency-lock", type=Path, required=True)
    parser.add_argument("--source-commit", required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    try:
        record = build_r141_runtime_manifest(
            distribution=args.distribution,
            source_freeze=args.source_freeze,
            configs=args.configs,
            preregistration=args.preregistration,
            dependency_lock=args.dependency_lock,
            source_commit=args.source_commit,
            output=args.output,
        )
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        parser.error(str(exc))
    print(json.dumps(record, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
