#!/usr/bin/env python3
"""Render exact publication-scale R14.1/R15 confirmatory configs."""

from __future__ import annotations

import argparse
import hashlib
import json
from dataclasses import asdict
from pathlib import Path

from experiments.common import canonical_json
from experiments.r141_protocol import (
    R141_CONFIRMATORY_NAMESPACE,
    R141_FREEZE_ID,
    R141_TAG,
    cells_for_attack_r141,
    confirmatory_attack_ids_r141,
    protocol_summary_r141,
)
from experiments.r141_schema import ConfirmatoryConfigR141

DEFAULT_OUTPUT = Path("experiments/configs/v3-confirmatory-r141-generated")


def _config(attack_id: str) -> ConfirmatoryConfigR141:
    summary = protocol_summary_r141()["attacks"]
    assert isinstance(summary, dict)
    attack = summary[attack_id]
    assert isinstance(attack, dict)
    cells = tuple(asdict(cell) for cell in cells_for_attack_r141(attack_id))
    return ConfirmatoryConfigR141(
        schema="sigma-v3-r15-config-v2",
        campaign="confirmatory-v3-r141",
        freeze_id=R141_FREEZE_ID,
        attack_id=attack_id,
        seed_namespace=R141_CONFIRMATORY_NAMESPACE,
        execution_kind=str(attack["execution_kind"]),
        claims=tuple(attack["claims"]),
        cells=cells,
    )


def render_r141_configs() -> dict[str, bytes]:
    rendered: dict[str, bytes] = {}
    index_attacks: list[dict[str, object]] = []
    total_cells = 0
    total_replicates = 0

    for attack_id in confirmatory_attack_ids_r141():
        config = _config(attack_id)
        filename = f"{attack_id.lower()}.json"
        data = canonical_json(config.to_dict()) + b"\n"
        rendered[filename] = data
        cells = cells_for_attack_r141(attack_id)
        cell_count = len(cells)
        replicate_count = sum(cell.replicates for cell in cells)
        total_cells += cell_count
        total_replicates += replicate_count
        index_attacks.append(
            {
                "attack_id": attack_id,
                "config": filename,
                "cells": cell_count,
                "replicates": replicate_count,
                "execution_kind": config.execution_kind,
            }
        )

    index = {
        "schema": "sigma-v3-r14-1-campaign-index-v1",
        "freeze_id": R141_FREEZE_ID,
        "tag": R141_TAG,
        "seed_namespace": R141_CONFIRMATORY_NAMESPACE,
        "confirmatory_executed": False,
        "attacks": index_attacks,
        "total_cells": total_cells,
        "total_run_units": total_replicates,
    }
    rendered["campaign-index.json"] = canonical_json(index) + b"\n"

    file_hashes = {
        name: hashlib.sha256(data).hexdigest()
        for name, data in sorted(rendered.items())
    }
    manifest = {
        "schema": "sigma-v3-r14-1-config-manifest-v1",
        "freeze_id": R141_FREEZE_ID,
        "files": file_hashes,
        "total_files": len(file_hashes),
        "total_cells": total_cells,
        "total_run_units": total_replicates,
    }
    rendered["config-manifest.json"] = canonical_json(manifest) + b"\n"
    return rendered


def prepare_r141_configs(output: Path, *, check: bool = False) -> list[Path]:
    rendered = render_r141_configs()
    if check:
        if not output.is_dir():
            raise ValueError("R14.1 generated config directory is missing")
        actual = {path.name for path in output.glob("*.json")}
        if actual != set(rendered):
            raise ValueError("R14.1 generated config file set mismatch")
        for name, expected in rendered.items():
            if (output / name).read_bytes() != expected:
                raise ValueError(f"stale R14.1 generated config: {name}")
        return [output / name for name in sorted(rendered)]

    output.mkdir(parents=True, exist_ok=True)
    for path in output.glob("*.json"):
        path.unlink()
    written: list[Path] = []
    for name, data in sorted(rendered.items()):
        path = output / name
        path.write_bytes(data)
        written.append(path)
    return written


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT)
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args()
    try:
        paths = prepare_r141_configs(args.output, check=args.check)
    except (OSError, TypeError, ValueError, json.JSONDecodeError) as exc:
        parser.error(str(exc))
    print(json.dumps({"files": [str(path) for path in paths]}, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
