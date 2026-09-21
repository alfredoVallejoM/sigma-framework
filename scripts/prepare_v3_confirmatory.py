#!/usr/bin/env python3
"""Generate the frozen Sigma v3 R15 configs from the R14 protocol."""

from __future__ import annotations

import argparse
import json
from dataclasses import asdict
from pathlib import Path

from experiments.common import canonical_json
from experiments.r13_attack_registry import ATTACK_REGISTRY
from experiments.r14_protocol import (
    ATTACK_DISPOSITIONS,
    CLAIMS,
    CONFIRMATORY_NAMESPACE,
    FREEZE_ID,
    R12_5_BASELINE,
    R13_BASELINE,
    confirmatory_attack_ids,
    confirmatory_cells,
)
from experiments.r14_schema import ConfirmatoryConfigV3

DEFAULT_OUTPUT = Path("experiments/configs/v3-confirmatory-frozen")


def _config(attack_id: str) -> ConfirmatoryConfigV3:
    attack = ATTACK_REGISTRY[attack_id]
    disposition = next(item for item in ATTACK_DISPOSITIONS if item.attack_id == attack_id)
    claims = tuple(
        sorted(
            claim.claim_id
            for claim in CLAIMS
            if attack_id in claim.attacks and claim.disposition == "confirmatory"
        )
    )
    if not claims:
        claims = attack.claims
    cells = tuple(asdict(cell) for cell in confirmatory_cells(attack_id))
    return ConfirmatoryConfigV3(
        schema="sigma-v3-r15-config-v1",
        campaign="confirmatory-v3",
        freeze_id=FREEZE_ID,
        attack_id=attack_id,
        seed_namespace=CONFIRMATORY_NAMESPACE,
        execution_kind=disposition.execution,
        claims=claims,
        cells=cells,
    )


def render_configs() -> dict[str, bytes]:
    rendered: dict[str, bytes] = {}
    for attack_id in confirmatory_attack_ids():
        filename = f"{attack_id.lower()}.json"
        rendered[filename] = canonical_json(_config(attack_id).to_dict()) + b"\n"
    index = {
        "schema": "sigma-v3-r14-campaign-index-v1",
        "freeze_id": FREEZE_ID,
        "r12_5_baseline": R12_5_BASELINE,
        "r13_baseline": R13_BASELINE,
        "seed_namespace": CONFIRMATORY_NAMESPACE,
        "confirmatory_executed": False,
        "attacks": [
            {
                "attack_id": attack_id,
                "config": f"{attack_id.lower()}.json",
                "execution_kind": next(
                    item.execution for item in ATTACK_DISPOSITIONS if item.attack_id == attack_id
                ),
                "cells": len(confirmatory_cells(attack_id)),
                "replicates": sum(cell.replicates for cell in confirmatory_cells(attack_id)),
            }
            for attack_id in confirmatory_attack_ids()
        ],
    }
    rendered["campaign-index.json"] = canonical_json(index) + b"\n"
    return rendered


def prepare(output: Path, *, check: bool = False) -> list[Path]:
    rendered = render_configs()
    if check:
        if not output.is_dir():
            raise ValueError("frozen v3 config directory is missing")
        actual = {
            path.name for path in output.glob("*.json") if path.name != "protocol-freeze.json"
        }
        if actual != set(rendered):
            raise ValueError("frozen v3 config file set differs from R14 protocol")
        for name, expected in rendered.items():
            path = output / name
            if not path.is_file() or path.read_bytes() != expected:
                raise ValueError(f"frozen v3 config is stale: {name}")
        return [output / name for name in sorted(rendered)]

    output.mkdir(parents=True, exist_ok=True)
    unexpected = [
        path
        for path in output.iterdir()
        if path.is_file() and path.name not in rendered and path.name != "protocol-freeze.json"
    ]
    if unexpected:
        raise ValueError(f"unexpected files in frozen config directory: {unexpected}")
    written = []
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
        paths = prepare(args.output, check=args.check)
    except (OSError, TypeError, ValueError, json.JSONDecodeError) as exc:
        parser.error(str(exc))
    print(json.dumps({"files": [str(path) for path in paths]}, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
