#!/usr/bin/env python3
"""Validate the exact R14.1 publication-scale protocol before data."""

from __future__ import annotations

import argparse
import json
import tempfile
from pathlib import Path

from experiments.r141_protocol import (
    R141_FREEZE_ID,
    cells_for_attack_r141,
    confirmatory_attack_ids_r141,
)
from scripts.check_r15_data_closure import check_r15_data_closure
from scripts.check_r15_execution_closure import check_r15_execution_closure
from scripts.check_r15_plan import check_r15_plan
from scripts.prepare_r141_confirmatory import prepare_r141_configs


def check_r141_protocol() -> dict[str, object]:
    plan = check_r15_plan()
    execution = check_r15_execution_closure()
    data = check_r15_data_closure()

    attacks = confirmatory_attack_ids_r141()
    total_cells = 0
    total_runs = 0
    regions: dict[str, int] = {}
    for attack_id in attacks:
        cells = cells_for_attack_r141(attack_id)
        if not cells:
            raise RuntimeError(f"{attack_id} has no R14.1 cells")
        total_cells += len(cells)
        total_runs += sum(cell.replicates for cell in cells)
        for cell in cells:
            regions[cell.region] = regions.get(cell.region, 0) + 1
            if cell.analysis.primary_metric == "":
                raise RuntimeError(f"{attack_id} has an empty primary metric")

    with tempfile.TemporaryDirectory(prefix="sigma-r141-configs-") as temporary:
        generated = prepare_r141_configs(Path(temporary))
        if len(generated) != len(attacks) + 2:
            raise RuntimeError("R14.1 config generator did not emit 21 configs + index/manifest")

    if total_runs < 150_000:
        raise RuntimeError("R14.1 publication-scale run count fell below the frozen target")

    return {
        "schema": "sigma-v3-r14-1-protocol-gate-v1",
        "freeze_id": R141_FREEZE_ID,
        "passed": True,
        "confirmatory_executed": False,
        "attacks": len(attacks),
        "cells": total_cells,
        "run_units": total_runs,
        "regions": regions,
        "r15_plan": plan,
        "execution_closure": execution,
        "data_closure": data,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--report", type=Path)
    args = parser.parse_args()
    try:
        report = check_r141_protocol()
    except (OSError, RuntimeError, TypeError, ValueError) as exc:
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
