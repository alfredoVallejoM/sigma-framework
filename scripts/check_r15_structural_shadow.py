#!/usr/bin/env python3
"""Run the R15-C structural shadow acquisition battery."""

from __future__ import annotations

import argparse
import json
import tempfile
from pathlib import Path

from experiments.r15_structural_shadow import (
    SHADOW_NAMESPACE,
    STRUCTURAL_ATTACKS,
    run_structural_shadow_suite_v3,
    selected_shadow_cells_v3,
)


def check_r15_structural_shadow() -> dict[str, object]:
    selected = selected_shadow_cells_v3()
    if len(selected) != 33:
        raise RuntimeError(f"unexpected R15-C shadow cell count: {len(selected)}")

    with tempfile.TemporaryDirectory(prefix="sigma-r15c-shadow-") as temporary:
        report = run_structural_shadow_suite_v3(Path(temporary))

    attacks = report["attacks"]
    if not isinstance(attacks, list) or set(attacks) != set(STRUCTURAL_ATTACKS):
        raise RuntimeError("R15-C shadow attack coverage is incomplete")
    results = report["results"]
    if not isinstance(results, list) or len(results) != 33:
        raise RuntimeError("R15-C shadow did not emit every selected record")
    if report["namespace"] != SHADOW_NAMESPACE or report["confirmatory"] is not False:
        raise RuntimeError("R15-C shadow crossed the confirmatory boundary")

    branch05_faults = {
        item["metrics"]["fault"] for item in results if item["attack_id"] == "BRANCH-05"
    }
    branch06_faults = {
        item["metrics"]["fault"] for item in results if item["attack_id"] == "BRANCH-06"
    }
    if len(branch05_faults) != 8:
        raise RuntimeError("BRANCH-05 shadow fault coverage is incomplete")
    if len(branch06_faults) != 6:
        raise RuntimeError("BRANCH-06 shadow fault coverage is incomplete")
    hist03_games = {item["metrics"]["game"] for item in results if item["attack_id"] == "HIST-03"}
    if hist03_games != {"collision", "second-preimage", "fixed-point", "cycle"}:
        raise RuntimeError("HIST-03 shadow game coverage is incomplete")

    return {
        "schema": "sigma-v3-r15-structural-shadow-gate-v1",
        "namespace": SHADOW_NAMESPACE,
        "confirmatory": False,
        "selected_cells": len(selected),
        "attacks": len(attacks),
        "hist03_games": sorted(hist03_games),
        "branch05_faults": sorted(branch05_faults),
        "branch06_faults": sorted(branch06_faults),
        "ledger_root": report["ledger_root"],
        "passed": True,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--report", type=Path)
    args = parser.parse_args()
    try:
        report = check_r15_structural_shadow()
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
