#!/usr/bin/env python3
"""Run the R15-D reduced-cryptanalysis shadow battery."""

from __future__ import annotations

import argparse
import json
import tempfile
from pathlib import Path

from experiments.r15_reduced_shadow import (
    REDUCED_ATTACKS,
    SHADOW_D_NAMESPACE,
    run_reduced_shadow_suite_v3,
    selected_reduced_shadow_cells_v3,
)


def check_r15_reduced_shadow() -> dict[str, object]:
    selected = selected_reduced_shadow_cells_v3()
    if len(selected) != 32:
        raise RuntimeError(f"unexpected R15-D shadow cell count: {len(selected)}")

    with tempfile.TemporaryDirectory(prefix="sigma-r15d-shadow-") as temporary:
        report = run_reduced_shadow_suite_v3(Path(temporary))

    attacks = report["attacks"]
    results = report["results"]
    if not isinstance(attacks, list) or set(attacks) != set(REDUCED_ATTACKS):
        raise RuntimeError("R15-D attack coverage is incomplete")
    if not isinstance(results, list) or len(results) != 32:
        raise RuntimeError("R15-D shadow did not emit every selected record")
    if report["namespace"] != SHADOW_D_NAMESPACE or report["confirmatory"] is not False:
        raise RuntimeError("R15-D shadow crossed the confirmatory boundary")

    red02_k = {
        int(item["metrics"]["state_count"]) for item in results if item["attack_id"] == "RED-02"
    }
    red04_policies = {
        item["metrics"]["policy"] for item in results if item["attack_id"] == "RED-04"
    }
    tmto_strategies = {
        item["metrics"]["strategy"]
        for item in results
        if item["attack_id"] in ("TMTO-01", "TMTO-02")
    }
    if red02_k != {1, 2, 3, 4}:
        raise RuntimeError("RED-02 k coverage is incomplete")
    if red04_policies != {"same-persistent", "any-persistent"}:
        raise RuntimeError("RED-04 policy coverage is incomplete")
    if tmto_strategies != {"direct", "distinguished", "rho", "hellman", "rainbow"}:
        raise RuntimeError("TMTO shadow strategy coverage is incomplete")

    return {
        "schema": "sigma-v3-r15-reduced-shadow-gate-v1",
        "namespace": SHADOW_D_NAMESPACE,
        "confirmatory": False,
        "selected_cells": len(selected),
        "attacks": len(attacks),
        "red02_state_counts": sorted(red02_k),
        "red04_policies": sorted(red04_policies),
        "tmto_strategies": sorted(tmto_strategies),
        "ledger_root": report["ledger_root"],
        "passed": True,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--report", type=Path)
    args = parser.parse_args()
    try:
        report = check_r15_reduced_shadow()
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
