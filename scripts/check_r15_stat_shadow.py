#!/usr/bin/env python3
"""Run the R15-F deterministic STAT-stream shadow battery."""

from __future__ import annotations

import argparse
import json
import tempfile
from pathlib import Path

from experiments.r15_stat_shadow import (
    SHADOW_F_NAMESPACE,
    run_stat_shadow_suite_v3,
)
from experiments.r15_stat_streams import STAT_CONSTRUCTIONS, STAT_CORPORA


def check_r15_stat_shadow() -> dict[str, object]:
    with tempfile.TemporaryDirectory(prefix="sigma-r15f-shadow-") as temporary:
        report = run_stat_shadow_suite_v3(Path(temporary))

    if report["namespace"] != SHADOW_F_NAMESPACE or report["confirmatory"] is not False:
        raise RuntimeError("R15-F shadow crossed the confirmatory boundary")
    expected = len(STAT_CONSTRUCTIONS) * len(STAT_CORPORA)
    if report["cells"] != expected:
        raise RuntimeError("R15-F shadow did not cover every construction/corpus cell")
    results = report["results"]
    if not isinstance(results, list) or len(results) != expected:
        raise RuntimeError("R15-F shadow result set is incomplete")
    observed = {(item["construction"], item["corpus"]) for item in results}
    expected_pairs = {
        (construction, corpus) for construction in STAT_CONSTRUCTIONS for corpus in STAT_CORPORA
    }
    if observed != expected_pairs:
        raise RuntimeError("R15-F construction/corpus coverage mismatch")
    if any(item["total_bytes"] != 2048 for item in results):
        raise RuntimeError("R15-F shadow stream length mismatch")

    return {
        "schema": "sigma-v3-r15-stat-shadow-gate-v1",
        "namespace": SHADOW_F_NAMESPACE,
        "confirmatory": False,
        "cells": expected,
        "logical_bytes": report["logical_bytes"],
        "ledger_root": report["ledger_root"],
        "passed": True,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--report", type=Path)
    args = parser.parse_args()
    try:
        report = check_r15_stat_shadow()
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
