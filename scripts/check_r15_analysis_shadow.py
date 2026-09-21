#!/usr/bin/env python3
"""Run the R15-G synthetic locked-analysis rehearsal."""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from experiments.r15_analysis_shadow import ANALYSIS_SHADOW_NAMESPACE, run_analysis_shadow_v3


def check_r15_analysis_shadow() -> dict[str, object]:
    left = run_analysis_shadow_v3()
    right = run_analysis_shadow_v3()
    if left != right:
        raise RuntimeError("R15-G synthetic analysis is not deterministic")
    if left["namespace"] != ANALYSIS_SHADOW_NAMESPACE or left["confirmatory"] is not False:
        raise RuntimeError("R15-G crossed the confirmatory boundary")
    if left["figures"] != 15 or left["tables"] != 9:
        raise RuntimeError("R15-G frozen output coverage is incomplete")
    figure_ids = left["figure_ids"]
    if not isinstance(figure_ids, list) or figure_ids != [
        f"F{index:02d}" for index in range(1, 16)
    ]:
        raise RuntimeError("R15-G figure registry is incomplete")
    return left


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--report", type=Path)
    args = parser.parse_args()
    try:
        report = check_r15_analysis_shadow()
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
