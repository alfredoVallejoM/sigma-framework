#!/usr/bin/env python3
"""Run the R15-H synthetic adversarial dataset audit."""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from experiments.r15_audit_shadow import AUDIT_SHADOW_NAMESPACE, run_audit_shadow_v3


def check_r15_audit_shadow() -> dict[str, object]:
    report = run_audit_shadow_v3()
    if report["namespace"] != AUDIT_SHADOW_NAMESPACE or report["confirmatory"] is not False:
        raise RuntimeError("R15-H crossed the confirmatory boundary")
    checks = report["checks"]
    if not isinstance(checks, dict) or not checks or not all(checks.values()):
        raise RuntimeError("R15-H audit coverage is incomplete")
    return report


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--report", type=Path)
    args = parser.parse_args()
    try:
        report = check_r15_audit_shadow()
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
