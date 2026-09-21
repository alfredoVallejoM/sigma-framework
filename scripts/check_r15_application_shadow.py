#!/usr/bin/env python3
"""Run the R15-E application shadow battery with production primitives."""

from __future__ import annotations

import argparse
import json
import tempfile
from pathlib import Path

from experiments.r15_application_shadow import (
    SHADOW_E_NAMESPACE,
    run_application_shadow_suite_v3,
)


def check_r15_application_shadow() -> dict[str, object]:
    with tempfile.TemporaryDirectory(prefix="sigma-r15e-shadow-") as temporary:
        report = run_application_shadow_suite_v3(Path(temporary))

    if report["namespace"] != SHADOW_E_NAMESPACE or report["confirmatory"] is not False:
        raise RuntimeError("R15-E shadow crossed the confirmatory boundary")
    results = report["results"]
    if not isinstance(results, list) or len(results) != 3:
        raise RuntimeError("R15-E shadow must emit three application records")
    attacks = {item["attack_id"] for item in results}
    if attacks != {"PARAM-04", "PARAM-05", "PARAM-06"}:
        raise RuntimeError("R15-E shadow attack coverage is incomplete")
    for item in results:
        value = item["primary_value"]
        if not isinstance(value, (int, float)) or value < 0:
            raise RuntimeError("R15-E primary metric is invalid")

    kdf = next(item for item in results if item["attack_id"] == "PARAM-04")
    if int(kdf["metrics"]["guesses"]) != 2:
        raise RuntimeError("KDF shadow did not execute the frozen paired treatment shape")
    pow_result = next(item for item in results if item["attack_id"] == "PARAM-05")
    if int(pow_result["metrics"]["nonces"]) != 4:
        raise RuntimeError("PoW shadow nonce count is invalid")
    mitigation = next(item for item in results if item["attack_id"] == "PARAM-06")
    if int(mitigation["metrics"]["samples"]) != 8:
        raise RuntimeError("mitigation shadow sample count is invalid")

    return {
        "schema": "sigma-v3-r15-application-shadow-gate-v1",
        "namespace": SHADOW_E_NAMESPACE,
        "confirmatory": False,
        "records": 3,
        "attacks": sorted(attacks),
        "ledger_root": report["ledger_root"],
        "passed": True,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--report", type=Path)
    args = parser.parse_args()
    try:
        report = check_r15_application_shadow()
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
