"""Validate the canonical R13 registry, schema and disposable design pilots."""

from __future__ import annotations

import argparse
import json
from collections import Counter
from pathlib import Path

from experiments.r13_attack_registry import ATTACK_REGISTRY
from experiments.r13_pilots import (
    CORE_EXECUTABLE_ATTACKS,
    run_r13_design_pilots,
    validate_r13_design_records,
)


def validate_r13_design() -> dict[str, object]:
    records = run_r13_design_pilots(b"sigma-r13-authoritative-design")
    validate_r13_design_records(records)
    counts = Counter(record.attack_id for record in records)
    missing = sorted(CORE_EXECUTABLE_ATTACKS - set(counts))
    if missing:
        raise RuntimeError(f"R13 executable attack set is incomplete: {missing}")
    if any(record.metrics.get("confirmatory") is not False for record in records):
        raise RuntimeError("R13 design pilots must never be confirmatory")
    return {
        "schema": "sigma-r13-design-gate-v1",
        "passed": True,
        "records": len(records),
        "attacks": dict(sorted(counts.items())),
        "registry_entries": len(ATTACK_REGISTRY),
        "executable_attack_ids": sorted(CORE_EXECUTABLE_ATTACKS),
        "confirmatory_records": sum(
            record.metrics.get("confirmatory") is True for record in records
        ),
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--report", type=Path)
    args = parser.parse_args()
    try:
        report = validate_r13_design()
    except (RuntimeError, TypeError, ValueError) as exc:
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
