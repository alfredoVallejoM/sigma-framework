#!/usr/bin/env python3
"""Validate R15-0C data/storage primitives without retaining large streams."""

from __future__ import annotations

import argparse
import json
import tempfile
from pathlib import Path

from experiments.r15_data import (
    RunKeyV3,
    ScratchQuotaV3,
    atomic_write_record_v3,
    build_ledger_v3,
    enforce_scratch_usage_v3,
)


def check_r15_data_closure() -> dict[str, object]:
    with tempfile.TemporaryDirectory(prefix="sigma-r15-data-") as temporary:
        root = Path(temporary)
        quota = ScratchQuotaV3(
            maximum_bytes=2 * 1024 * 1024,
            minimum_free_bytes=0,
        )
        keys = [RunKeyV3("fixture-freeze", "HIST-01", "hist-01-000", index) for index in range(3)]
        for key in keys:
            atomic_write_record_v3(
                root,
                key,
                {
                    "schema": "fixture",
                    "run_key": key.stable_id,
                    "confirmatory": False,
                },
            )
        try:
            atomic_write_record_v3(
                root,
                keys[0],
                {"schema": "duplicate", "confirmatory": False},
            )
        except FileExistsError:
            duplicate_rejected = True
        else:
            duplicate_rejected = False
        if not duplicate_rejected:
            raise RuntimeError("duplicate RunKey was silently accepted")
        scratch = enforce_scratch_usage_v3(root, quota)
        ledger = build_ledger_v3(root, keys)
        entries = ledger["entries"]
        if not isinstance(entries, list) or len(entries) != len(keys):
            raise RuntimeError("ledger does not contain every canonical record")

    return {
        "schema": "sigma-v3-r15-data-closure-v1",
        "passed": True,
        "confirmatory": False,
        "duplicate_runkey_rejected": True,
        "fixture_records": len(keys),
        "fixture_scratch_bytes": scratch,
        "ledger_root": ledger["root_sha256"],
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--report", type=Path)
    args = parser.parse_args()
    try:
        report = check_r15_data_closure()
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
