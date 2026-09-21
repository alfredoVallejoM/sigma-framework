"""R15-H synthetic dataset audit rehearsal."""

from __future__ import annotations

import json
import tempfile
from pathlib import Path

from .r15_data import (
    RunKeyV3,
    atomic_write_record_v3,
    build_ledger_v3,
    receipt_path_v3,
    record_path_v3,
    verify_record_v3,
)

AUDIT_SHADOW_NAMESPACE = "sigma-v3-r15-shadow-h-v1"
AUDIT_SHADOW_FREEZE_ID = "synthetic-r15h-shadow"


def _record(key: RunKeyV3) -> dict[str, object]:
    return {
        "schema": "sigma-v3-r15-audit-shadow-record-v1",
        "namespace": AUDIT_SHADOW_NAMESPACE,
        "confirmatory": False,
        "run_key": key.stable_id,
        "metric": key.replicate_id,
    }


def run_audit_shadow_v3() -> dict[str, object]:
    checks: dict[str, bool] = {}
    with tempfile.TemporaryDirectory(prefix="sigma-r15h-") as temporary:
        root = Path(temporary)
        keys = [
            RunKeyV3(AUDIT_SHADOW_FREEZE_ID, "AUDIT", "cell-000", index)
            for index in range(5)
        ]
        for key in keys:
            atomic_write_record_v3(root, key, _record(key))

        first = build_ledger_v3(root, keys)
        reverse = build_ledger_v3(root, list(reversed(keys)))
        checks["ledger_order_independent"] = first["root_sha256"] == reverse["root_sha256"]

        observed = {
            path.stem
            for path in (root / "raw" / "AUDIT" / "cell-000").glob("*.json")
        }
        expected = {f"{index:08d}" for index in range(5)}
        checks["complete_runkey_set"] = observed == expected

        duplicate_rejected = False
        try:
            atomic_write_record_v3(root, keys[0], _record(keys[0]))
        except FileExistsError:
            duplicate_rejected = True
        checks["duplicate_rejected"] = duplicate_rejected

        record = record_path_v3(root, keys[1])
        original = record.read_bytes()
        record.write_bytes(original.replace(b'"metric":1', b'"metric":9'))
        try:
            verify_record_v3(root, keys[1])
        except ValueError:
            checks["record_tamper_rejected"] = True
        else:
            checks["record_tamper_rejected"] = False
        record.write_bytes(original)

        receipt = receipt_path_v3(root, keys[2])
        receipt_value = json.loads(receipt.read_text(encoding="utf-8"))
        receipt_value["record_sha256"] = "00" * 32
        receipt.write_text(json.dumps(receipt_value), encoding="utf-8")
        try:
            verify_record_v3(root, keys[2])
        except ValueError:
            checks["receipt_tamper_rejected"] = True
        else:
            checks["receipt_tamper_rejected"] = False

        missing = record_path_v3(root, keys[3])
        missing.unlink()
        try:
            build_ledger_v3(root, keys)
        except ValueError:
            checks["missing_record_rejected"] = True
        else:
            checks["missing_record_rejected"] = False

        try:
            build_ledger_v3(root, keys + [keys[4]])
        except ValueError:
            checks["duplicate_ledger_key_rejected"] = True
        else:
            checks["duplicate_ledger_key_rejected"] = False

    failed = sorted(name for name, passed in checks.items() if not passed)
    if failed:
        raise RuntimeError(f"R15-H shadow audit failed: {failed}")
    return {
        "schema": "sigma-v3-r15-audit-shadow-v1",
        "namespace": AUDIT_SHADOW_NAMESPACE,
        "confirmatory": False,
        "checks": checks,
        "check_count": len(checks),
        "baseline_ledger_root": first["root_sha256"],
        "passed": True,
    }


__all__ = ["AUDIT_SHADOW_FREEZE_ID", "AUDIT_SHADOW_NAMESPACE", "run_audit_shadow_v3"]
