"""Merge and audit R15 STAT-01 confirmatory shards."""

from __future__ import annotations

import argparse
import hashlib
import json
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any

from .common import canonical_json, sha256_file
from .r15_data import RunKeyV3, atomic_write_record_v3, build_ledger_v3
from .r141_protocol import R141_FREEZE_ID

EXPECTED_STAT_RUN_UNITS = 1_536


def expected_stat_runkeys(config_root: Path) -> tuple[RunKeyV3, ...]:
    path = config_root / "stat-01.json"
    config = json.loads(path.read_text(encoding="utf-8"))
    if config.get("attack_id") != "STAT-01":
        raise ValueError("STAT config attack mismatch")
    if config.get("freeze_id") != R141_FREEZE_ID:
        raise ValueError("STAT config freeze mismatch")

    keys: list[RunKeyV3] = []
    for cell in config["cells"]:
        for replicate_id in range(int(cell["replicates"])):
            keys.append(
                RunKeyV3(
                    R141_FREEZE_ID,
                    "STAT-01",
                    str(cell["cell_id"]),
                    replicate_id,
                )
            )
    if len(keys) != EXPECTED_STAT_RUN_UNITS:
        raise RuntimeError(
            f"STAT expected-run cardinality drifted: {len(keys)} != {EXPECTED_STAT_RUN_UNITS}"
        )
    if len(keys) != len(set(keys)):
        raise RuntimeError("STAT expected RunKeys contain duplicates")
    return tuple(sorted(keys))


def _receipt_for_record(record_path: Path) -> Path:
    parts = record_path.parts
    try:
        raw_index = parts.index("raw")
    except ValueError as exc:
        raise ValueError("STAT record path is not below raw/") from exc
    root = Path(*parts[:raw_index])
    relative = Path(*parts[raw_index + 1 :])
    return root / "receipts" / relative


def _load_record(record_path: Path) -> tuple[dict[str, Any], str]:
    data = record_path.read_bytes()
    digest = hashlib.sha256(data).hexdigest()
    value = json.loads(data)
    if not isinstance(value, dict):
        raise ValueError("STAT record must be an object")
    receipt_path = _receipt_for_record(record_path)
    if not receipt_path.is_file():
        raise ValueError(f"missing STAT receipt for {record_path}")
    receipt = json.loads(receipt_path.read_text(encoding="utf-8"))
    if receipt.get("record_sha256") != digest:
        raise ValueError(f"STAT receipt digest mismatch for {record_path}")
    if receipt.get("run_key") != value.get("run_key"):
        raise ValueError(f"STAT receipt RunKey mismatch for {record_path}")
    return value


def audit_and_merge_stat(
    *,
    shards_root: Path,
    config_root: Path,
    execution_manifest_path: Path,
    output_root: Path,
) -> dict[str, object]:
    execution = json.loads(execution_manifest_path.read_text(encoding="utf-8"))
    if execution.get("schema") != "sigma-v3-r15-stat-execution-manifest-v1":
        raise ValueError("unexpected STAT execution manifest schema")
    if execution.get("confirmatory_unlocked") is not True:
        raise ValueError("STAT execution manifest is not unlocked")
    if execution.get("external_batteries") != ["nist-sts", "practrand"]:
        raise ValueError("STAT mandatory battery set mismatch")

    expected = expected_stat_runkeys(config_root)
    expected_ids = {key.stable_id for key in expected}
    execution_sha256 = sha256_file(execution_manifest_path)
    config_sha256 = sha256_file(config_root / "stat-01.json")

    observed: dict[str, dict[str, Any]] = {}
    statuses: Counter[str] = Counter()
    anomaly_by_cell: dict[str, list[bool]] = defaultdict(list)

    for path in sorted(shards_root.glob("**/raw/**/*.json")):
        record = _load_record(path)
        run_key = record.get("run_key")
        if not isinstance(run_key, str):
            raise ValueError(f"STAT record lacks RunKey: {path}")
        if run_key in observed:
            raise RuntimeError(f"duplicate STAT RunKey: {run_key}")
        if run_key not in expected_ids:
            raise RuntimeError(f"unexpected STAT RunKey: {run_key}")
        if record.get("schema") != "sigma-v3-r15-record-v2":
            raise ValueError("unexpected STAT confirmatory record schema")
        if record.get("phase") != "confirmatory" or record.get("attack_id") != "STAT-01":
            raise ValueError("record is not STAT-01 confirmatory data")
        if record.get("code_commit") != execution.get("source_commit"):
            raise ValueError("STAT source commit mismatch")
        if record.get("artifact_sha256") != execution.get("artifact_sha256"):
            raise ValueError("STAT artifact hash mismatch")
        if record.get("execution_manifest_sha256") != execution_sha256:
            raise ValueError("STAT execution-manifest hash mismatch")
        if record.get("config_sha256") != config_sha256:
            raise ValueError("STAT config hash mismatch")
        if record.get("preregistration_sha256") != execution.get("preregistration_sha256"):
            raise ValueError("STAT preregistration hash mismatch")
        if record.get("dependency_lock_sha256") != execution.get("dependency_lock_sha256"):
            raise ValueError("STAT dependency-lock hash mismatch")

        metrics = record.get("metrics")
        if not isinstance(metrics, dict):
            raise ValueError("STAT record metrics are invalid")
        if metrics.get("stream_bytes") != 64 * 1024 * 1024:
            raise ValueError("STAT record does not represent an exact 64 MiB stream")
        if metrics.get("adjusted_anomaly_rate") is not None:
            raise ValueError("per-stream adjusted anomaly rate must remain aggregate-only")

        observed[run_key] = record
        statuses[str(record.get("status"))] += 1
        anomaly_by_cell[str(record.get("cell_id"))].append(
            bool(metrics.get("raw_anomaly_indicator"))
        )

    observed_ids = set(observed)
    missing = expected_ids - observed_ids
    extra = observed_ids - expected_ids
    if missing or extra:
        raise RuntimeError(
            f"STAT coverage mismatch: missing={len(missing)}, extra={len(extra)}"
        )

    output_root.mkdir(parents=True, exist_ok=True)
    merged: list[RunKeyV3] = []
    for key in expected:
        atomic_write_record_v3(output_root, key, observed[key.stable_id])
        merged.append(key)

    ledger = build_ledger_v3(output_root, merged)
    (output_root / "stat-ledger.json").write_bytes(canonical_json(ledger) + b"\n")
    raw_rates = {
        cell_id: sum(values) / len(values)
        for cell_id, values in sorted(anomaly_by_cell.items())
    }
    summary = {
        "schema": "sigma-v3-r15-stat-dataset-v1",
        "confirmatory": True,
        "expected_run_units": len(expected),
        "observed_run_units": len(observed),
        "mandatory_batteries": ["nist-sts", "practrand"],
        "statuses": dict(sorted(statuses.items())),
        "raw_anomaly_rates_by_cell": raw_rates,
        "adjusted_anomaly_analysis": "pending locked R15-G aggregate analysis",
        "ledger_root": ledger["root_sha256"],
        "passed": True,
    }
    (output_root / "stat-summary.json").write_bytes(canonical_json(summary) + b"\n")
    return summary


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--shards", type=Path, required=True)
    parser.add_argument("--configs", type=Path, required=True)
    parser.add_argument("--execution-manifest", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--report", type=Path)
    args = parser.parse_args()
    try:
        report = audit_and_merge_stat(
            shards_root=args.shards,
            config_root=args.configs,
            execution_manifest_path=args.execution_manifest,
            output_root=args.output,
        )
    except (OSError, RuntimeError, TypeError, ValueError, json.JSONDecodeError) as exc:
        parser.error(str(exc))

    if args.report is not None:
        args.report.parent.mkdir(parents=True, exist_ok=True)
        args.report.write_text(
            json.dumps(report, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )
    print(json.dumps(report, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
