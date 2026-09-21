"""Merge and audit the R15 internal pre-execution amendment dataset."""

from __future__ import annotations

import argparse
import hashlib
import json
from collections import Counter
from pathlib import Path
from typing import Any

from .common import canonical_json, sha256_file
from .r15_data import RunKeyV3, atomic_write_record_v3, build_ledger_v3
from .r15_internal_amendment import AMENDED_ATTACKS, EXPECTED_RUN_UNITS, FREEZE_ID

AMENDMENT_EXPECTED_RUN_UNITS = EXPECTED_RUN_UNITS


def expected_amendment_runkeys(config_root: Path) -> tuple[RunKeyV3, ...]:
    keys: list[RunKeyV3] = []
    for attack_id in AMENDED_ATTACKS:
        path = config_root / f"{attack_id.lower()}.json"
        if not path.is_file():
            raise ValueError(f"missing amendment config: {path.name}")
        config = json.loads(path.read_text(encoding="utf-8"))
        if config.get("attack_id") != attack_id:
            raise ValueError(f"amendment config attack mismatch: {path.name}")
        if config.get("freeze_id") != FREEZE_ID:
            raise ValueError("amendment config freeze id mismatch")
        for cell in config["cells"]:
            for replicate_id in range(int(cell["replicates"])):
                keys.append(
                    RunKeyV3(
                        FREEZE_ID,
                        attack_id,
                        str(cell["cell_id"]),
                        replicate_id,
                    )
                )
    if len(keys) != AMENDMENT_EXPECTED_RUN_UNITS:
        raise RuntimeError(
            "amendment expected-run cardinality drifted: "
            f"{len(keys)} != {AMENDMENT_EXPECTED_RUN_UNITS}"
        )
    if len(keys) != len(set(keys)):
        raise RuntimeError("amendment expected RunKeys contain duplicates")
    return tuple(sorted(keys))


def _receipt_for_record(record_path: Path) -> Path:
    parts = record_path.parts
    try:
        raw_index = parts.index("raw")
    except ValueError as exc:
        raise ValueError("record path is not below raw/") from exc
    root = Path(*parts[:raw_index])
    relative = Path(*parts[raw_index + 1 :])
    return root / "receipts" / relative


def _load_record(record_path: Path) -> dict[str, Any]:
    data = record_path.read_bytes()
    digest = hashlib.sha256(data).hexdigest()
    value = json.loads(data)
    if not isinstance(value, dict):
        raise ValueError("confirmatory record must be an object")
    receipt_path = _receipt_for_record(record_path)
    if not receipt_path.is_file():
        raise ValueError(f"missing receipt for {record_path}")
    receipt = json.loads(receipt_path.read_text(encoding="utf-8"))
    if receipt.get("record_sha256") != digest:
        raise ValueError(f"receipt digest mismatch for {record_path}")
    if receipt.get("run_key") != value.get("run_key"):
        raise ValueError(f"receipt RunKey mismatch for {record_path}")
    return value


def audit_and_merge_amendment(
    *,
    shards_root: Path,
    config_root: Path,
    execution_manifest_path: Path,
    output_root: Path,
) -> dict[str, object]:
    execution = json.loads(execution_manifest_path.read_text(encoding="utf-8"))
    if execution.get("schema") != "sigma-v3-r15-internal-amendment-manifest-v1":
        raise ValueError("unexpected amendment execution manifest schema")
    if execution.get("scope") != "internal-amendment":
        raise ValueError("amendment manifest has invalid scope")
    if execution.get("confirmatory_unlocked") is not True:
        raise ValueError("amendment execution is not unlocked")

    authorized = execution.get("authorized_attacks")
    if not isinstance(authorized, list) or set(authorized) != set(AMENDED_ATTACKS):
        raise ValueError("amendment attack authorization mismatch")

    expected = expected_amendment_runkeys(config_root)
    expected_ids = {key.stable_id for key in expected}
    execution_sha256 = sha256_file(execution_manifest_path)
    config_hashes = {
        attack_id: sha256_file(config_root / f"{attack_id.lower()}.json")
        for attack_id in AMENDED_ATTACKS
    }

    observed: dict[str, dict[str, Any]] = {}
    statuses: dict[str, Counter[str]] = {}
    for path in sorted(shards_root.glob("**/raw/**/*.json")):
        record = _load_record(path)
        run_key = record.get("run_key")
        if not isinstance(run_key, str):
            raise ValueError(f"record lacks RunKey: {path}")
        if run_key in observed:
            raise RuntimeError(f"duplicate amendment RunKey: {run_key}")
        if run_key not in expected_ids:
            raise RuntimeError(f"unexpected amendment RunKey: {run_key}")
        if record.get("schema") != "sigma-v3-r15-record-v2":
            raise ValueError("unexpected confirmatory record schema")
        if record.get("phase") != "confirmatory":
            raise ValueError("amendment record is not confirmatory")
        attack_id = record.get("attack_id")
        if attack_id not in AMENDED_ATTACKS:
            raise ValueError("amendment record has unexpected attack")
        if record.get("code_commit") != execution.get("source_commit"):
            raise ValueError("amendment record source commit mismatch")
        if record.get("artifact_sha256") != execution.get("artifact_sha256"):
            raise ValueError("amendment record artifact hash mismatch")
        if record.get("execution_manifest_sha256") != execution_sha256:
            raise ValueError("amendment record manifest hash mismatch")
        if record.get("preregistration_sha256") != execution.get("preregistration_sha256"):
            raise ValueError("amendment preregistration hash mismatch")
        if record.get("dependency_lock_sha256") != execution.get("dependency_lock_sha256"):
            raise ValueError("amendment dependency-lock hash mismatch")
        if record.get("config_sha256") != config_hashes[str(attack_id)]:
            raise ValueError("amendment config hash mismatch")
        observed[run_key] = record
        status = str(record.get("status"))
        statuses.setdefault(str(attack_id), Counter())[status] += 1

    observed_ids = set(observed)
    missing = expected_ids - observed_ids
    extra = observed_ids - expected_ids
    if missing or extra:
        raise RuntimeError(
            f"amendment coverage mismatch: missing={len(missing)}, extra={len(extra)}"
        )

    output_root.mkdir(parents=True, exist_ok=True)
    merged_keys: list[RunKeyV3] = []
    for key in expected:
        atomic_write_record_v3(output_root, key, observed[key.stable_id])
        merged_keys.append(key)

    ledger = build_ledger_v3(output_root, merged_keys)
    (output_root / "internal-amendment-ledger.json").write_bytes(canonical_json(ledger) + b"\n")
    summary = {
        "schema": "sigma-v3-r15-internal-amendment-dataset-v1",
        "confirmatory": True,
        "amendment_id": execution["amendment_id"],
        "base_source_commit": execution["base_source_commit"],
        "source_commit": execution["source_commit"],
        "execution_manifest_sha256": execution_sha256,
        "expected_run_units": len(expected),
        "observed_run_units": len(observed),
        "attacks": list(AMENDED_ATTACKS),
        "statuses": {
            attack_id: dict(sorted(counter.items()))
            for attack_id, counter in sorted(statuses.items())
        },
        "ledger_root": ledger["root_sha256"],
        "passed": True,
    }
    (output_root / "internal-amendment-summary.json").write_bytes(canonical_json(summary) + b"\n")
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
        report = audit_and_merge_amendment(
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


__all__ = [
    "AMENDMENT_EXPECTED_RUN_UNITS",
    "audit_and_merge_amendment",
    "expected_amendment_runkeys",
    "main",
]


if __name__ == "__main__":
    raise SystemExit(main())
