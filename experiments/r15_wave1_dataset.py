"""Merge and audit R15 internal Wave 1 confirmatory shards."""

from __future__ import annotations

import json
from collections import Counter
from pathlib import Path
from typing import Any

from .common import canonical_json, sha256_file
from .r15_data import RunKeyV3, atomic_write_record_v3, build_ledger_v3

WAVE1_SPECS: tuple[tuple[str, dict[str, str]], ...] = (
    ("HIST-01", {"mode": "conditional-crossing"}),
    ("PARAM-01", {}),
    ("PARAM-03", {}),
)
WAVE1_EXPECTED_RUN_UNITS = 8_256


def _matches(factors: dict[str, Any], filters: dict[str, str]) -> bool:
    return all(str(factors.get(key)) == value for key, value in filters.items())


def expected_wave1_runkeys(config_root: Path) -> tuple[RunKeyV3, ...]:
    keys: list[RunKeyV3] = []
    for attack_id, filters in WAVE1_SPECS:
        path = config_root / f"{attack_id.lower()}.json"
        if not path.is_file():
            raise ValueError(f"missing Wave 1 config: {path.name}")
        config = json.loads(path.read_text(encoding="utf-8"))
        if config.get("attack_id") != attack_id:
            raise ValueError(f"Wave 1 config attack mismatch: {path.name}")
        freeze_id = config.get("freeze_id")
        if not isinstance(freeze_id, str) or not freeze_id:
            raise ValueError("Wave 1 config has invalid freeze_id")
        for cell in config["cells"]:
            if not _matches(cell["factors"], filters):
                continue
            for replicate_id in range(int(cell["replicates"])):
                keys.append(
                    RunKeyV3(
                        freeze_id,
                        attack_id,
                        str(cell["cell_id"]),
                        replicate_id,
                    )
                )
    if len(keys) != WAVE1_EXPECTED_RUN_UNITS:
        raise RuntimeError(
            f"Wave 1 expected-run cardinality drifted: {len(keys)} "
            f"!= {WAVE1_EXPECTED_RUN_UNITS}"
        )
    if len(keys) != len(set(keys)):
        raise RuntimeError("Wave 1 expected RunKeys contain duplicates")
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


def _load_record(record_path: Path) -> tuple[dict[str, Any], str]:
    data = record_path.read_bytes()
    digest = __import__("hashlib").sha256(data).hexdigest()
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
    return value, digest


def audit_and_merge_wave1(
    *,
    shards_root: Path,
    config_root: Path,
    execution_manifest_path: Path,
    output_root: Path,
) -> dict[str, object]:
    execution = json.loads(execution_manifest_path.read_text(encoding="utf-8"))
    if execution.get("schema") != "sigma-v3-r15-execution-manifest-v2":
        raise ValueError("unexpected execution manifest schema")
    if execution.get("scope") not in ("internal", "full"):
        raise ValueError("Wave 1 requires internal/full execution scope")
    authorized = execution.get("authorized_attacks")
    if not isinstance(authorized, list):
        raise ValueError("execution manifest authorized_attacks is invalid")
    required_attacks = {attack_id for attack_id, _filters in WAVE1_SPECS}
    if not required_attacks.issubset(set(authorized)):
        raise ValueError("execution manifest does not authorize all Wave 1 attacks")

    expected = expected_wave1_runkeys(config_root)
    expected_ids = {key.stable_id for key in expected}
    execution_sha256 = sha256_file(execution_manifest_path)
    config_hashes = {
        attack_id: sha256_file(config_root / f"{attack_id.lower()}.json")
        for attack_id in required_attacks
    }

    record_paths = sorted(shards_root.glob("**/raw/**/*.json"))
    observed: dict[str, tuple[dict[str, Any], Path]] = {}
    statuses: dict[str, Counter[str]] = {}

    for path in record_paths:
        record, _digest = _load_record(path)
        run_key = record.get("run_key")
        if not isinstance(run_key, str):
            raise ValueError(f"record lacks RunKey: {path}")
        if run_key in observed:
            raise RuntimeError(f"duplicate observed RunKey: {run_key}")
        if run_key not in expected_ids:
            raise RuntimeError(f"unexpected Wave 1 RunKey: {run_key}")
        if record.get("schema") != "sigma-v3-r15-record-v2":
            raise ValueError("unexpected confirmatory record schema")
        if record.get("phase") != "confirmatory":
            raise ValueError("Wave 1 record is not confirmatory")
        attack_id = record.get("attack_id")
        if attack_id not in required_attacks:
            raise ValueError("Wave 1 record has unexpected attack_id")
        if record.get("code_commit") != execution.get("source_commit"):
            raise ValueError("Wave 1 record source commit mismatch")
        if record.get("artifact_sha256") != execution.get("artifact_sha256"):
            raise ValueError("Wave 1 record artifact hash mismatch")
        if record.get("execution_manifest_sha256") != execution_sha256:
            raise ValueError("Wave 1 record execution-manifest hash mismatch")
        if record.get("preregistration_sha256") != execution.get("preregistration_sha256"):
            raise ValueError("Wave 1 record preregistration hash mismatch")
        if record.get("dependency_lock_sha256") != execution.get("dependency_lock_sha256"):
            raise ValueError("Wave 1 record dependency-lock hash mismatch")
        if record.get("config_sha256") != config_hashes[str(attack_id)]:
            raise ValueError("Wave 1 record config hash mismatch")
        observed[run_key] = (record, path)
        status = str(record.get("status"))
        statuses.setdefault(str(attack_id), Counter())[status] += 1

    observed_ids = set(observed)
    missing = sorted(expected_ids - observed_ids)
    extra = sorted(observed_ids - expected_ids)
    if missing or extra:
        raise RuntimeError(
            f"Wave 1 coverage mismatch: missing={len(missing)}, extra={len(extra)}"
        )

    output_root.mkdir(parents=True, exist_ok=True)
    merged_keys: list[RunKeyV3] = []
    for key in expected:
        record, _source = observed[key.stable_id]
        atomic_write_record_v3(output_root, key, record)
        merged_keys.append(key)

    ledger = build_ledger_v3(output_root, merged_keys)
    ledger_path = output_root / "wave1-ledger.json"
    ledger_path.write_bytes(canonical_json(ledger) + b"\n")
    summary = {
        "schema": "sigma-v3-r15-wave1-dataset-v1",
        "confirmatory": True,
        "source_commit": execution["source_commit"],
        "execution_manifest_sha256": execution_sha256,
        "expected_run_units": len(expected),
        "observed_run_units": len(observed),
        "attacks": sorted(required_attacks),
        "statuses": {
            attack_id: dict(sorted(counter.items()))
            for attack_id, counter in sorted(statuses.items())
        },
        "ledger_root": ledger["root_sha256"],
        "passed": True,
    }
    (output_root / "wave1-summary.json").write_bytes(canonical_json(summary) + b"\n")
    return summary


__all__ = [
    "WAVE1_EXPECTED_RUN_UNITS",
    "WAVE1_SPECS",
    "audit_and_merge_wave1",
    "expected_wave1_runkeys",
]
