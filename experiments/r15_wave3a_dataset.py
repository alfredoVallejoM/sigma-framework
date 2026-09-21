"""Merge and audit R15 internal Wave 3A reduced-cryptanalysis shards.

RED-04 is deliberately excluded because a pre-execution implementation defect
was detected in the frozen confirmatory runner. No RED-04 confirmatory seed is
consumed by Wave 3A.
"""

from __future__ import annotations

import argparse
import hashlib
import json
from collections import Counter
from pathlib import Path
from typing import Any

from .common import canonical_json, sha256_file
from .r15_data import RunKeyV3, atomic_write_record_v3, build_ledger_v3

WAVE3A_SPECS: tuple[tuple[str, dict[str, str]], ...] = (
    ("RED-02", {}),
    ("RED-03", {}),
    ("RED-05", {}),
    ("TMTO-01", {}),
    ("TMTO-02", {}),
)
WAVE3A_EXPECTED_RUN_UNITS = 74_240


def expected_wave3a_runkeys(config_root: Path) -> tuple[RunKeyV3, ...]:
    keys: list[RunKeyV3] = []
    for attack_id, _filters in WAVE3A_SPECS:
        path = config_root / f"{attack_id.lower()}.json"
        if not path.is_file():
            raise ValueError(f"missing Wave 3A config: {path.name}")
        config = json.loads(path.read_text(encoding="utf-8"))
        if config.get("attack_id") != attack_id:
            raise ValueError(f"Wave 3A config attack mismatch: {path.name}")
        freeze_id = config.get("freeze_id")
        if not isinstance(freeze_id, str) or not freeze_id:
            raise ValueError("Wave 3A config has invalid freeze_id")
        for cell in config["cells"]:
            for replicate_id in range(int(cell["replicates"])):
                keys.append(
                    RunKeyV3(
                        freeze_id,
                        attack_id,
                        str(cell["cell_id"]),
                        replicate_id,
                    )
                )
    if len(keys) != WAVE3A_EXPECTED_RUN_UNITS:
        raise RuntimeError(
            f"Wave 3A expected-run cardinality drifted: {len(keys)} != {WAVE3A_EXPECTED_RUN_UNITS}"
        )
    if len(keys) != len(set(keys)):
        raise RuntimeError("Wave 3A expected RunKeys contain duplicates")
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


def audit_and_merge_wave3a(
    *,
    shards_root: Path,
    config_root: Path,
    execution_manifest_path: Path,
    output_root: Path,
    controller_commit: str,
) -> dict[str, object]:
    execution = json.loads(execution_manifest_path.read_text(encoding="utf-8"))
    if execution.get("schema") != "sigma-v3-r15-execution-manifest-v2":
        raise ValueError("unexpected execution manifest schema")
    if execution.get("scope") not in ("internal", "full"):
        raise ValueError("Wave 3A requires internal/full execution scope")
    authorized = execution.get("authorized_attacks")
    if not isinstance(authorized, list):
        raise ValueError("execution manifest authorized_attacks is invalid")
    required_attacks = {attack_id for attack_id, _filters in WAVE3A_SPECS}
    if "RED-04" in required_attacks:
        raise RuntimeError("Wave 3A must never include RED-04")
    if not required_attacks.issubset(set(authorized)):
        raise ValueError("execution manifest does not authorize all Wave 3A attacks")
    if len(controller_commit) != 40 or any(
        ch not in "0123456789abcdef" for ch in controller_commit
    ):
        raise ValueError("controller_commit must be a lowercase 40-hex Git commit")

    expected = expected_wave3a_runkeys(config_root)
    expected_ids = {key.stable_id for key in expected}
    execution_sha256 = sha256_file(execution_manifest_path)
    config_hashes = {
        attack_id: sha256_file(config_root / f"{attack_id.lower()}.json")
        for attack_id in required_attacks
    }

    record_paths = sorted(shards_root.glob("**/raw/**/*.json"))
    observed: dict[str, dict[str, Any]] = {}
    statuses: dict[str, Counter[str]] = {}

    for path in record_paths:
        record = _load_record(path)
        run_key = record.get("run_key")
        if not isinstance(run_key, str):
            raise ValueError(f"record lacks RunKey: {path}")
        if run_key in observed:
            raise RuntimeError(f"duplicate observed RunKey: {run_key}")
        if run_key not in expected_ids:
            raise RuntimeError(f"unexpected Wave 3A RunKey: {run_key}")
        if record.get("schema") != "sigma-v3-r15-record-v2":
            raise ValueError("unexpected confirmatory record schema")
        if record.get("phase") != "confirmatory":
            raise ValueError("Wave 3A record is not confirmatory")
        attack_id = record.get("attack_id")
        if attack_id not in required_attacks:
            raise ValueError("Wave 3A record has unexpected attack_id")
        if record.get("code_commit") != execution.get("source_commit"):
            raise ValueError("Wave 3A record source commit mismatch")
        if record.get("artifact_sha256") != execution.get("artifact_sha256"):
            raise ValueError("Wave 3A record artifact hash mismatch")
        if record.get("execution_manifest_sha256") != execution_sha256:
            raise ValueError("Wave 3A execution-manifest hash mismatch")
        if record.get("preregistration_sha256") != execution.get("preregistration_sha256"):
            raise ValueError("Wave 3A preregistration hash mismatch")
        if record.get("dependency_lock_sha256") != execution.get("dependency_lock_sha256"):
            raise ValueError("Wave 3A dependency-lock hash mismatch")
        if record.get("config_sha256") != config_hashes[str(attack_id)]:
            raise ValueError("Wave 3A config hash mismatch")
        observed[run_key] = record
        status = str(record.get("status"))
        statuses.setdefault(str(attack_id), Counter())[status] += 1

    observed_ids = set(observed)
    missing = expected_ids - observed_ids
    extra = observed_ids - expected_ids
    if missing or extra:
        raise RuntimeError(f"Wave 3A coverage mismatch: missing={len(missing)}, extra={len(extra)}")

    output_root.mkdir(parents=True, exist_ok=True)
    merged_keys: list[RunKeyV3] = []
    for key in expected:
        atomic_write_record_v3(output_root, key, observed[key.stable_id])
        merged_keys.append(key)

    ledger = build_ledger_v3(output_root, merged_keys)
    (output_root / "wave3a-ledger.json").write_bytes(canonical_json(ledger) + b"\n")
    summary = {
        "schema": "sigma-v3-r15-wave3a-dataset-v1",
        "confirmatory": True,
        "source_commit": execution["source_commit"],
        "controller_commit": controller_commit,
        "execution_manifest_sha256": execution_sha256,
        "expected_run_units": len(expected),
        "observed_run_units": len(observed),
        "attacks": sorted(required_attacks),
        "excluded_attack": "RED-04",
        "excluded_reason": "pre-execution-confirmatory-runner-defect",
        "statuses": {
            attack_id: dict(sorted(counter.items()))
            for attack_id, counter in sorted(statuses.items())
        },
        "ledger_root": ledger["root_sha256"],
        "passed": True,
    }
    (output_root / "wave3a-summary.json").write_bytes(canonical_json(summary) + b"\n")
    return summary


def main() -> int:
    parser = argparse.ArgumentParser(description="Audit and merge R15 Wave 3A shards.")
    parser.add_argument("--shards", type=Path, required=True)
    parser.add_argument("--configs", type=Path, required=True)
    parser.add_argument("--execution-manifest", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--controller-commit", required=True)
    parser.add_argument("--report", type=Path)
    args = parser.parse_args()
    try:
        report = audit_and_merge_wave3a(
            shards_root=args.shards,
            config_root=args.configs,
            execution_manifest_path=args.execution_manifest,
            output_root=args.output,
            controller_commit=args.controller_commit,
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
    "WAVE3A_EXPECTED_RUN_UNITS",
    "WAVE3A_SPECS",
    "audit_and_merge_wave3a",
    "expected_wave3a_runkeys",
    "main",
]


if __name__ == "__main__":
    raise SystemExit(main())
