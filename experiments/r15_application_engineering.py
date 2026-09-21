"""Exploratory engineering acquisition for PARAM-04/05/06.

These measurements are intentionally outside the R15 confirmatory namespace.
They are environment-specific implementation/application observations and do
not count toward R15 PASS or core security claims.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import platform
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from sigma.applications.kdf_argon2id_v3 import Argon2idParametersV3
from sigma.applications.pow_v3 import PowParametersV3, pow_input_v3
from sigma.binding.parameters import derive_trajectory_parameters
from sigma.binding.prepare import prepare_binding_v3
from sigma.sources import BytesSource
from sigma.spec.ids_v3 import SuiteIdV3

from .common import canonical_json
from .r15_application_campaigns import (
    mitigation_cost_profile_v3,
    profile_pow_nonce_selection_v3,
    run_kdf_campaign_mode_v3,
)
from .r15_data import RunKeyV3, atomic_write_record_v3, build_ledger_v3

ENGINEERING_NAMESPACE = "sigma-v3-r15-exploratory-engineering-v1"
ENGINEERING_CLASSIFICATION = "exploratory-engineering"
ENGINEERING_ATTACKS = ("PARAM-04", "PARAM-05", "PARAM-06")

PARAM04_REPLICATES = 16
PARAM04_GUESSES = 32
PARAM05_REPLICATES_PER_BUDGET = 16
PARAM05_NONCE_BUDGETS = (128, 512)
PARAM06_REPLICATES = 16
PARAM06_SAMPLES = 512
EXPECTED_RECORDS = 64


@dataclass(frozen=True)
class EngineeringResult:
    attack_id: str
    cell_id: str
    replicate_id: int
    metrics: dict[str, int | float | str | bool | None]


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _seed(attack_id: str, cell_id: str, replicate_id: int) -> bytes:
    fields = (
        ENGINEERING_NAMESPACE.encode("ascii"),
        attack_id.encode("ascii"),
        cell_id.encode("ascii"),
        replicate_id.to_bytes(8, "big"),
    )
    framed = b"".join(len(field).to_bytes(4, "big") + field for field in fields)
    return hashlib.sha256(framed).digest()


def _bytes(seed: bytes, label: bytes, index: int = 0) -> bytes:
    return hashlib.sha256(seed + b"\0" + label + index.to_bytes(8, "big")).digest()


def _pow_costs(
    *,
    payload: bytes,
    parameters: PowParametersV3,
    nonce_start: int,
    samples: int,
) -> tuple[int, ...]:
    context = parameters.context()
    values: list[int] = []
    for offset in range(samples):
        nonce = nonce_start + offset
        binding = prepare_binding_v3(
            context,
            BytesSource(pow_input_v3(payload, nonce)),
        )
        trajectory = derive_trajectory_parameters(context, binding)
        values.append(trajectory.target_round + trajectory.state_count - 1)
    return tuple(values)


def _param04(replicate_id: int) -> EngineeringResult:
    attack_id = "PARAM-04"
    cell_id = "param-04-engineering"
    seed = _seed(attack_id, cell_id, replicate_id)
    parameters = Argon2idParametersV3(
        memory_kib=19_456,
        time_cost=2,
        parallelism=1,
        output_length=32,
        suite_id=SuiteIdV3.REFERENCE_IAP_HISTORY_V3,
    )
    salt = _bytes(seed, b"salt")[:16]
    target = _bytes(seed, b"target")
    guesses = tuple(_bytes(seed, b"guess", index) for index in range(PARAM04_GUESSES))

    argon = run_kdf_campaign_mode_v3(
        guesses,
        target_password=target,
        salt=salt,
        parameters=parameters,
        mode="argon2id",
    )
    full = run_kdf_campaign_mode_v3(
        guesses,
        target_password=target,
        salt=salt,
        parameters=parameters,
        mode="full-sigma",
    )
    early = run_kdf_campaign_mode_v3(
        guesses,
        target_password=target,
        salt=salt,
        parameters=parameters,
        mode="early-reject-sigma",
    )
    return EngineeringResult(
        attack_id,
        cell_id,
        replicate_id,
        {
            "guesses": PARAM04_GUESSES,
            "argon_work_per_guess_ns": argon.work_per_guess_ns,
            "full_sigma_work_per_guess_ns": full.work_per_guess_ns,
            "early_reject_work_per_guess_ns": early.work_per_guess_ns,
            "full_vs_argon_ratio": full.work_per_guess_ns / max(1.0, argon.work_per_guess_ns),
            "early_vs_full_ratio": early.work_per_guess_ns / max(1.0, full.work_per_guess_ns),
            "early_reject_rate": early.early_reject_rate,
            "early_full_sigma_guesses": early.full_sigma_guesses,
            "argon_total_ns": argon.total_ns,
            "full_total_ns": full.total_ns,
            "early_total_ns": early.total_ns,
        },
    )


def _param05(replicate_id: int, nonce_budget: int) -> EngineeringResult:
    attack_id = "PARAM-05"
    cell_id = f"param-05-nonces-{nonce_budget}"
    seed = _seed(attack_id, cell_id, replicate_id)
    parameters = PowParametersV3(
        challenge=_bytes(seed, b"challenge"),
        difficulty_bits=0,
        suite_id=SuiteIdV3.REFERENCE_IAP_HISTORY_V3,
    )
    payload = _bytes(seed, b"payload")
    nonce_start = replicate_id * 1_000_000
    result = profile_pow_nonce_selection_v3(
        payload,
        nonce_start=nonce_start,
        nonces=nonce_budget,
        parameters=parameters,
    )
    return EngineeringResult(
        attack_id,
        cell_id,
        replicate_id,
        {
            "nonces": nonce_budget,
            "selected_nonce": result.selected_nonce,
            "selected_cost": result.selected_cost,
            "mean_cost": result.mean_cost,
            "preparation_ns": result.preparation_ns,
            "selected_evaluation_ns": result.selected_evaluation_ns,
            "selection_total_ns": result.selection_total_ns,
            "full_evaluation_ns": result.full_evaluation_ns,
            "full_vs_selection_ratio": result.full_evaluation_ns / max(1, result.selection_total_ns),
        },
    )


def _param06(replicate_id: int) -> EngineeringResult:
    attack_id = "PARAM-06"
    cell_id = "param-06-engineering"
    seed = _seed(attack_id, cell_id, replicate_id)
    parameters = PowParametersV3(
        challenge=_bytes(seed, b"challenge"),
        difficulty_bits=0,
        suite_id=SuiteIdV3.REFERENCE_IAP_HISTORY_V3,
    )
    payload = _bytes(seed, b"payload")
    nonce_start = replicate_id * 1_000_000
    started = time.perf_counter_ns()
    costs = _pow_costs(
        payload=payload,
        parameters=parameters,
        nonce_start=nonce_start,
        samples=PARAM06_SAMPLES,
    )
    derivation_ns = time.perf_counter_ns() - started

    derived = mitigation_cost_profile_v3(costs, mode="input-derived")
    fixed = mitigation_cost_profile_v3(costs, mode="context-fixed")
    bucketed = mitigation_cost_profile_v3(costs, mode="cost-bucketed")
    return EngineeringResult(
        attack_id,
        cell_id,
        replicate_id,
        {
            "samples": PARAM06_SAMPLES,
            "derivation_ns": derivation_ns,
            "input_derived_mean": derived.mean_cost,
            "input_derived_variance": derived.variance,
            "context_fixed_mean": fixed.mean_cost,
            "context_fixed_variance": fixed.variance,
            "cost_bucketed_mean": bucketed.mean_cost,
            "cost_bucketed_variance": bucketed.variance,
            "fixed_vs_derived_ratio": fixed.mean_cost / derived.mean_cost,
            "bucketed_vs_derived_ratio": bucketed.mean_cost / derived.mean_cost,
            "derived_minimum": derived.minimum,
            "derived_maximum": derived.maximum,
        },
    )


def _specs(attack_id: str) -> tuple[tuple[str, int, dict[str, int]], ...]:
    if attack_id == "PARAM-04":
        return tuple(
            ("param-04-engineering", replicate, {})
            for replicate in range(PARAM04_REPLICATES)
        )
    if attack_id == "PARAM-05":
        return tuple(
            (f"param-05-nonces-{budget}", replicate, {"nonce_budget": budget})
            for budget in PARAM05_NONCE_BUDGETS
            for replicate in range(PARAM05_REPLICATES_PER_BUDGET)
        )
    if attack_id == "PARAM-06":
        return tuple(
            ("param-06-engineering", replicate, {})
            for replicate in range(PARAM06_REPLICATES)
        )
    raise ValueError("unsupported exploratory engineering attack")


def expected_engineering_runkeys() -> tuple[RunKeyV3, ...]:
    keys: list[RunKeyV3] = []
    for attack_id in ENGINEERING_ATTACKS:
        for cell_id, replicate_id, _factors in _specs(attack_id):
            keys.append(
                RunKeyV3(
                    ENGINEERING_NAMESPACE,
                    attack_id,
                    cell_id,
                    replicate_id,
                )
            )
    if len(keys) != EXPECTED_RECORDS:
        raise RuntimeError("exploratory engineering record cardinality drifted")
    if len(keys) != len(set(keys)):
        raise RuntimeError("duplicate exploratory engineering RunKeys")
    return tuple(sorted(keys))


def _execute(attack_id: str, replicate_id: int, factors: dict[str, int]) -> EngineeringResult:
    if attack_id == "PARAM-04":
        return _param04(replicate_id)
    if attack_id == "PARAM-05":
        return _param05(replicate_id, int(factors["nonce_budget"]))
    if attack_id == "PARAM-06":
        return _param06(replicate_id)
    raise ValueError("unsupported exploratory engineering attack")


def run_engineering_shard(
    *,
    attack_id: str,
    shard_index: int,
    shard_count: int,
    output_root: Path,
    controller_commit: str,
) -> dict[str, object]:
    if attack_id not in ENGINEERING_ATTACKS:
        raise ValueError("attack is not exploratory engineering")
    if shard_count <= 0 or not 0 <= shard_index < shard_count:
        raise ValueError("invalid shard index/count")
    if len(controller_commit) != 40:
        raise ValueError("controller_commit must be a 40-character Git commit")

    selected = [
        item
        for ordinal, item in enumerate(_specs(attack_id))
        if ordinal % shard_count == shard_index
    ]
    keys: list[RunKeyV3] = []
    for cell_id, replicate_id, factors in selected:
        started = _utc_now()
        result = _execute(attack_id, replicate_id, factors)
        completed = _utc_now()
        key = RunKeyV3(
            ENGINEERING_NAMESPACE,
            result.attack_id,
            result.cell_id,
            result.replicate_id,
        )
        record: dict[str, Any] = {
            "schema": "sigma-v3-r15-exploratory-engineering-record-v1",
            "namespace": ENGINEERING_NAMESPACE,
            "classification": ENGINEERING_CLASSIFICATION,
            "confirmatory": False,
            "counts_toward_r15_pass": False,
            "counts_toward_core_security_claims": False,
            "run_key": key.stable_id,
            "attack_id": result.attack_id,
            "cell_id": result.cell_id,
            "replicate_id": result.replicate_id,
            "controller_commit": controller_commit,
            "platform_name": platform.system(),
            "architecture": platform.machine(),
            "python_version": platform.python_version(),
            "runner_note": "GitHub-hosted runner; environment-specific engineering evidence only",
            "started_utc": started,
            "completed_utc": completed,
            "metrics": result.metrics,
        }
        atomic_write_record_v3(output_root, key, record)
        keys.append(key)

    ledger = build_ledger_v3(output_root, keys)
    return {
        "schema": "sigma-v3-r15-exploratory-engineering-shard-v1",
        "classification": ENGINEERING_CLASSIFICATION,
        "confirmatory": False,
        "attack_id": attack_id,
        "shard_index": shard_index,
        "shard_count": shard_count,
        "written_records": len(keys),
        "ledger_root": ledger["root_sha256"],
    }





def _receipt_for_record(record_path: Path) -> Path:
    parts = record_path.parts
    try:
        raw_index = parts.index("raw")
    except ValueError as exc:
        raise ValueError("engineering record path is not below raw/") from exc
    root = Path(*parts[:raw_index])
    relative = Path(*parts[raw_index + 1 :])
    return root / "receipts" / relative


def _load_engineering_record(record_path: Path) -> dict[str, Any]:
    data = record_path.read_bytes()
    digest = hashlib.sha256(data).hexdigest()
    value = json.loads(data)
    if not isinstance(value, dict):
        raise ValueError("engineering record must be an object")
    receipt_path = _receipt_for_record(record_path)
    if not receipt_path.is_file():
        raise ValueError(f"missing engineering receipt for {record_path}")
    receipt = json.loads(receipt_path.read_text(encoding="utf-8"))
    if receipt.get("record_sha256") != digest:
        raise ValueError(f"engineering receipt digest mismatch for {record_path}")
    if receipt.get("run_key") != value.get("run_key"):
        raise ValueError(f"engineering receipt RunKey mismatch for {record_path}")
    return value


def audit_engineering_dataset(
    *,
    shards_root: Path,
    output_root: Path,
) -> dict[str, object]:
    expected = expected_engineering_runkeys()
    expected_ids = {key.stable_id for key in expected}
    records: dict[str, dict[str, Any]] = {}
    for path in sorted(shards_root.glob("**/raw/**/*.json")):
        value = _load_engineering_record(path)
        run_key = value.get("run_key")
        if not isinstance(run_key, str):
            raise ValueError("engineering record lacks RunKey")
        if run_key in records:
            raise RuntimeError(f"duplicate engineering RunKey: {run_key}")
        if run_key not in expected_ids:
            raise RuntimeError(f"unexpected engineering RunKey: {run_key}")
        if value.get("classification") != ENGINEERING_CLASSIFICATION:
            raise ValueError("engineering record classification mismatch")
        if value.get("confirmatory") is not False:
            raise ValueError("engineering record incorrectly marked confirmatory")
        if value.get("counts_toward_r15_pass") is not False:
            raise ValueError("engineering record incorrectly counts toward R15 PASS")
        records[run_key] = value

    observed_ids = set(records)
    if observed_ids != expected_ids:
        raise RuntimeError(
            f"engineering coverage mismatch: missing={len(expected_ids-observed_ids)}, "
            f"extra={len(observed_ids-expected_ids)}"
        )

    output_root.mkdir(parents=True, exist_ok=True)
    merged: list[RunKeyV3] = []
    for key in expected:
        atomic_write_record_v3(output_root, key, records[key.stable_id])
        merged.append(key)
    ledger = build_ledger_v3(output_root, merged)
    (output_root / "engineering-ledger.json").write_bytes(canonical_json(ledger) + b"\n")
    summary = {
        "schema": "sigma-v3-r15-exploratory-engineering-dataset-v1",
        "classification": ENGINEERING_CLASSIFICATION,
        "confirmatory": False,
        "counts_toward_r15_pass": False,
        "expected_records": EXPECTED_RECORDS,
        "observed_records": len(records),
        "attacks": list(ENGINEERING_ATTACKS),
        "ledger_root": ledger["root_sha256"],
        "passed": True,
    }
    (output_root / "engineering-summary.json").write_bytes(canonical_json(summary) + b"\n")
    return summary


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="command", required=True)

    run_parser = subparsers.add_parser("run")
    run_parser.add_argument("--attack", choices=ENGINEERING_ATTACKS, required=True)
    run_parser.add_argument("--shard-index", type=int, required=True)
    run_parser.add_argument("--shard-count", type=int, required=True)
    run_parser.add_argument("--output", type=Path, required=True)
    run_parser.add_argument("--controller-commit", required=True)
    run_parser.add_argument("--report", type=Path)

    audit_parser = subparsers.add_parser("audit")
    audit_parser.add_argument("--shards", type=Path, required=True)
    audit_parser.add_argument("--output", type=Path, required=True)
    audit_parser.add_argument("--report", type=Path)

    args = parser.parse_args()
    try:
        if args.command == "run":
            report = run_engineering_shard(
                attack_id=args.attack,
                shard_index=args.shard_index,
                shard_count=args.shard_count,
                output_root=args.output,
                controller_commit=args.controller_commit,
            )
        else:
            report = audit_engineering_dataset(
                shards_root=args.shards,
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
