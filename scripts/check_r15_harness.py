#!/usr/bin/env python3
"""Run the R15-B synthetic harness adversarial battery."""

from __future__ import annotations

import argparse
import json
import tempfile
from pathlib import Path

from experiments.r13_schema import ResourceBudget
from experiments.r15_data import RunKeyV3, record_path_v3
from experiments.r15_harness import (
    HARNESS_NAMESPACE,
    RetryPolicyV3,
    SyntheticCrash,
    derive_harness_seed_v3,
    read_checkpoint_v3,
    run_synthetic_task_v3,
    validate_harness_seed_v3,
    validate_observed_budget_v3,
    verify_harness_record_v3,
    write_harness_record_v3,
)


def check_r15_harness() -> dict[str, object]:
    checks: dict[str, bool] = {}

    with tempfile.TemporaryDirectory(prefix="sigma-r15-harness-") as temporary:
        root = Path(temporary)
        key = RunKeyV3("synthetic-r15b", "HARNESS", "fixture-000", 0)
        checkpoint = root / "checkpoint.json"

        baseline = run_synthetic_task_v3(key, total_steps=64)
        try:
            run_synthetic_task_v3(
                key,
                total_steps=64,
                checkpoint_path=checkpoint,
                checkpoint_interval=8,
                crash_after_step=23,
            )
        except SyntheticCrash:
            checks["crash_observed"] = True
        else:
            checks["crash_observed"] = False

        resumed = run_synthetic_task_v3(
            key,
            total_steps=64,
            checkpoint_path=checkpoint,
            checkpoint_interval=8,
            resume=True,
        )
        checks["resume_equivalent"] = (
            resumed.status == "success"
            and resumed.final_state_hex == baseline.final_state_hex
            and resumed.steps_completed == baseline.steps_completed
        )

        timeout_key = RunKeyV3("synthetic-r15b", "HARNESS", "fixture-timeout", 0)
        timeout = run_synthetic_task_v3(
            timeout_key,
            total_steps=64,
            checkpoint_path=root / "timeout-checkpoint.json",
            timeout_after_steps=7,
        )
        checks["timeout_distinct"] = timeout.status == "timeout" and timeout.steps_completed == 7

        seed = derive_harness_seed_v3(key).hex()
        try:
            validate_harness_seed_v3(key, "00" * 32)
        except ValueError:
            checks["wrong_seed_rejected"] = True
        else:
            checks["wrong_seed_rejected"] = False
        validate_harness_seed_v3(key, seed)

        declared = ResourceBudget(100, 10, 10, 10, 10, 10, 1, 1024, 1)
        observed = ResourceBudget(64, 5, 5, 5, 5, 5, 1, 512, 1)
        manifest_hash = "ab" * 32
        write_harness_record_v3(
            root,
            key,
            resumed,
            declared=declared,
            observed=observed,
            execution_manifest_sha256=manifest_hash,
        )

        try:
            write_harness_record_v3(
                root,
                key,
                resumed,
                declared=declared,
                observed=observed,
                execution_manifest_sha256=manifest_hash,
            )
        except FileExistsError:
            checks["duplicate_runkey_rejected"] = True
        else:
            checks["duplicate_runkey_rejected"] = False

        verify_harness_record_v3(
            root,
            key,
            execution_manifest_sha256=manifest_hash,
        )
        checks["record_integrity_initial"] = True

        path = record_path_v3(root, key)
        original = path.read_bytes()
        path.write_bytes(original.replace(b'"status":"success"', b'"status":"timeout"'))
        try:
            verify_harness_record_v3(
                root,
                key,
                execution_manifest_sha256=manifest_hash,
            )
        except ValueError:
            checks["record_tamper_rejected"] = True
        else:
            checks["record_tamper_rejected"] = False
        path.write_bytes(original)

        try:
            verify_harness_record_v3(
                root,
                key,
                execution_manifest_sha256="cd" * 32,
            )
        except ValueError:
            checks["wrong_manifest_rejected"] = True
        else:
            checks["wrong_manifest_rejected"] = False

        excessive = ResourceBudget(101, 10, 10, 10, 10, 10, 1, 1024, 1)
        try:
            validate_observed_budget_v3(declared, excessive)
        except ValueError:
            checks["budget_overflow_rejected"] = True
        else:
            checks["budget_overflow_rejected"] = False

        checkpoint_value = read_checkpoint_v3(checkpoint, key)
        raw_checkpoint = json.loads(checkpoint.read_text(encoding="utf-8"))
        raw_checkpoint["state_hex"] = "00" * 32
        checkpoint.write_text(json.dumps(raw_checkpoint), encoding="utf-8")
        try:
            read_checkpoint_v3(checkpoint, key)
        except ValueError:
            checks["checkpoint_tamper_rejected"] = True
        else:
            checks["checkpoint_tamper_rejected"] = False
        if checkpoint_value.next_step <= 0:
            raise RuntimeError("fixture checkpoint did not capture progress")

        retry = RetryPolicyV3(max_transient_retries=2)
        checks["retry_policy"] = (
            retry.may_retry("transient-infrastructure", 0)
            and retry.may_retry("transient-infrastructure", 1)
            and not retry.may_retry("transient-infrastructure", 2)
            and not retry.may_retry("semantic-protocol", 0)
        )

    failed = sorted(name for name, passed in checks.items() if not passed)
    if failed:
        raise RuntimeError(f"R15-B harness checks failed: {failed}")

    return {
        "schema": "sigma-v3-r15-harness-gate-v1",
        "namespace": HARNESS_NAMESPACE,
        "confirmatory": False,
        "checks": checks,
        "check_count": len(checks),
        "passed": True,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--report", type=Path)
    args = parser.parse_args()
    try:
        report = check_r15_harness()
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
