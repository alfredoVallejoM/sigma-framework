from __future__ import annotations

import json
from pathlib import Path

import pytest

from experiments.r13_schema import ResourceBudget
from experiments.r15_data import RunKeyV3
from experiments.r15_harness import (
    HARNESS_NAMESPACE,
    RetryPolicyV3,
    SyntheticCrash,
    derive_harness_seed_v3,
    read_checkpoint_v3,
    run_synthetic_task_v3,
    validate_harness_seed_v3,
    validate_observed_budget_v3,
)
from scripts.check_r15_harness import check_r15_harness


def test_r15_b_harness_gate_is_synthetic_and_complete() -> None:
    report = check_r15_harness()
    assert report["passed"] is True
    assert report["confirmatory"] is False
    assert report["namespace"] == HARNESS_NAMESPACE
    assert report["check_count"] >= 10
    checks = report["checks"]
    assert isinstance(checks, dict)
    assert all(checks.values())


def test_crash_resume_matches_uninterrupted_execution(tmp_path: Path) -> None:
    key = RunKeyV3("fixture", "HARNESS", "resume", 0)
    checkpoint = tmp_path / "checkpoint.json"
    baseline = run_synthetic_task_v3(key, total_steps=41)
    with pytest.raises(SyntheticCrash):
        run_synthetic_task_v3(
            key,
            total_steps=41,
            checkpoint_path=checkpoint,
            checkpoint_interval=5,
            crash_after_step=17,
        )
    resumed = run_synthetic_task_v3(
        key,
        total_steps=41,
        checkpoint_path=checkpoint,
        checkpoint_interval=5,
        resume=True,
    )
    assert resumed.final_state_hex == baseline.final_state_hex
    assert resumed.steps_completed == 41
    assert resumed.resumed is True


def test_timeout_is_terminal_and_checkpointed(tmp_path: Path) -> None:
    key = RunKeyV3("fixture", "HARNESS", "timeout", 0)
    checkpoint = tmp_path / "checkpoint.json"
    outcome = run_synthetic_task_v3(
        key,
        total_steps=50,
        checkpoint_path=checkpoint,
        timeout_after_steps=11,
    )
    assert outcome.status == "timeout"
    assert outcome.steps_completed == 11
    stored = read_checkpoint_v3(checkpoint, key)
    assert stored.next_step == 11


def test_wrong_harness_seed_is_rejected() -> None:
    key = RunKeyV3("fixture", "HARNESS", "seed", 0)
    good = derive_harness_seed_v3(key).hex()
    validate_harness_seed_v3(key, good)
    with pytest.raises(ValueError, match="seed mismatch"):
        validate_harness_seed_v3(key, "ff" * 32)


def test_budget_overflow_is_rejected() -> None:
    declared = ResourceBudget(10, 1, 1, 1, 1, 1, 1, 10, 1)
    valid = ResourceBudget(9, 1, 1, 1, 1, 1, 1, 9, 1)
    validate_observed_budget_v3(declared, valid)
    invalid = ResourceBudget(11, 1, 1, 1, 1, 1, 1, 9, 1)
    with pytest.raises(ValueError, match="exceeds"):
        validate_observed_budget_v3(declared, invalid)


def test_retry_policy_only_retries_transient_errors() -> None:
    policy = RetryPolicyV3(2)
    assert policy.may_retry("transient-infrastructure", 0)
    assert policy.may_retry("transient-infrastructure", 1)
    assert not policy.may_retry("transient-infrastructure", 2)
    assert not policy.may_retry("semantic-protocol", 0)


def test_checkpoint_integrity_rejects_mutation(tmp_path: Path) -> None:
    key = RunKeyV3("fixture", "HARNESS", "checkpoint", 0)
    checkpoint = tmp_path / "checkpoint.json"
    with pytest.raises(SyntheticCrash):
        run_synthetic_task_v3(
            key,
            total_steps=20,
            checkpoint_path=checkpoint,
            checkpoint_interval=2,
            crash_after_step=6,
        )
    value = json.loads(checkpoint.read_text(encoding="utf-8"))
    value["next_step"] = 7
    checkpoint.write_text(json.dumps(value), encoding="utf-8")
    with pytest.raises(ValueError, match="integrity"):
        read_checkpoint_v3(checkpoint, key)
