from __future__ import annotations

import pytest

from experiments.r13_schema import (
    AttackRunRecord,
    AttackRunStatus,
    ResourceBudget,
)


def _budget(**changes: int) -> ResourceBudget:
    values = {
        "W": 100,
        "Q_A": 10,
        "Q_J": 10,
        "Q_H": 30,
        "Q_R": 40,
        "d": 8,
        "p": 1,
        "mu": 1024,
        "u": 1,
    }
    values.update(changes)
    return ResourceBudget(**values)


def test_resource_budget_requires_nonnegative_resources_and_positive_p_u() -> None:
    _budget()
    with pytest.raises(ValueError):
        _budget(W=-1)
    with pytest.raises(ValueError):
        _budget(p=0)
    with pytest.raises(TypeError):
        ResourceBudget(True, 0, 0, 0, 0, 0, 1, 0, 1)


def test_attack_record_serialization_is_canonical_and_keeps_null_result_separate() -> None:
    record = AttackRunRecord.create(
        attack_id="HIST-01",
        construction="r12.5-reduced",
        seed_label="seed-001",
        status=AttackRunStatus.NO_SUCCESS,
        budget=_budget(),
        observed=_budget(W=80, Q_H=25, Q_R=35),
        metrics={"crossings": 0, "best_run": None},
    )
    assert '"status":"no-success"' in record.to_json()
    assert record.to_json() == record.to_json()


def test_censoring_and_errors_are_not_encoded_as_no_success() -> None:
    with pytest.raises(ValueError, match="censor_reason"):
        AttackRunRecord.create(
            attack_id="HIST-01",
            construction="r12.5-reduced",
            seed_label="seed",
            status=AttackRunStatus.CENSORED,
            budget=_budget(),
            observed=_budget(W=50),
            metrics={},
        )
    with pytest.raises(ValueError, match="error_class"):
        AttackRunRecord.create(
            attack_id="HIST-01",
            construction="r12.5-reduced",
            seed_label="seed",
            status=AttackRunStatus.ERROR,
            budget=_budget(),
            observed=_budget(W=1),
            metrics={},
        )


def test_observed_resources_cannot_exceed_preregistered_budget() -> None:
    with pytest.raises(ValueError, match="exceed"):
        AttackRunRecord.create(
            attack_id="HIST-01",
            construction="r12.5-reduced",
            seed_label="seed",
            status=AttackRunStatus.NO_SUCCESS,
            budget=_budget(),
            observed=_budget(W=101),
            metrics={},
        )


def test_unknown_attack_identifier_is_rejected() -> None:
    with pytest.raises(ValueError, match="unknown R13 attack"):
        AttackRunRecord.create(
            attack_id="UNKNOWN-00",
            construction="x",
            seed_label="seed",
            status=AttackRunStatus.NO_SUCCESS,
            budget=_budget(),
            observed=_budget(),
            metrics={},
        )
