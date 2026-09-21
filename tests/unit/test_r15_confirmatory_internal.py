from __future__ import annotations

from experiments.r13_schema import ResourceBudget
from experiments.r15_confirmatory_internal import execute_internal_run


def test_internal_runner_executes_hist01b_fixture_without_confirmatory_seed() -> None:
    declared = ResourceBudget(128, 0, 0, 32, 64, 64, 1, 16, 1)
    outcome = execute_internal_run(
        "HIST-01",
        {
            "mode": "conditional-crossing",
            "state_bits": 6,
            "history_bits": 6,
            "round_index": 1,
            "trials_per_batch": 16,
        },
        declared,
        b"synthetic-r15-runner-hist01b",
    )
    assert outcome.status == "success"
    assert outcome.metrics["trials"] == 16
    rate = outcome.metrics["next_state_match_rate"]
    assert isinstance(rate, float) and 0.0 <= rate <= 1.0


def test_internal_runner_executes_param03_fixture_without_confirmatory_seed() -> None:
    declared = ResourceBudget(128, 32, 32, 0, 0, 1, 1, 0, 1)
    outcome = execute_internal_run(
        "PARAM-03",
        {"candidate_budget": 32, "cost": "t+k-1"},
        declared,
        b"synthetic-r15-runner-param03",
    )
    assert outcome.status == "success"
    ratio = outcome.metrics["net_work_ratio"]
    assert isinstance(ratio, float) and ratio > 0.0
    assert outcome.observed.W <= declared.W
