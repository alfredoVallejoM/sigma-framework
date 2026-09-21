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


def test_internal_runner_executes_red02_fixture() -> None:
    declared = ResourceBudget(256, 256, 0, 256, 256, 256, 1, 256, 1)
    outcome = execute_internal_run(
        "RED-02",
        {
            "construction": "r125",
            "state_bits": 4,
            "history_bits": 4,
            "state_count": 1,
            "target_round": 2,
            "max_candidates": 64,
        },
        declared,
        b"synthetic-r15-runner-red02",
    )
    assert outcome.status in ("success", "censored")
    queries = outcome.metrics["queries_to_first_window_collision"]
    assert isinstance(queries, int) and 1 <= queries <= 64


def test_internal_runner_executes_red04_fixture() -> None:
    declared = ResourceBudget(128, 128, 0, 128, 128, 128, 1, 0, 1)
    outcome = execute_internal_run(
        "RED-04",
        {
            "construction": "r125",
            "state_bits": 4,
            "history_bits": 4,
            "state_count": 2,
            "target_round": 2,
            "policy": "same-persistent",
            "max_candidates": 64,
        },
        declared,
        b"synthetic-r15-runner-red04",
    )
    assert outcome.status in ("success", "censored")
    queries = outcome.metrics["queries"]
    assert isinstance(queries, int) and 1 <= queries <= 64
    assert outcome.metrics["policy"] == "same-persistent"


def test_internal_runner_executes_red03_fixture() -> None:
    declared = ResourceBudget(128, 128, 0, 128, 128, 128, 1, 0, 1)
    outcome = execute_internal_run(
        "RED-03",
        {
            "construction": "r125",
            "state_bits": 4,
            "history_bits": 4,
            "state_count": 2,
            "target_round": 2,
            "policy": "fixed-target",
            "max_candidates": 64,
        },
        declared,
        b"synthetic-r15-runner-red03",
    )
    assert outcome.status in ("success", "censored")
    queries = outcome.metrics["queries"]
    assert isinstance(queries, int) and 1 <= queries <= 64


def test_internal_runner_executes_red05_fixture() -> None:
    declared = ResourceBudget(128, 128, 0, 128, 128, 128, 1, 0, 4)
    outcome = execute_internal_run(
        "RED-05",
        {
            "construction": "r125",
            "state_bits": 4,
            "history_bits": 4,
            "targets": 4,
            "state_count": 2,
            "max_candidates": 64,
        },
        declared,
        b"synthetic-r15-runner-red05",
    )
    assert outcome.status in ("success", "censored")
    assert outcome.metrics["targets"] == 4


def test_internal_runner_executes_tmto_fixture() -> None:
    declared = ResourceBudget(4096, 0, 0, 4096, 4096, 64, 1, 128, 4)
    outcome = execute_internal_run(
        "TMTO-01",
        {
            "construction": "r125",
            "state_bits": 8,
            "history_bits": 8,
            "strategy": "rho",
            "entries": 32,
            "chain_length": 8,
            "distinguished_bits": 2,
            "targets": 4,
        },
        declared,
        b"synthetic-r15-runner-tmto",
    )
    assert outcome.status == "success"
    assert outcome.metrics["strategy"] == "rho"
    online = outcome.metrics["online_queries"]
    assert isinstance(online, int) and online > 0
