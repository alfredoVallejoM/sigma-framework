from __future__ import annotations

from pathlib import Path

import pytest

from experiments.r13_schema import ResourceBudget
from experiments.r15_confirmatory_internal import execute_internal_run
from experiments.r15_internal_amendment import (
    AMENDED_ATTACKS,
    EXPECTED_RUN_UNITS,
)
from experiments.r15_internal_amendment_dataset import expected_amendment_runkeys
from experiments.r15_parameter_analysis import parameter_mutual_information_profile_v3
from experiments.r15_parameter_analysis_fast import (
    parameter_mutual_information_profile_vectorized_v3,
)
from experiments.reduced_oracle import ReducedOracle
from scripts.prepare_r141_confirmatory import prepare_r141_configs


def test_red04_corrective_path_executes_without_runner_defect() -> None:
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
        b"synthetic-r15-amendment-red04",
    )
    assert outcome.status in ("success", "censored")
    queries = outcome.metrics["queries"]
    assert isinstance(queries, int) and 1 <= queries <= 64
    assert outcome.metrics["policy"] == "same-persistent"


def test_vectorized_param02_matches_original_observed_mi() -> None:
    pytest.importorskip("numpy")
    slow = parameter_mutual_information_profile_v3(
        ReducedOracle(b"r15-amendment-mi"),
        256,
        permutations=17,
        seed=b"synthetic-r15-amendment-param02",
        persistent_bits=12,
        candidate_bucket_bits=4,
        persistent_bucket_bits=4,
    )
    fast = parameter_mutual_information_profile_vectorized_v3(
        ReducedOracle(b"r15-amendment-mi"),
        256,
        permutations=17,
        seed=b"synthetic-r15-amendment-param02",
        persistent_bits=12,
        candidate_bucket_bits=4,
        persistent_bucket_bits=4,
    )
    assert fast.mi_candidate == pytest.approx(slow.mi_candidate, abs=1e-12)
    assert fast.mi_persistent == pytest.approx(slow.mi_persistent, abs=1e-12)


def test_vectorized_param02_is_deterministic_and_uses_add_one_pvalue() -> None:
    pytest.importorskip("numpy")
    left = parameter_mutual_information_profile_vectorized_v3(
        ReducedOracle(b"r15-amendment-mi-determinism"),
        256,
        permutations=31,
        seed=b"synthetic-r15-amendment-param02-determinism",
        persistent_bits=12,
        candidate_bucket_bits=4,
        persistent_bucket_bits=4,
    )
    right = parameter_mutual_information_profile_vectorized_v3(
        ReducedOracle(b"r15-amendment-mi-determinism"),
        256,
        permutations=31,
        seed=b"synthetic-r15-amendment-param02-determinism",
        persistent_bits=12,
        candidate_bucket_bits=4,
        persistent_bucket_bits=4,
    )
    assert left == right
    denominator = 32
    for p_value in (left.permutation_p_candidate, left.permutation_p_persistent):
        assert 0.0 < p_value <= 1.0
        assert p_value * denominator == pytest.approx(round(p_value * denominator))


def test_amendment_runkeys_are_exact_and_only_red04_param02(tmp_path: Path) -> None:
    configs = tmp_path / "configs"
    prepare_r141_configs(configs)
    keys = expected_amendment_runkeys(configs)
    assert len(keys) == EXPECTED_RUN_UNITS == 11_392
    assert len(keys) == len(set(keys))
    assert {key.attack_id for key in keys} == set(AMENDED_ATTACKS) == {"RED-04", "PARAM-02"}
