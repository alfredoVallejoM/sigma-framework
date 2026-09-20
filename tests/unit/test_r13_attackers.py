from __future__ import annotations

import pytest

from experiments.branch_failures_v3 import (
    BranchFailureConfigV3,
    profile_branch_failure_v3,
)
from experiments.history_attackers_v3 import (
    find_same_persistent_crossings_v3,
    profile_crossing_outcome_v3,
    profile_history_collisions_v3,
    profile_history_truncation_v3,
    profile_layout_ablation_v3,
)
from experiments.history_reduced import ReducedHistoryConfig
from experiments.parameter_grinding_v3 import (
    ParameterSpaceV3,
    find_cheapest_stratum,
    kdf_early_rejection_profile,
    parameter_distribution,
    pow_nonce_grinding_profile,
)
from experiments.r13_registry import ATTACK_REGISTRY_V3, get_attack_spec_v3
from experiments.reduced_oracle import ReducedOracle
from experiments.tmto_v3 import TMTOConfigV3, measure_tmto_v3


def _oracle(label: bytes = b"r13-attacker-tests") -> ReducedOracle:
    return ReducedOracle(label)


def test_r13_registry_is_closed_and_claim_linked() -> None:
    required = {
        "HIST-01",
        "HIST-02",
        "HIST-03",
        "HIST-05",
        "HIST-06",
        "PARAM-01",
        "PARAM-03",
        "PARAM-04",
        "PARAM-05",
        "TMTO-01",
        "BRANCH-01",
    }
    assert required <= set(ATTACK_REGISTRY_V3)
    for attack_id in required:
        spec = get_attack_spec_v3(attack_id)
        assert spec.claims
        assert spec.resources
        assert spec.baselines
        assert spec.output_fields
    with pytest.raises(ValueError):
        get_attack_spec_v3("UNKNOWN")


def test_same_persistent_crossing_is_a_clean_r12_vs_r125_ablation() -> None:
    config = ReducedHistoryConfig(
        state_bits=3,
        history_bits=5,
        persistent_bits=2,
        target_round=2,
        state_count=2,
    )
    crossings = find_same_persistent_crossings_v3(
        _oracle(), config, round_index=1, candidates=512, limit=32
    )
    assert crossings
    assert all(item.left_history != item.right_history for item in crossings)
    outcomes = [
        profile_crossing_outcome_v3(_oracle(), config, crossing)
        for crossing in crossings
    ]
    assert all(item.r12_successors_equal for item in outcomes)
    assert any(not item.next_full_states_equal for item in outcomes)


def test_history_collision_and_truncation_profiles_are_exhaustive() -> None:
    config = ReducedHistoryConfig(
        state_bits=5,
        history_bits=6,
        persistent_bits=6,
        target_round=2,
        state_count=2,
    )
    profile = profile_history_collisions_v3(
        _oracle(), config, persistent=7, state=9, round_index=0
    )
    assert profile.inputs == 64
    assert 1 <= profile.image_size <= profile.inputs
    assert profile.collision_pairs >= 0

    truncation = profile_history_truncation_v3(
        b"r13-truncation",
        (3, 4, 5),
        state_bits=5,
        persistent_bits=6,
        persistent=7,
        state=9,
        round_index=0,
    )
    assert [item.history_bits for item in truncation] == [3, 4, 5]
    assert all(item.full_collision_pairs <= item.visible_collision_pairs for item in truncation)


def test_history_adaptive_layout_ablation_changes_layout_family() -> None:
    profile = profile_layout_ablation_v3(
        _oracle(b"r13-layout"),
        history_bits=5,
        field_count=5,
        slots=17,
    )
    assert profile.fixed_unique_layouts == 1
    assert 1 < profile.adaptive_unique_layouts <= profile.histories
    assert profile.adaptive_collision_pairs >= 0


def test_parameter_distribution_and_cheapest_stratum_are_bounded() -> None:
    oracle = _oracle(b"r13-parameters")
    space = ParameterSpaceV3(2, 5, 2, 3)
    counts = parameter_distribution(oracle, 512, persistent_bits=10, space=space)
    assert sum(counts.values()) == 512
    assert all(space.t_min <= t <= space.t_max for t, _ in counts)
    assert all(space.k_min <= k <= space.k_max for _, k in counts)

    result = find_cheapest_stratum(
        oracle,
        512,
        persistent_bits=10,
        space=space,
    )
    assert 1 <= result.attempts <= 512
    assert result.transition_cost >= space.t_min + space.k_min - 1
    assert result.parameter_queries >= result.attempts


def test_kdf_early_rejection_accounts_every_guess_and_saved_rounds() -> None:
    profile = kdf_early_rejection_profile(
        _oracle(b"r13-kdf"),
        target_candidate=77,
        guesses=256,
        persistent_bits=10,
        space=ParameterSpaceV3(2, 6, 2, 4),
    )
    assert profile.early_rejected + profile.full_trajectory_guesses == profile.guesses
    assert profile.round_queries_saved >= profile.early_rejected
    assert profile.parameter_queries >= profile.guesses


def test_pow_nonce_grinding_reports_selected_cost_without_security_claim() -> None:
    profile = pow_nonce_grinding_profile(
        _oracle(b"r13-pow"),
        256,
        persistent_bits=10,
        space=ParameterSpaceV3(2, 8, 2, 4),
    )
    assert 0 <= profile.best_nonce < 256
    assert profile.best_cost <= profile.mean_cost
    assert profile.parameter_queries >= 256


@pytest.mark.parametrize("construction", ("r12", "r125"))
@pytest.mark.parametrize("strategy", ("direct", "distinguished", "rho", "hellman", "rainbow"))
def test_tmto_registry_strategies_return_explicit_resource_counts(
    construction: str,
    strategy: str,
) -> None:
    result = measure_tmto_v3(
        _oracle(f"r13-tmto-{construction}-{strategy}".encode()),
        TMTOConfigV3(
            bits=6,
            history_bits=6,
            entries=32,
            chain_length=4,
            distinguished_bits=2,
            targets=3,
        ),
        strategy,  # type: ignore[arg-type]
        construction,  # type: ignore[arg-type]
    )
    assert result.offline_queries >= 0
    assert result.online_queries >= 0
    assert result.history_queries >= 0
    assert result.memory_entries >= 0
    assert 0.0 <= result.reuse_rate <= 1.0
    if construction == "r12":
        assert result.history_queries == 0


def test_branch_failure_controls_expose_fold_bottleneck_and_vector_width() -> None:
    oracle = _oracle(b"r13-branch")
    config = BranchFailureConfigV3(bits=6, branch_count=4, candidates=128)

    normal_deep = profile_branch_failure_v3(oracle, config, "deep", "normal")
    constant_fold = profile_branch_failure_v3(
        oracle, config, "deep", "constant-fold"
    )
    vector = profile_branch_failure_v3(
        oracle, config, "deep-vector", "constant-first"
    )

    assert constant_fold.image_size == 1
    assert constant_fold.conservative_bits == 0
    assert normal_deep.physical_bits == 6
    assert vector.physical_bits == 24
    assert vector.conservative_bits == 6
    with pytest.raises(ValueError):
        profile_branch_failure_v3(
            oracle, config, "deep-vector", "constant-fold"
        )


def test_r13_model_guards_refuse_infeasible_or_invalid_inputs() -> None:
    with pytest.raises(ValueError):
        ParameterSpaceV3(5, 2, 2, 4)
    with pytest.raises(ValueError):
        TMTOConfigV3(bits=33, history_bits=8)
    with pytest.raises(ValueError):
        BranchFailureConfigV3(bits=8, branch_count=1)
    with pytest.raises(ValueError):
        profile_layout_ablation_v3(_oracle(), history_bits=21)
