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
    mitigation_profile,
    parameter_correlation_profile,
    parameter_distribution,
    pow_nonce_grinding_profile,
)
from experiments.r13_attack_registry import ATTACK_REGISTRY, get_attack
from experiments.r13_pilots import (
    CORE_EXECUTABLE_ATTACKS,
    run_r13_design_pilots,
    validate_r13_design_records,
)
from experiments.reduced_oracle import ReducedOracle
from experiments.tmto_v3 import TMTOConfigV3, measure_tmto_v3
from experiments.trajectory_attacks_v3 import (
    collision_scaling_v3,
    find_window_collision_v3,
    find_window_preimage_v3,
    find_window_second_preimage_v3,
    multi_target_window_attack_v3,
)


def _oracle(label: bytes = b"r13-attacker-tests") -> ReducedOracle:
    return ReducedOracle(label)


def test_r13_registry_is_closed_and_claim_linked() -> None:
    assert set(ATTACK_REGISTRY) >= CORE_EXECUTABLE_ATTACKS
    for attack_id in CORE_EXECUTABLE_ATTACKS:
        spec = get_attack(attack_id)
        assert spec.claims
        assert spec.resources
        assert spec.baselines
        assert spec.metrics
        assert spec.success_event
    with pytest.raises(ValueError):
        get_attack("UNKNOWN")


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
    outcomes = [profile_crossing_outcome_v3(_oracle(), config, crossing) for crossing in crossings]
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
    profile = profile_history_collisions_v3(_oracle(), config, persistent=7, state=9, round_index=0)
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


def test_parameter_correlation_and_fixed_cost_mitigation_are_explicit() -> None:
    oracle = _oracle(b"r13-param-correlation")
    space = ParameterSpaceV3(2, 8, 2, 4)
    correlation = parameter_correlation_profile(
        oracle,
        256,
        persistent_bits=10,
        space=space,
    )
    assert correlation.samples == 256
    assert all(
        -1.0 <= value <= 1.0
        for value in (
            correlation.candidate_t,
            correlation.candidate_k,
            correlation.persistent_t,
            correlation.persistent_k,
        )
    )
    mitigation = mitigation_profile(
        oracle,
        256,
        fixed_t=5,
        fixed_k=3,
        persistent_bits=10,
        space=space,
    )
    assert mitigation.fixed_variance == 0.0
    assert mitigation.derived_variance >= 0.0
    assert mitigation.derived_min_cost <= mitigation.derived_max_cost


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


def test_reduced_collision_preimage_second_preimage_and_multi_target_interfaces() -> None:
    config = ReducedHistoryConfig(
        state_bits=4,
        history_bits=5,
        persistent_bits=3,
        target_round=1,
        state_count=2,
    )
    oracle = _oracle(b"r13-reduced-family")
    collision = find_window_collision_v3(
        oracle,
        config,
        construction="r125",
        candidates=4096,
        persistent_policy="any",
    )
    assert collision is not None
    assert collision.evaluated_candidates <= 4096

    target_window = tuple(
        oracle.query(
            "test-external-window",
            config.state_bits,
            index.to_bytes(2, "big"),
        )
        for index in range(config.state_count)
    )
    preimage = find_window_preimage_v3(
        oracle,
        config,
        construction="r125",
        target_window=target_window,
        candidates=4096,
    )
    if preimage is not None:
        assert preimage["success"] is True
        assert int(preimage["evaluated_candidates"]) <= 4096

    second = find_window_second_preimage_v3(
        oracle,
        config,
        construction="r125",
        target_candidate=0,
        candidates=4096,
        persistent_policy="same",
    )
    if second is not None:
        assert second.target_candidate == 0
        assert second.persistent_equal

    multi = multi_target_window_attack_v3(
        oracle,
        config,
        construction="r125",
        targets=8,
        search_candidates=1024,
    )
    assert multi["targets"] == 8
    assert int(multi["evaluated"]) <= 1024

    scaling = collision_scaling_v3(
        b"r13-scaling",
        (3, 4, 5),
        construction="r125",
        history_bits=5,
        persistent_bits=3,
        target_round=1,
        state_count=2,
        max_candidates=2048,
    )
    assert [point.state_bits for point in scaling] == [3, 4, 5]
    assert all(point.max_candidates == 2048 for point in scaling)


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
    constant_fold = profile_branch_failure_v3(oracle, config, "deep", "constant-fold")
    vector = profile_branch_failure_v3(oracle, config, "deep-vector", "constant-first")

    assert constant_fold.image_size == 1
    assert constant_fold.conservative_bits == 0
    assert normal_deep.physical_bits == 6
    assert vector.physical_bits == 24
    assert vector.conservative_bits == 6
    with pytest.raises(ValueError):
        profile_branch_failure_v3(oracle, config, "deep-vector", "constant-fold")


def test_r13_design_pilot_harness_is_deterministic_schema_complete_and_nonconfirmatory() -> None:
    first = run_r13_design_pilots(b"r13-design-test")
    second = run_r13_design_pilots(b"r13-design-test")
    assert first == second
    validate_r13_design_records(first)
    assert all(record.metrics["confirmatory"] is False for record in first)
    observed = {record.attack_id for record in first}
    assert observed >= CORE_EXECUTABLE_ATTACKS


def test_r13_model_guards_refuse_infeasible_or_invalid_inputs() -> None:
    with pytest.raises(ValueError):
        ParameterSpaceV3(5, 2, 2, 4)
    with pytest.raises(ValueError):
        TMTOConfigV3(bits=33, history_bits=8)
    with pytest.raises(ValueError):
        BranchFailureConfigV3(bits=8, branch_count=1)
    with pytest.raises(ValueError):
        profile_layout_ablation_v3(_oracle(), history_bits=21)
