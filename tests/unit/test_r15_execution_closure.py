from __future__ import annotations

import hashlib

from experiments.history_reduced import ReducedHistoryConfig
from experiments.r15_application_campaigns import (
    mitigation_cost_profile_v3,
    profile_pow_nonce_selection_v3,
    run_kdf_campaign_mode_v3,
)
from experiments.r15_attack_bindings import R15_EXECUTOR_BINDINGS
from experiments.r15_branch_dependency import profile_deep_vector_dependency_v3
from experiments.r15_endpoint_wrappers import (
    find_first_full_state_collision_v3,
    parameter_grinding_work_ratio_v3,
    parameter_uniformity_profile_v3,
)
from experiments.r15_history_games import (
    conditional_crossing_trials_v3,
    profile_history_game_v3,
)
from experiments.r15_layout_ablation import profile_layout_ablation_three_way_v3
from experiments.r15_parameter_analysis import parameter_mutual_information_profile_v3
from experiments.r15_stat_adapters import StreamHasherV3, derive_stream_seed_v3
from experiments.reduced_oracle import ReducedOracle
from scripts.check_r15_execution_closure import check_r15_execution_closure


def test_r15_execution_closure_gate() -> None:
    report = check_r15_execution_closure()
    assert report["passed"] is True
    assert report["confirmatory"] is False
    assert report["executor_bindings"] == 21


def test_history_games_and_conditional_crossing_are_executable() -> None:
    oracle = ReducedOracle(b"r15-unit-history")
    config = ReducedHistoryConfig(4, 4, 4, target_round=1, state_count=1)
    for game in ("collision", "second-preimage", "fixed-point", "cycle"):
        result = profile_history_game_v3(
            oracle,
            config,
            persistent=1,
            state=2,
            round_index=0,
            game=game,
            input_budget=16,
        )
        assert result.game == game
        assert 1 <= result.queries <= 16
    crossing = conditional_crossing_trials_v3(oracle, config, round_index=0, trials=64)
    assert crossing.trials == 64
    assert 0.0 <= crossing.visible_match_rate <= 1.0
    assert 0.0 <= crossing.full_state_match_rate <= 1.0


def test_layout_values_only_separates_frames_without_changing_plan() -> None:
    profiles = {
        item.variant: item
        for item in profile_layout_ablation_three_way_v3(
            ReducedOracle(b"r15-layout"),
            history_bits=4,
            field_count=5,
            slots=17,
        )
    }
    assert profiles["fixed"].unique_plans == profiles["values-only"].unique_plans
    assert profiles["fixed"].plan_collision_pairs == profiles["values-only"].plan_collision_pairs
    assert profiles["values-only"].frame_collision_pairs == 0
    assert profiles["adaptive"].frame_collision_pairs == 0


def test_parameter_mi_permutation_is_deterministic() -> None:
    left = parameter_mutual_information_profile_v3(
        ReducedOracle(b"r15-mi"),
        96,
        permutations=17,
        seed=b"r15-mi-seed",
        persistent_bits=8,
        candidate_bucket_bits=4,
        persistent_bucket_bits=4,
    )
    right = parameter_mutual_information_profile_v3(
        ReducedOracle(b"r15-mi"),
        96,
        permutations=17,
        seed=b"r15-mi-seed",
        persistent_bits=8,
        candidate_bucket_bits=4,
        persistent_bucket_bits=4,
    )
    assert left == right
    assert 0.0 < left.permutation_p_candidate <= 1.0
    assert 0.0 < left.permutation_p_persistent <= 1.0


def test_deep_vector_dependency_reports_interventions() -> None:
    result = profile_deep_vector_dependency_v3(
        ReducedOracle(b"r15-branch"),
        bits=4,
        branch_count=4,
        candidates=8,
    )
    assert result.interventions == 32
    assert 0.0 <= result.all_branches_affected_rate <= 1.0
    assert 0.0 <= result.mean_affected_branches <= 4.0


def test_mitigation_cost_profiles_are_frozen() -> None:
    values = (3, 7, 11, 20, 35)
    derived = mitigation_cost_profile_v3(values, mode="input-derived")
    fixed = mitigation_cost_profile_v3(values, mode="context-fixed")
    bucketed = mitigation_cost_profile_v3(values, mode="cost-bucketed")
    assert derived.minimum == 3 and derived.maximum == 35
    assert fixed.minimum == fixed.maximum == 19
    assert bucketed.minimum >= derived.minimum
    assert bucketed.maximum == 35


def test_kdf_campaign_early_rejection_accounting(monkeypatch) -> None:
    import experiments.r15_application_campaigns as campaign

    class FakeParams:
        pass

    monkeypatch.setattr(
        campaign,
        "derive_argon2id_v3",
        lambda password, salt, parameters: bytes([sum(password) % 256]) * 32,
    )
    monkeypatch.setattr(
        campaign,
        "_parameters_for_base_key",
        lambda key, salt, parameters: (2 + key[0] % 3, 2),
    )
    monkeypatch.setattr(
        campaign,
        "compose_argon2id_output_v3",
        lambda base_key, salt, parameters: object(),
    )

    ticks = iter(range(10_000))
    result = run_kdf_campaign_mode_v3(
        (b"a", b"b", b"c"),
        target_password=b"target",
        salt=b"12345678",
        parameters=FakeParams(),  # type: ignore[arg-type]
        mode="early-reject-sigma",
        clock_ns=lambda: next(ticks),
    )
    assert result.guesses == 3
    assert result.early_rejected + result.full_sigma_guesses == 3
    assert result.work_per_guess_ns >= 0


def test_pow_selection_accounts_preparation_and_full_baseline(monkeypatch) -> None:
    import experiments.r15_application_campaigns as campaign

    class FakePow:
        pass

    monkeypatch.setattr(
        campaign,
        "_pow_parameters_for_nonce",
        lambda payload, nonce, parameters: (2 + nonce % 5, 2),
    )
    monkeypatch.setattr(
        campaign,
        "evaluate_nonce_v3",
        lambda payload, nonce, parameters: object(),
    )
    ticks = iter(range(10_000))
    result = profile_pow_nonce_selection_v3(
        b"payload",
        nonce_start=10,
        nonces=8,
        parameters=FakePow(),  # type: ignore[arg-type]
        clock_ns=lambda: next(ticks),
    )
    assert result.nonces == 8
    assert result.selected_cost == min(3 + nonce % 5 for nonce in range(10, 18))
    assert result.selection_total_ns >= 0
    assert result.full_evaluation_ns >= 0


def test_stream_hashing_and_identity_are_deterministic() -> None:
    seed = derive_stream_seed_v3("freeze", "R12.5-wide", "counter", 7)
    assert seed == derive_stream_seed_v3("freeze", "R12.5-wide", "counter", 7)
    hasher = StreamHasherV3(chunk_bytes=4)
    hasher.update(b"abcd")
    hasher.update(b"efgh")
    result = hasher.finish()
    assert result["sha256"] == hashlib.sha256(b"abcdefgh").hexdigest()
    assert result["total_bytes"] == 8
    chunk_hashes = result["chunk_sha256"]
    assert isinstance(chunk_hashes, tuple) and len(chunk_hashes) == 2


def test_every_frozen_attack_has_one_binding() -> None:
    assert len(R15_EXECUTOR_BINDINGS) == 21


def test_exact_primary_endpoint_wrappers() -> None:
    oracle = ReducedOracle(b"r15-endpoints")
    config = ReducedHistoryConfig(4, 4, 4, target_round=1, state_count=1)
    full = find_first_full_state_collision_v3(oracle, config, round_index=0, candidates=32)
    assert 1 <= full.queries <= 32
    assert full.censored is (not full.success)

    uniformity = parameter_uniformity_profile_v3(
        ReducedOracle(b"r15-uniformity"),
        186,
        persistent_bits=8,
    )
    assert uniformity.samples == 186
    assert uniformity.pair_count == 93
    assert uniformity.expected_per_pair == 2
    assert uniformity.max_deviation >= 0

    grinding = parameter_grinding_work_ratio_v3(
        ReducedOracle(b"r15-grinding"),
        93,
        persistent_bits=8,
    )
    assert 0.0 < grinding.net_work_ratio <= 1.0
    assert grinding.selected_work <= grinding.full_evaluation_baseline_work
