from __future__ import annotations

import pytest

from experiments.history_reduced import (
    ReducedHistoryConfig,
    evaluate_reduced_history,
    find_full_state_collisions,
    find_visible_state_crossings,
    history_step_query,
    profile_history_map,
    r12_round_query,
    r125_round_query,
)
from experiments.reduced_oracle import ReducedOracle


def _oracle() -> ReducedOracle:
    return ReducedOracle(b"r13-history-reduced-tests")


def test_reduced_history_config_validates_ranges() -> None:
    assert ReducedHistoryConfig(8, 8, 8).transition_count == 3
    with pytest.raises(ValueError):
        ReducedHistoryConfig(0, 8, 8)
    with pytest.raises(TypeError):
        ReducedHistoryConfig(True, 8, 8)  # type: ignore[arg-type]
    with pytest.raises(ValueError):
        ReducedHistoryConfig(8, 8, 8, state_count=0)


def test_r12_and_r125_queries_expose_the_ablation_exactly() -> None:
    config = ReducedHistoryConfig(8, 8, 8)
    r12 = r12_round_query(config, 7, 11, 2)
    left = r125_round_query(config, 7, 3, 11, 2)
    right = r125_round_query(config, 7, 4, 11, 2)

    assert left != right
    assert r12 != left
    assert history_step_query(config, 7, 3, 11, 2) != history_step_query(config, 7, 4, 11, 2)


def test_reduced_trace_is_deterministic_and_has_correct_window() -> None:
    config = ReducedHistoryConfig(10, 9, 8, target_round=2, state_count=3)
    first = evaluate_reduced_history(_oracle(), config, 17, "r125")
    second = evaluate_reduced_history(_oracle(), config, 17, "r125")

    assert first == second
    assert len(first.states) == config.target_round + config.state_count
    assert len(first.histories) == len(first.states)
    assert first.window == first.states[2:5]

    baseline = evaluate_reduced_history(_oracle(), config, 17, "r12")
    assert baseline.histories == ()
    assert baseline.window == baseline.states[2:5]


def test_reduced_trace_rejects_unknown_construction_and_candidate() -> None:
    config = ReducedHistoryConfig(8, 8, 8)
    with pytest.raises(ValueError):
        evaluate_reduced_history(_oracle(), config, 1, "bad")  # type: ignore[arg-type]
    with pytest.raises(ValueError):
        evaluate_reduced_history(_oracle(), config, -1, "r125")


def test_history_map_shows_fixed_binding_ablation_and_full_state_profile() -> None:
    config = ReducedHistoryConfig(
        state_bits=5,
        history_bits=5,
        persistent_bits=6,
        target_round=2,
        state_count=2,
    )
    profile = profile_history_map(
        _oracle(),
        config,
        persistent=7,
        state=13,
        round_index=0,
    )

    assert profile.inputs == 32
    assert profile.r12_visible_image_size == 1
    assert 1 <= profile.r125_visible_image_size <= 32
    assert 1 <= profile.r125_full_image_size <= 32
    assert profile.r125_full_collision_pairs <= profile.r125_visible_collision_pairs


def test_history_map_refuses_infeasible_exhaustive_width() -> None:
    config = ReducedHistoryConfig(8, 21, 8)
    with pytest.raises(ValueError, match="20 bits"):
        profile_history_map(
            _oracle(),
            config,
            persistent=1,
            state=1,
            round_index=0,
        )


def test_visible_crossing_finder_only_returns_distinct_histories() -> None:
    config = ReducedHistoryConfig(
        state_bits=4,
        history_bits=6,
        persistent_bits=5,
        target_round=2,
        state_count=2,
    )
    crossings = find_visible_state_crossings(
        _oracle(),
        config,
        round_index=1,
        candidates=128,
        limit=16,
    )
    assert crossings
    for crossing in crossings:
        assert crossing.left_candidate != crossing.right_candidate
        assert crossing.left_history != crossing.right_history


def test_full_state_collision_finder_reports_true_equal_pairs() -> None:
    config = ReducedHistoryConfig(
        state_bits=4,
        history_bits=4,
        persistent_bits=4,
        target_round=2,
        state_count=2,
    )
    collisions = find_full_state_collisions(
        _oracle(),
        config,
        round_index=1,
        candidates=512,
        limit=8,
    )
    assert collisions
    traces = {
        candidate: evaluate_reduced_history(_oracle(), config, candidate, "r125")
        for collision in collisions
        for candidate in (collision.left_candidate, collision.right_candidate)
    }
    for collision in collisions:
        left = traces[collision.left_candidate]
        right = traces[collision.right_candidate]
        assert left.states[1] == right.states[1] == collision.state
        assert left.histories[1] == right.histories[1] == collision.history


@pytest.mark.parametrize("round_index", (-1, 4))
def test_crossing_search_rejects_invalid_round(round_index: int) -> None:
    config = ReducedHistoryConfig(4, 4, 4)
    with pytest.raises(ValueError):
        find_visible_state_crossings(
            _oracle(),
            config,
            round_index=round_index,
            candidates=16,
        )
