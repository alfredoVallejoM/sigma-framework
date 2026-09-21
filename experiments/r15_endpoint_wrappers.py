"""Exact primary-endpoint wrappers for the R15 execution closure."""

from __future__ import annotations

from collections import Counter
from dataclasses import dataclass

from .history_reduced import ReducedHistoryConfig, evaluate_reduced_history
from .parameter_grinding_v3 import (
    DEFAULT_PARAMETER_SPACE_V3,
    ParameterSpaceV3,
    derive_parameters_reduced,
    find_cheapest_stratum,
    parameter_distribution,
)
from .reduced_oracle import ReducedOracle


@dataclass(frozen=True)
class FullStateFirstHitResultV3:
    queries: int
    success: bool
    censored: bool
    collision_pairs_at_stop: int
    left_candidate: int | None
    right_candidate: int | None


@dataclass(frozen=True)
class ParameterUniformityResultV3:
    samples: int
    pair_count: int
    expected_per_pair: float
    max_deviation: float
    relative_max_deviation: float
    chi_square: float
    observed_pairs: int


@dataclass(frozen=True)
class GrindingWorkRatioResultV3:
    candidate_budget: int
    attempts: int
    selected_cost: int
    selected_work: int
    full_evaluation_baseline_work: int
    net_work_ratio: float


def find_first_full_state_collision_v3(
    oracle: ReducedOracle,
    config: ReducedHistoryConfig,
    *,
    round_index: int,
    candidates: int,
) -> FullStateFirstHitResultV3:
    """Return exact first-hit work or right-censoring for (H_i,S_i)."""

    if not 0 <= round_index <= config.transition_count:
        raise ValueError("round_index is outside the trace")
    if candidates <= 1:
        raise ValueError("candidates must be greater than one")

    first: dict[tuple[int, int], int] = {}
    counts: Counter[tuple[int, int]] = Counter()
    for candidate in range(candidates):
        trace = evaluate_reduced_history(oracle, config, candidate, "r125")
        key = (trace.histories[round_index], trace.states[round_index])
        counts[key] += 1
        prior = first.get(key)
        if prior is not None:
            pairs = sum(value * (value - 1) // 2 for value in counts.values())
            return FullStateFirstHitResultV3(
                queries=candidate + 1,
                success=True,
                censored=False,
                collision_pairs_at_stop=pairs,
                left_candidate=prior,
                right_candidate=candidate,
            )
        first[key] = candidate

    return FullStateFirstHitResultV3(
        queries=candidates,
        success=False,
        censored=True,
        collision_pairs_at_stop=0,
        left_candidate=None,
        right_candidate=None,
    )


def parameter_uniformity_profile_v3(
    oracle: ReducedOracle,
    samples: int,
    *,
    persistent_bits: int = 16,
    space: ParameterSpaceV3 = DEFAULT_PARAMETER_SPACE_V3,
) -> ParameterUniformityResultV3:
    """Materialize the frozen PARAM-01 max-deviation/GOF endpoint."""

    if samples <= 0:
        raise ValueError("samples must be positive")
    counts = parameter_distribution(
        oracle,
        samples,
        persistent_bits=persistent_bits,
        space=space,
    )
    expected = samples / space.pair_count
    deviations: list[float] = []
    chi_square = 0.0
    for t in range(space.t_min, space.t_max + 1):
        for k in range(space.k_min, space.k_max + 1):
            observed = counts.get((t, k), 0)
            deviation = abs(observed - expected)
            deviations.append(deviation)
            chi_square += (observed - expected) ** 2 / expected
    max_deviation = max(deviations)
    return ParameterUniformityResultV3(
        samples=samples,
        pair_count=space.pair_count,
        expected_per_pair=expected,
        max_deviation=max_deviation,
        relative_max_deviation=max_deviation / expected,
        chi_square=chi_square,
        observed_pairs=len(counts),
    )


def parameter_grinding_work_ratio_v3(
    oracle: ReducedOracle,
    candidates: int,
    *,
    persistent_bits: int = 16,
    space: ParameterSpaceV3 = DEFAULT_PARAMETER_SPACE_V3,
) -> GrindingWorkRatioResultV3:
    """Compare screening+selected trajectory with full work on the same inspected candidates."""

    if candidates <= 0:
        raise ValueError("candidates must be positive")
    selected = find_cheapest_stratum(
        oracle,
        candidates,
        persistent_bits=persistent_bits,
        space=space,
    )
    inspected = [
        derive_parameters_reduced(
            oracle,
            candidate,
            persistent_bits=persistent_bits,
            space=space,
        )
        for candidate in range(selected.attempts)
    ]
    screening_work = selected.attempts + sum(value.parameter_queries for value in inspected)
    selected_work = screening_work + selected.transition_cost
    baseline_work = sum(1 + value.parameter_queries + value.transition_cost for value in inspected)
    return GrindingWorkRatioResultV3(
        candidate_budget=candidates,
        attempts=selected.attempts,
        selected_cost=selected.transition_cost,
        selected_work=selected_work,
        full_evaluation_baseline_work=baseline_work,
        net_work_ratio=selected_work / baseline_work,
    )


__all__ = [
    "FullStateFirstHitResultV3",
    "GrindingWorkRatioResultV3",
    "ParameterUniformityResultV3",
    "find_first_full_state_collision_v3",
    "parameter_grinding_work_ratio_v3",
    "parameter_uniformity_profile_v3",
]
