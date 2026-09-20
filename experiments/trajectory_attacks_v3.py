"""Reduced collision/preimage-family attackers for Sigma v3 R13."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Literal

from .history_reduced import (
    Construction,
    ReducedHistoryConfig,
    ReducedTrace,
    evaluate_reduced_history,
)
from .reduced_oracle import ReducedOracle

PersistentPolicyV3 = Literal["same", "any"]


@dataclass(frozen=True)
class WindowCollisionV3:
    left_candidate: int
    right_candidate: int
    persistent_equal: bool
    window: tuple[int, ...]
    first_state_divergence: int | None
    first_history_divergence: int | None
    evaluated_candidates: int


@dataclass(frozen=True)
class WindowSecondPreimageV3:
    target_candidate: int
    candidate: int
    persistent_equal: bool
    window: tuple[int, ...]
    first_state_divergence: int | None
    first_history_divergence: int | None
    evaluated_candidates: int


@dataclass(frozen=True)
class CollisionScalingPointV3:
    state_bits: int
    history_bits: int
    construction: Construction
    candidates_to_first_window_collision: int | None
    censored: bool
    max_candidates: int


def _first_difference(left: tuple[int, ...], right: tuple[int, ...]) -> int | None:
    for index, (left_value, right_value) in enumerate(zip(left, right, strict=True)):
        if left_value != right_value:
            return index
    return None


def _history_difference(left: ReducedTrace, right: ReducedTrace) -> int | None:
    if not left.histories and not right.histories:
        return None
    if len(left.histories) != len(right.histories):
        return 0
    return _first_difference(left.histories, right.histories)


def _collision_record(
    left: ReducedTrace,
    right: ReducedTrace,
    evaluated_candidates: int,
) -> WindowCollisionV3:
    return WindowCollisionV3(
        left_candidate=left.candidate,
        right_candidate=right.candidate,
        persistent_equal=left.persistent == right.persistent,
        window=left.window,
        first_state_divergence=_first_difference(left.states, right.states),
        first_history_divergence=_history_difference(left, right),
        evaluated_candidates=evaluated_candidates,
    )


def find_window_collision_v3(
    oracle: ReducedOracle,
    config: ReducedHistoryConfig,
    *,
    construction: Construction,
    candidates: int,
    persistent_policy: PersistentPolicyV3 = "any",
) -> WindowCollisionV3 | None:
    if construction not in ("r12", "r125"):
        raise ValueError("unknown construction")
    if candidates <= 1:
        raise ValueError("candidates must be greater than one")
    if persistent_policy not in ("same", "any"):
        raise ValueError("unknown persistent policy")

    buckets: dict[tuple[object, ...], ReducedTrace] = {}
    for candidate in range(candidates):
        trace = evaluate_reduced_history(oracle, config, candidate, construction)
        key: tuple[object, ...]
        if persistent_policy == "same":
            key = (trace.persistent, *trace.window)
        else:
            key = tuple(trace.window)
        prior = buckets.get(key)
        if prior is not None and prior.candidate != trace.candidate:
            return _collision_record(prior, trace, candidate + 1)
        buckets[key] = trace
    return None


def find_window_preimage_v3(
    oracle: ReducedOracle,
    config: ReducedHistoryConfig,
    *,
    construction: Construction,
    target_window: tuple[int, ...],
    candidates: int,
) -> dict[str, int | bool] | None:
    if candidates <= 0:
        raise ValueError("candidates must be positive")
    if len(target_window) != config.state_count:
        raise ValueError("target_window must match state_count")
    for candidate in range(candidates):
        trace = evaluate_reduced_history(oracle, config, candidate, construction)
        if trace.window == target_window:
            return {
                "candidate": candidate,
                "evaluated_candidates": candidate + 1,
                "success": True,
            }
    return None


def find_window_second_preimage_v3(
    oracle: ReducedOracle,
    config: ReducedHistoryConfig,
    *,
    construction: Construction,
    target_candidate: int,
    candidates: int,
    persistent_policy: PersistentPolicyV3 = "same",
) -> WindowSecondPreimageV3 | None:
    if candidates <= 0:
        raise ValueError("candidates must be positive")
    target = evaluate_reduced_history(
        oracle, config, target_candidate, construction
    )
    evaluated = 0
    for candidate in range(candidates):
        if candidate == target_candidate:
            continue
        trace = evaluate_reduced_history(oracle, config, candidate, construction)
        evaluated += 1
        if persistent_policy == "same" and trace.persistent != target.persistent:
            continue
        if trace.window != target.window:
            continue
        return WindowSecondPreimageV3(
            target_candidate=target_candidate,
            candidate=candidate,
            persistent_equal=trace.persistent == target.persistent,
            window=trace.window,
            first_state_divergence=_first_difference(target.states, trace.states),
            first_history_divergence=_history_difference(target, trace),
            evaluated_candidates=evaluated,
        )
    return None


def collision_scaling_v3(
    seed: bytes,
    widths: tuple[int, ...],
    *,
    construction: Construction,
    history_bits: int,
    persistent_bits: int,
    target_round: int,
    state_count: int,
    max_candidates: int,
) -> tuple[CollisionScalingPointV3, ...]:
    if not widths:
        raise ValueError("widths must be non-empty")
    if max_candidates <= 1:
        raise ValueError("max_candidates must be greater than one")
    points: list[CollisionScalingPointV3] = []
    for bits in widths:
        config = ReducedHistoryConfig(
            state_bits=bits,
            history_bits=history_bits,
            persistent_bits=persistent_bits,
            target_round=target_round,
            state_count=state_count,
        )
        found = find_window_collision_v3(
            ReducedOracle(seed + bits.to_bytes(2, "big")),
            config,
            construction=construction,
            candidates=max_candidates,
            persistent_policy="any",
        )
        points.append(
            CollisionScalingPointV3(
                state_bits=bits,
                history_bits=history_bits,
                construction=construction,
                candidates_to_first_window_collision=(
                    None if found is None else found.evaluated_candidates
                ),
                censored=found is None,
                max_candidates=max_candidates,
            )
        )
    return tuple(points)


def multi_target_window_attack_v3(
    oracle: ReducedOracle,
    config: ReducedHistoryConfig,
    *,
    construction: Construction,
    targets: int,
    search_candidates: int,
) -> dict[str, int | bool]:
    if targets <= 0 or search_candidates <= 0:
        raise ValueError("targets and search_candidates must be positive")
    target_traces = [
        evaluate_reduced_history(oracle, config, candidate, construction)
        for candidate in range(targets)
    ]
    windows = {trace.window for trace in target_traces}
    for offset in range(search_candidates):
        candidate = (1 << 96) + offset
        trace = evaluate_reduced_history(oracle, config, candidate, construction)
        if trace.window in windows:
            return {
                "targets": targets,
                "search_candidates": search_candidates,
                "evaluated": offset + 1,
                "success": True,
            }
    return {
        "targets": targets,
        "search_candidates": search_candidates,
        "evaluated": search_candidates,
        "success": False,
    }


__all__ = [
    "CollisionScalingPointV3",
    "PersistentPolicyV3",
    "WindowCollisionV3",
    "WindowSecondPreimageV3",
    "collision_scaling_v3",
    "find_window_collision_v3",
    "find_window_preimage_v3",
    "find_window_second_preimage_v3",
    "multi_target_window_attack_v3",
]
