"""Executable R13 history attackers and ablations."""

from __future__ import annotations

from collections import Counter, defaultdict
from dataclasses import dataclass

from .history_reduced import (
    ReducedHistoryConfig,
    ReducedTrace,
    evaluate_reduced_history,
    history_successor,
    profile_history_map,
    r12_successor,
    r125_successor,
)
from .reduced_oracle import ReducedOracle, encode_integer


@dataclass(frozen=True)
class SamePersistentCrossingV3:
    left_candidate: int
    right_candidate: int
    round_index: int
    persistent: int
    state: int
    left_history: int
    right_history: int


@dataclass(frozen=True)
class CrossingOutcomeV3:
    crossing: SamePersistentCrossingV3
    r12_successors_equal: bool
    r125_successors_equal: bool
    next_histories_equal: bool
    next_full_states_equal: bool


@dataclass(frozen=True)
class HistoryCollisionProfileV3:
    history_bits: int
    inputs: int
    image_size: int
    collision_pairs: int


@dataclass(frozen=True)
class TruncationProfileV3:
    history_bits: int
    visible_collision_pairs: int
    full_collision_pairs: int
    visible_image_size: int
    full_image_size: int


@dataclass(frozen=True)
class LayoutAblationProfileV3:
    history_bits: int
    histories: int
    field_count: int
    fixed_unique_layouts: int
    adaptive_unique_layouts: int
    adaptive_collision_pairs: int


def find_same_persistent_crossings_v3(
    oracle: ReducedOracle,
    config: ReducedHistoryConfig,
    *,
    round_index: int,
    candidates: int,
    limit: int = 32,
) -> tuple[SamePersistentCrossingV3, ...]:
    """Find equal visible states with equal P but distinct histories."""

    if not 0 <= round_index <= config.transition_count:
        raise ValueError("round_index is outside the trace")
    if candidates <= 1 or limit <= 0:
        raise ValueError("candidates and limit must be positive")

    buckets: dict[tuple[int, int], list[ReducedTrace]] = defaultdict(list)
    crossings: list[SamePersistentCrossingV3] = []
    for candidate in range(candidates):
        trace = evaluate_reduced_history(oracle, config, candidate, "r125")
        key = (trace.persistent, trace.states[round_index])
        for prior in buckets[key]:
            if prior.histories[round_index] == trace.histories[round_index]:
                continue
            crossings.append(
                SamePersistentCrossingV3(
                    prior.candidate,
                    trace.candidate,
                    round_index,
                    trace.persistent,
                    trace.states[round_index],
                    prior.histories[round_index],
                    trace.histories[round_index],
                )
            )
            if len(crossings) >= limit:
                return tuple(crossings)
        buckets[key].append(trace)
    return tuple(crossings)


def profile_crossing_outcome_v3(
    oracle: ReducedOracle,
    config: ReducedHistoryConfig,
    crossing: SamePersistentCrossingV3,
) -> CrossingOutcomeV3:
    """Compare fixed-binding coalescence against history-feedback separation."""

    i = crossing.round_index
    p = crossing.persistent
    s = crossing.state
    baseline_left = r12_successor(oracle, config, p, s, i)
    baseline_right = r12_successor(oracle, config, p, s, i)
    left_state = r125_successor(oracle, config, p, crossing.left_history, s, i)
    right_state = r125_successor(oracle, config, p, crossing.right_history, s, i)
    left_history = history_successor(oracle, config, p, crossing.left_history, s, i)
    right_history = history_successor(oracle, config, p, crossing.right_history, s, i)
    return CrossingOutcomeV3(
        crossing=crossing,
        r12_successors_equal=baseline_left == baseline_right,
        r125_successors_equal=left_state == right_state,
        next_histories_equal=left_history == right_history,
        next_full_states_equal=(left_history, left_state) == (right_history, right_state),
    )


def profile_history_collisions_v3(
    oracle: ReducedOracle,
    config: ReducedHistoryConfig,
    *,
    persistent: int,
    state: int,
    round_index: int,
) -> HistoryCollisionProfileV3:
    """Exhaust HistoryStep inputs for one fixed P,S,i in small widths."""

    if config.history_bits > 20:
        raise ValueError("history collision profile is limited to <=20 bits")
    outputs = [
        history_successor(oracle, config, persistent, history, state, round_index)
        for history in range(1 << config.history_bits)
    ]
    counts = Counter(outputs)
    collision_pairs = sum(count * (count - 1) // 2 for count in counts.values())
    return HistoryCollisionProfileV3(
        history_bits=config.history_bits,
        inputs=len(outputs),
        image_size=len(counts),
        collision_pairs=collision_pairs,
    )


def profile_history_truncation_v3(
    seed: bytes,
    widths: tuple[int, ...],
    *,
    state_bits: int,
    persistent_bits: int,
    persistent: int,
    state: int,
    round_index: int,
) -> tuple[TruncationProfileV3, ...]:
    """HIST-05: expose the bottleneck as history width is reduced."""

    if not widths:
        raise ValueError("widths must be non-empty")
    profiles: list[TruncationProfileV3] = []
    for width in widths:
        config = ReducedHistoryConfig(
            state_bits=state_bits,
            history_bits=width,
            persistent_bits=persistent_bits,
            target_round=max(1, round_index + 1),
            state_count=1,
        )
        measured = profile_history_map(
            ReducedOracle(seed),
            config,
            persistent=persistent,
            state=state,
            round_index=round_index,
        )
        profiles.append(
            TruncationProfileV3(
                history_bits=width,
                visible_collision_pairs=measured.r125_visible_collision_pairs,
                full_collision_pairs=measured.r125_full_collision_pairs,
                visible_image_size=measured.r125_visible_image_size,
                full_image_size=measured.r125_full_image_size,
            )
        )
    return tuple(profiles)


def _layout_signature(
    oracle: ReducedOracle,
    history: int,
    history_bits: int,
    *,
    field_count: int,
    slots: int,
    adaptive: bool,
) -> tuple[int, ...]:
    label = "r13-layout-adaptive" if adaptive else "r13-layout-fixed"
    history_bytes = encode_integer(history, history_bits) if adaptive else b""
    return tuple(
        oracle.query(
            label,
            16,
            history_bytes,
            field.to_bytes(2, "big"),
        )
        % slots
        for field in range(field_count)
    )


def profile_layout_ablation_v3(
    oracle: ReducedOracle,
    *,
    history_bits: int,
    field_count: int = 5,
    slots: int = 65,
) -> LayoutAblationProfileV3:
    """HIST-06: fixed layout versus a history-dependent layout signature."""

    if not 1 <= history_bits <= 20:
        raise ValueError("history_bits must be in [1,20]")
    if field_count <= 0 or slots <= 0:
        raise ValueError("field_count and slots must be positive")
    fixed = [
        _layout_signature(
            oracle,
            history,
            history_bits,
            field_count=field_count,
            slots=slots,
            adaptive=False,
        )
        for history in range(1 << history_bits)
    ]
    adaptive = [
        _layout_signature(
            oracle,
            history,
            history_bits,
            field_count=field_count,
            slots=slots,
            adaptive=True,
        )
        for history in range(1 << history_bits)
    ]
    counts = Counter(adaptive)
    return LayoutAblationProfileV3(
        history_bits=history_bits,
        histories=1 << history_bits,
        field_count=field_count,
        fixed_unique_layouts=len(set(fixed)),
        adaptive_unique_layouts=len(counts),
        adaptive_collision_pairs=sum(count * (count - 1) // 2 for count in counts.values()),
    )


__all__ = [
    "CrossingOutcomeV3",
    "HistoryCollisionProfileV3",
    "LayoutAblationProfileV3",
    "SamePersistentCrossingV3",
    "TruncationProfileV3",
    "find_same_persistent_crossings_v3",
    "profile_crossing_outcome_v3",
    "profile_history_collisions_v3",
    "profile_history_truncation_v3",
    "profile_layout_ablation_v3",
]
