"""Reduced-width R13 model for history-feedback cryptanalysis.

This module is experimental only. It models the causal topology of R12 and
R12.5 with deterministic reduced random functions; it is never imported by the
product implementation and its results are not concrete security claims.
"""

from __future__ import annotations

from collections import Counter, defaultdict
from dataclasses import dataclass
from typing import Literal

from .reduced_oracle import ReducedOracle, encode_integer

Construction = Literal["r12", "r125"]


@dataclass(frozen=True)
class ReducedHistoryConfig:
    state_bits: int
    history_bits: int
    persistent_bits: int
    target_round: int = 2
    state_count: int = 2

    def __post_init__(self) -> None:
        for name, value in (
            ("state_bits", self.state_bits),
            ("history_bits", self.history_bits),
            ("persistent_bits", self.persistent_bits),
        ):
            if isinstance(value, bool) or not isinstance(value, int):
                raise TypeError(f"{name} must be int")
            if not 1 <= value <= 64:
                raise ValueError(f"{name} must be in [1, 64]")
        for name, value, minimum in (
            ("target_round", self.target_round, 0),
            ("state_count", self.state_count, 1),
        ):
            if isinstance(value, bool) or not isinstance(value, int):
                raise TypeError(f"{name} must be int")
            if not minimum <= value <= 64:
                raise ValueError(f"{name} is out of range")

    @property
    def transition_count(self) -> int:
        return self.target_round + self.state_count - 1


@dataclass(frozen=True)
class ReducedTrace:
    construction: Construction
    candidate: int
    persistent: int
    states: tuple[int, ...]
    histories: tuple[int, ...]
    window: tuple[int, ...]

    def __post_init__(self) -> None:
        if self.construction == "r125":
            if len(self.histories) != len(self.states):
                raise ValueError("R12.5 trace requires one history per state")
        elif self.histories:
            raise ValueError("R12 trace must not carry causal history")


@dataclass(frozen=True)
class Crossing:
    left_candidate: int
    right_candidate: int
    round_index: int
    state: int
    left_history: int
    right_history: int


@dataclass(frozen=True)
class FullStateCollision:
    left_candidate: int
    right_candidate: int
    round_index: int
    history: int
    state: int


@dataclass(frozen=True)
class HistoryMapProfile:
    history_bits: int
    state_bits: int
    inputs: int
    r12_visible_image_size: int
    r125_visible_image_size: int
    r125_full_image_size: int
    r125_visible_collision_pairs: int
    r125_full_collision_pairs: int


def _candidate_bytes(candidate: int) -> bytes:
    if isinstance(candidate, bool) or not isinstance(candidate, int):
        raise TypeError("candidate must be int")
    if not 0 <= candidate < (1 << 128):
        raise ValueError("candidate must fit uint128")
    return candidate.to_bytes(16, "big")


def _frame(label: bytes, *parts: bytes) -> bytes:
    if not isinstance(label, bytes) or not label:
        raise ValueError("label must be non-empty bytes")
    encoded = [len(label).to_bytes(2, "big"), label]
    for part in parts:
        if not isinstance(part, bytes):
            raise TypeError("frame parts must be bytes")
        encoded.extend((len(part).to_bytes(4, "big"), part))
    return b"".join(encoded)


def r12_round_query(
    config: ReducedHistoryConfig,
    persistent: int,
    state: int,
    round_index: int,
) -> bytes:
    return _frame(
        b"R13-R12-ROUND",
        encode_integer(persistent, config.persistent_bits),
        round_index.to_bytes(8, "big"),
        encode_integer(state, config.state_bits),
    )


def r125_round_query(
    config: ReducedHistoryConfig,
    persistent: int,
    history: int,
    state: int,
    round_index: int,
) -> bytes:
    return _frame(
        b"R13-R125-ROUND",
        encode_integer(persistent, config.persistent_bits),
        round_index.to_bytes(8, "big"),
        encode_integer(history, config.history_bits),
        encode_integer(state, config.state_bits),
    )


def history_step_query(
    config: ReducedHistoryConfig,
    persistent: int,
    history: int,
    state: int,
    round_index: int,
) -> bytes:
    return _frame(
        b"R13-HISTORY-STEP",
        encode_integer(persistent, config.persistent_bits),
        round_index.to_bytes(8, "big"),
        encode_integer(history, config.history_bits),
        encode_integer(state, config.state_bits),
    )


def r12_successor(
    oracle: ReducedOracle,
    config: ReducedHistoryConfig,
    persistent: int,
    state: int,
    round_index: int,
) -> int:
    return oracle.query(
        "r13-r12-round",
        config.state_bits,
        r12_round_query(config, persistent, state, round_index),
    )


def r125_successor(
    oracle: ReducedOracle,
    config: ReducedHistoryConfig,
    persistent: int,
    history: int,
    state: int,
    round_index: int,
) -> int:
    return oracle.query(
        "r13-r125-round",
        config.state_bits,
        r125_round_query(config, persistent, history, state, round_index),
    )


def history_successor(
    oracle: ReducedOracle,
    config: ReducedHistoryConfig,
    persistent: int,
    history: int,
    state: int,
    round_index: int,
) -> int:
    return oracle.query(
        "r13-history-step",
        config.history_bits,
        history_step_query(config, persistent, history, state, round_index),
    )


def evaluate_reduced_history(
    oracle: ReducedOracle,
    config: ReducedHistoryConfig,
    candidate: int,
    construction: Construction,
) -> ReducedTrace:
    if construction not in ("r12", "r125"):
        raise ValueError("construction must be 'r12' or 'r125'")
    candidate_bytes = _candidate_bytes(candidate)
    persistent = oracle.query(
        "r13-persistent",
        config.persistent_bits,
        candidate_bytes,
    )
    persistent_bytes = encode_integer(persistent, config.persistent_bits)
    state = oracle.query(
        "r13-init",
        config.state_bits,
        candidate_bytes,
        persistent_bytes,
    )
    states = [state]

    histories: list[int] = []
    history = 0
    if construction == "r125":
        history = oracle.query(
            "r13-history-seed",
            config.history_bits,
            persistent_bytes,
        )
        histories.append(history)

    for round_index in range(config.transition_count):
        prior_state = state
        if construction == "r125":
            state = r125_successor(
                oracle,
                config,
                persistent,
                history,
                prior_state,
                round_index,
            )
            history = history_successor(
                oracle,
                config,
                persistent,
                history,
                prior_state,
                round_index,
            )
            histories.append(history)
        else:
            state = r12_successor(
                oracle,
                config,
                persistent,
                prior_state,
                round_index,
            )
        states.append(state)

    state_tuple = tuple(states)
    return ReducedTrace(
        construction=construction,
        candidate=candidate,
        persistent=persistent,
        states=state_tuple,
        histories=tuple(histories),
        window=state_tuple[
            config.target_round : config.target_round + config.state_count
        ],
    )


def find_visible_state_crossings(
    oracle: ReducedOracle,
    config: ReducedHistoryConfig,
    *,
    round_index: int,
    candidates: int,
    limit: int = 32,
) -> tuple[Crossing, ...]:
    """Find R12.5 pairs with equal S_i but distinct H_i."""

    if not 0 <= round_index <= config.transition_count:
        raise ValueError("round_index is outside the trace")
    if candidates <= 1 or limit <= 0:
        raise ValueError("candidates and limit must be positive")

    buckets: dict[int, list[ReducedTrace]] = defaultdict(list)
    crossings: list[Crossing] = []
    for candidate in range(candidates):
        trace = evaluate_reduced_history(oracle, config, candidate, "r125")
        state = trace.states[round_index]
        for prior in buckets[state]:
            if prior.histories[round_index] != trace.histories[round_index]:
                crossings.append(
                    Crossing(
                        prior.candidate,
                        trace.candidate,
                        round_index,
                        state,
                        prior.histories[round_index],
                        trace.histories[round_index],
                    )
                )
                if len(crossings) >= limit:
                    return tuple(crossings)
        buckets[state].append(trace)
    return tuple(crossings)


def find_full_state_collisions(
    oracle: ReducedOracle,
    config: ReducedHistoryConfig,
    *,
    round_index: int,
    candidates: int,
    limit: int = 32,
) -> tuple[FullStateCollision, ...]:
    """Find R12.5 pairs equal in the complete reduced state (H_i,S_i)."""

    if not 0 <= round_index <= config.transition_count:
        raise ValueError("round_index is outside the trace")
    if candidates <= 1 or limit <= 0:
        raise ValueError("candidates and limit must be positive")

    buckets: dict[tuple[int, int], list[ReducedTrace]] = defaultdict(list)
    collisions: list[FullStateCollision] = []
    for candidate in range(candidates):
        trace = evaluate_reduced_history(oracle, config, candidate, "r125")
        key = (trace.histories[round_index], trace.states[round_index])
        for prior in buckets[key]:
            collisions.append(
                FullStateCollision(
                    prior.candidate,
                    trace.candidate,
                    round_index,
                    key[0],
                    key[1],
                )
            )
            if len(collisions) >= limit:
                return tuple(collisions)
        buckets[key].append(trace)
    return tuple(collisions)


def _collision_pairs(values: list[int] | list[tuple[int, int]]) -> int:
    counts = Counter(values)
    return sum(count * (count - 1) // 2 for count in counts.values())


def profile_history_map(
    oracle: ReducedOracle,
    config: ReducedHistoryConfig,
    *,
    persistent: int,
    state: int,
    round_index: int,
) -> HistoryMapProfile:
    """Exhaustively compare fixed-binding R12 against all reduced histories.

    Intended for HIST-01/HIST-02/HIST-05. The enumeration is deliberately
    capped so that callers cannot accidentally launch an infeasible sweep.
    """

    if config.history_bits > 20:
        raise ValueError("exhaustive history map is limited to <=20 bits")
    if not 0 <= round_index < config.transition_count:
        raise ValueError("round_index is outside transition range")

    histories = range(1 << config.history_bits)
    r12_value = r12_successor(oracle, config, persistent, state, round_index)
    r125_visible: list[int] = []
    r125_full: list[tuple[int, int]] = []
    for history in histories:
        next_state = r125_successor(
            oracle,
            config,
            persistent,
            history,
            state,
            round_index,
        )
        next_history = history_successor(
            oracle,
            config,
            persistent,
            history,
            state,
            round_index,
        )
        r125_visible.append(next_state)
        r125_full.append((next_history, next_state))

    return HistoryMapProfile(
        history_bits=config.history_bits,
        state_bits=config.state_bits,
        inputs=1 << config.history_bits,
        r12_visible_image_size=len({r12_value}),
        r125_visible_image_size=len(set(r125_visible)),
        r125_full_image_size=len(set(r125_full)),
        r125_visible_collision_pairs=_collision_pairs(r125_visible),
        r125_full_collision_pairs=_collision_pairs(r125_full),
    )


__all__ = [
    "Construction",
    "Crossing",
    "FullStateCollision",
    "HistoryMapProfile",
    "ReducedHistoryConfig",
    "ReducedTrace",
    "evaluate_reduced_history",
    "find_full_state_collisions",
    "find_visible_state_crossings",
    "history_step_query",
    "history_successor",
    "profile_history_map",
    "r12_round_query",
    "r12_successor",
    "r125_round_query",
    "r125_successor",
]
