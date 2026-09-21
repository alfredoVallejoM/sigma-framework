"""R15 pre-data execution closure for history games.

These executors complete endpoints frozen by R13/R14. They are deterministic
reduced-model tools and must not be run with confirmatory seeds before TAG-01.
"""

from __future__ import annotations

from collections import Counter
from dataclasses import dataclass
from typing import Literal

from .history_reduced import ReducedHistoryConfig, history_successor, r125_successor
from .reduced_oracle import ReducedOracle

HistoryGame = Literal["collision", "second-preimage", "fixed-point", "cycle"]


@dataclass(frozen=True)
class HistoryGameResultV3:
    game: HistoryGame
    history_bits: int
    queries: int
    success: bool
    collision_pairs: int
    cycles: int
    max_cycle_length: int
    max_tail_length: int
    witness_left: int | None = None
    witness_right: int | None = None


@dataclass(frozen=True)
class ConditionalCrossingResultV3:
    trials: int
    visible_successor_matches: int
    full_state_matches: int

    @property
    def visible_match_rate(self) -> float:
        return self.visible_successor_matches / self.trials

    @property
    def full_state_match_rate(self) -> float:
        return self.full_state_matches / self.trials


def _functional_graph_stats(outputs: list[int]) -> tuple[int, int, int]:
    seen_cycles: set[tuple[int, ...]] = set()
    max_cycle = 0
    max_tail = 0
    for start in range(len(outputs)):
        path: list[int] = []
        positions: dict[int, int] = {}
        current = start
        while current not in positions and 0 <= current < len(outputs):
            positions[current] = len(path)
            path.append(current)
            current = outputs[current]
        if current in positions:
            cycle = tuple(path[positions[current] :])
            if cycle:
                rotations = tuple(cycle[i:] + cycle[:i] for i in range(len(cycle)))
                seen_cycles.add(min(rotations))
                max_cycle = max(max_cycle, len(cycle))
                max_tail = max(max_tail, positions[current])
        else:
            max_tail = max(max_tail, len(path))
    return len(seen_cycles), max_cycle, max_tail


def profile_history_game_v3(
    oracle: ReducedOracle,
    config: ReducedHistoryConfig,
    *,
    persistent: int,
    state: int,
    round_index: int,
    game: HistoryGame,
    input_budget: int,
    target_history: int = 0,
) -> HistoryGameResultV3:
    if game not in ("collision", "second-preimage", "fixed-point", "cycle"):
        raise ValueError("unsupported history game")
    if input_budget <= 0:
        raise ValueError("input_budget must be positive")
    space = 1 << config.history_bits
    limit = min(space, input_budget)

    outputs = [
        history_successor(oracle, config, persistent, history, state, round_index)
        for history in range(limit)
    ]
    counts = Counter(outputs)
    pairs = sum(count * (count - 1) // 2 for count in counts.values())

    if game == "collision":
        first: dict[int, int] = {}
        for history, output in enumerate(outputs):
            prior = first.get(output)
            if prior is not None and prior != history:
                return HistoryGameResultV3(
                    game,
                    config.history_bits,
                    history + 1,
                    True,
                    pairs,
                    0,
                    0,
                    0,
                    prior,
                    history,
                )
            first[output] = history
        return HistoryGameResultV3(
            game, config.history_bits, limit, False, pairs, 0, 0, 0
        )

    if game == "second-preimage":
        if not 0 <= target_history < limit:
            raise ValueError("target_history must lie inside the enumerated domain")
        target = outputs[target_history]
        for history, output in enumerate(outputs):
            if history != target_history and output == target:
                return HistoryGameResultV3(
                    game,
                    config.history_bits,
                    history + 1,
                    True,
                    pairs,
                    0,
                    0,
                    0,
                    target_history,
                    history,
                )
        return HistoryGameResultV3(
            game, config.history_bits, limit, False, pairs, 0, 0, 0
        )

    if game == "fixed-point":
        for history, output in enumerate(outputs):
            if output == history:
                return HistoryGameResultV3(
                    game,
                    config.history_bits,
                    history + 1,
                    True,
                    pairs,
                    1,
                    1,
                    0,
                    history,
                    history,
                )
        return HistoryGameResultV3(
            game, config.history_bits, limit, False, pairs, 0, 0, 0
        )

    cycles, max_cycle, max_tail = _functional_graph_stats(outputs)
    return HistoryGameResultV3(
        game,
        config.history_bits,
        limit,
        cycles > 0,
        pairs,
        cycles,
        max_cycle,
        max_tail,
    )


def conditional_crossing_trials_v3(
    oracle: ReducedOracle,
    config: ReducedHistoryConfig,
    *,
    round_index: int,
    trials: int,
) -> ConditionalCrossingResultV3:
    """Evaluate non-coalescence conditional on an equal visible state."""

    if trials <= 0:
        raise ValueError("trials must be positive")
    mask_p = (1 << config.persistent_bits) - 1
    mask_s = (1 << config.state_bits) - 1
    mask_h = (1 << config.history_bits) - 1
    visible_matches = 0
    full_matches = 0

    for trial in range(trials):
        tag = trial.to_bytes(8, "big")
        persistent = oracle.query("r15-crossing-p", config.persistent_bits, tag) & mask_p
        state = oracle.query("r15-crossing-s", config.state_bits, tag) & mask_s
        left_history = oracle.query("r15-crossing-h0", config.history_bits, tag) & mask_h
        right_history = oracle.query("r15-crossing-h1", config.history_bits, tag) & mask_h
        if right_history == left_history:
            right_history = (right_history + 1) & mask_h

        left_state = r125_successor(
            oracle, config, persistent, left_history, state, round_index
        )
        right_state = r125_successor(
            oracle, config, persistent, right_history, state, round_index
        )
        left_next_history = history_successor(
            oracle, config, persistent, left_history, state, round_index
        )
        right_next_history = history_successor(
            oracle, config, persistent, right_history, state, round_index
        )
        visible_matches += int(left_state == right_state)
        full_matches += int(
            (left_next_history, left_state) == (right_next_history, right_state)
        )

    return ConditionalCrossingResultV3(trials, visible_matches, full_matches)


__all__ = [
    "ConditionalCrossingResultV3",
    "HistoryGame",
    "HistoryGameResultV3",
    "conditional_crossing_trials_v3",
    "profile_history_game_v3",
]
