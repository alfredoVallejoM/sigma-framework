"""Reduced time-memory trade-off attackers for R13."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Literal

from .history_reduced import (
    ReducedHistoryConfig,
    history_successor,
    r12_successor,
    r125_successor,
)
from .reduced_oracle import ReducedOracle

TMTOConstruction = Literal["r12", "r125"]
TMTOStrategy = Literal["direct", "distinguished", "rho", "hellman", "rainbow"]


@dataclass(frozen=True)
class TMTOConfigV3:
    bits: int
    history_bits: int
    entries: int = 128
    chain_length: int = 16
    distinguished_bits: int = 2
    targets: int = 4

    def __post_init__(self) -> None:
        for name in ("bits", "history_bits", "entries", "chain_length", "distinguished_bits", "targets"):
            value = getattr(self, name)
            if isinstance(value, bool) or not isinstance(value, int):
                raise TypeError(f"{name} must be int")
            if value <= 0:
                raise ValueError(f"{name} must be positive")
        if self.bits > 32 or self.history_bits > 32:
            raise ValueError("R13 TMTO widths are capped at 32 bits")
        if self.distinguished_bits > self.bits:
            raise ValueError("distinguished_bits exceeds state width")


@dataclass(frozen=True)
class TMTOResultV3:
    strategy: TMTOStrategy
    construction: TMTOConstruction
    offline_queries: int
    online_queries: int
    history_queries: int
    memory_entries: int
    parallel_depth: int
    reuse_rate: float
    targets: int


def _step(
    oracle: ReducedOracle,
    config: ReducedHistoryConfig,
    construction: TMTOConstruction,
    persistent: int,
    history: int,
    state: int,
    step: int,
) -> tuple[int, int]:
    if construction == "r12":
        return history, r12_successor(oracle, config, persistent, state, step)
    next_state = r125_successor(oracle, config, persistent, history, state, step)
    next_history = history_successor(oracle, config, persistent, history, state, step)
    return next_history, next_state


def _chain(
    oracle: ReducedOracle,
    config: ReducedHistoryConfig,
    construction: TMTOConstruction,
    persistent: int,
    history: int,
    state: int,
    length: int,
    *,
    rainbow: bool,
) -> tuple[tuple[int, int], ...]:
    mask = (1 << config.state_bits) - 1
    path = [(history, state)]
    for step in range(length):
        history, state = _step(
            oracle, config, construction, persistent, history, state, step
        )
        if rainbow:
            state = (state + (step + 1) * 0x9E37) & mask
        path.append((history, state))
    return tuple(path)


def measure_tmto_v3(
    oracle: ReducedOracle,
    config: TMTOConfigV3,
    strategy: TMTOStrategy,
    construction: TMTOConstruction,
) -> TMTOResultV3:
    if strategy not in ("direct", "distinguished", "rho", "hellman", "rainbow"):
        raise ValueError("unsupported TMTO strategy")
    if construction not in ("r12", "r125"):
        raise ValueError("unsupported TMTO construction")

    reduced = ReducedHistoryConfig(
        state_bits=config.bits,
        history_bits=config.history_bits,
        persistent_bits=config.bits,
        target_round=max(1, config.chain_length),
        state_count=1,
    )
    base_persistent = oracle.query("r13-tmto-persistent", config.bits, b"offline")
    base_history = oracle.query("r13-tmto-history", config.history_bits, b"offline")
    starts = [
        oracle.query("r13-tmto-start", config.bits, index.to_bytes(8, "big"))
        for index in range(config.entries)
    ]
    online_persistents = [
        oracle.query("r13-tmto-persistent", config.bits, b"target", index.to_bytes(4, "big"))
        for index in range(config.targets)
    ]

    history_factor = 0 if construction == "r12" else 1

    if strategy in ("direct", "distinguished"):
        if strategy == "distinguished":
            mask = (1 << config.distinguished_bits) - 1
            starts = [value for value in starts if value & mask == 0]
        table = {
            state: _step(
                oracle,
                reduced,
                construction,
                base_persistent,
                base_history,
                state,
                0,
            )
            for state in starts
        }
        reused = 0
        comparisons = 0
        for persistent in online_persistents:
            for state, offline_value in table.items():
                online_value = _step(
                    oracle,
                    reduced,
                    construction,
                    persistent,
                    base_history,
                    state,
                    0,
                )
                reused += int(online_value == offline_value)
                comparisons += 1
        return TMTOResultV3(
            strategy,
            construction,
            len(table),
            comparisons,
            history_factor * (len(table) + comparisons),
            len(table),
            1 if table else 0,
            reused / comparisons if comparisons else 0.0,
            config.targets,
        )

    if strategy == "rho":
        start = starts[0]
        offline = set(
            _chain(
                oracle,
                reduced,
                construction,
                base_persistent,
                base_history,
                start,
                config.chain_length,
                rainbow=False,
            )
        )
        reused = 0
        for persistent in online_persistents:
            online = _chain(
                oracle,
                reduced,
                construction,
                persistent,
                base_history,
                start,
                config.chain_length,
                rainbow=False,
            )
            reused += int(any(value in offline for value in online[1:]))
        offline_q = config.chain_length
        online_q = config.chain_length * config.targets
        return TMTOResultV3(
            strategy,
            construction,
            offline_q,
            online_q,
            history_factor * (offline_q + online_q),
            len(offline),
            config.chain_length,
            reused / config.targets,
            config.targets,
        )

    rainbow = strategy == "rainbow"
    chain_count = max(1, config.entries // config.chain_length)
    selected = starts[:chain_count]
    endpoints = {
        _chain(
            oracle,
            reduced,
            construction,
            base_persistent,
            base_history,
            start,
            config.chain_length,
            rainbow=rainbow,
        )[-1]
        for start in selected
    }
    reused = 0
    comparisons = 0
    for persistent in online_persistents:
        for start in selected:
            endpoint = _chain(
                oracle,
                reduced,
                construction,
                persistent,
                base_history,
                start,
                config.chain_length,
                rainbow=rainbow,
            )[-1]
            reused += int(endpoint in endpoints)
            comparisons += 1
    offline_q = len(selected) * config.chain_length
    online_q = comparisons * config.chain_length
    return TMTOResultV3(
        strategy,
        construction,
        offline_q,
        online_q,
        history_factor * (offline_q + online_q),
        len(endpoints),
        config.chain_length,
        reused / comparisons if comparisons else 0.0,
        config.targets,
    )


__all__ = [
    "TMTOConfigV3",
    "TMTOConstruction",
    "TMTOResultV3",
    "TMTOStrategy",
    "measure_tmto_v3",
]
