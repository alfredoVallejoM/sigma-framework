"""Reduced R13 parameter/grinding models.

These functions model selection effects around public trajectory parameters.
They do not instantiate the production hash functions and do not produce
security claims.
"""

from __future__ import annotations

import statistics
from collections import Counter
from dataclasses import dataclass

from .reduced_oracle import ReducedOracle, encode_integer


@dataclass(frozen=True)
class ParameterSpaceV3:
    t_min: int = 2
    t_max: int = 32
    k_min: int = 2
    k_max: int = 4

    def __post_init__(self) -> None:
        for name in ("t_min", "t_max", "k_min", "k_max"):
            value = getattr(self, name)
            if isinstance(value, bool) or not isinstance(value, int):
                raise TypeError(f"{name} must be int")
        if self.t_min < 0 or self.t_max < self.t_min:
            raise ValueError("invalid t range")
        if self.k_min < 1 or self.k_max < self.k_min:
            raise ValueError("invalid k range")

    @property
    def pair_count(self) -> int:
        return (self.t_max - self.t_min + 1) * (self.k_max - self.k_min + 1)


DEFAULT_PARAMETER_SPACE_V3 = ParameterSpaceV3()


class _ParameterReader:
    def __init__(self, oracle: ReducedOracle, persistent: int, persistent_bits: int) -> None:
        self._oracle = oracle
        self._persistent = encode_integer(persistent, persistent_bits)
        self._counter = 0
        self.queries = 0

    def read(self, length: int) -> bytes:
        if isinstance(length, bool) or not isinstance(length, int) or length < 0:
            raise ValueError("length must be a non-negative int")
        output = bytearray()
        for _ in range(length):
            output.append(
                self._oracle.query(
                    "r13-parameter-byte",
                    8,
                    self._persistent,
                    self._counter.to_bytes(8, "big"),
                )
            )
            self._counter += 1
            self.queries += 1
        return bytes(output)


def _sample_uniform(reader: _ParameterReader, minimum: int, maximum: int) -> int:
    width = maximum - minimum + 1
    count = max(1, ((width - 1).bit_length() + 7) // 8)
    space = 1 << (8 * count)
    limit = space - space % width
    while True:
        candidate = int.from_bytes(reader.read(count), "big")
        if candidate < limit:
            return minimum + candidate % width


@dataclass(frozen=True)
class DerivedParametersV3:
    candidate: int
    persistent: int
    t: int
    k: int
    parameter_queries: int

    @property
    def transition_cost(self) -> int:
        return self.t + self.k - 1


@dataclass(frozen=True)
class GrindingProfileV3:
    attempts: int
    selected_candidate: int
    t: int
    k: int
    transition_cost: int
    preparation_queries: int
    parameter_queries: int


@dataclass(frozen=True)
class EarlyRejectionProfileV3:
    guesses: int
    early_rejected: int
    full_trajectory_guesses: int
    round_queries_saved: int
    parameter_queries: int


@dataclass(frozen=True)
class NonceGrindingProfileV3:
    nonces: int
    best_nonce: int
    best_t: int
    best_k: int
    best_cost: int
    mean_cost: float
    parameter_queries: int


@dataclass(frozen=True)
class ParameterCorrelationProfileV3:
    samples: int
    candidate_t: float
    candidate_k: float
    persistent_t: float
    persistent_k: float


@dataclass(frozen=True)
class MitigationProfileV3:
    samples: int
    derived_mean_cost: float
    derived_variance: float
    derived_min_cost: int
    derived_max_cost: int
    fixed_cost: int
    fixed_variance: float


def _pearson(left: list[float], right: list[float]) -> float:
    if len(left) != len(right) or not left:
        raise ValueError("correlation inputs must be equal and non-empty")
    left_mean = statistics.fmean(left)
    right_mean = statistics.fmean(right)
    numerator = sum((x - left_mean) * (y - right_mean) for x, y in zip(left, right, strict=True))
    left_norm = sum((x - left_mean) ** 2 for x in left)
    right_norm = sum((y - right_mean) ** 2 for y in right)
    if left_norm == 0.0 or right_norm == 0.0:
        return 0.0
    return numerator / (left_norm * right_norm) ** 0.5


def derive_parameters_reduced(
    oracle: ReducedOracle,
    candidate: int,
    *,
    persistent_bits: int = 16,
    space: ParameterSpaceV3 = DEFAULT_PARAMETER_SPACE_V3,
) -> DerivedParametersV3:
    if isinstance(candidate, bool) or not isinstance(candidate, int) or candidate < 0:
        raise ValueError("candidate must be a non-negative int")
    if not 1 <= persistent_bits <= 64:
        raise ValueError("persistent_bits must be in [1,64]")
    candidate_bytes = candidate.to_bytes(max(1, (candidate.bit_length() + 7) // 8), "big")
    persistent = oracle.query("r13-parameter-persistent", persistent_bits, candidate_bytes)
    reader = _ParameterReader(oracle, persistent, persistent_bits)
    t = _sample_uniform(reader, space.t_min, space.t_max)
    k = _sample_uniform(reader, space.k_min, space.k_max)
    return DerivedParametersV3(candidate, persistent, t, k, reader.queries)


def parameter_distribution(
    oracle: ReducedOracle,
    candidates: int,
    *,
    persistent_bits: int = 16,
    space: ParameterSpaceV3 = DEFAULT_PARAMETER_SPACE_V3,
) -> dict[tuple[int, int], int]:
    if candidates <= 0:
        raise ValueError("candidates must be positive")
    counts: Counter[tuple[int, int]] = Counter()
    for candidate in range(candidates):
        value = derive_parameters_reduced(
            oracle, candidate, persistent_bits=persistent_bits, space=space
        )
        counts[(value.t, value.k)] += 1
    return dict(counts)


def parameter_correlation_profile(
    oracle: ReducedOracle,
    candidates: int,
    *,
    persistent_bits: int = 16,
    space: ParameterSpaceV3 = DEFAULT_PARAMETER_SPACE_V3,
) -> ParameterCorrelationProfileV3:
    if candidates < 2:
        raise ValueError("candidates must be at least two")
    values = [
        derive_parameters_reduced(
            oracle,
            candidate,
            persistent_bits=persistent_bits,
            space=space,
        )
        for candidate in range(candidates)
    ]
    candidate_axis = [float(value.candidate) for value in values]
    persistent_axis = [float(value.persistent) for value in values]
    t_axis = [float(value.t) for value in values]
    k_axis = [float(value.k) for value in values]
    return ParameterCorrelationProfileV3(
        samples=candidates,
        candidate_t=_pearson(candidate_axis, t_axis),
        candidate_k=_pearson(candidate_axis, k_axis),
        persistent_t=_pearson(persistent_axis, t_axis),
        persistent_k=_pearson(persistent_axis, k_axis),
    )


def mitigation_profile(
    oracle: ReducedOracle,
    candidates: int,
    *,
    fixed_t: int,
    fixed_k: int,
    persistent_bits: int = 16,
    space: ParameterSpaceV3 = DEFAULT_PARAMETER_SPACE_V3,
) -> MitigationProfileV3:
    if candidates <= 0:
        raise ValueError("candidates must be positive")
    if not (space.t_min <= fixed_t <= space.t_max):
        raise ValueError("fixed_t is outside the registered range")
    if not (space.k_min <= fixed_k <= space.k_max):
        raise ValueError("fixed_k is outside the registered range")
    costs = [
        derive_parameters_reduced(
            oracle,
            candidate,
            persistent_bits=persistent_bits,
            space=space,
        ).transition_cost
        for candidate in range(candidates)
    ]
    fixed_cost = fixed_t + fixed_k - 1
    return MitigationProfileV3(
        samples=candidates,
        derived_mean_cost=statistics.fmean(costs),
        derived_variance=statistics.pvariance(costs),
        derived_min_cost=min(costs),
        derived_max_cost=max(costs),
        fixed_cost=fixed_cost,
        fixed_variance=0.0,
    )


def find_cheapest_stratum(
    oracle: ReducedOracle,
    candidates: int,
    *,
    persistent_bits: int = 16,
    space: ParameterSpaceV3 = DEFAULT_PARAMETER_SPACE_V3,
) -> GrindingProfileV3:
    if candidates <= 0:
        raise ValueError("candidates must be positive")
    best: DerivedParametersV3 | None = None
    parameter_queries = 0
    attempts = 0
    minimum_cost = space.t_min + space.k_min - 1
    for candidate in range(candidates):
        attempts += 1
        current = derive_parameters_reduced(
            oracle, candidate, persistent_bits=persistent_bits, space=space
        )
        parameter_queries += current.parameter_queries
        if best is None or current.transition_cost < best.transition_cost:
            best = current
        if current.transition_cost == minimum_cost:
            break
    assert best is not None
    return GrindingProfileV3(
        attempts=attempts,
        selected_candidate=best.candidate,
        t=best.t,
        k=best.k,
        transition_cost=best.transition_cost,
        preparation_queries=attempts,
        parameter_queries=parameter_queries,
    )


def kdf_early_rejection_profile(
    oracle: ReducedOracle,
    *,
    target_candidate: int,
    guesses: int,
    persistent_bits: int = 16,
    space: ParameterSpaceV3 = DEFAULT_PARAMETER_SPACE_V3,
) -> EarlyRejectionProfileV3:
    if guesses <= 0:
        raise ValueError("guesses must be positive")
    target = derive_parameters_reduced(
        oracle, target_candidate, persistent_bits=persistent_bits, space=space
    )
    early = 0
    full = 0
    saved = 0
    parameter_queries = 0
    for guess in range(guesses):
        current = derive_parameters_reduced(
            oracle,
            (1 << 64) + guess,
            persistent_bits=persistent_bits,
            space=space,
        )
        parameter_queries += current.parameter_queries
        if (current.t, current.k) != (target.t, target.k):
            early += 1
            saved += current.transition_cost
        else:
            full += 1
    return EarlyRejectionProfileV3(
        guesses=guesses,
        early_rejected=early,
        full_trajectory_guesses=full,
        round_queries_saved=saved,
        parameter_queries=parameter_queries,
    )


def pow_nonce_grinding_profile(
    oracle: ReducedOracle,
    nonces: int,
    *,
    persistent_bits: int = 16,
    space: ParameterSpaceV3 = DEFAULT_PARAMETER_SPACE_V3,
) -> NonceGrindingProfileV3:
    if nonces <= 0:
        raise ValueError("nonces must be positive")
    values = [
        derive_parameters_reduced(
            oracle,
            (1 << 96) + nonce,
            persistent_bits=persistent_bits,
            space=space,
        )
        for nonce in range(nonces)
    ]
    best = min(values, key=lambda value: (value.transition_cost, value.candidate))
    return NonceGrindingProfileV3(
        nonces=nonces,
        best_nonce=best.candidate - (1 << 96),
        best_t=best.t,
        best_k=best.k,
        best_cost=best.transition_cost,
        mean_cost=statistics.fmean(value.transition_cost for value in values),
        parameter_queries=sum(value.parameter_queries for value in values),
    )


__all__ = [
    "DEFAULT_PARAMETER_SPACE_V3",
    "DerivedParametersV3",
    "EarlyRejectionProfileV3",
    "GrindingProfileV3",
    "MitigationProfileV3",
    "NonceGrindingProfileV3",
    "ParameterCorrelationProfileV3",
    "ParameterSpaceV3",
    "derive_parameters_reduced",
    "find_cheapest_stratum",
    "kdf_early_rejection_profile",
    "mitigation_profile",
    "parameter_correlation_profile",
    "parameter_distribution",
    "pow_nonce_grinding_profile",
]
