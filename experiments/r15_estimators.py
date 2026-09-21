"""Frozen statistical estimators for R15 confirmatory analysis."""

from __future__ import annotations

import hashlib
import math
import random
from dataclasses import dataclass
from typing import Iterable, Sequence

PRIMARY_ALPHA = 0.05
RARE_EVENT_ALPHA = 0.01
BOOTSTRAP_REPLICATES = 10_000


@dataclass(frozen=True)
class SurvivalPointV3:
    time: int
    at_risk: int
    events: int
    censored: int
    survival: float


@dataclass(frozen=True)
class IntervalV3:
    lower: float
    upper: float
    level: float


def clopper_pearson_interval_v3(
    successes: int,
    trials: int,
    *,
    level: float = 0.95,
) -> IntervalV3:
    if trials <= 0 or not 0 <= successes <= trials:
        raise ValueError("invalid binomial counts")
    if not 0.0 < level < 1.0:
        raise ValueError("level must be in (0,1)")
    alpha = 1.0 - level
    try:
        from scipy.stats import beta
    except ImportError as exc:
        raise RuntimeError("Clopper-Pearson requires the analysis extra") from exc
    lower = 0.0 if successes == 0 else float(beta.ppf(alpha / 2, successes, trials - successes + 1))
    upper = (
        1.0
        if successes == trials
        else float(beta.ppf(1 - alpha / 2, successes + 1, trials - successes))
    )
    return IntervalV3(lower, upper, level)


def zero_event_upper_bound_v3(
    trials: int,
    *,
    level: float = 0.99,
) -> float:
    if trials <= 0:
        raise ValueError("trials must be positive")
    if not 0.0 < level < 1.0:
        raise ValueError("level must be in (0,1)")
    alpha = 1.0 - level
    return 1.0 - alpha ** (1.0 / trials)


def kaplan_meier_v3(
    times: Sequence[int],
    events: Sequence[bool],
) -> tuple[SurvivalPointV3, ...]:
    if len(times) != len(events) or not times:
        raise ValueError("times/events must be equal and non-empty")
    if any(time < 0 for time in times):
        raise ValueError("times must be non-negative")

    grouped: dict[int, list[int]] = {}
    for time, event in zip(times, events, strict=True):
        counts = grouped.setdefault(time, [0, 0])
        counts[0 if event else 1] += 1

    at_risk = len(times)
    survival = 1.0
    points: list[SurvivalPointV3] = []
    for time in sorted(grouped):
        event_count, censored_count = grouped[time]
        if at_risk <= 0:
            break
        if event_count:
            survival *= 1.0 - event_count / at_risk
        points.append(
            SurvivalPointV3(
                time=time,
                at_risk=at_risk,
                events=event_count,
                censored=censored_count,
                survival=survival,
            )
        )
        at_risk -= event_count + censored_count
    return tuple(points)


def km_q50_v3(points: Sequence[SurvivalPointV3]) -> int | None:
    for point in points:
        if point.survival <= 0.5:
            return point.time
    return None


def km_rmst_v3(
    points: Sequence[SurvivalPointV3],
    *,
    tau: int,
) -> float:
    if tau < 0:
        raise ValueError("tau must be non-negative")
    area = 0.0
    previous_time = 0
    previous_survival = 1.0
    for point in points:
        if point.time > tau:
            break
        area += (point.time - previous_time) * previous_survival
        previous_time = point.time
        previous_survival = point.survival
    area += max(0, tau - previous_time) * previous_survival
    return area


def _bootstrap_rng(label: str) -> random.Random:
    digest = hashlib.sha256(b"sigma-v3-r15-analysis\0" + label.encode("utf-8")).digest()
    return random.Random(int.from_bytes(digest, "big"))


def _percentile(values: list[float], probability: float) -> float:
    if not values:
        raise ValueError("values must be non-empty")
    if not 0.0 <= probability <= 1.0:
        raise ValueError("probability must be in [0,1]")
    ordered = sorted(values)
    if len(ordered) == 1:
        return ordered[0]
    position = probability * (len(ordered) - 1)
    low = math.floor(position)
    high = math.ceil(position)
    if low == high:
        return ordered[low]
    weight = position - low
    return ordered[low] * (1 - weight) + ordered[high] * weight


def bootstrap_mean_interval_v3(
    values: Sequence[float],
    *,
    label: str,
    replicates: int = BOOTSTRAP_REPLICATES,
    level: float = 0.95,
) -> IntervalV3:
    if not values:
        raise ValueError("values must be non-empty")
    if replicates <= 0:
        raise ValueError("replicates must be positive")
    if not 0.0 < level < 1.0:
        raise ValueError("level must be in (0,1)")
    rng = _bootstrap_rng(label)
    n = len(values)
    estimates: list[float] = []
    for _ in range(replicates):
        sample = [values[rng.randrange(n)] for _ in range(n)]
        estimates.append(sum(sample) / n)
    alpha = 1.0 - level
    return IntervalV3(
        _percentile(estimates, alpha / 2),
        _percentile(estimates, 1 - alpha / 2),
        level,
    )


def paired_bootstrap_ratio_interval_v3(
    numerator: Sequence[float],
    denominator: Sequence[float],
    *,
    label: str,
    replicates: int = BOOTSTRAP_REPLICATES,
    level: float = 0.95,
) -> IntervalV3:
    if len(numerator) != len(denominator) or not numerator:
        raise ValueError("paired inputs must be equal and non-empty")
    if any(value <= 0 for value in denominator):
        raise ValueError("denominator values must be positive")
    rng = _bootstrap_rng(label)
    n = len(numerator)
    ratios: list[float] = []
    for _ in range(replicates):
        indices = [rng.randrange(n) for _ in range(n)]
        num = sum(numerator[index] for index in indices) / n
        den = sum(denominator[index] for index in indices) / n
        ratios.append(num / den)
    alpha = 1.0 - level
    return IntervalV3(
        _percentile(ratios, alpha / 2),
        _percentile(ratios, 1 - alpha / 2),
        level,
    )


def holm_adjust_v3(p_values: Sequence[float]) -> tuple[float, ...]:
    if any(not 0.0 <= value <= 1.0 for value in p_values):
        raise ValueError("p-values must be in [0,1]")
    indexed = sorted(enumerate(p_values), key=lambda item: item[1])
    adjusted = [0.0] * len(p_values)
    running = 0.0
    total = len(p_values)
    for rank, (index, value) in enumerate(indexed):
        candidate = min(1.0, (total - rank) * value)
        running = max(running, candidate)
        adjusted[index] = running
    return tuple(adjusted)


def pareto_frontier_v3(
    points: Iterable[tuple[int, int, int]],
) -> tuple[tuple[int, int, int], ...]:
    values = tuple(points)
    if any(any(component < 0 for component in point) for point in values):
        raise ValueError("Pareto coordinates must be non-negative")
    frontier: list[tuple[int, int, int]] = []
    for point in values:
        dominated = any(
            other != point
            and all(a <= b for a, b in zip(other, point, strict=True))
            and any(a < b for a, b in zip(other, point, strict=True))
            for other in values
        )
        if not dominated:
            frontier.append(point)
    return tuple(sorted(set(frontier)))


__all__ = [
    "BOOTSTRAP_REPLICATES",
    "PRIMARY_ALPHA",
    "RARE_EVENT_ALPHA",
    "IntervalV3",
    "SurvivalPointV3",
    "bootstrap_mean_interval_v3",
    "clopper_pearson_interval_v3",
    "holm_adjust_v3",
    "kaplan_meier_v3",
    "km_q50_v3",
    "km_rmst_v3",
    "paired_bootstrap_ratio_interval_v3",
    "pareto_frontier_v3",
    "zero_event_upper_bound_v3",
]
