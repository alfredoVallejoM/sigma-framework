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



def _linear_slope(xs: Sequence[float], ys: Sequence[float]) -> float:
    if len(xs) != len(ys) or len(xs) < 2:
        raise ValueError("slope inputs must be equal with at least two points")
    x_mean = sum(xs) / len(xs)
    y_mean = sum(ys) / len(ys)
    denominator = sum((x - x_mean) ** 2 for x in xs)
    if denominator == 0:
        raise ValueError("slope x-axis has zero variance")
    return sum((x - x_mean) * (y - y_mean) for x, y in zip(xs, ys, strict=True)) / denominator


def scaling_slope_v3(
    xs: Sequence[float],
    works: Sequence[float],
) -> float:
    if any(work <= 0 for work in works):
        raise ValueError("work values must be positive")
    return _linear_slope(xs, [math.log2(work) for work in works])


def bootstrap_survival_statistic_v3(
    times: Sequence[int],
    events: Sequence[bool],
    *,
    statistic: str,
    label: str,
    tau: int | None = None,
    replicates: int = BOOTSTRAP_REPLICATES,
    level: float = 0.95,
) -> IntervalV3:
    if len(times) != len(events) or not times:
        raise ValueError("times/events must be equal and non-empty")
    if statistic not in ("q50", "rmst"):
        raise ValueError("statistic must be q50 or rmst")
    if statistic == "rmst" and tau is None:
        raise ValueError("RMST bootstrap requires tau")
    rng = _bootstrap_rng(label)
    n = len(times)
    estimates: list[float] = []
    for _ in range(replicates):
        indices = [rng.randrange(n) for _ in range(n)]
        sample_times = [times[index] for index in indices]
        sample_events = [events[index] for index in indices]
        curve = kaplan_meier_v3(sample_times, sample_events)
        if statistic == "q50":
            estimate = km_q50_v3(curve)
            if estimate is None:
                continue
            estimates.append(float(estimate))
        else:
            assert tau is not None
            estimates.append(km_rmst_v3(curve, tau=tau))
    if len(estimates) < max(100, int(0.8 * replicates)):
        raise ValueError("too many bootstrap samples have a non-estimable survival statistic")
    alpha = 1.0 - level
    return IntervalV3(
        _percentile(estimates, alpha / 2),
        _percentile(estimates, 1 - alpha / 2),
        level,
    )


@dataclass(frozen=True)
class ScalingCellV3:
    x: float
    times: tuple[int, ...]
    events: tuple[bool, ...]

    def __post_init__(self) -> None:
        if len(self.times) != len(self.events) or not self.times:
            raise ValueError("scaling cell survival data must be equal and non-empty")


def bootstrap_scaling_slope_interval_v3(
    cells: Sequence[ScalingCellV3],
    *,
    label: str,
    replicates: int = BOOTSTRAP_REPLICATES,
    level: float = 0.95,
) -> IntervalV3:
    if len(cells) < 2:
        raise ValueError("scaling bootstrap requires at least two cells")
    observed_x = [cell.x for cell in cells]
    if len(set(observed_x)) != len(observed_x):
        raise ValueError("scaling x coordinates must be unique")
    rng = _bootstrap_rng(label)
    slopes: list[float] = []
    for _ in range(replicates):
        q50s: list[float] = []
        xs: list[float] = []
        for cell in cells:
            n = len(cell.times)
            indices = [rng.randrange(n) for _ in range(n)]
            curve = kaplan_meier_v3(
                [cell.times[index] for index in indices],
                [cell.events[index] for index in indices],
            )
            q50 = km_q50_v3(curve)
            if q50 is None:
                break
            xs.append(cell.x)
            q50s.append(float(q50))
        if len(q50s) == len(cells):
            slopes.append(scaling_slope_v3(xs, q50s))
    if len(slopes) < max(100, int(0.8 * replicates)):
        raise ValueError("too many bootstrap slope samples are non-estimable")
    alpha = 1.0 - level
    return IntervalV3(
        _percentile(slopes, alpha / 2),
        _percentile(slopes, 1 - alpha / 2),
        level,
    )


@dataclass(frozen=True)
class SimultaneousBandPointV3:
    x: float
    estimate: float
    lower: float
    upper: float


def simultaneous_mean_band_v3(
    groups: Sequence[tuple[float, Sequence[float]]],
    *,
    label: str,
    replicates: int = BOOTSTRAP_REPLICATES,
    level: float = 0.95,
) -> tuple[SimultaneousBandPointV3, ...]:
    if len(groups) < 2:
        raise ValueError("simultaneous band requires at least two groups")
    if any(not values for _x, values in groups):
        raise ValueError("simultaneous band groups must be non-empty")
    estimates = [sum(values) / len(values) for _x, values in groups]
    rng = _bootstrap_rng(label)
    max_deviations: list[float] = []
    for _ in range(replicates):
        deviations: list[float] = []
        for estimate, (_x, values) in zip(estimates, groups, strict=True):
            n = len(values)
            sample_mean = sum(values[rng.randrange(n)] for _ in range(n)) / n
            deviations.append(abs(sample_mean - estimate))
        max_deviations.append(max(deviations))
    radius = _percentile(max_deviations, level)
    return tuple(
        SimultaneousBandPointV3(x, estimate, estimate - radius, estimate + radius)
        for estimate, (x, _values) in zip(estimates, groups, strict=True)
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
    "ScalingCellV3",
    "SimultaneousBandPointV3",
    "SurvivalPointV3",
    "bootstrap_mean_interval_v3",
    "bootstrap_scaling_slope_interval_v3",
    "bootstrap_survival_statistic_v3",
    "clopper_pearson_interval_v3",
    "holm_adjust_v3",
    "kaplan_meier_v3",
    "km_q50_v3",
    "km_rmst_v3",
    "paired_bootstrap_ratio_interval_v3",
    "pareto_frontier_v3",
    "scaling_slope_v3",
    "simultaneous_mean_band_v3",
    "zero_event_upper_bound_v3",
]
