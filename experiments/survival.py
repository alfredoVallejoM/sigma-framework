"""Small dependency-free Kaplan-Meier helpers for censored search experiments."""

from typing import Any


def kaplan_meier(durations: list[int], events: list[bool]) -> list[dict[str, Any]]:
    if not durations or len(durations) != len(events):
        raise ValueError("durations and events must be non-empty and equally sized")
    if any(value <= 0 for value in durations):
        raise ValueError("durations must be positive")
    survival = 1.0
    curve: list[dict[str, Any]] = []
    for time in sorted(set(durations)):
        at_risk = sum(duration >= time for duration in durations)
        observed = sum(
            duration == time and event for duration, event in zip(durations, events, strict=True)
        )
        censored = sum(
            duration == time and not event
            for duration, event in zip(durations, events, strict=True)
        )
        if observed:
            survival *= 1.0 - observed / at_risk
        curve.append(
            {
                "at_risk": at_risk,
                "candidates": time,
                "censored": censored,
                "events": observed,
                "survival": survival,
            }
        )
    return curve


def survival_median(curve: list[dict[str, Any]]) -> int | None:
    return next(
        (int(point["candidates"]) for point in curve if float(point["survival"]) <= 0.5),
        None,
    )


def restricted_mean(curve: list[dict[str, Any]], limit: int) -> float:
    previous = 0
    survival = 1.0
    area = 0.0
    for point in curve:
        time = min(int(point["candidates"]), limit)
        area += (time - previous) * survival
        survival = float(point["survival"])
        previous = time
        if time == limit:
            break
    if previous < limit:
        area += (limit - previous) * survival
    return area
