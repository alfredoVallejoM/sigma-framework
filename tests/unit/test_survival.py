import pytest

from experiments.survival import kaplan_meier, restricted_mean, survival_median


def test_kaplan_meier_keeps_censoring_distinct_from_events() -> None:
    curve = kaplan_meier([2, 2, 4, 5], [True, False, True, False])
    assert curve == [
        {"at_risk": 4, "candidates": 2, "censored": 1, "events": 1, "survival": 0.75},
        {"at_risk": 2, "candidates": 4, "censored": 0, "events": 1, "survival": 0.375},
        {"at_risk": 1, "candidates": 5, "censored": 1, "events": 0, "survival": 0.375},
    ]
    assert survival_median(curve) == 4
    assert restricted_mean(curve, 5) == pytest.approx(3.875)


def test_survival_median_is_unknown_when_curve_never_crosses_half() -> None:
    curve = kaplan_meier([3, 5], [False, False])
    assert survival_median(curve) is None
    assert restricted_mean(curve, 5) == 5
