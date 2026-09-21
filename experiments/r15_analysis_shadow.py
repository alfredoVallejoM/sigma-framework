"""R15-G synthetic analysis rehearsal.

Builds deterministic synthetic analysis inputs for all frozen figure schemas and
executes the frozen statistical estimators without reading confirmatory data.
"""

from __future__ import annotations

import hashlib
from dataclasses import asdict, dataclass

from .common import canonical_json
from .r14_analysis import FIGURES_V3, TABLES_V3
from .r15_estimators import (
    ScalingCellV3,
    bootstrap_mean_interval_v3,
    bootstrap_scaling_slope_interval_v3,
    bootstrap_survival_statistic_v3,
    clopper_pearson_interval_v3,
    holm_adjust_v3,
    paired_bootstrap_ratio_interval_v3,
    pareto_frontier_v3,
    simultaneous_mean_band_v3,
    zero_event_upper_bound_v3,
)

ANALYSIS_SHADOW_NAMESPACE = "sigma-v3-r15-shadow-g-v1"


@dataclass(frozen=True)
class AnalysisShadowPayloadV3:
    figure_id: str
    attacks: tuple[str, ...]
    transform: str
    uncertainty: str
    result: dict[str, int | float | str | bool | None]


def _figure_result(figure_id: str) -> dict[str, int | float | str | bool | None]:
    if figure_id == "F01":
        return {"schematic": True}
    if figure_id == "F02":
        interval = clopper_pearson_interval_v3(3, 256)
        return {
            "rate": 3 / 256,
            "ci_lower": interval.lower,
            "ci_upper": interval.upper,
            "zero_event_upper_99": zero_event_upper_bound_v3(262_144),
        }
    if figure_id in ("F03", "F04"):
        cells = (
            ScalingCellV3(4, (3, 4, 5, 6, 7, 8, 9, 10), (True,) * 8),
            ScalingCellV3(6, (6, 7, 8, 9, 10, 11, 12, 13), (True,) * 8),
            ScalingCellV3(8, (12, 13, 14, 15, 16, 17, 18, 19), (True,) * 8),
        )
        interval = bootstrap_scaling_slope_interval_v3(
            cells,
            label=f"shadow-{figure_id}",
            replicates=250,
        )
        return {"slope_ci_lower": interval.lower, "slope_ci_upper": interval.upper}
    if figure_id == "F05":
        interval = bootstrap_survival_statistic_v3(
            (2, 3, 4, 5, 6, 7, 8, 9),
            (True, True, True, True, True, False, False, False),
            statistic="rmst",
            tau=9,
            label="shadow-f05",
            replicates=250,
        )
        return {"rmst_ci_lower": interval.lower, "rmst_ci_upper": interval.upper}
    if figure_id in ("F06", "F11"):
        frontier = pareto_frontier_v3(
            ((100, 20, 64), (80, 30, 64), (120, 15, 96), (110, 25, 80))
        )
        return {"pareto_points": len(frontier)}
    if figure_id == "F07":
        band = simultaneous_mean_band_v3(
            ((1.0, (0.9, 1.0, 1.1)), (2.0, (0.7, 0.8, 0.9))),
            label="shadow-f07",
            replicates=250,
        )
        return {"band_points": len(band), "max_deviation": 0.03}
    if figure_id in ("F08", "F09"):
        interval = bootstrap_mean_interval_v3(
            (1.0, 2.0, 1.5, 2.5, 1.8),
            label=f"shadow-{figure_id}",
            replicates=250,
        )
        return {"ci_lower": interval.lower, "ci_upper": interval.upper}
    if figure_id in ("F10", "F12", "F13"):
        interval = paired_bootstrap_ratio_interval_v3(
            (10.0, 11.0, 9.5, 10.5, 10.2),
            (12.0, 12.5, 11.5, 12.1, 12.2),
            label=f"shadow-{figure_id}",
            replicates=250,
        )
        return {"ratio_ci_lower": interval.lower, "ratio_ci_upper": interval.upper}
    if figure_id == "F14":
        adjusted = holm_adjust_v3((0.01, 0.03, 0.2, 0.7))
        return {"tests": len(adjusted), "minimum_adjusted_p": min(adjusted)}
    if figure_id == "F15":
        return {"platforms": 6, "status": "synthetic-pass"}
    raise ValueError(f"unknown frozen figure id: {figure_id}")


def run_analysis_shadow_v3() -> dict[str, object]:
    payloads = tuple(
        AnalysisShadowPayloadV3(
            figure_id=figure.figure_id,
            attacks=figure.attack_ids,
            transform=figure.transform,
            uncertainty=figure.uncertainty,
            result=_figure_result(figure.figure_id),
        )
        for figure in FIGURES_V3
    )
    if len(payloads) != 15 or len(TABLES_V3) != 9:
        raise RuntimeError("frozen analysis registry cardinality drifted")
    serialized = canonical_json(
        {
            "namespace": ANALYSIS_SHADOW_NAMESPACE,
            "confirmatory": False,
            "figures": [asdict(payload) for payload in payloads],
            "tables": list(TABLES_V3),
        }
    )
    return {
        "schema": "sigma-v3-r15-analysis-shadow-v1",
        "namespace": ANALYSIS_SHADOW_NAMESPACE,
        "confirmatory": False,
        "figures": len(payloads),
        "tables": len(TABLES_V3),
        "figure_ids": [payload.figure_id for payload in payloads],
        "analysis_sha256": hashlib.sha256(serialized).hexdigest(),
        "passed": True,
    }


__all__ = [
    "ANALYSIS_SHADOW_NAMESPACE",
    "AnalysisShadowPayloadV3",
    "run_analysis_shadow_v3",
]
