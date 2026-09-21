import hashlib
import math
import random
import statistics
from typing import Any

from .common import derived_random
from .reduced_oracle import ReducedOracle, controlled_trajectory, trajectory
from .survival import kaplan_meier, restricted_mean, survival_median


def _slope(xs: list[float], ys: list[float]) -> float | None:
    if len(xs) < 2 or len(set(xs)) < 2:
        return None
    center_x = statistics.fmean(xs)
    center_y = statistics.fmean(ys)
    denominator = sum((value - center_x) ** 2 for value in xs)
    return (
        sum(
            (x_value - center_x) * (y_value - center_y)
            for x_value, y_value in zip(xs, ys, strict=True)
        )
        / denominator
    )


def _quantile(values: list[float], probability: float) -> float:
    ordered = sorted(values)
    position = probability * (len(ordered) - 1)
    lower = int(position)
    upper = min(lower + 1, len(ordered) - 1)
    fraction = position - lower
    return ordered[lower] * (1 - fraction) + ordered[upper] * fraction


def run(config: dict[str, Any]) -> list[dict[str, Any]]:
    records = []
    master_seed = str(config["master_seed"])
    repetitions = int(config.get("repetitions", 16))
    max_candidates = int(config.get("max_candidates", 1_000_000))
    constructions = config.get(
        "constructions",
        ["simple-single", "simple-consecutive", "reinjected-single", "reinjected-consecutive"],
    )
    for n_value in config["widths"]:
        n = int(n_value)
        for k_value in config["state_counts"]:
            requested_k = int(k_value)
            for target_value in config["target_rounds"]:
                target = int(target_value)
                for multiplier_value in config["anchor_multipliers"]:
                    anchor_bits = n * int(multiplier_value)
                    for construction in constructions:
                        raw_family, output = str(construction).rsplit("-", 1)
                        aliases = {"simple": "indexed", "reinjected": "anchored-indexed"}
                        family = aliases.get(raw_family, raw_family)
                        if family not in {
                            "stationary",
                            "indexed",
                            "anchored",
                            "anchored-indexed",
                        } or output not in {"single", "consecutive"}:
                            raise ValueError(f"unsupported construction: {construction}")
                        k = requested_k if output == "consecutive" else 1
                        predicted_bits = (
                            min(anchor_bits, k * n)
                            if family in {"anchored", "anchored-indexed"}
                            else n
                        )
                        for repetition in range(repetitions):
                            label = f"EXP-02/{n}/{requested_k}/{target}/{anchor_bits}/{construction}/{repetition}"
                            rng = derived_random(master_seed, label)
                            oracle = ReducedOracle(rng.randbytes(32))
                            seen: dict[tuple[int, ...], int] = {}
                            collision_at = None
                            for query_count in range(1, max_candidates + 1):
                                candidate = rng.getrandbits(128)
                                if raw_family in aliases:
                                    _, segment = trajectory(
                                        oracle,
                                        candidate,
                                        n,
                                        anchor_bits,
                                        target,
                                        k,
                                        raw_family == "reinjected",
                                    )
                                else:
                                    _, segment = controlled_trajectory(
                                        oracle, candidate, n, anchor_bits, target, k, family
                                    )
                                if segment in seen and seen[segment] != candidate:
                                    collision_at = query_count
                                    break
                                seen[segment] = candidate
                            records.append(
                                {
                                    "anchor_bits": anchor_bits,
                                    "candidates": collision_at or max_candidates,
                                    "censored": collision_at is None,
                                    "construction": construction,
                                    "log2_candidates": math.log2(collision_at or max_candidates),
                                    "predicted_log2": predicted_bits / 2,
                                    "repetition": repetition,
                                    "state_bits": n,
                                    "state_count": k,
                                    "target_round": target,
                                }
                            )
    return records


def summarize(records: list[dict[str, Any]]) -> list[dict[str, Any]]:
    grouped: dict[tuple[Any, ...], list[dict[str, Any]]] = {}
    fields = ("construction", "state_bits", "state_count", "target_round", "anchor_bits")
    for record in records:
        grouped.setdefault(tuple(record[field] for field in fields), []).append(record)
    summaries = []
    for key, group in sorted(grouped.items()):
        log_values = [float(record["log2_candidates"]) for record in group]
        durations = [int(record["candidates"]) for record in group]
        events = [not bool(record["censored"]) for record in group]
        survival = kaplan_meier(durations, events)
        median = survival_median(survival)
        limit = max(durations)
        summaries.append(
            {
                **dict(zip(fields, key, strict=False)),
                "censored": sum(bool(record["censored"]) for record in group),
                "mean_log2_candidates": statistics.fmean(log_values),
                "median_candidates_km": median,
                "median_log2_candidates": (
                    math.log2(median) if median is not None else statistics.median(log_values)
                ),
                "predicted_log2": group[0]["predicted_log2"],
                "repetitions": len(group),
                "restricted_mean_candidates": restricted_mean(survival, limit),
                "survival": survival,
            }
        )
    cells_by_construction: dict[str, list[tuple[dict[str, Any], list[dict[str, Any]]]]] = {}
    for summary in summaries:
        key = tuple(summary[field] for field in fields)
        cells_by_construction.setdefault(str(summary["construction"]), []).append(
            (summary, grouped[key])
        )
    for _construction, cells in cells_by_construction.items():
        usable = [cell for cell in cells if cell[0]["median_candidates_km"] is not None]
        xs = [float(summary["predicted_log2"]) * 2 for summary, _ in usable]
        ys = [float(summary["median_log2_candidates"]) for summary, _ in usable]
        observed_slope = _slope(xs, ys)
        bootstrap: list[float] = []
        seed_material = repr(
            [
                (
                    summary["state_bits"],
                    summary["state_count"],
                    summary["target_round"],
                    summary["anchor_bits"],
                    [(item["candidates"], item["censored"]) for item in group],
                )
                for summary, group in usable
            ]
        ).encode()
        rng = random.Random(
            int.from_bytes(
                hashlib.sha256(b"sigma-exp02r-analysis-v1\0" + seed_material).digest(), "big"
            )
        )
        for _ in range(512):
            sampled_y: list[float] = []
            valid = True
            for _, group in usable:
                sample = [group[rng.randrange(len(group))] for _ in group]
                curve = kaplan_meier(
                    [int(item["candidates"]) for item in sample],
                    [not bool(item["censored"]) for item in sample],
                )
                median = survival_median(curve)
                if median is None:
                    valid = False
                    break
                sampled_y.append(math.log2(median))
            candidate = _slope(xs, sampled_y) if valid else None
            if candidate is not None:
                bootstrap.append(candidate)
        predictions = {
            "min-anchor-segment": [float(summary["predicted_log2"]) for summary, _ in usable],
            "state-only": [float(summary["state_bits"]) / 2 for summary, _ in usable],
            "anchor-only": [float(summary["anchor_bits"]) / 2 for summary, _ in usable],
            "segment-only": [
                float(summary["state_bits"] * summary["state_count"]) / 2 for summary, _ in usable
            ],
        }
        rmse = (
            {
                name: (
                    sum(
                        (actual - predicted) ** 2
                        for actual, predicted in zip(ys, values, strict=True)
                    )
                    / len(ys)
                )
                ** 0.5
                for name, values in predictions.items()
            }
            if ys
            else {}
        )
        for summary, _ in cells:
            summary["model_best_rmse"] = min(rmse, key=lambda name: rmse[name]) if rmse else None
            summary["model_rmse"] = rmse
            summary["slope_log2_work_per_effective_bit"] = observed_slope
            summary["slope_bootstrap_95"] = (
                [_quantile(bootstrap, 0.025), _quantile(bootstrap, 0.975)] if bootstrap else None
            )
            summary["slope_bootstrap_replicates"] = len(bootstrap)
    return summaries
