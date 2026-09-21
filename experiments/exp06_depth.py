import hashlib
import statistics
import time
from concurrent.futures import ThreadPoolExecutor
from functools import partial
from typing import Any

from sigma.presets import (
    lightweight_v2_2,
    paranoid_deep_v2_2,
    paranoid_deep_vector_v2_2,
)
from sigma.v2 import _anchor_engine, _round_engine

from .common import derived_random


def _theil_sen(xs: list[float], ys: list[float]) -> tuple[float, float]:
    slopes = [
        (ys[right] - ys[left]) / (xs[right] - xs[left])
        for left in range(len(xs))
        for right in range(left + 1, len(xs))
        if xs[right] != xs[left]
    ]
    slope = statistics.median(slopes) if slopes else 0.0
    intercept = statistics.median(y - slope * x for x, y in zip(xs, ys, strict=True))
    return intercept, slope


def _evaluate(payload: bytes, context) -> tuple[bytes, int, int]:
    anchor_started = time.perf_counter_ns()
    anchor_engine = _anchor_engine(context)
    anchor_engine.update(payload)
    anchor = anchor_engine.finalize()
    anchor_ns = time.perf_counter_ns() - anchor_started
    round_started = time.perf_counter_ns()
    digest = _round_engine(context).evaluate_digest(anchor).to_bytes()
    round_ns = time.perf_counter_ns() - round_started
    return digest, anchor_ns, round_ns


def run(config: dict[str, Any]) -> list[dict[str, Any]]:
    records = []
    repetitions = int(config.get("repetitions", 5))
    message_bytes = int(config.get("message_bytes", 64))
    master_seed = str(config["master_seed"])
    for profile in config["profiles"]:
        if profile == "wide-once":
            constructor = lightweight_v2_2
        elif profile == "deep":
            constructor = paranoid_deep_v2_2
        elif profile == "deep-vector":
            constructor = paranoid_deep_vector_v2_2
        else:
            raise ValueError(f"unsupported round profile: {profile}")
        branch_count = 2 if profile == "wide-once" else 4
        per_level_queries = (
            1
            if profile == "wide-once"
            else branch_count
            if profile == "deep-vector"
            else branch_count + 1
        )
        anchor_queries = branch_count if profile == "wide-once" else branch_count * 2
        initial_queries = branch_count if profile == "deep-vector" else 1
        for target_value in config["target_rounds"]:
            target = int(target_value)
            for state_count_value in config["state_counts"]:
                state_count = int(state_count_value)
                context = constructor(target_round=target, state_count=state_count)
                levels = target + state_count - 1
                for candidate_value in config["candidate_counts"]:
                    candidates = int(candidate_value)
                    for worker_value in config["candidate_workers"]:
                        workers = int(worker_value)
                        if workers > candidates:
                            continue
                        for repetition in range(repetitions):
                            label = (
                                f"EXP-06/{profile}/{target}/{state_count}/"
                                f"{candidates}/{workers}/{repetition}"
                            )
                            rng = derived_random(master_seed, label)
                            payloads = [rng.randbytes(message_bytes) for _ in range(candidates)]
                            cpu_started = time.process_time_ns()
                            started = time.perf_counter_ns()
                            if workers == 1:
                                outputs = [_evaluate(payload, context) for payload in payloads]
                            else:
                                with ThreadPoolExecutor(max_workers=workers) as executor:
                                    outputs = list(
                                        executor.map(partial(_evaluate, context=context), payloads)
                                    )
                            elapsed = time.perf_counter_ns() - started
                            cpu_elapsed = time.process_time_ns() - cpu_started
                            digests = [output[0] for output in outputs]
                            records.append(
                                {
                                    "anchor_queries": candidates * anchor_queries,
                                    "anchor_wall_ns_sum": sum(output[1] for output in outputs),
                                    "candidate_workers": workers,
                                    "candidates": candidates,
                                    "critical_levels": levels,
                                    "cpu_time_ns": cpu_elapsed,
                                    "digests_sha256": hashlib.sha256(b"".join(digests)).hexdigest(),
                                    "elapsed_ns": elapsed,
                                    "implementation_round_span_queries": levels * per_level_queries,
                                    "initial_queries": candidates * initial_queries,
                                    "model_parallel_round_span_queries": levels
                                    if profile in {"wide-once", "deep-vector"}
                                    else levels * 2,
                                    "profile": profile,
                                    "repetition": repetition,
                                    "round_queries": candidates * levels * per_level_queries,
                                    "round_wall_ns_sum": sum(output[2] for output in outputs),
                                    "state_count": state_count,
                                    "target_round": target,
                                    "throughput_candidates_s": candidates * 1_000_000_000 / elapsed,
                                    "total_primitive_queries": candidates
                                    * (
                                        anchor_queries
                                        + initial_queries
                                        + levels * per_level_queries
                                    ),
                                }
                            )
    return records


def summarize(records: list[dict[str, Any]]) -> list[dict[str, Any]]:
    fields = (
        "profile",
        "target_round",
        "state_count",
        "candidates",
        "candidate_workers",
    )
    grouped: dict[tuple[Any, ...], list[dict[str, Any]]] = {}
    for record in records:
        grouped.setdefault(tuple(record[field] for field in fields), []).append(record)
    summaries = []
    for key, group in sorted(grouped.items()):
        elapsed = [int(item["elapsed_ns"]) for item in group]
        throughput = [float(item["throughput_candidates_s"]) for item in group]
        summaries.append(
            {
                **dict(zip(fields, key, strict=False)),
                "critical_levels": group[0]["critical_levels"],
                "median_anchor_wall_ns_sum": int(
                    statistics.median(int(item["anchor_wall_ns_sum"]) for item in group)
                ),
                "median_cpu_time_ns": int(
                    statistics.median(int(item["cpu_time_ns"]) for item in group)
                ),
                "median_elapsed_ns": int(statistics.median(elapsed)),
                "median_round_wall_ns_sum": int(
                    statistics.median(int(item["round_wall_ns_sum"]) for item in group)
                ),
                "median_precomputed_anchor_round_ns": int(
                    statistics.median(int(item["round_wall_ns_sum"]) for item in group)
                ),
                "median_throughput_candidates_s": statistics.median(throughput),
                "observations": len(group),
                "round_queries": group[0]["round_queries"],
                "total_primitive_queries": group[0]["total_primitive_queries"],
                "quality_control_passed": all(
                    int(item["total_primitive_queries"])
                    == int(item["anchor_queries"])
                    + int(item["round_queries"])
                    + int(item["initial_queries"])
                    for item in group
                ),
            }
        )
    baselines = {
        (
            item["profile"],
            item["target_round"],
            item["state_count"],
            item["candidates"],
        ): item
        for item in summaries
        if item["candidate_workers"] == 1
    }
    for item in summaries:
        baseline = baselines.get(
            (item["profile"], item["target_round"], item["state_count"], item["candidates"])
        )
        speedup = (
            float(baseline["median_elapsed_ns"]) / float(item["median_elapsed_ns"])
            if baseline is not None
            else None
        )
        item["speedup_vs_worker1"] = speedup
        item["parallel_efficiency"] = (
            speedup / int(item["candidate_workers"]) if speedup is not None else None
        )
    regression_fields = ("profile", "state_count", "candidates", "candidate_workers")
    regression_groups: dict[tuple[Any, ...], list[dict[str, Any]]] = {}
    for item in summaries:
        regression_groups.setdefault(tuple(item[field] for field in regression_fields), []).append(
            item
        )
    for group in regression_groups.values():
        ordered = sorted(group, key=lambda item: int(item["critical_levels"]))
        xs = [float(item["critical_levels"]) for item in ordered]
        elapsed_fit = [float(item["median_elapsed_ns"]) for item in ordered]
        round_fit = [float(item["median_precomputed_anchor_round_ns"]) for item in ordered]
        elapsed_intercept, elapsed_slope = _theil_sen(xs, elapsed_fit)
        round_intercept, round_slope = _theil_sen(xs, round_fit)
        for item in group:
            item["robust_elapsed_intercept_ns"] = elapsed_intercept
            item["robust_elapsed_slope_ns_per_level"] = elapsed_slope
            item["robust_precomputed_round_intercept_ns"] = round_intercept
            item["robust_precomputed_round_slope_ns_per_level"] = round_slope
            item["robust_regression_cells"] = len(group)
    return summaries
