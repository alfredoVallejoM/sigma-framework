import math
import statistics
from typing import Any

from .common import derived_random
from .reduced_oracle import ReducedOracle, trajectory


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
                        reinjected = construction.startswith("reinjected")
                        k = requested_k if construction.endswith("consecutive") else 1
                        predicted_bits = min(anchor_bits, k * n if reinjected else n)
                        for repetition in range(repetitions):
                            label = f"EXP-02/{n}/{requested_k}/{target}/{anchor_bits}/{construction}/{repetition}"
                            rng = derived_random(master_seed, label)
                            oracle = ReducedOracle(rng.randbytes(32))
                            seen: dict[tuple[int, ...], int] = {}
                            collision_at = None
                            for query_count in range(1, max_candidates + 1):
                                candidate = rng.getrandbits(128)
                                _, segment = trajectory(
                                    oracle, candidate, n, anchor_bits, target, k, reinjected
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
        summaries.append(
            {
                **dict(zip(fields, key, strict=False)),
                "censored": sum(bool(record["censored"]) for record in group),
                "mean_log2_candidates": statistics.fmean(log_values),
                "median_log2_candidates": statistics.median(log_values),
                "predicted_log2": group[0]["predicted_log2"],
                "repetitions": len(group),
            }
        )
    return summaries
