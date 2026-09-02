"""EXP-19: reduced commitment-reuse events under an unreduced signature layer."""

import math
import statistics
from typing import Any

from .common import derived_random
from .reduced_oracle import ReducedOracle, trajectory
from .survival import kaplan_meier, restricted_mean


def _commitment(
    oracle: ReducedOracle,
    candidate: int,
    bits: int,
    anchor_bits: int,
    target: int,
    states: int,
    mode: str,
) -> tuple[tuple[int, ...], int]:
    anchor, segment = trajectory(oracle, candidate, bits, anchor_bits, target, states, True)
    queries = 2 + target + states - 1
    if mode == "one-state":
        return segment[:1], queries
    if mode == "multi-state":
        return segment, queries
    if mode == "anchor-and-states":
        return (anchor, *segment), queries
    raise ValueError(f"unsupported commitment mode: {mode}")


def run(config: dict[str, Any]) -> list[dict[str, Any]]:
    records: list[dict[str, Any]] = []
    maximum = int(config.get("max_candidates", 1_000_000))
    repetitions = int(config.get("repetitions", 8))
    modes = [
        str(value)
        for value in config.get("commitments", ["one-state", "multi-state", "anchor-and-states"])
    ]
    target_rounds = [int(value) for value in config.get("target_rounds", [1])]
    anchor_multipliers = [int(value) for value in config.get("anchor_multipliers", [1])]
    for bits_value in config["widths"]:
        bits = int(bits_value)
        for multiplier in anchor_multipliers:
            anchor_bits = bits * multiplier
            for states_value in config["state_counts"]:
                states = int(states_value)
                for target in target_rounds:
                    for mode in modes:
                        for repetition in range(repetitions):
                            label = (
                                f"EXP-19/{bits}/{anchor_bits}/{target}/{states}/{mode}/{repetition}"
                            )
                            rng = derived_random(str(config["master_seed"]), label)
                            oracle = ReducedOracle(rng.randbytes(32))
                            seen: dict[tuple[int, ...], int] = {}
                            collision = None
                            primitive_queries = 0
                            for candidates in range(1, maximum + 1):
                                candidate = rng.getrandbits(128)
                                commitment, queries = _commitment(
                                    oracle,
                                    candidate,
                                    bits,
                                    anchor_bits,
                                    target,
                                    states,
                                    mode,
                                )
                                primitive_queries += queries
                                if commitment in seen and seen[commitment] != candidate:
                                    collision = candidates
                                    break
                                seen[commitment] = candidate
                            work = collision or maximum
                            signed_components = len(
                                _commitment(oracle, 0, bits, anchor_bits, target, states, mode)[0]
                            )
                            if mode == "one-state":
                                bottleneck_bits = min(anchor_bits, bits)
                            else:
                                bottleneck_bits = min(anchor_bits, bits * states)
                            records.append(
                                {
                                    "anchor_bits": anchor_bits,
                                    "candidates": work,
                                    "censored": collision is None,
                                    "commitment": mode,
                                    "conservative_bottleneck_bits": bottleneck_bits,
                                    "log2_candidates": math.log2(work),
                                    "primitive_queries": primitive_queries,
                                    "repetition": repetition,
                                    "signature_algorithm": "Ed25519-not-reduced",
                                    "signature_semantics": "reuse-event-only",
                                    "signed_components": signed_components,
                                    "signed_physical_bits": (
                                        bits * signed_components
                                        if mode != "anchor-and-states"
                                        else anchor_bits + bits * states
                                    ),
                                    "state_bits": bits,
                                    "state_count": states,
                                    "target_round": target,
                                    "verification_primitive_queries": 2 + target + states - 1,
                                }
                            )
    return records


def summarize(records: list[dict[str, Any]]) -> list[dict[str, Any]]:
    fields = ("commitment", "state_bits", "anchor_bits", "target_round", "state_count")
    grouped: dict[tuple[Any, ...], list[dict[str, Any]]] = {}
    for record in records:
        grouped.setdefault(tuple(record[field] for field in fields), []).append(record)
    summaries = []
    for key, group in sorted(grouped.items()):
        durations = [int(item["candidates"]) for item in group]
        events = [not bool(item["censored"]) for item in group]
        curve = kaplan_meier(durations, events)
        summaries.append(
            {
                **dict(zip(fields, key, strict=True)),
                "censored": sum(bool(item["censored"]) for item in group),
                "conservative_bottleneck_bits": group[0]["conservative_bottleneck_bits"],
                "median_log2_candidates": statistics.median(
                    float(item["log2_candidates"]) for item in group
                ),
                "median_primitive_queries": statistics.median(
                    int(item["primitive_queries"]) for item in group
                ),
                "observations": len(group),
                "restricted_mean_candidates": restricted_mean(curve, max(durations)),
                "signature_algorithm": "Ed25519-not-reduced",
                "signed_physical_bits": group[0]["signed_physical_bits"],
                "verification_primitive_queries": group[0]["verification_primitive_queries"],
            }
        )
    return summaries
