"""EXP-18: reduced-width comparison of Deep fold and DeepVector segments."""

import math
import statistics
from typing import Any

from .common import derived_random
from .reduced_oracle import ReducedOracle, encode_integer
from .survival import kaplan_meier, restricted_mean


def _apply_fault(values: list[int], fault: str) -> list[int]:
    changed = list(values)
    if fault == "normal":
        return changed
    if fault == "constant-first":
        changed[0] = 0
    elif fault == "correlated-first-two":
        changed[1] = changed[0]
    elif fault == "omitted-last":
        changed[-1] = 0
    elif fault == "permuted":
        changed.reverse()
    elif fault != "constant-fold":
        raise ValueError(f"unsupported fault: {fault}")
    return changed


def _output(
    oracle: ReducedOracle,
    candidate: int,
    bits: int,
    branches: int,
    mode: str,
    fault: str,
    target_round: int,
    state_count: int,
) -> tuple[tuple[int, ...], int]:
    candidate_bytes = candidate.to_bytes(16, "big")
    previous = candidate_bytes
    segment: list[tuple[int, ...]] = []
    queries = 0
    last = target_round + state_count
    for level in range(last):
        framed_level = level.to_bytes(8, "big") + previous
        values = [
            oracle.query(f"branch-{index}", bits, candidate_bytes, framed_level)
            for index in range(branches)
        ]
        queries += branches
        values = _apply_fault(values, fault)
        framed = b"".join(encode_integer(value, bits) for value in values)
        if mode == "deep-fold":
            state = 0 if fault == "constant-fold" else oracle.query("deep-fold", bits, framed)
            queries += int(fault != "constant-fold")
            current: tuple[int, ...] = (state,)
        elif mode == "deep-vector":
            if fault == "constant-fold":
                raise ValueError("constant-fold is not applicable to DeepVector")
            current = tuple(
                oracle.query(f"deep-vector-{index}", bits, framed) for index in range(branches)
            )
            queries += branches
        else:
            raise ValueError(f"unsupported mode: {mode}")
        previous = b"".join(encode_integer(value, bits) for value in current)
        if level >= target_round:
            segment.append(current)
    return tuple(value for state in segment for value in state), queries


def run(config: dict[str, Any]) -> list[dict[str, Any]]:
    records: list[dict[str, Any]] = []
    maximum = int(config.get("max_candidates", 1_000_000))
    repetitions = int(config.get("repetitions", 8))
    target_rounds = [int(value) for value in config.get("target_rounds", [1])]
    state_counts = [int(value) for value in config.get("state_counts", [1])]
    for bits_value in config["widths"]:
        bits = int(bits_value)
        for branches_value in config["branch_counts"]:
            branches = int(branches_value)
            if branches < 2:
                raise ValueError("EXP-18 requires at least two branches")
            for target_round in target_rounds:
                for state_count in state_counts:
                    if target_round < 0 or state_count < 1:
                        raise ValueError("invalid EXP-18 trajectory dimensions")
                    for fault_value in config["faults"]:
                        fault = str(fault_value)
                        for mode in ("deep-fold", "deep-vector"):
                            if mode == "deep-vector" and fault == "constant-fold":
                                continue
                            for repetition in range(repetitions):
                                label = (
                                    f"EXP-18/{bits}/{branches}/{target_round}/{state_count}/"
                                    f"{fault}/{mode}/{repetition}"
                                )
                                rng = derived_random(str(config["master_seed"]), label)
                                oracle = ReducedOracle(rng.randbytes(32))
                                seen: dict[tuple[int, ...], int] = {}
                                collision = None
                                query_count = 0
                                for candidates in range(1, maximum + 1):
                                    candidate = rng.getrandbits(128)
                                    output, queries = _output(
                                        oracle,
                                        candidate,
                                        bits,
                                        branches,
                                        mode,
                                        fault,
                                        target_round,
                                        state_count,
                                    )
                                    query_count += queries
                                    if output in seen and seen[output] != candidate:
                                        collision = candidates
                                        break
                                    seen[output] = candidate
                                work = collision or maximum
                                components = branches if mode == "deep-vector" else 1
                                physical_bits = bits * components * state_count
                                conservative_bits = (
                                    0 if mode == "deep-fold" and fault == "constant-fold" else bits
                                )
                                records.append(
                                    {
                                        "branches": branches,
                                        "candidates": work,
                                        "censored": collision is None,
                                        "conservative_bits": conservative_bits,
                                        "fault": fault,
                                        "joint_model_bits": physical_bits,
                                        "log2_candidates": math.log2(work),
                                        "mode": mode,
                                        "physical_bits": physical_bits,
                                        "primitive_queries": query_count,
                                        "repetition": repetition,
                                        "state_bits": bits,
                                        "state_count": state_count,
                                        "target_round": target_round,
                                    }
                                )
    return records


def summarize(records: list[dict[str, Any]]) -> list[dict[str, Any]]:
    fields = ("mode", "fault", "state_bits", "branches", "target_round", "state_count")
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
                "conservative_bits": group[0]["conservative_bits"],
                "joint_model_bits": group[0]["joint_model_bits"],
                "median_log2_candidates": statistics.median(
                    float(item["log2_candidates"]) for item in group
                ),
                "median_primitive_queries": statistics.median(
                    int(item["primitive_queries"]) for item in group
                ),
                "observations": len(group),
                "physical_bits": group[0]["physical_bits"],
                "restricted_mean_candidates": restricted_mean(
                    curve, max(int(item["candidates"]) for item in group)
                ),
            }
        )
    return summaries
