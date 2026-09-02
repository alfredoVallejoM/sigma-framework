"""EXP-18: reduced-width comparison of Deep fold and DeepVector."""

import math
import statistics
from typing import Any

from .common import derived_random
from .reduced_oracle import ReducedOracle, encode_integer


def _output(
    oracle: ReducedOracle, candidate: int, bits: int, branches: int, mode: str, fault: str
) -> tuple[int, ...]:
    message = candidate.to_bytes(16, "big")
    values = [oracle.query(f"branch-{index}", bits, message) for index in range(branches)]
    if fault == "constant-first":
        values[0] = 0
    elif fault == "correlated-first-two":
        values[1] = values[0]
    elif fault != "normal":
        raise ValueError(f"unsupported fault: {fault}")
    framed = b"".join(encode_integer(value, bits) for value in values)
    if mode == "deep-fold":
        return (oracle.query("deep-fold", bits, framed),)
    if mode == "deep-vector":
        return tuple(
            oracle.query(f"deep-vector-{index}", bits, framed) for index in range(branches)
        )
    raise ValueError(f"unsupported mode: {mode}")


def run(config: dict[str, Any]) -> list[dict[str, Any]]:
    records: list[dict[str, Any]] = []
    maximum = int(config.get("max_candidates", 1_000_000))
    repetitions = int(config.get("repetitions", 8))
    for bits_value in config["widths"]:
        bits = int(bits_value)
        for branches_value in config["branch_counts"]:
            branches = int(branches_value)
            if branches < 2:
                raise ValueError("EXP-18 requires at least two branches")
            for fault in config["faults"]:
                for mode in ("deep-fold", "deep-vector"):
                    for repetition in range(repetitions):
                        label = f"EXP-18/{bits}/{branches}/{fault}/{mode}/{repetition}"
                        rng = derived_random(str(config["master_seed"]), label)
                        oracle = ReducedOracle(rng.randbytes(32))
                        seen: dict[tuple[int, ...], int] = {}
                        collision = None
                        for queries in range(1, maximum + 1):
                            candidate = rng.getrandbits(128)
                            output = _output(oracle, candidate, bits, branches, mode, str(fault))
                            if output in seen and seen[output] != candidate:
                                collision = queries
                                break
                            seen[output] = candidate
                        work = collision or maximum
                        records.append(
                            {
                                "branches": branches,
                                "candidates": work,
                                "censored": collision is None,
                                "fault": fault,
                                "log2_candidates": math.log2(work),
                                "mode": mode,
                                "physical_bits": bits * (branches if mode == "deep-vector" else 1),
                                "repetition": repetition,
                                "state_bits": bits,
                            }
                        )
    return records


def summarize(records: list[dict[str, Any]]) -> list[dict[str, Any]]:
    fields = ("mode", "fault", "state_bits", "branches")
    grouped: dict[tuple[Any, ...], list[dict[str, Any]]] = {}
    for record in records:
        grouped.setdefault(tuple(record[field] for field in fields), []).append(record)
    return [
        {
            **dict(zip(fields, key, strict=True)),
            "censored": sum(bool(item["censored"]) for item in group),
            "median_log2_candidates": statistics.median(
                float(item["log2_candidates"]) for item in group
            ),
            "observations": len(group),
        }
        for key, group in sorted(grouped.items())
    ]
