"""EXP-19: reduced Sigma commitments while retaining a standard signature layer."""

import math
import statistics
from typing import Any

from .common import derived_random
from .reduced_oracle import ReducedOracle, trajectory


def _commitment(
    oracle: ReducedOracle, candidate: int, bits: int, target: int, states: int, mode: str
) -> tuple[int, ...]:
    anchor, segment = trajectory(oracle, candidate, bits, bits, target, states, True)
    if mode == "one-state":
        return segment[:1]
    if mode == "multi-state":
        return segment
    if mode == "anchor-and-states":
        return (anchor, *segment)
    raise ValueError(f"unsupported commitment mode: {mode}")


def run(config: dict[str, Any]) -> list[dict[str, Any]]:
    records: list[dict[str, Any]] = []
    maximum = int(config.get("max_candidates", 1_000_000))
    repetitions = int(config.get("repetitions", 8))
    modes = config.get("commitments", ["one-state", "multi-state", "anchor-and-states"])
    for bits_value in config["widths"]:
        bits = int(bits_value)
        for states_value in config["state_counts"]:
            states = int(states_value)
            for mode in modes:
                for repetition in range(repetitions):
                    label = f"EXP-19/{bits}/{states}/{mode}/{repetition}"
                    rng = derived_random(str(config["master_seed"]), label)
                    oracle = ReducedOracle(rng.randbytes(32))
                    seen: dict[tuple[int, ...], int] = {}
                    collision = None
                    for queries in range(1, maximum + 1):
                        candidate = rng.getrandbits(128)
                        commitment = _commitment(oracle, candidate, bits, 1, states, str(mode))
                        if commitment in seen and seen[commitment] != candidate:
                            collision = queries
                            break
                        seen[commitment] = candidate
                    work = collision or maximum
                    records.append(
                        {
                            "candidates": work,
                            "censored": collision is None,
                            "commitment": mode,
                            "log2_candidates": math.log2(work),
                            "repetition": repetition,
                            "signature_algorithm": "Ed25519-not-reduced",
                            "signed_components": len(
                                _commitment(oracle, 0, bits, 1, states, str(mode))
                            ),
                            "state_bits": bits,
                            "state_count": states,
                        }
                    )
    return records


def summarize(records: list[dict[str, Any]]) -> list[dict[str, Any]]:
    fields = ("commitment", "state_bits", "state_count")
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
