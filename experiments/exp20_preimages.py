"""EXP-20R: distinct reduced preimage, second-preimage and multi-target games."""

import math
import statistics
from typing import Any

from .common import derived_random
from .reduced_oracle import ReducedOracle, encode_integer, trajectory


def _image(
    oracle: ReducedOracle,
    candidate: int,
    bits: int,
    anchor_bits: int,
    construction: str,
    state_count: int,
) -> tuple[int, ...]:
    anchor, segment = trajectory(
        oracle, candidate, bits, anchor_bits, 1, state_count, construction != "simple"
    )
    if construction in {"simple", "reinjected"}:
        return segment
    if construction == "deep-vector":
        framed = encode_integer(anchor, bits) + b"".join(
            encode_integer(value, bits) for value in segment
        )
        return tuple(oracle.query(f"vector-{index}", bits, framed) for index in range(state_count))
    raise ValueError(f"unsupported construction: {construction}")


def run(config: dict[str, Any]) -> list[dict[str, Any]]:
    records: list[dict[str, Any]] = []
    maximum = int(config.get("max_candidates", 1_000_000))
    repetitions = int(config.get("repetitions", 8))
    constructions = config.get("constructions", ["simple", "reinjected", "deep-vector"])
    games = config.get("games", ["preimage", "second-preimage", "multi-target"])
    target_kinds = config.get("target_kinds", ["regular-image", "uniform"])
    objectives = [int(value) for value in config.get("target_counts", [1, 4])]
    for bits_value in config["widths"]:
        bits = int(bits_value)
        for multiplier_value in config.get("anchor_multipliers", [1]):
            anchor_bits = bits * int(multiplier_value)
            for states_value in config["state_counts"]:
                states = int(states_value)
                for construction in constructions:
                    for game in games:
                        for target_kind in target_kinds:
                            if game == "second-preimage" and target_kind == "uniform":
                                continue
                            target_counts = objectives if game == "multi-target" else [1]
                            for target_count in target_counts:
                                for repetition in range(repetitions):
                                    label = (
                                        f"EXP-20/{bits}/{states}/{construction}/{game}/"
                                        f"{target_kind}/{target_count}/{repetition}"
                                    )
                                    fixed_rng = derived_random(
                                        str(config["master_seed"]), label + "/targets"
                                    )
                                    search_rng = derived_random(
                                        str(config["master_seed"]), label + "/search"
                                    )
                                    oracle = ReducedOracle(fixed_rng.randbytes(32))
                                    fixed_messages = [
                                        fixed_rng.getrandbits(128) for _ in range(target_count)
                                    ]
                                    if target_kind == "regular-image":
                                        targets = {
                                            _image(
                                                oracle,
                                                message,
                                                bits,
                                                anchor_bits,
                                                str(construction),
                                                states,
                                            )
                                            for message in fixed_messages
                                        }
                                    else:
                                        targets = {
                                            tuple(
                                                fixed_rng.getrandbits(bits) for _ in range(states)
                                            )
                                            for _ in range(target_count)
                                        }
                                    found = None
                                    for queries in range(1, maximum + 1):
                                        candidate = search_rng.getrandbits(128)
                                        if (
                                            game == "second-preimage"
                                            and candidate == fixed_messages[0]
                                        ):
                                            continue
                                        if (
                                            _image(
                                                oracle,
                                                candidate,
                                                bits,
                                                anchor_bits,
                                                str(construction),
                                                states,
                                            )
                                            in targets
                                        ):
                                            found = queries
                                            break
                                    work = found or maximum
                                    effective_targets = len(targets)
                                    prediction = (
                                        bits * states
                                        if target_kind == "uniform"
                                        else min(anchor_bits, bits * states)
                                    )
                                    records.append(
                                        {
                                            "anchor_bits": anchor_bits,
                                            "candidates": work,
                                            "censored": found is None,
                                            "construction": construction,
                                            "game": game,
                                            "log2_candidates": math.log2(work),
                                            "predicted_log2": max(
                                                0.0,
                                                prediction - math.log2(max(1, effective_targets)),
                                            ),
                                            "repetition": repetition,
                                            "state_bits": bits,
                                            "state_count": states,
                                            "target_count": effective_targets,
                                            "target_kind": target_kind,
                                        }
                                    )
    return records


def summarize(records: list[dict[str, Any]]) -> list[dict[str, Any]]:
    fields = (
        "game",
        "construction",
        "target_kind",
        "state_bits",
        "state_count",
        "target_count",
        "anchor_bits",
    )
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
            "predicted_log2": group[0]["predicted_log2"],
        }
        for key, group in sorted(grouped.items())
    ]
