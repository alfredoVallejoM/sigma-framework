"""EXP-20R: distinct reduced preimage, second-preimage and multi-target games."""

import math
import statistics
from typing import Any, Iterator

from .common import derived_random
from .reduced_oracle import ReducedOracle, encode_integer, trajectory
from .survival import kaplan_meier, restricted_mean


def _image(
    oracle: ReducedOracle,
    candidate: int,
    bits: int,
    anchor_bits: int,
    construction: str,
    state_count: int,
) -> tuple[tuple[int, ...], int, int]:
    anchor, segment = trajectory(
        oracle, candidate, bits, anchor_bits, 1, state_count, construction != "simple"
    )
    anchor_queries = 1
    round_queries = 1 + 1 + state_count - 1
    if construction in {"simple", "reinjected"}:
        return segment, anchor_queries, round_queries
    if construction == "deep-vector":
        framed = encode_integer(anchor, anchor_bits) + b"".join(
            encode_integer(value, bits) for value in segment
        )
        output = tuple(
            oracle.query(f"vector-{index}", bits, framed) for index in range(state_count)
        )
        return output, anchor_queries, round_queries + state_count
    raise ValueError(f"unsupported construction: {construction}")


def _candidates(attacker: str, rng, maximum: int) -> Iterator[int]:
    if attacker == "random-search":
        for _ in range(maximum):
            yield rng.getrandbits(128)
        return
    if attacker in {"exhaustive", "inversion-table"}:
        start = rng.getrandbits(128)
        for offset in range(maximum):
            yield (start + offset) & ((1 << 128) - 1)
        return
    raise ValueError(f"unsupported EXP-20 attacker: {attacker}")


def run(config: dict[str, Any]) -> list[dict[str, Any]]:
    records: list[dict[str, Any]] = []
    maximum = int(config.get("max_candidates", 1_000_000))
    repetitions = int(config.get("repetitions", 8))
    constructions = [
        str(value) for value in config.get("constructions", ["simple", "reinjected", "deep-vector"])
    ]
    games = [
        str(value) for value in config.get("games", ["preimage", "second-preimage", "multi-target"])
    ]
    target_kinds = [
        str(value) for value in config.get("target_kinds", ["regular-image", "uniform"])
    ]
    objectives = [int(value) for value in config.get("target_counts", [1, 4])]
    attackers = [str(value) for value in config.get("attackers", ["random-search"])]
    for bits_value in config["widths"]:
        bits = int(bits_value)
        for multiplier_value in config.get("anchor_multipliers", [1]):
            anchor_multiplier = int(multiplier_value)
            anchor_bits = bits * anchor_multiplier
            for states_value in config["state_counts"]:
                states = int(states_value)
                for construction in constructions:
                    for game in games:
                        for target_kind in target_kinds:
                            if game == "second-preimage" and target_kind == "uniform":
                                continue
                            target_counts = objectives if game == "multi-target" else [1]
                            for target_count in target_counts:
                                for attacker in attackers:
                                    for repetition in range(repetitions):
                                        label = (
                                            f"EXP-20/{bits}/{states}/{construction}/{game}/"
                                            f"{target_kind}/{target_count}/{attacker}/{repetition}"
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
                                        anchor_queries = 0
                                        round_queries = 0
                                        if target_kind == "regular-image":
                                            targets = set()
                                            for message in fixed_messages:
                                                image, aq, rq = _image(
                                                    oracle,
                                                    message,
                                                    bits,
                                                    anchor_bits,
                                                    construction,
                                                    states,
                                                )
                                                targets.add(image)
                                                anchor_queries += aq
                                                round_queries += rq
                                        else:
                                            targets = {
                                                tuple(
                                                    fixed_rng.getrandbits(bits)
                                                    for _ in range(states)
                                                )
                                                for _ in range(target_count)
                                            }
                                        found = None
                                        tested = 0
                                        for candidate in _candidates(attacker, search_rng, maximum):
                                            if (
                                                game == "second-preimage"
                                                and candidate == fixed_messages[0]
                                            ):
                                                continue
                                            tested += 1
                                            image, aq, rq = _image(
                                                oracle,
                                                candidate,
                                                bits,
                                                anchor_bits,
                                                construction,
                                                states,
                                            )
                                            anchor_queries += aq
                                            round_queries += rq
                                            if image in targets:
                                                found = tested
                                                break
                                        work = found or tested
                                        effective_targets = len(targets)
                                        prediction = (
                                            bits * states
                                            if target_kind == "uniform"
                                            else min(anchor_bits, bits * states)
                                        )
                                        offline_queries = (
                                            anchor_queries + round_queries
                                            if attacker == "inversion-table"
                                            else 0
                                        )
                                        records.append(
                                            {
                                                "anchor_bits": anchor_bits,
                                                "anchor_multiplier": anchor_multiplier,
                                                "anchor_queries": anchor_queries,
                                                "attacker": attacker,
                                                "candidates": work,
                                                "censored": found is None,
                                                "construction": construction,
                                                "game": game,
                                                "log2_candidates": math.log2(max(1, work)),
                                                "memory_entries": (
                                                    work
                                                    if attacker == "inversion-table"
                                                    else effective_targets
                                                ),
                                                "offline_queries": offline_queries,
                                                "online_queries": (
                                                    1
                                                    if attacker == "inversion-table"
                                                    and found is not None
                                                    else anchor_queries + round_queries
                                                ),
                                                "predicted_log2": max(
                                                    0.0,
                                                    prediction
                                                    - math.log2(max(1, effective_targets)),
                                                ),
                                                "repetition": repetition,
                                                "round_queries": round_queries,
                                                "state_bits": bits,
                                                "state_count": states,
                                                "target_count": effective_targets,
                                                "target_kind": target_kind,
                                            }
                                        )
    return records


def _linear_fit(xs: list[float], ys: list[float]) -> tuple[float, float]:
    mean_x = statistics.fmean(xs)
    mean_y = statistics.fmean(ys)
    variance = sum((value - mean_x) ** 2 for value in xs)
    slope = (
        sum((x - mean_x) * (y - mean_y) for x, y in zip(xs, ys, strict=True)) / variance
        if variance
        else 0.0
    )
    return mean_y - slope * mean_x, slope


def summarize(records: list[dict[str, Any]]) -> list[dict[str, Any]]:
    fields = (
        "game",
        "attacker",
        "construction",
        "target_kind",
        "state_bits",
        "state_count",
        "target_count",
        "anchor_bits",
        "anchor_multiplier",
    )
    grouped: dict[tuple[Any, ...], list[dict[str, Any]]] = {}
    for record in records:
        grouped.setdefault(tuple(record[field] for field in fields), []).append(record)
    summaries: list[dict[str, Any]] = []
    for key, group in sorted(grouped.items()):
        durations = [int(item["candidates"]) for item in group]
        events = [not bool(item["censored"]) for item in group]
        curve = kaplan_meier(durations, events)
        summaries.append(
            {
                **dict(zip(fields, key, strict=True)),
                "censored": sum(bool(item["censored"]) for item in group),
                "median_anchor_queries": statistics.median(
                    int(item["anchor_queries"]) for item in group
                ),
                "median_log2_candidates": statistics.median(
                    float(item["log2_candidates"]) for item in group
                ),
                "median_memory_entries": statistics.median(
                    int(item["memory_entries"]) for item in group
                ),
                "median_round_queries": statistics.median(
                    int(item["round_queries"]) for item in group
                ),
                "observations": len(group),
                "predicted_log2": group[0]["predicted_log2"],
                "restricted_mean_candidates": restricted_mean(curve, max(durations)),
            }
        )
    fit_fields = (
        "game",
        "attacker",
        "construction",
        "target_kind",
        "state_count",
        "target_count",
        "anchor_multiplier",
    )
    fit_groups: dict[tuple[Any, ...], list[dict[str, Any]]] = {}
    for item in summaries:
        fit_groups.setdefault(tuple(item[field] for field in fit_fields), []).append(item)
    for group in fit_groups.values():
        xs = [float(item["predicted_log2"]) for item in group]
        ys = [math.log2(float(item["restricted_mean_candidates"])) for item in group]
        intercept, slope = _linear_fit(xs, ys)
        for item in group:
            item["work_exponent_intercept"] = intercept
            item["work_exponent_slope"] = slope
            item["work_exponent_width_cells"] = len(group)
    return summaries
