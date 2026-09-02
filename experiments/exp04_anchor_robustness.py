import math
import statistics
from typing import Any

from .common import derived_random
from .reduced_oracle import ReducedOracle, encode_integer


def _roots(
    oracle: ReducedOracle, candidate: int, n: int, branches: int, fault: str
) -> tuple[int, ...]:
    message = candidate.to_bytes(16, "big")
    values = [oracle.query(f"branch-{index}", n, message) for index in range(branches)]
    if fault == "constant-first":
        values[0] = 0
    elif fault == "correlated-first-two":
        values[1] = values[0]
    elif fault != "normal":
        raise ValueError(f"unsupported branch fault: {fault}")
    return tuple(values)


def _framed(values: tuple[int, ...], n: int) -> bytes:
    return b"".join(
        index.to_bytes(2, "big") + n.to_bytes(2, "big") + encode_integer(value, n)
        for index, value in enumerate(values)
    )


def _anchor(
    oracle: ReducedOracle, construction: str, roots: tuple[int, ...], n: int
) -> tuple[int, ...]:
    framed = _framed(roots, n)
    if construction == "psi-compressed":
        return (oracle.query("psi-compressed", n, framed),)
    connections = tuple(oracle.query(f"cross-{index}", n, framed) for index in range(len(roots)))
    if construction == "concat-wide":
        return roots
    if construction == "cross-wide":
        return roots + connections
    if construction == "cross-only":
        return connections
    raise ValueError(f"unsupported construction: {construction}")


def _segment(
    oracle: ReducedOracle, anchor: tuple[int, ...], n: int, target: int, k: int
) -> tuple[int, ...]:
    anchor_bytes = _framed(anchor, n)
    state = oracle.query("digest-init", n, anchor_bytes)
    states = [state]
    for index in range(target + k - 1):
        state = oracle.query(
            "digest-round",
            n,
            anchor_bytes,
            index.to_bytes(8, "big"),
            encode_integer(state, n),
        )
        states.append(state)
    return tuple(states[target : target + k])


def run(config: dict[str, Any]) -> list[dict[str, Any]]:
    records = []
    master_seed = str(config["master_seed"])
    repetitions = int(config.get("repetitions", 8))
    maximum = int(config.get("max_candidates", 1_000_000))
    constructions = ("psi-compressed", "concat-wide", "cross-wide", "cross-only")
    for n_value in config["widths"]:
        n = int(n_value)
        for branch_value in config["branch_counts"]:
            branches = int(branch_value)
            for fault in config["faults"]:
                for construction in constructions:
                    for repetition in range(repetitions):
                        label = f"EXP-04/{n}/{branches}/{fault}/{construction}/{repetition}"
                        rng = derived_random(master_seed, label)
                        oracle = ReducedOracle(rng.randbytes(32))
                        seen: dict[tuple[int, ...], tuple[int, tuple[int, ...]]] = {}
                        collision = None
                        for queries in range(1, maximum + 1):
                            candidate = rng.getrandbits(128)
                            roots = _roots(oracle, candidate, n, branches, str(fault))
                            anchor = _anchor(oracle, construction, roots, n)
                            if anchor in seen and seen[anchor][0] != candidate:
                                previous_candidate, previous_roots = seen[anchor]
                                collision = (
                                    queries,
                                    sum(
                                        a == b for a, b in zip(roots, previous_roots, strict=False)
                                    ),
                                    _segment(oracle, anchor, n, 1, 2)
                                    == _segment(
                                        oracle,
                                        _anchor(oracle, construction, previous_roots, n),
                                        n,
                                        1,
                                        2,
                                    ),
                                    previous_candidate,
                                    candidate,
                                )
                                break
                            seen[anchor] = (candidate, roots)
                        records.append(
                            {
                                "attack": "generic-birthday",
                                "anchor_collision": collision is not None,
                                "branches": branches,
                                "candidates": collision[0] if collision else maximum,
                                "censored": collision is None,
                                "components_equal": collision[1] if collision else None,
                                "construction": construction,
                                "digest_collision": collision[2] if collision else None,
                                "fault": fault,
                                "log2_candidates": math.log2(
                                    collision[0] if collision else maximum
                                ),
                                "repetition": repetition,
                                "state_bits": n,
                            }
                        )
                if fault == "normal":
                    for repetition in range(repetitions):
                        label = f"EXP-04/single-branch/{n}/{branches}/{repetition}"
                        rng = derived_random(master_seed, label)
                        oracle = ReducedOracle(rng.randbytes(32))
                        seen_branch: dict[int, tuple[int, tuple[int, ...]]] = {}
                        pair = None
                        for queries in range(1, maximum + 1):
                            candidate = rng.getrandbits(128)
                            roots = _roots(oracle, candidate, n, branches, "normal")
                            if roots[0] in seen_branch and seen_branch[roots[0]][0] != candidate:
                                pair = (queries, seen_branch[roots[0]], (candidate, roots))
                                break
                            seen_branch[roots[0]] = (candidate, roots)
                        if pair is None:
                            continue
                        queries, (_, left_roots), (_, right_roots) = pair
                        for construction in constructions:
                            left_anchor = _anchor(oracle, construction, left_roots, n)
                            right_anchor = _anchor(oracle, construction, right_roots, n)
                            records.append(
                                {
                                    "attack": "single-branch-collision",
                                    "anchor_collision": left_anchor == right_anchor,
                                    "branches": branches,
                                    "candidates": queries,
                                    "censored": False,
                                    "components_equal": sum(
                                        left == right
                                        for left, right in zip(left_roots, right_roots, strict=True)
                                    ),
                                    "construction": construction,
                                    "digest_collision": _segment(oracle, left_anchor, n, 1, 2)
                                    == _segment(oracle, right_anchor, n, 1, 2),
                                    "fault": fault,
                                    "log2_candidates": math.log2(queries),
                                    "repetition": repetition,
                                    "state_bits": n,
                                }
                            )
    # A control demonstrating why variable-length components require canonical framing.
    raw_left = b"a" + b"bc"
    raw_right = b"ab" + b"c"
    framed_left = b"\x00\x01a\x00\x02bc"
    framed_right = b"\x00\x02ab\x00\x01c"
    for construction, framing_collision in (
        ("unframed-concat-control", raw_left == raw_right),
        ("canonical-framing-control", framed_left == framed_right),
    ):
        records.append(
            {
                "attack": "framing-ambiguity-control",
                "anchor_collision": framing_collision,
                "branches": 2,
                "candidates": 2,
                "censored": False,
                "components_equal": 0,
                "construction": construction,
                "digest_collision": None,
                "fault": "normal",
                "log2_candidates": 1.0,
                "repetition": 0,
                "state_bits": 0,
            }
        )
    return records


def summarize(records: list[dict[str, Any]]) -> list[dict[str, Any]]:
    fields = ("attack", "construction", "fault", "state_bits", "branches")
    grouped: dict[tuple[Any, ...], list[dict[str, Any]]] = {}
    for record in records:
        grouped.setdefault(tuple(record[field] for field in fields), []).append(record)
    result = []
    for key, group in sorted(grouped.items()):
        result.append(
            {
                **dict(zip(fields, key, strict=False)),
                "anchor_collisions": sum(bool(item["anchor_collision"]) for item in group),
                "censored": sum(bool(item["censored"]) for item in group),
                "digest_collisions": sum(item["digest_collision"] is True for item in group),
                "median_log2_candidates": statistics.median(
                    float(item["log2_candidates"]) for item in group
                ),
                "observations": len(group),
            }
        )
    return result
