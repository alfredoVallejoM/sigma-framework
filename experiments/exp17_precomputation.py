"""EXP-17: reduced cross-anchor precomputation and time-memory controls."""

import statistics
from typing import Any

from .common import derived_random
from .reduced_oracle import ReducedOracle, encode_integer


def _transition(
    oracle: ReducedOracle, state: int, anchor: int, bits: int, construction: str
) -> int:
    parts = [encode_integer(state, bits)]
    if construction == "reinjected":
        parts.insert(0, encode_integer(anchor, bits))
    elif construction != "stationary":
        raise ValueError(f"unsupported construction: {construction}")
    return oracle.query(f"precompute-{construction}", bits, *parts)


def _chain(
    oracle: ReducedOracle,
    start: int,
    anchor: int,
    bits: int,
    construction: str,
    length: int,
    *,
    rainbow: bool = False,
) -> list[int]:
    mask = (1 << bits) - 1
    path = [start]
    state = start
    for step in range(length):
        state = _transition(oracle, state, anchor, bits, construction)
        if rainbow:
            state = (state + (step + 1) * 0x9E3779B1) & mask
        path.append(state)
    return path


def _measure_strategy(
    oracle: ReducedOracle,
    rng,
    strategy: str,
    construction: str,
    anchors: list[int],
    bits: int,
    entries: int,
    distinguished_bits: int,
    chain_length: int,
) -> dict[str, int | float]:
    states = [rng.getrandbits(bits) for _ in range(entries)]
    online_anchors = anchors[1:]
    if strategy in {"direct-table", "distinguished-points"}:
        if strategy == "distinguished-points":
            mask = (1 << distinguished_bits) - 1
            states = [state for state in states if state & mask == 0]
        offline = [_transition(oracle, state, anchors[0], bits, construction) for state in states]
        reused = 0
        for anchor in online_anchors:
            reused += sum(
                value == _transition(oracle, state, anchor, bits, construction)
                for state, value in zip(states, offline, strict=True)
            )
        comparisons = len(states) * len(online_anchors)
        return {
            "memory_entries": len(states),
            "offline_queries": len(states),
            "online_queries": comparisons,
            "parallel_depth": 1 if states else 0,
            "reuse_rate": reused / comparisons if comparisons else 0.0,
            "reused_entries": reused,
        }
    if strategy == "rho":
        start = states[0] if states else 0
        offline_path = set(_chain(oracle, start, anchors[0], bits, construction, chain_length))
        reused = 0
        for anchor in online_anchors:
            online_path = _chain(oracle, start, anchor, bits, construction, chain_length)
            reused += int(any(state in offline_path for state in online_path[1:]))
        return {
            "memory_entries": len(offline_path),
            "offline_queries": chain_length,
            "online_queries": chain_length * len(online_anchors),
            "parallel_depth": chain_length,
            "reuse_rate": reused / len(online_anchors) if online_anchors else 0.0,
            "reused_entries": reused,
        }
    if strategy in {"hellman", "rainbow"}:
        starts = states[: max(1, entries // chain_length)]
        rainbow = strategy == "rainbow"
        endpoints = {
            _chain(
                oracle,
                start,
                anchors[0],
                bits,
                construction,
                chain_length,
                rainbow=rainbow,
            )[-1]
            for start in starts
        }
        reused = 0
        for anchor in online_anchors:
            reused += sum(
                _chain(
                    oracle,
                    start,
                    anchor,
                    bits,
                    construction,
                    chain_length,
                    rainbow=rainbow,
                )[-1]
                in endpoints
                for start in starts
            )
        comparisons = len(starts) * len(online_anchors)
        return {
            "memory_entries": len(endpoints),
            "offline_queries": len(starts) * chain_length,
            "online_queries": comparisons * chain_length,
            "parallel_depth": chain_length,
            "reuse_rate": reused / comparisons if comparisons else 0.0,
            "reused_entries": reused,
        }
    if strategy == "multicollision":
        images = [
            {_transition(oracle, state, anchor, bits, construction) for state in states}
            for anchor in anchors
        ]
        shared = set.intersection(*images) if images else set()
        return {
            "memory_entries": sum(len(image) for image in images),
            "offline_queries": len(states),
            "online_queries": len(states) * len(online_anchors),
            "parallel_depth": 1,
            "reuse_rate": len(shared) / max(1, len(images[0])),
            "reused_entries": len(shared),
        }
    raise ValueError(f"unsupported EXP-17 strategy: {strategy}")


def run(config: dict[str, Any]) -> list[dict[str, Any]]:
    records: list[dict[str, Any]] = []
    repetitions = int(config.get("repetitions", 8))
    entries = int(config.get("table_entries", 1024))
    distinguished_bits = int(config.get("distinguished_bits", 3))
    chain_length = int(config.get("chain_length", 16))
    strategies = [
        str(value) for value in config.get("strategies", ["direct-table", "distinguished-points"])
    ]
    anchor_counts = [int(value) for value in config.get("anchor_counts", [2])]
    if entries < 1 or chain_length < 1:
        raise ValueError("table_entries and chain_length must be positive")
    for bits_value in config["widths"]:
        bits = int(bits_value)
        if not 1 <= distinguished_bits <= bits:
            raise ValueError("distinguished_bits must be within the reduced width")
        for anchor_count in anchor_counts:
            if anchor_count < 2:
                raise ValueError("EXP-17 requires at least two anchors")
            if anchor_count > 1 << bits:
                raise ValueError("anchor_count exceeds the reduced anchor space")
            for strategy in strategies:
                for construction in ("stationary", "reinjected"):
                    for repetition in range(repetitions):
                        label = (
                            f"EXP-17/{bits}/{anchor_count}/{strategy}/{construction}/{repetition}"
                        )
                        rng = derived_random(str(config["master_seed"]), label)
                        oracle = ReducedOracle(rng.randbytes(32))
                        anchors: list[int] = []
                        while len(anchors) < anchor_count:
                            value = rng.getrandbits(bits)
                            if value not in anchors:
                                anchors.append(value)
                        metrics = _measure_strategy(
                            oracle,
                            rng,
                            strategy,
                            construction,
                            anchors,
                            bits,
                            entries,
                            distinguished_bits,
                            chain_length,
                        )
                        total_queries = int(metrics["offline_queries"]) + int(
                            metrics["online_queries"]
                        )
                        records.append(
                            {
                                "anchor_count": anchor_count,
                                "construction": construction,
                                **metrics,
                                "queries_per_anchor": total_queries / anchor_count,
                                "repetition": repetition,
                                "state_bits": bits,
                                "strategy": strategy,
                                "total_queries": total_queries,
                            }
                        )
    return records


def summarize(records: list[dict[str, Any]]) -> list[dict[str, Any]]:
    fields = ("strategy", "construction", "state_bits", "anchor_count")
    grouped: dict[tuple[Any, ...], list[dict[str, Any]]] = {}
    for record in records:
        grouped.setdefault(tuple(record[field] for field in fields), []).append(record)
    return [
        {
            **dict(zip(fields, key, strict=True)),
            "mean_reuse_rate": statistics.fmean(float(item["reuse_rate"]) for item in group),
            "median_memory_entries": statistics.median(
                int(item["memory_entries"]) for item in group
            ),
            "median_online_queries": statistics.median(
                int(item["online_queries"]) for item in group
            ),
            "median_parallel_depth": statistics.median(
                int(item["parallel_depth"]) for item in group
            ),
            "observations": len(group),
            "total_offline_queries": sum(int(item["offline_queries"]) for item in group),
        }
        for key, group in sorted(grouped.items())
    ]
