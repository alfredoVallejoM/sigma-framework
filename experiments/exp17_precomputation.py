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


def run(config: dict[str, Any]) -> list[dict[str, Any]]:
    records: list[dict[str, Any]] = []
    repetitions = int(config.get("repetitions", 8))
    entries = int(config.get("table_entries", 1024))
    distinguished_bits = int(config.get("distinguished_bits", 3))
    for bits_value in config["widths"]:
        bits = int(bits_value)
        if not 1 <= distinguished_bits <= bits:
            raise ValueError("distinguished_bits must be within the reduced width")
        for strategy in ("direct-table", "distinguished-points"):
            for construction in ("stationary", "reinjected"):
                for repetition in range(repetitions):
                    label = f"EXP-17/{bits}/{strategy}/{construction}/{repetition}"
                    rng = derived_random(str(config["master_seed"]), label)
                    oracle = ReducedOracle(rng.randbytes(32))
                    left_anchor = rng.getrandbits(bits)
                    right_anchor = rng.getrandbits(bits)
                    while right_anchor == left_anchor:
                        right_anchor = rng.getrandbits(bits)
                    states = [rng.getrandbits(bits) for _ in range(entries)]
                    if strategy == "distinguished-points":
                        mask = (1 << distinguished_bits) - 1
                        states = [state for state in states if state & mask == 0]
                    reusable = sum(
                        _transition(oracle, state, left_anchor, bits, construction)
                        == _transition(oracle, state, right_anchor, bits, construction)
                        for state in states
                    )
                    records.append(
                        {
                            "construction": construction,
                            "memory_entries": len(states),
                            "offline_queries": len(states),
                            "repetition": repetition,
                            "reuse_rate": reusable / len(states) if states else 0.0,
                            "reused_entries": reusable,
                            "state_bits": bits,
                            "strategy": strategy,
                        }
                    )
    return records


def summarize(records: list[dict[str, Any]]) -> list[dict[str, Any]]:
    fields = ("strategy", "construction", "state_bits")
    grouped: dict[tuple[Any, ...], list[dict[str, Any]]] = {}
    for record in records:
        grouped.setdefault(tuple(record[field] for field in fields), []).append(record)
    return [
        {
            **dict(zip(fields, key, strict=True)),
            "mean_reuse_rate": statistics.fmean(float(item["reuse_rate"]) for item in group),
            "observations": len(group),
            "total_offline_queries": sum(int(item["offline_queries"]) for item in group),
        }
        for key, group in sorted(grouped.items())
    ]
