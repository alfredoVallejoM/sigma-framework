"""Small reproducible complexity ledger for Sigma Tree ST0."""

from __future__ import annotations

import argparse
import json
import math
import statistics
import time
from pathlib import Path

from sigma.tree import TreeBuilder

DEFAULT_SIZES = (0, 65_536, 262_144, 1_048_576, 4_194_304, 8_388_608)


def _slope(rows: list[dict[str, int]]) -> float | None:
    points = [row for row in rows if row["bytes"] >= 262_144 and row["median_ns"] > 0]
    if len(points) < 2:
        return None
    xs = [math.log(row["bytes"]) for row in points]
    ys = [math.log(row["median_ns"]) for row in points]
    xm = statistics.fmean(xs)
    ym = statistics.fmean(ys)
    den = sum((x - xm) ** 2 for x in xs)
    return sum((x - xm) * (y - ym) for x, y in zip(xs, ys)) / den


def run_benchmark(*, repeats: int, sizes: tuple[int, ...] = DEFAULT_SIZES) -> dict[str, object]:
    rows: list[dict[str, int]] = []
    for size in sizes:
        data = b"x" * size
        samples: list[int] = []
        max_frontier = 0
        leaf_count = 0
        for _ in range(repeats):
            builder = TreeBuilder()
            started = time.perf_counter_ns()
            builder.update(data)
            max_frontier = max(max_frontier, len(builder.frontier.nodes))
            root = builder.finalize()
            samples.append(time.perf_counter_ns() - started)
            leaf_count = root.leaf_count
        rows.append(
            {
                "bytes": size,
                "leaf_count": leaf_count,
                "frontier_nodes": max_frontier,
                "median_ns": int(statistics.median(samples)),
            }
        )
    return {
        "schema": "sigma-tree-st0-complexity-ledger-v1",
        "repeats": repeats,
        "rows": rows,
        "empirical_time_exponent": _slope(rows),
        "interpretation": (
            "exploratory local engineering evidence; not a cross-host performance claim"
        ),
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repeats", type=int, default=5)
    parser.add_argument("--report", type=Path)
    args = parser.parse_args()
    if args.repeats <= 0:
        parser.error("repeats must be positive")
    report = run_benchmark(repeats=args.repeats)
    payload = json.dumps(report, indent=2, sort_keys=True) + "\n"
    if args.report is not None:
        args.report.parent.mkdir(parents=True, exist_ok=True)
        args.report.write_text(payload, encoding="utf-8")
    print(payload, end="")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
