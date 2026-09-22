"""Complexity ledger for Sigma Tree V1 ST3 checkpoint decode/restore."""

from __future__ import annotations

import argparse
import json
import statistics
import time
from pathlib import Path

from sigma.tree import (
    DEFAULT_PROFILE,
    TreeFrontier,
    TreeNode,
    TreeResumeCheckpointV1,
    restore_builder,
)

FRONTIER_NODE_COUNTS = (1, 2, 4, 8, 16, 24, 32, 40)


def _checkpoint(frontier_nodes: int) -> TreeResumeCheckpointV1:
    if not 1 <= frontier_nodes <= 48:
        raise ValueError("frontier_nodes outside benchmark range")
    nodes = []
    start = 0
    digests = (b"d" * 64,) * 4
    for height in range(frontier_nodes - 1, -1, -1):
        count = 1 << height
        nodes.append(
            TreeNode(
                start,
                count,
                count * DEFAULT_PROFILE.chunk_size,
                height,
                digests,
            )
        )
        start += count
    frontier = TreeFrontier(tuple(nodes))
    tail = b"t" * 123
    return TreeResumeCheckpointV1(
        DEFAULT_PROFILE,
        frontier.byte_length + len(tail),
        frontier.leaf_count,
        frontier,
        tail,
    )


def _linear_slope(points: list[tuple[float, float]]) -> float:
    xm = statistics.fmean(x for x, _ in points)
    ym = statistics.fmean(y for _, y in points)
    den = sum((x - xm) ** 2 for x, _ in points)
    if den == 0:
        return 0.0
    return sum((x - xm) * (y - ym) for x, y in points) / den


def run_benchmark(*, repeats: int) -> dict[str, object]:
    rows = []
    for node_count in FRONTIER_NODE_COUNTS:
        checkpoint = _checkpoint(node_count)
        wire = checkpoint.to_bytes()
        decode_times = []
        restore_times = []
        for _ in range(repeats):
            started = time.perf_counter_ns()
            decoded = TreeResumeCheckpointV1.from_bytes(wire)
            decode_times.append(time.perf_counter_ns() - started)

            started = time.perf_counter_ns()
            builder = restore_builder(decoded)
            restore_times.append(time.perf_counter_ns() - started)
            state = builder.checkpoint_state()
            if state[0] != checkpoint.frontier or state[1] != checkpoint.tail:
                raise AssertionError("restored benchmark checkpoint drifted")

        rows.append(
            {
                "frontier_nodes": node_count,
                "logical_leaf_count": checkpoint.completed_leaf_count,
                "checkpoint_wire_bytes": len(wire),
                "decode_median_ns": int(statistics.median(decode_times)),
                "restore_median_ns": int(statistics.median(restore_times)),
            }
        )

    return {
        "schema": "sigma-tree-st3-complexity-ledger-v1",
        "repeats": repeats,
        "rows": rows,
        "wire_bytes_per_frontier_node_slope": _linear_slope(
            [(float(row["frontier_nodes"]), float(row["checkpoint_wire_bytes"])) for row in rows]
        ),
        "decode_ns_per_frontier_node_slope": _linear_slope(
            [(float(row["frontier_nodes"]), float(row["decode_median_ns"])) for row in rows]
        ),
        "restore_ns_per_frontier_node_slope": _linear_slope(
            [(float(row["frontier_nodes"]), float(row["restore_median_ns"])) for row in rows]
        ),
        "derived_contract": {
            "frontier_nodes": "O(log N)",
            "checkpoint_wire": "O(m log N + chunk_size)",
            "decode": "O(m log N + tail)",
            "restore": "O(m log N + tail)",
            "tail": "strictly less than fixed 65,536-byte V1 chunk",
        },
        "interpretation": "local engineering evidence; no prefix bytes are rehashed during restore",
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repeats", type=int, default=25)
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
