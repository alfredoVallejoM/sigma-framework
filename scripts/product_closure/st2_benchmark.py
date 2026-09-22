"""Complexity ledger for Sigma Tree V1 ST2 proof size and verification."""

from __future__ import annotations

import argparse
import json
import math
import statistics
import time
from pathlib import Path

from sigma.tree import DEFAULT_PROFILE, TreeProofIndex, verify_inclusion, verify_range

LEAF_COUNTS = (1, 2, 4, 8, 16, 32, 64, 128)


def _linear_fit(points: list[tuple[float, float]]) -> tuple[float, float]:
    if len(points) < 2:
        return 0.0, 0.0
    xm = statistics.fmean(x for x, _ in points)
    ym = statistics.fmean(y for _, y in points)
    den = sum((x - xm) ** 2 for x, _ in points)
    if den == 0:
        return 0.0, ym
    slope = sum((x - xm) * (y - ym) for x, y in points) / den
    return slope, ym - slope * xm


def run_benchmark(*, repeats: int) -> dict[str, object]:
    rows = []
    chunk = b"x" * DEFAULT_PROFILE.chunk_size

    for leaf_count in LEAF_COUNTS:
        data = chunk * leaf_count
        index = TreeProofIndex(data)
        target = leaf_count // 2 if leaf_count > 1 else 0
        inclusion = index.prove_leaf(target)
        leaf_start = target * DEFAULT_PROFILE.chunk_size
        leaf_bytes = data[leaf_start : leaf_start + DEFAULT_PROFILE.chunk_size]

        inclusion_times = []
        for _ in range(repeats):
            started = time.perf_counter_ns()
            if not verify_inclusion(leaf_bytes, inclusion):
                raise AssertionError("inclusion benchmark verification failed")
            inclusion_times.append(time.perf_counter_ns() - started)

        start = 0 if leaf_count == 1 else DEFAULT_PROFILE.chunk_size // 2
        length = min(DEFAULT_PROFILE.chunk_size, len(data) - start)
        range_proof = index.prove_range(start, length)
        range_bytes = data[start : start + length]
        range_times = []
        for _ in range(repeats):
            started = time.perf_counter_ns()
            if not verify_range(range_bytes, range_proof):
                raise AssertionError("range benchmark verification failed")
            range_times.append(time.perf_counter_ns() - started)

        rows.append(
            {
                "leaf_count": leaf_count,
                "log2_leaf_count": math.log2(leaf_count),
                "inclusion_steps": len(inclusion.steps),
                "inclusion_wire_bytes": len(inclusion.to_bytes()),
                "inclusion_verify_median_ns": int(statistics.median(inclusion_times)),
                "range_witnesses": len(range_proof.witnesses),
                "range_wire_bytes": len(range_proof.to_bytes()),
                "range_verify_median_ns": int(statistics.median(range_times)),
            }
        )

    slope, intercept = _linear_fit(
        [
            (float(row["log2_leaf_count"]), float(row["inclusion_wire_bytes"]))
            for row in rows
        ]
    )
    return {
        "schema": "sigma-tree-st2-complexity-ledger-v1",
        "repeats": repeats,
        "rows": rows,
        "inclusion_wire_bytes_per_log2_leaf_slope": slope,
        "inclusion_wire_intercept": intercept,
        "derived_contract": {
            "inclusion_steps": "O(log N)",
            "inclusion_size": "O(m log N), m=4 fixed V1 branches",
            "range_witness_nodes": "O(log N) maximal complement cover",
            "range_edge_bytes": "at most 2*(chunk_size-1) bytes",
            "verification_io": "range bytes + proof only; no source-object read",
        },
        "interpretation": "local engineering complexity evidence; proof-generation index build cost is separately O(mB)",
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
