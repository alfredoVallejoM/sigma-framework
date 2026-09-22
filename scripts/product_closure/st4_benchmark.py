"""Performance/work ledger for Sigma Tree V1 ST4 delta and append."""

from __future__ import annotations

import argparse
import json
import math
import resource
import statistics
import time
import tracemalloc
from pathlib import Path

from sigma.tree import TreeDeltaIndex, TreeEditV1, build_tree

CHUNK = 65_536
DEFAULT_LEAVES = 1_000


def _fraction_cases(leaves: int) -> tuple[tuple[str, int], ...]:
    return (
        ("one_leaf", 1),
        ("0.1%", max(1, round(leaves * 0.001))),
        ("1%", max(1, round(leaves * 0.01))),
        ("10%", max(1, round(leaves * 0.10))),
        ("100%", leaves),
    )


def _rss_kib() -> int:
    return int(resource.getrusage(resource.RUSAGE_SELF).ru_maxrss)


def run_benchmark(*, leaves: int, repeats: int) -> dict[str, object]:
    if leaves < 10:
        raise ValueError("benchmark needs at least 10 leaves")
    chunk = bytes((i * 47 + 17) % 251 for i in range(CHUNK))
    data = chunk * leaves
    index = TreeDeltaIndex(data)

    rows = []
    for row_index, (label, affected_count) in enumerate(_fraction_cases(leaves)):
        selected = tuple(
            min(leaves - 1, math.floor(i * leaves / affected_count))
            for i in range(affected_count)
        )
        selected = tuple(dict.fromkeys(selected))
        edits = [
            TreeEditV1(
                leaf * CHUNK + (row_index % CHUNK),
                1,
                bytes(((row_index + leaf + 1) % 251,)),
            )
            for leaf in selected
        ]

        samples = []
        peak_allocations = []
        rss_before = _rss_kib()
        last_result = None
        for _ in range(repeats):
            # Repeat with a new byte value so every run remains a real semantic update.
            shifted = [
                TreeEditV1(
                    edit.start,
                    edit.delete_length,
                    bytes(((edit.data[0] + 1) % 251,)),
                )
                for edit in edits
            ]
            tracemalloc.start()
            started = time.perf_counter_ns()
            last_result = index.apply_delta(shifted)
            samples.append(time.perf_counter_ns() - started)
            _, peak = tracemalloc.get_traced_memory()
            peak_allocations.append(peak)
            tracemalloc.stop()
            edits = shifted

        assert last_result is not None
        materialized = index.materialize()
        started = time.perf_counter_ns()
        rebuilt = build_tree(materialized)
        rebuild_ns = time.perf_counter_ns() - started
        if rebuilt != last_result.root:
            raise AssertionError("incremental benchmark root diverged from rebuild")

        telemetry = last_result.telemetry
        median_ns = int(statistics.median(samples))
        rows.append(
            {
                "label": label,
                "target_fraction": affected_count / leaves,
                "affected_leaves": len(telemetry.affected_leaves),
                "replacement_bytes": telemetry.edit_bytes,
                "leaf_payload_bytes_rehashed": telemetry.leaf_payload_bytes_rehashed,
                "ancestor_nodes_recomputed": telemetry.recomputed_internal_node_count,
                "recomputed_nodes_total": len(telemetry.recomputed_nodes),
                "reused_nodes": len(telemetry.reused_nodes),
                "incremental_median_ns": median_ns,
                "full_rebuild_ns": rebuild_ns,
                "speedup_vs_rebuild": rebuild_ns / median_ns if median_ns else None,
                "tracemalloc_peak_bytes": int(max(peak_allocations)),
                "rss_highwater_kib_before": rss_before,
                "rss_highwater_kib_after": _rss_kib(),
            }
        )

    append_rows = []
    for label, size in (
        ("append_1_byte", 1),
        ("append_1_chunk", CHUNK),
        ("append_4_chunks_tail", 4 * CHUNK + 17),
    ):
        suffix = bytes((i * 13 + len(label)) % 251 for i in range(size))
        started = time.perf_counter_ns()
        result = index.append(suffix)
        elapsed = time.perf_counter_ns() - started
        materialized = index.materialize()
        started = time.perf_counter_ns()
        rebuilt = build_tree(materialized)
        rebuild_ns = time.perf_counter_ns() - started
        if result.root != rebuilt:
            raise AssertionError("append benchmark root diverged from rebuild")
        append_rows.append(
            {
                "label": label,
                "appended_bytes": size,
                "affected_leaf_records": len(result.telemetry.affected_leaves),
                "leaf_payload_bytes_rehashed": result.telemetry.leaf_payload_bytes_rehashed,
                "recomputed_nodes_total": len(result.telemetry.recomputed_nodes),
                "reused_nodes": len(result.telemetry.reused_nodes),
                "frontier_nodes_reused": result.telemetry.frontier_nodes_reused,
                "incremental_ns": elapsed,
                "full_rebuild_ns": rebuild_ns,
                "speedup_vs_rebuild": rebuild_ns / elapsed if elapsed else None,
            }
        )

    local_rows = [row for row in rows if row["target_fraction"] <= 0.01]
    if not local_rows:
        raise AssertionError("missing local ST4 benchmark regime")
    if any(row["leaf_payload_bytes_rehashed"] >= len(data) for row in local_rows):
        raise AssertionError("local incremental update rehashed approximately the full object")

    return {
        "schema": "sigma-tree-st4-performance-ledger-v1",
        "tree_leaves": leaves,
        "tree_bytes": len(data),
        "repeats": repeats,
        "delta_rows": rows,
        "append_rows": append_rows,
        "derived_contract": {
            "delta": "O(B_delta + m*|Anc(A)|) after index construction",
            "delta_upper": "O(B_delta + m*k*log N)",
            "append": "O(tail + appended bytes + m*new/bridge nodes)",
            "index_build": "O(mB), excluded from per-update incremental timing",
        },
        "interpretation": (
            "engineering ledger; full rebuild baseline excludes materialize() time, "
            "RSS is process high-water and tracemalloc is per-update Python allocation peak"
        ),
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--leaves", type=int, default=DEFAULT_LEAVES)
    parser.add_argument("--repeats", type=int, default=1)
    parser.add_argument("--report", type=Path)
    args = parser.parse_args()
    if args.repeats <= 0:
        parser.error("repeats must be positive")
    report = run_benchmark(leaves=args.leaves, repeats=args.repeats)
    payload = json.dumps(report, indent=2, sort_keys=True) + "\n"
    if args.report is not None:
        args.report.parent.mkdir(parents=True, exist_ok=True)
        args.report.write_text(payload, encoding="utf-8")
    print(payload, end="")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
