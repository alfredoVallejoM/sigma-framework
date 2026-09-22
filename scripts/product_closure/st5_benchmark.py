"""Comprehensive performance/scale ledger for Sigma Tree V1 ST5."""

from __future__ import annotations

import argparse
import cProfile
import json
import pstats
import statistics
import tempfile
import time
import tracemalloc
from pathlib import Path

from reference.tree_v1 import root_wire as reference_root_wire
from sigma.tree import (
    DEFAULT_PROFILE,
    TreeDeltaIndex,
    TreeEditV1,
    TreeProofIndex,
    TreeResumeCheckpointV1,
    build_directory_manifest,
    build_tree,
    checkpoint_bytes,
    prove_leaf_streaming,
    prove_range_streaming,
    restore_builder,
    verify_inclusion,
    verify_range,
)

CHUNK = DEFAULT_PROFILE.chunk_size
BUILD_SIZES = (CHUNK, 4 * CHUNK, 16 * CHUNK, 64 * CHUNK)
STREAM_CHUNKS = (1, 4, 16, 64, 256, 512)
PROOF_LEAVES = (8, 32, 128, 256)


def _measure(callable_, repeats: int = 1):
    observations = []
    peaks = []
    result = None
    for _ in range(repeats):
        tracemalloc.start()
        started = time.perf_counter_ns()
        result = callable_()
        observations.append(time.perf_counter_ns() - started)
        _, peak = tracemalloc.get_traced_memory()
        tracemalloc.stop()
        peaks.append(peak)
    return result, int(statistics.median(observations)), int(max(peaks))


def _pattern(size: int, salt: int = 0) -> bytes:
    block = bytes((i * 37 + salt) % 251 for i in range(CHUNK))
    full, tail = divmod(size, CHUNK)
    return block * full + block[:tail]


def _cpu_profile_build(data: bytes) -> list[dict[str, object]]:
    profiler = cProfile.Profile()
    profiler.enable()
    root = build_tree(data)
    profiler.disable()
    if root.byte_length != len(data):
        raise AssertionError("CPU profile build drift")
    stats = pstats.Stats(profiler)
    rows = []
    for (filename, line, function), values in stats.stats.items():
        cc, nc, tt, ct, _ = values
        rows.append(
            {
                "file": Path(filename).name,
                "line": line,
                "function": function,
                "primitive_calls": cc,
                "calls": nc,
                "total_seconds": tt,
                "cumulative_seconds": ct,
            }
        )
    rows.sort(key=lambda row: float(row["cumulative_seconds"]), reverse=True)
    return rows[:15]


def run_ledger(*, repeats: int) -> dict[str, object]:
    build_rows = []
    for size in BUILD_SIZES:
        data = _pattern(size, salt=size // CHUNK)
        optimized_root, optimized_ns, optimized_peak = _measure(
            lambda data=data: build_tree(data),
            repeats,
        )
        reference_wire, reference_ns, reference_peak = _measure(
            lambda data=data: reference_root_wire(data),
            1,
        )
        if optimized_root.to_bytes() != reference_wire:
            raise AssertionError(f"optimized/reference build drift at {size}")
        build_rows.append(
            {
                "bytes": size,
                "optimized_median_ns": optimized_ns,
                "reference_ns": reference_ns,
                "speedup_vs_reference": reference_ns / optimized_ns if optimized_ns else None,
                "optimized_peak_allocated_bytes": optimized_peak,
                "reference_peak_allocated_bytes": reference_peak,
                "optimized_throughput_mib_s": (
                    size / (1024 * 1024) / (optimized_ns / 1e9)
                    if optimized_ns
                    else None
                ),
            }
        )

    streaming_rows = []
    shared_chunk = _pattern(CHUNK, salt=91)
    for chunks in STREAM_CHUNKS:
        def run_stream(chunks=chunks):
            from sigma.tree import TreeBuilder

            builder = TreeBuilder()
            for _ in range(chunks):
                builder.update(shared_chunk)
            return builder.finalize()

        root, elapsed_ns, peak = _measure(run_stream, 1)
        expected_bytes = chunks * CHUNK
        if root.byte_length != expected_bytes:
            raise AssertionError("streaming sweep byte accounting drift")
        streaming_rows.append(
            {
                "chunks": chunks,
                "input_bytes": expected_bytes,
                "elapsed_ns": elapsed_ns,
                "peak_allocated_bytes": peak,
                "peak_to_input_ratio": peak / expected_bytes,
            }
        )

    proof_rows = []
    for leaves in PROOF_LEAVES:
        data = _pattern(leaves * CHUNK + 19, salt=leaves)
        target = leaves // 2
        index, index_ns, index_peak = _measure(lambda data=data: TreeProofIndex(data), 1)

        full_inclusion, full_inc_ns, full_inc_peak = _measure(
            lambda index=index, target=target: index.prove_leaf(target),
            repeats,
        )
        stream_inclusion, stream_inc_ns, stream_inc_peak = _measure(
            lambda data=data, target=target: prove_leaf_streaming(data, target),
            1,
        )
        if full_inclusion.to_bytes() != stream_inclusion.to_bytes():
            raise AssertionError("inclusion FULL/STREAMING drift")

        start = CHUNK - 7
        length = min(2 * CHUNK + 23, len(data) - start)
        full_range, full_range_ns, full_range_peak = _measure(
            lambda index=index, start=start, length=length: index.prove_range(start, length),
            repeats,
        )
        stream_range, stream_range_ns, stream_range_peak = _measure(
            lambda data=data, start=start, length=length: prove_range_streaming(
                data, start, length
            ),
            1,
        )
        if full_range.to_bytes() != stream_range.to_bytes():
            raise AssertionError("range FULL/STREAMING drift")

        _, inc_verify_ns, inc_verify_peak = _measure(
            lambda data=data, proof=full_inclusion, target=target: verify_inclusion(
                data[target * CHUNK : min((target + 1) * CHUNK, len(data))],
                proof,
            ),
            repeats,
        )
        _, range_verify_ns, range_verify_peak = _measure(
            lambda data=data, proof=full_range, start=start, length=length: verify_range(
                data[start : start + length],
                proof,
            ),
            repeats,
        )

        proof_rows.append(
            {
                "leaves": leaves + 1,
                "source_bytes": len(data),
                "index_build_ns": index_ns,
                "index_peak_allocated_bytes": index_peak,
                "index_peak_to_source_ratio": index_peak / len(data),
                "inclusion_steps": len(full_inclusion.steps),
                "full_inclusion_generation_ns": full_inc_ns,
                "streaming_inclusion_generation_ns": stream_inc_ns,
                "full_inclusion_peak_bytes": full_inc_peak,
                "streaming_inclusion_peak_bytes": stream_inc_peak,
                "inclusion_verify_ns": inc_verify_ns,
                "inclusion_verify_peak_bytes": inc_verify_peak,
                "range_witnesses": len(full_range.witnesses),
                "full_range_generation_ns": full_range_ns,
                "streaming_range_generation_ns": stream_range_ns,
                "full_range_peak_bytes": full_range_peak,
                "streaming_range_peak_bytes": stream_range_peak,
                "range_verify_ns": range_verify_ns,
                "range_verify_peak_bytes": range_verify_peak,
            }
        )

    # Resume: restore is independent of prefix size except frontier O(log N)+tail.
    prefix = _pattern(256 * CHUNK + 123, salt=17)
    checkpoint = checkpoint_bytes(prefix)
    _, restore_ns, restore_peak = _measure(
        lambda checkpoint=checkpoint: restore_builder(checkpoint),
        max(10, repeats),
    )

    # Delta/append representative local regime; detailed fraction sweep remains ST4 ledger.
    delta_data = _pattern(256 * CHUNK + 19, salt=23)
    delta_index = TreeDeltaIndex(delta_data)
    delta_edit = TreeEditV1(200 * CHUNK + 17, 1, b"Z")
    delta_result, delta_ns, delta_peak = _measure(
        lambda: delta_index.apply_delta([delta_edit]),
        repeats,
    )
    if delta_result.telemetry.leaf_payload_bytes_rehashed > CHUNK:
        raise AssertionError("ST5 representative local delta lost locality")
    append_result, append_ns, append_peak = _measure(
        lambda: delta_index.append(b"A" * (CHUNK + 17)),
        repeats,
    )

    # Manifest includes real file I/O and one-chunk read policy.
    with tempfile.TemporaryDirectory(prefix="sigma-st5-manifest-") as temp:
        root = Path(temp)
        for index in range(64):
            (root / f"{index:03d}.bin").write_bytes(_pattern(CHUNK, salt=index))
        manifest, manifest_ns, manifest_peak = _measure(
            lambda: build_directory_manifest(root),
            1,
        )
        manifest_wire_bytes = len(manifest.to_bytes())

    cpu_profile_data = _pattern(16 * CHUNK, salt=101)
    cpu_profile = _cpu_profile_build(cpu_profile_data)

    return {
        "schema": "sigma-tree-st5-performance-ledger-v1",
        "repeats": repeats,
        "build": build_rows,
        "streaming_memory": streaming_rows,
        "proofs": proof_rows,
        "resume": {
            "prefix_bytes": len(prefix),
            "frontier_nodes": len(checkpoint.frontier.nodes),
            "tail_bytes": len(checkpoint.tail),
            "restore_median_ns": restore_ns,
            "restore_peak_allocated_bytes": restore_peak,
        },
        "delta": {
            "source_bytes": len(delta_data),
            "incremental_ns": delta_ns,
            "peak_allocated_bytes": delta_peak,
            "rehashed_payload_bytes": delta_result.telemetry.leaf_payload_bytes_rehashed,
            "recomputed_nodes": len(delta_result.telemetry.recomputed_nodes),
        },
        "append": {
            "appended_bytes": CHUNK + 17,
            "incremental_ns": append_ns,
            "peak_allocated_bytes": append_peak,
            "rehashed_payload_bytes": append_result.telemetry.leaf_payload_bytes_rehashed,
            "frontier_nodes_reused": append_result.telemetry.frontier_nodes_reused,
        },
        "manifest": {
            "files": 64,
            "input_bytes": 64 * CHUNK,
            "manifest_wire_bytes": manifest_wire_bytes,
            "elapsed_ns": manifest_ns,
            "peak_allocated_bytes": manifest_peak,
        },
        "cpu_profile_top": cpu_profile,
        "claims": {
            "optimized_build_wire": "byte-identical to independent Tree V1 reference",
            "proof_index_payload_copy": "zero-copy memoryviews; source retained once",
            "streaming_build_memory": "bounded independently of B apart from caller input/read chunk",
            "streaming_proof_fallback": "O(log N) auxiliary structure, O(B) hashing work",
            "delta_index_payload_copy": "one explicit mutable payload copy, policy-budgeted",
        },
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repeats", type=int, default=3)
    parser.add_argument("--report", type=Path)
    args = parser.parse_args()
    if args.repeats <= 0:
        parser.error("repeats must be positive")
    report = run_ledger(repeats=args.repeats)
    payload = json.dumps(report, indent=2, sort_keys=True) + "\n"
    if args.report is not None:
        args.report.parent.mkdir(parents=True, exist_ok=True)
        args.report.write_text(payload, encoding="utf-8")
    print(payload, end="")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
