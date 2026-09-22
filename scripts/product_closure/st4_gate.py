"""Reproducible ST4 closure gate for Sigma Tree V1 delta/append."""

from __future__ import annotations

import argparse
import hashlib
import json
import random
import time
from pathlib import Path

import sigma.tree.delta as delta_module
from reference.tree_delta_v1 import (
    ancestor_closure as reference_ancestor_closure,
    append_root_wire,
    apply_same_length,
    delta_root_wire,
)
from sigma.tree import (
    RebuildRequired,
    TreeDeltaIndex,
    TreeEditV1,
    build_tree,
    normalize_tree_edits,
)

MIN_DELTA_CASES = 5_000
MIN_APPEND_CASES = 1_000
MIN_DIFFERENTIAL_CASES = 500
LOCALITY_LEAVES = 128


def _random_edit(rng: random.Random, size: int, max_width: int = 128) -> TreeEditV1:
    start = rng.randrange(size)
    width = rng.randrange(1, min(max_width, size - start) + 1)
    return TreeEditV1(start, width, rng.randbytes(width))


def run_gate(
    *,
    delta_cases: int,
    append_cases: int,
    differential_cases: int,
) -> dict[str, object]:
    if delta_cases < MIN_DELTA_CASES:
        raise ValueError(f"ST4 requires at least {MIN_DELTA_CASES} delta cases")
    if append_cases < MIN_APPEND_CASES:
        raise ValueError(f"ST4 requires at least {MIN_APPEND_CASES} append cases")
    if differential_cases < MIN_DIFFERENTIAL_CASES:
        raise ValueError(
            f"ST4 requires at least {MIN_DIFFERENTIAL_CASES} differential cases"
        )

    started = time.perf_counter()
    rng = random.Random(0x53543447415445)

    chunk = bytes((i * 43 + 7) % 251 for i in range(65_536))
    data = chunk * 64 + b"tail-state"
    index = TreeDeltaIndex(data)
    reference = bytearray(data)

    delta_digest = hashlib.sha256()
    max_local_recomputed_nodes = 0
    max_local_rehashed_payload = 0

    for case in range(delta_cases):
        edit = _random_edit(rng, len(reference))
        result = index.apply_delta([edit])
        reference[edit.start : edit.end] = edit.data

        if result.telemetry.recomputed_leaf_count > 2:
            raise AssertionError("small ST4 delta unexpectedly recomputed >2 leaves")
        max_local_recomputed_nodes = max(
            max_local_recomputed_nodes, len(result.telemetry.recomputed_nodes)
        )
        max_local_rehashed_payload = max(
            max_local_rehashed_payload, result.telemetry.leaf_payload_bytes_rehashed
        )
        if set(result.telemetry.recomputed_nodes) != set(
            result.telemetry.invalidated_nodes
        ):
            raise AssertionError("delta recomputation exceeds exact invalidation closure")

        if case % 50 == 0:
            expected = build_tree(bytes(reference))
            if result.root != expected:
                raise AssertionError(f"sampled full rebuild divergence at delta case {case}")
            delta_digest.update(hashlib.sha256(result.root.to_bytes()).digest())

    # Canonical overlap normalization is order-independent.
    overlap = (
        TreeEditV1(0, 4, b"ABCD"),
        TreeEditV1(2, 4, b"CDEF"),
        TreeEditV1(6, 2, b"GH"),
    )
    normalized = normalize_tree_edits(list(overlap), total_bytes=len(reference))
    if normalized != (TreeEditV1(0, 8, b"ABCDEFGH"),):
        raise AssertionError("overlap normalization drifted")
    for order in (overlap, tuple(reversed(overlap)), (overlap[1], overlap[0], overlap[2])):
        if normalize_tree_edits(list(order), total_bytes=len(reference)) != normalized:
            raise AssertionError("overlap normalization depends on input order")

    try:
        normalize_tree_edits(
            [TreeEditV1(1, 0, b"x")],
            total_bytes=len(reference),
        )
    except RebuildRequired:
        pass
    else:
        raise AssertionError("boundary-shifting edit did not request rebuild")

    # Delta failure before publication.
    before_root = index.root
    before_bytes = index.materialize()
    original_combine = delta_module.combine_nodes
    fail_counter = 0

    def fail_delta(*args, **kwargs):
        nonlocal fail_counter
        fail_counter += 1
        if fail_counter == 1:
            raise RuntimeError("ST4 injected delta failure")
        return original_combine(*args, **kwargs)

    delta_module.combine_nodes = fail_delta
    try:
        try:
            index.apply_delta([TreeEditV1(65_536 + 3, 1, b"Q")])
        except RuntimeError as exc:
            if "injected" not in str(exc):
                raise
        else:
            raise AssertionError("delta failure injection did not fail")
    finally:
        delta_module.combine_nodes = original_combine

    if index.root != before_root or index.materialize() != before_bytes:
        raise AssertionError("delta failure published partial state")

    # Append campaign: small suffixes exercise tail reuse repeatedly.
    append_digest = hashlib.sha256()
    total_frontier_reused = 0
    append_reference = bytearray(reference)
    for case in range(append_cases):
        width = rng.randrange(0, 4097)
        suffix = rng.randbytes(width)
        result = index.append(suffix)
        append_reference.extend(suffix)
        total_frontier_reused += result.telemetry.frontier_nodes_reused
        if case % 25 == 0:
            expected = build_tree(bytes(append_reference))
            if result.root != expected:
                raise AssertionError(f"sampled append rebuild divergence at case {case}")
            append_digest.update(hashlib.sha256(result.root.to_bytes()).digest())

    if bytes(append_reference) != index.materialize():
        raise AssertionError("append materialized bytes diverged")
    if total_frontier_reused == 0:
        raise AssertionError("append campaign reused no prior frontier nodes")

    # Append failure before publication.
    before_root = index.root
    before_bytes = index.materialize()
    fail_counter = 0

    def fail_append(*args, **kwargs):
        nonlocal fail_counter
        fail_counter += 1
        if fail_counter == 1:
            raise RuntimeError("ST4 injected append failure")
        return original_combine(*args, **kwargs)

    delta_module.combine_nodes = fail_append
    try:
        try:
            index.append(b"fault-suffix" * 100)
        except RuntimeError as exc:
            if "injected append" not in str(exc):
                raise
        else:
            raise AssertionError("append failure injection did not fail")
    finally:
        delta_module.combine_nodes = original_combine

    if index.root != before_root or index.materialize() != before_bytes:
        raise AssertionError("append failure published partial state")

    # Independent fresh-tree differential corpus.
    differential_digest = hashlib.sha256()
    for case in range(differential_cases):
        size = rng.randrange(1, 8 * 65_536 + 257)
        source = rng.randbytes(size)

        edits = []
        available_leaves = list(range((size + 65_535) // 65_536))
        rng.shuffle(available_leaves)
        for leaf in available_leaves[: rng.randrange(1, min(5, len(available_leaves) + 1))]:
            leaf_start = leaf * 65_536
            leaf_end = min(leaf_start + 65_536, size)
            start = rng.randrange(leaf_start, leaf_end)
            width = rng.randrange(1, min(256, leaf_end - start) + 1)
            edits.append(TreeEditV1(start, width, rng.randbytes(width)))
        product = TreeDeltaIndex(source)
        delta_result = product.apply_delta(edits)
        tuples = [(edit.start, edit.delete_length, edit.data) for edit in edits]
        if delta_result.root.to_bytes() != delta_root_wire(source, tuples):
            raise AssertionError(f"independent delta divergence at case {case}")
        if delta_result.telemetry.invalidated_nodes != reference_ancestor_closure(
            delta_result.root.leaf_count,
            delta_result.telemetry.affected_leaves,
        ):
            raise AssertionError(f"ancestor closure divergence at case {case}")

        suffix = rng.randbytes(rng.randrange(0, 2 * 65_536 + 257))
        append_source = apply_same_length(source, tuples)
        append_result = product.append(suffix)
        if append_result.root.to_bytes() != append_root_wire(append_source, suffix):
            raise AssertionError(f"independent append divergence at case {case}")

        differential_digest.update(
            hashlib.sha256(delta_result.root.to_bytes()).digest()
            + hashlib.sha256(append_result.root.to_bytes()).digest()
        )

    # Explicit local-regime work proof on a larger tree.
    locality_data = chunk * LOCALITY_LEAVES
    locality = TreeDeltaIndex(locality_data)
    unaffected_before = locality.node(0, 64)
    local_edit = TreeEditV1(
        (LOCALITY_LEAVES - 1) * 65_536 + 17,
        1,
        b"Z",
    )
    local = locality.apply_delta([local_edit])
    if local.telemetry.recomputed_leaf_count != 1:
        raise AssertionError("one-leaf local edit did not stay one-leaf")
    if local.telemetry.leaf_payload_bytes_rehashed != 65_536:
        raise AssertionError("one-leaf local edit rehashed non-local payload bytes")
    if len(local.telemetry.recomputed_nodes) > LOCALITY_LEAVES.bit_length() + 1:
        raise AssertionError("local edit recomputed more than logarithmic ancestor path")
    if locality.node(0, 64) is not unaffected_before:
        raise AssertionError("unaffected canonical subtree was not preserved")

    return {
        "schema": "sigma-tree-st4-gate-v1",
        "passed": True,
        "closure_eligible": True,
        "delta_cases": delta_cases,
        "append_cases": append_cases,
        "independent_differential_cases": differential_cases,
        "sampled_full_rebuild_interval_delta": 50,
        "sampled_full_rebuild_interval_append": 25,
        "max_small_delta_recomputed_nodes": max_local_recomputed_nodes,
        "max_small_delta_leaf_payload_bytes_rehashed": max_local_rehashed_payload,
        "append_frontier_reuse_events": total_frontier_reused,
        "locality_tree_leaves": LOCALITY_LEAVES,
        "one_leaf_recomputed_nodes": len(local.telemetry.recomputed_nodes),
        "one_leaf_rehashed_payload_bytes": local.telemetry.leaf_payload_bytes_rehashed,
        "delta_stream_sha256": delta_digest.hexdigest(),
        "append_stream_sha256": append_digest.hexdigest(),
        "differential_stream_sha256": differential_digest.hexdigest(),
        "elapsed_seconds": time.perf_counter() - started,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--delta-cases", type=int, default=MIN_DELTA_CASES)
    parser.add_argument("--append-cases", type=int, default=MIN_APPEND_CASES)
    parser.add_argument("--differential-cases", type=int, default=MIN_DIFFERENTIAL_CASES)
    parser.add_argument("--report", type=Path)
    args = parser.parse_args()

    try:
        report = run_gate(
            delta_cases=args.delta_cases,
            append_cases=args.append_cases,
            differential_cases=args.differential_cases,
        )
    except ValueError as exc:
        parser.error(str(exc))

    payload = json.dumps(report, indent=2, sort_keys=True) + "\n"
    if args.report is not None:
        args.report.parent.mkdir(parents=True, exist_ok=True)
        args.report.write_text(payload, encoding="utf-8")
    print(payload, end="")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
