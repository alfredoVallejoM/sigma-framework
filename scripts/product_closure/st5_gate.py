"""Reproducible ST5 semantic/scale closure gate for Sigma Tree V1."""

from __future__ import annotations

import argparse
import hashlib
import json
import random
import tracemalloc
from pathlib import Path

from reference.tree_proof_v1 import verify_inclusion_wire, verify_range_wire
from reference.tree_v1 import root_wire as reference_root_wire
from sigma.tree import (
    DEFAULT_PROFILE,
    TreeBuilder,
    TreeFallbackV1,
    TreeIndexBudgetExceeded,
    TreeIndexedOperationV1,
    TreeIndexModeV1,
    TreeProofIndex,
    TreeScalePolicyV1,
    build_tree,
    delta_index_scaled,
    estimate_index_bytes,
    plan_tree_index,
    prove_leaf_streaming,
    prove_range_streaming,
)

MIN_BUILD_DIFFERENTIAL_CASES = 1_000
MIN_PROOF_DIFFERENTIAL_CASES = 500
STREAMING_MEMORY_BYTES = 32 * 1024 * 1024
PROOF_INDEX_AUDIT_BYTES = 16 * 1024 * 1024


def run_gate(
    *,
    build_differential_cases: int,
    proof_differential_cases: int,
) -> dict[str, object]:
    if build_differential_cases < MIN_BUILD_DIFFERENTIAL_CASES:
        raise ValueError(
            f"ST5 requires at least {MIN_BUILD_DIFFERENTIAL_CASES} build differential cases"
        )
    if proof_differential_cases < MIN_PROOF_DIFFERENTIAL_CASES:
        raise ValueError(
            f"ST5 requires at least {MIN_PROOF_DIFFERENTIAL_CASES} proof differential cases"
        )

    rng = random.Random(0x53543547415445)

    build_digest = hashlib.sha256()
    boundary_sizes = (
        0,
        1,
        65_535,
        65_536,
        65_537,
        131_071,
        131_072,
        131_073,
        5 * 65_536 + 19,
    )
    for case in range(build_differential_cases):
        size = (
            boundary_sizes[case]
            if case < len(boundary_sizes)
            else rng.randrange(0, 10 * DEFAULT_PROFILE.chunk_size + 257)
        )
        data = rng.randbytes(size)
        product = build_tree(data).to_bytes()
        reference = reference_root_wire(data)
        if product != reference:
            raise AssertionError(f"optimized Tree divergence at build case {case}")
        build_digest.update(hashlib.sha256(product).digest())

    proof_digest = hashlib.sha256()
    for case in range(proof_differential_cases):
        size = rng.randrange(1, 12 * DEFAULT_PROFILE.chunk_size + 257)
        data = rng.randbytes(size)
        index = TreeProofIndex(data)

        leaf_index = rng.randrange(index.root.leaf_count)
        full_inclusion = index.prove_leaf(leaf_index)
        streaming_inclusion = prove_leaf_streaming(data, leaf_index)
        if full_inclusion.to_bytes() != streaming_inclusion.to_bytes():
            raise AssertionError(f"FULL/STREAMING inclusion drift at case {case}")
        leaf_start = leaf_index * DEFAULT_PROFILE.chunk_size
        leaf_end = min(leaf_start + DEFAULT_PROFILE.chunk_size, len(data))
        if not verify_inclusion_wire(
            data[leaf_start:leaf_end], streaming_inclusion.to_bytes()
        ):
            raise AssertionError(f"independent inclusion reject at case {case}")

        start = rng.randrange(size)
        length = rng.randrange(1, size - start + 1)
        full_range = index.prove_range(start, length)
        streaming_range = prove_range_streaming(data, start, length)
        if full_range.to_bytes() != streaming_range.to_bytes():
            raise AssertionError(f"FULL/STREAMING range drift at case {case}")
        if not verify_range_wire(
            data[start : start + length], streaming_range.to_bytes()
        ):
            raise AssertionError(f"independent range reject at case {case}")

        proof_digest.update(
            hashlib.sha256(full_inclusion.to_bytes()).digest()
            + hashlib.sha256(full_range.to_bytes()).digest()
        )

    # O02: zero-copy proof index must not allocate another B-sized payload.
    proof_data = bytes(
        (i * 17 + 5) % 251 for i in range(PROOF_INDEX_AUDIT_BYTES)
    )
    tracemalloc.start()
    proof_index = TreeProofIndex(proof_data)
    _, proof_index_peak = tracemalloc.get_traced_memory()
    tracemalloc.stop()
    if not proof_index._leaves or not all(
        isinstance(leaf, memoryview) and leaf.obj is proof_data
        for leaf in proof_index._leaves
    ):
        raise AssertionError("proof index does not retain zero-copy leaf views")
    if proof_index_peak >= PROOF_INDEX_AUDIT_BYTES // 4:
        raise AssertionError(
            "proof index allocated a suspicious payload-sized hidden copy"
        )
    proof_estimate = estimate_index_bytes(
        len(proof_data), TreeIndexedOperationV1.PROOF
    )
    if proof_index_peak > proof_estimate:
        raise AssertionError(
            "conservative proof-index budget estimate underestimates measured peak"
        )

    # O03: streaming builder extra memory stays bounded while B grows to 32 MiB.
    chunk = bytes((i * 37 + 11) % 251 for i in range(DEFAULT_PROFILE.chunk_size))
    chunk_count = STREAMING_MEMORY_BYTES // DEFAULT_PROFILE.chunk_size
    tracemalloc.start()
    builder = TreeBuilder()
    for _ in range(chunk_count):
        builder.update(chunk)
    streaming_root = builder.finalize()
    _, streaming_peak = tracemalloc.get_traced_memory()
    tracemalloc.stop()
    if streaming_root.byte_length != STREAMING_MEMORY_BYTES:
        raise AssertionError("streaming memory audit byte accounting drift")
    if streaming_peak > 2 * 1024 * 1024:
        raise AssertionError(
            f"streaming Tree extra-memory budget exceeded: {streaming_peak}"
        )

    # O04: decisions are explicit, deterministic and happen before index build.
    generous = TreeScalePolicyV1(max_index_bytes=1 << 30)
    tiny = TreeScalePolicyV1(max_index_bytes=1)
    proof_full = plan_tree_index(
        PROOF_INDEX_AUDIT_BYTES,
        TreeIndexedOperationV1.PROOF,
        generous,
    )
    proof_stream = plan_tree_index(
        PROOF_INDEX_AUDIT_BYTES,
        TreeIndexedOperationV1.PROOF,
        tiny,
    )
    delta_reject = plan_tree_index(
        PROOF_INDEX_AUDIT_BYTES,
        TreeIndexedOperationV1.DELTA,
        tiny,
    )
    if proof_full.mode is not TreeIndexModeV1.FULL:
        raise AssertionError("generous proof policy did not select FULL")
    if proof_stream.mode is not TreeIndexModeV1.STREAMING:
        raise AssertionError("tiny proof policy did not select STREAMING")
    if delta_reject.mode is not TreeIndexModeV1.REJECT:
        raise AssertionError("tiny delta policy did not select REJECT")

    reject_proof_policy = TreeScalePolicyV1(
        max_index_bytes=1,
        proof_fallback=TreeFallbackV1.REJECT,
    )
    if plan_tree_index(
        PROOF_INDEX_AUDIT_BYTES,
        TreeIndexedOperationV1.PROOF,
        reject_proof_policy,
    ).mode is not TreeIndexModeV1.REJECT:
        raise AssertionError("explicit proof REJECT policy was ignored")

    try:
        delta_index_scaled(b"x" * (2 * DEFAULT_PROFILE.chunk_size), policy=tiny)
    except TreeIndexBudgetExceeded:
        pass
    else:
        raise AssertionError("delta budget overflow did not reject explicitly")

    return {
        "schema": "sigma-tree-st5-gate-v1",
        "passed": True,
        "closure_eligible": True,
        "build_differential_cases": build_differential_cases,
        "proof_differential_cases": proof_differential_cases,
        "build_stream_sha256": build_digest.hexdigest(),
        "proof_stream_sha256": proof_digest.hexdigest(),
        "proof_index_audit_source_bytes": PROOF_INDEX_AUDIT_BYTES,
        "proof_index_peak_allocated_bytes": proof_index_peak,
        "proof_index_estimated_budget_bytes": proof_estimate,
        "proof_index_peak_to_source_ratio": proof_index_peak / PROOF_INDEX_AUDIT_BYTES,
        "streaming_builder_input_bytes": STREAMING_MEMORY_BYTES,
        "streaming_builder_peak_allocated_bytes": streaming_peak,
        "streaming_builder_peak_to_input_ratio": streaming_peak / STREAMING_MEMORY_BYTES,
        "scale_decisions": {
            "generous_proof": proof_full.mode.value,
            "tiny_proof": proof_stream.mode.value,
            "tiny_delta": delta_reject.mode.value,
        },
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--build-differential-cases",
        type=int,
        default=MIN_BUILD_DIFFERENTIAL_CASES,
    )
    parser.add_argument(
        "--proof-differential-cases",
        type=int,
        default=MIN_PROOF_DIFFERENTIAL_CASES,
    )
    parser.add_argument("--report", type=Path)
    args = parser.parse_args()

    try:
        report = run_gate(
            build_differential_cases=args.build_differential_cases,
            proof_differential_cases=args.proof_differential_cases,
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
