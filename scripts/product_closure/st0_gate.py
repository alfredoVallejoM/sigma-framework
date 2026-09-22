"""Reproducible ST0 structural/conformance gate for Sigma Tree V1."""

from __future__ import annotations

import argparse
import hashlib
import json
import random
import time
from pathlib import Path

from reference.tree_v1 import build as reference_build, root_wire as reference_root_wire
from sigma.tree import TreeBuilder, TreeFrontier, TreeRoot, build_tree, build_tree_chunks
from sigma.tree.model import canonical_frontier_heights


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def run_gate(*, structural_cases: int, differential_cases: int, fuzz_cases: int) -> dict[str, object]:
    started = time.perf_counter()
    for n in range(structural_cases):
        heights = canonical_frontier_heights(n)
        if sum(1 << h for h in heights) != n:
            raise AssertionError(f"frontier decomposition mismatch at n={n}")
        if any(a <= b for a, b in zip(heights, heights[1:])):
            raise AssertionError(f"frontier heights not strictly decreasing at n={n}")

    rng = random.Random(0x535447415445)
    differential_digest = hashlib.sha256()
    for index in range(differential_cases):
        size = rng.randrange(0, 6 * 65_536 + 257)
        if index < 9:
            size = (0, 1, 65_535, 65_536, 65_537, 131_071, 131_072, 131_073, 196_611)[index]
        data = rng.randbytes(size)
        ref_length, ref_leaves, ref_digests = reference_build(data)
        got = build_tree(data)
        if (got.byte_length, got.leaf_count, got.digests) != (ref_length, ref_leaves, ref_digests):
            raise AssertionError(f"reference divergence at differential case {index}")
        if got.to_bytes() != reference_root_wire(data):
            raise AssertionError(f"root-wire divergence at differential case {index}")
        chunks: list[bytes] = []
        cursor = 0
        while cursor < size:
            width = rng.randrange(1, 100_001)
            chunks.append(data[cursor : cursor + width])
            cursor += width
        if build_tree_chunks(chunks) != got:
            raise AssertionError(f"partition divergence at differential case {index}")
        differential_digest.update(got.to_bytes())

    seed_root = build_tree(b"Sigma Tree ST0 codec mutation seed" * 4096)
    encoded = seed_root.to_bytes()
    mutation_digest = hashlib.sha256()
    rejected = 0
    changed = 0
    for i in range(fuzz_cases):
        mutant = bytearray(encoded)
        pos = rng.randrange(len(mutant))
        mutant[pos] ^= 1 << rng.randrange(8)
        raw = bytes(mutant)
        mutation_digest.update(raw)
        try:
            parsed = TreeRoot.from_bytes(raw)
        except (TypeError, ValueError):
            rejected += 1
        else:
            if parsed == seed_root:
                raise AssertionError(f"non-injective accepted mutation at fuzz case {i}")
            changed += 1

    builder = TreeBuilder()
    builder.update(b"F" * (17 * 65_536 + 19))
    frontier = builder.frontier
    if TreeFrontier.from_bytes(frontier.to_bytes()) != frontier:
        raise AssertionError("frontier codec round-trip failed")

    return {
        "schema": "sigma-tree-st0-gate-v1",
        "structural_cases": structural_cases,
        "differential_cases": differential_cases,
        "fuzz_cases": fuzz_cases,
        "fuzz_rejected": rejected,
        "fuzz_changed_valid": changed,
        "differential_root_stream_sha256": differential_digest.hexdigest(),
        "mutation_stream_sha256": mutation_digest.hexdigest(),
        "frontier_wire_sha256": _sha256(frontier.to_bytes()),
        "elapsed_seconds": time.perf_counter() - started,
        "passed": True,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--structural-cases", type=int, default=100_001)
    parser.add_argument("--differential-cases", type=int, default=2_000)
    parser.add_argument("--fuzz-cases", type=int, default=10_000)
    parser.add_argument("--report", type=Path)
    args = parser.parse_args()
    if min(args.structural_cases, args.differential_cases, args.fuzz_cases) < 0:
        parser.error("case counts must be non-negative")
    report = run_gate(structural_cases=args.structural_cases, differential_cases=args.differential_cases, fuzz_cases=args.fuzz_cases)
    payload = json.dumps(report, indent=2, sort_keys=True) + "\n"
    if args.report is not None:
        args.report.parent.mkdir(parents=True, exist_ok=True)
        args.report.write_text(payload, encoding="utf-8")
    print(payload, end="")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
