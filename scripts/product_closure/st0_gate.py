"""Reproducible ST0 structural/conformance gate for Sigma Tree V1."""

from __future__ import annotations

import argparse
import hashlib
import json
import random
import time
from pathlib import Path
from typing import Callable

from reference.tree_v1 import (
    build as reference_build,
    frontier_wire as reference_frontier_wire,
    root_wire as reference_root_wire,
)
from sigma.tree import (
    DEFAULT_PROFILE,
    TreeBuilder,
    TreeFrontier,
    TreeNode,
    TreeProfileV1,
    TreeRoot,
    build_tree_chunks,
)
from sigma.tree.model import canonical_frontier_heights

MIN_STRUCTURAL_CASES = 100_001
MIN_DIFFERENTIAL_CASES = 2_000
MIN_FUZZ_CASES = 100_000


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _raw_fields(encoded: bytes) -> list[tuple[int, bytes]]:
    if len(encoded) < 14:
        raise AssertionError("seed record is truncated")
    body_length = int.from_bytes(encoded[10:14], "big")
    if body_length != len(encoded) - 14:
        raise AssertionError("seed record length mismatch")
    fields: list[tuple[int, bytes]] = []
    offset = 14
    while offset < len(encoded):
        if offset + 6 > len(encoded):
            raise AssertionError("seed TLV is truncated")
        tag = int.from_bytes(encoded[offset : offset + 2], "big")
        length = int.from_bytes(encoded[offset + 2 : offset + 6], "big")
        offset += 6
        end = offset + length
        if end > len(encoded):
            raise AssertionError("seed TLV value is truncated")
        fields.append((tag, encoded[offset:end]))
        offset = end
    return fields


def _raw_record(template: bytes, fields: list[tuple[int, bytes]]) -> bytes:
    body = b"".join(
        tag.to_bytes(2, "big") + len(value).to_bytes(4, "big") + value
        for tag, value in fields
    )
    return template[:10] + len(body).to_bytes(4, "big") + body


def _schema_mutations(encoded: bytes) -> list[tuple[str, bytes]]:
    fields = _raw_fields(encoded)
    mutations: list[tuple[str, bytes]] = []
    for index, (tag, value) in enumerate(fields):
        missing = fields[:index] + fields[index + 1 :]
        mutations.append((f"missing-{tag}", _raw_record(encoded, missing)))
        duplicate = fields[: index + 1] + [(tag, value)] + fields[index + 1 :]
        mutations.append((f"duplicate-{tag}", _raw_record(encoded, duplicate)))
    if len(fields) >= 2:
        reordered = list(fields)
        reordered[0], reordered[1] = reordered[1], reordered[0]
        mutations.append(("reordered-first-two", _raw_record(encoded, reordered)))
    mutations.append(("unknown-tag", _raw_record(encoded, fields + [(0xFFFF, b"")])))
    return mutations


def _require_campaign_scale(
    *, structural_cases: int, differential_cases: int, fuzz_cases: int
) -> None:
    if structural_cases < MIN_STRUCTURAL_CASES:
        raise ValueError(
            f"ST0 closure gate requires at least {MIN_STRUCTURAL_CASES} structural cases"
        )
    if differential_cases < MIN_DIFFERENTIAL_CASES:
        raise ValueError(
            f"ST0 closure gate requires at least {MIN_DIFFERENTIAL_CASES} differential cases"
        )
    if fuzz_cases < MIN_FUZZ_CASES:
        raise ValueError(
            f"ST0 closure gate requires at least {MIN_FUZZ_CASES} codec mutations"
        )


def run_gate(
    *, structural_cases: int, differential_cases: int, fuzz_cases: int
) -> dict[str, object]:
    _require_campaign_scale(
        structural_cases=structural_cases,
        differential_cases=differential_cases,
        fuzz_cases=fuzz_cases,
    )
    started = time.perf_counter()

    for n in range(structural_cases):
        heights = canonical_frontier_heights(n)
        if sum(1 << h for h in heights) != n:
            raise AssertionError(f"frontier decomposition mismatch at n={n}")
        if any(a <= b for a, b in zip(heights, heights[1:])):
            raise AssertionError(f"frontier heights not strictly decreasing at n={n}")

    rng = random.Random(0x535447415445)
    differential_digest = hashlib.sha256()
    frontier_digest = hashlib.sha256()
    fixed_sizes = (
        0,
        1,
        65_535,
        65_536,
        65_537,
        131_071,
        131_072,
        131_073,
        196_611,
    )
    for index in range(differential_cases):
        size = rng.randrange(0, 6 * 65_536 + 257)
        if index < len(fixed_sizes):
            size = fixed_sizes[index]
        data = rng.randbytes(size)

        ref_length, ref_leaves, ref_digests = reference_build(data)
        builder = TreeBuilder()
        builder.update(data)
        got = builder.finalize()

        if (got.byte_length, got.leaf_count, got.digests) != (
            ref_length,
            ref_leaves,
            ref_digests,
        ):
            raise AssertionError(f"reference divergence at differential case {index}")
        if got.to_bytes() != reference_root_wire(data):
            raise AssertionError(f"root-wire divergence at differential case {index}")
        if builder.frontier.to_bytes() != reference_frontier_wire(data):
            raise AssertionError(f"frontier-wire divergence at differential case {index}")

        chunks: list[bytes] = []
        cursor = 0
        while cursor < size:
            width = rng.randrange(1, 100_001)
            chunks.append(data[cursor : cursor + width])
            cursor += width
        if build_tree_chunks(chunks) != got:
            raise AssertionError(f"partition divergence at differential case {index}")

        differential_digest.update(got.to_bytes())
        frontier_digest.update(builder.frontier.to_bytes())

    seed_builder = TreeBuilder()
    seed_builder.update(b"F" * (17 * 65_536 + 19))
    seed_root = seed_builder.finalize()
    seed_frontier = seed_builder.frontier
    if not seed_frontier.nodes:
        raise AssertionError("ST0 fuzz seed must have a non-empty frontier")
    seed_node = seed_frontier.nodes[-1]

    codec_cases: tuple[
        tuple[str, bytes, Callable[[bytes], object], object], ...
    ] = (
        ("profile", DEFAULT_PROFILE.to_bytes(), TreeProfileV1.from_bytes, DEFAULT_PROFILE),
        ("node", seed_node.to_bytes(), TreeNode.from_bytes, seed_node),
        ("frontier", seed_frontier.to_bytes(), TreeFrontier.from_bytes, seed_frontier),
        ("root", seed_root.to_bytes(), TreeRoot.from_bytes, seed_root),
    )

    mutation_digest = hashlib.sha256()
    fuzz_stats = {
        name: {"rejected": 0, "changed_valid": 0}
        for name, _, _, _ in codec_cases
    }
    for i in range(fuzz_cases):
        name, encoded, decoder, expected = codec_cases[i % len(codec_cases)]
        mutant = bytearray(encoded)
        pos = rng.randrange(len(mutant))
        mutant[pos] ^= 1 << rng.randrange(8)
        raw = bytes(mutant)
        mutation_digest.update(name.encode("ascii") + b"\0" + raw)
        try:
            parsed = decoder(raw)
        except (TypeError, ValueError):
            fuzz_stats[name]["rejected"] += 1
        else:
            if parsed == expected:
                raise AssertionError(
                    f"non-injective accepted {name} mutation at fuzz case {i}"
                )
            fuzz_stats[name]["changed_valid"] += 1

    schema_mutation_cases = 0
    for name, encoded, decoder, _ in codec_cases:
        for mutation_name, raw in _schema_mutations(encoded):
            schema_mutation_cases += 1
            mutation_digest.update(
                b"schema\0"
                + name.encode("ascii")
                + b"\0"
                + mutation_name.encode("ascii")
                + b"\0"
                + raw
            )
            try:
                decoder(raw)
            except (TypeError, ValueError):
                continue
            raise AssertionError(
                f"{name} decoder accepted structural mutation {mutation_name}"
            )

    if TreeFrontier.from_bytes(seed_frontier.to_bytes()) != seed_frontier:
        raise AssertionError("frontier codec round-trip failed")

    rejected = sum(stats["rejected"] for stats in fuzz_stats.values())
    changed = sum(stats["changed_valid"] for stats in fuzz_stats.values())
    if rejected + changed != fuzz_cases:
        raise AssertionError("codec mutation accounting mismatch")

    return {
        "schema": "sigma-tree-st0-gate-v2",
        "campaign_thresholds": {
            "structural_cases": MIN_STRUCTURAL_CASES,
            "differential_cases": MIN_DIFFERENTIAL_CASES,
            "fuzz_cases": MIN_FUZZ_CASES,
        },
        "structural_cases": structural_cases,
        "differential_cases": differential_cases,
        "fuzz_cases": fuzz_cases,
        "fuzz_rejected": rejected,
        "fuzz_changed_valid": changed,
        "fuzz_by_codec": fuzz_stats,
        "schema_mutation_cases": schema_mutation_cases,
        "differential_root_stream_sha256": differential_digest.hexdigest(),
        "differential_frontier_stream_sha256": frontier_digest.hexdigest(),
        "mutation_stream_sha256": mutation_digest.hexdigest(),
        "frontier_wire_sha256": _sha256(seed_frontier.to_bytes()),
        "elapsed_seconds": time.perf_counter() - started,
        "closure_eligible": True,
        "passed": True,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--structural-cases", type=int, default=MIN_STRUCTURAL_CASES
    )
    parser.add_argument(
        "--differential-cases", type=int, default=MIN_DIFFERENTIAL_CASES
    )
    parser.add_argument("--fuzz-cases", type=int, default=MIN_FUZZ_CASES)
    parser.add_argument("--report", type=Path)
    args = parser.parse_args()
    try:
        report = run_gate(
            structural_cases=args.structural_cases,
            differential_cases=args.differential_cases,
            fuzz_cases=args.fuzz_cases,
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
