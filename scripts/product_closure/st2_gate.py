"""Reproducible ST2 closure gate for Sigma Tree V1 proofs."""

from __future__ import annotations

import argparse
import hashlib
import json
import random
import time
from dataclasses import replace
from pathlib import Path

from reference.tree_proof_v1 import verify_inclusion_wire, verify_range_wire
from sigma.tree import (
    DEFAULT_PROFILE,
    InclusionProofV1,
    RangeProofV1,
    TreeProofIndex,
    TreeRoot,
    range_witness_geometry,
    verify_inclusion,
    verify_range,
)

MIN_INCLUSION_PROOFS = 100_000
MIN_RANGE_PROOFS = 100_000
MIN_DIFFERENTIAL_CASES = 500
MIN_MUTATION_CASES = 20_000
EXHAUSTIVE_COVER_LEAVES = 64


def _dummy_root(leaf_count: int) -> TreeRoot:
    return TreeRoot(
        DEFAULT_PROFILE,
        leaf_count * DEFAULT_PROFILE.chunk_size,
        leaf_count,
        (b"d" * 64,) * 4,
    )


def _independent_cover(leaf_count: int, first: int, last: int):
    out = []

    def visit(start: int, count: int):
        end = start + count
        if end <= first or start >= last:
            out.append((start, count))
            return
        if count == 1:
            return
        left = 1 << ((count - 1).bit_length() - 1)
        visit(start, left)
        visit(start + left, count - left)

    visit(0, leaf_count)
    return tuple(out)


def _raw_fields(encoded: bytes) -> list[tuple[int, bytes]]:
    body_length = int.from_bytes(encoded[10:14], "big")
    if body_length != len(encoded) - 14:
        raise AssertionError("seed record length mismatch")
    fields = []
    offset = 14
    while offset < len(encoded):
        if offset + 6 > len(encoded):
            raise AssertionError("truncated seed TLV")
        tag = int.from_bytes(encoded[offset : offset + 2], "big")
        length = int.from_bytes(encoded[offset + 2 : offset + 6], "big")
        offset += 6
        end = offset + length
        if end > len(encoded):
            raise AssertionError("truncated seed TLV value")
        fields.append((tag, encoded[offset:end]))
        offset = end
    return fields


def _raw_record(template: bytes, fields: list[tuple[int, bytes]]) -> bytes:
    body = b"".join(
        tag.to_bytes(2, "big") + len(value).to_bytes(4, "big") + value
        for tag, value in fields
    )
    return template[:10] + len(body).to_bytes(4, "big") + body


def _schema_mutations(encoded: bytes) -> list[bytes]:
    fields = _raw_fields(encoded)
    values = []
    for index, field in enumerate(fields):
        values.append(_raw_record(encoded, fields[:index] + fields[index + 1 :]))
        values.append(
            _raw_record(
                encoded,
                fields[: index + 1] + [field] + fields[index + 1 :],
            )
        )
    if len(fields) >= 2:
        reordered = list(fields)
        reordered[0], reordered[1] = reordered[1], reordered[0]
        values.append(_raw_record(encoded, reordered))
    values.append(_raw_record(encoded, fields + [(0xFFFF, b"")]))
    return values


def run_gate(
    *,
    inclusion_proofs: int,
    range_proofs: int,
    differential_cases: int,
    mutation_cases: int,
) -> dict[str, object]:
    if inclusion_proofs < MIN_INCLUSION_PROOFS:
        raise ValueError(f"ST2 requires at least {MIN_INCLUSION_PROOFS} inclusion proofs")
    if range_proofs < MIN_RANGE_PROOFS:
        raise ValueError(f"ST2 requires at least {MIN_RANGE_PROOFS} range proofs")
    if differential_cases < MIN_DIFFERENTIAL_CASES:
        raise ValueError(f"ST2 requires at least {MIN_DIFFERENTIAL_CASES} differential cases")
    if mutation_cases < MIN_MUTATION_CASES:
        raise ValueError(f"ST2 requires at least {MIN_MUTATION_CASES} proof mutations")

    started = time.perf_counter()
    rng = random.Random(0x53543247415445)

    # Structural proof of the unique maximal complement cover.
    cover_cases = 0
    cover_digest = hashlib.sha256()
    for leaf_count in range(1, EXHAUSTIVE_COVER_LEAVES + 1):
        root = _dummy_root(leaf_count)
        for first in range(leaf_count):
            for last in range(first + 1, leaf_count + 1):
                got = range_witness_geometry(root, first, last)
                expected = _independent_cover(leaf_count, first, last)
                if tuple((start, count) for start, count, _ in got) != expected:
                    raise AssertionError(
                        f"range cover divergence n={leaf_count} [{first},{last})"
                    )
                cover_cases += 1
                cover_digest.update(
                    leaf_count.to_bytes(2, "big")
                    + first.to_bytes(2, "big")
                    + last.to_bytes(2, "big")
                    + b"".join(
                        start.to_bytes(2, "big") + count.to_bytes(2, "big")
                        for start, count, _ in got
                    )
                )

    # One materialized tree amortizes ST0 hashing across the 200k generation campaign.
    chunk = bytes((i * 37 + 11) % 251 for i in range(DEFAULT_PROFILE.chunk_size))
    data = chunk * 64 + b"final-tail-19-bytes"[:19]
    index = TreeProofIndex(data)
    if index.root.leaf_count != 65:
        raise AssertionError("unexpected gate tree geometry")

    inclusion_digest = hashlib.sha256()
    max_inclusion_steps = 0
    for case in range(inclusion_proofs):
        leaf_index = (case * 17 + case // 65) % index.root.leaf_count
        proof = index.prove_leaf(leaf_index)
        max_inclusion_steps = max(max_inclusion_steps, len(proof.steps))
        inclusion_digest.update(
            leaf_index.to_bytes(2, "big")
            + proof.leaf_byte_length.to_bytes(4, "big")
            + len(proof.steps).to_bytes(1, "big")
        )
        if case % 1000 == 0:
            inclusion_digest.update(hashlib.sha256(proof.to_bytes()).digest())

    range_digest = hashlib.sha256()
    max_range_witnesses = 0
    for case in range(range_proofs):
        if case % 100 == 0:
            # 1% partial-edge cases exercise prefix/suffix without dominating work.
            start = rng.randrange(len(data))
            length = rng.randrange(1, min(257, len(data) - start) + 1)
        else:
            first = rng.randrange(0, 64)
            last = rng.randrange(first + 1, 65)
            start = first * DEFAULT_PROFILE.chunk_size
            length = (last - first) * DEFAULT_PROFILE.chunk_size
        proof = index.prove_range(start, length)
        max_range_witnesses = max(max_range_witnesses, len(proof.witnesses))
        range_digest.update(
            start.to_bytes(8, "big")
            + length.to_bytes(8, "big")
            + len(proof.witnesses).to_bytes(1, "big")
            + len(proof.prefix).to_bytes(4, "big")
            + len(proof.suffix).to_bytes(4, "big")
        )
        if case % 1000 == 0:
            range_digest.update(hashlib.sha256(proof.to_bytes()).digest())

    # Independent verification corpus.
    differential_digest = hashlib.sha256()
    for case in range(differential_cases):
        leaf_index = rng.randrange(index.root.leaf_count)
        leaf_start = leaf_index * DEFAULT_PROFILE.chunk_size
        leaf_end = min(leaf_start + DEFAULT_PROFILE.chunk_size, len(data))
        leaf_bytes = data[leaf_start:leaf_end]
        inclusion = index.prove_leaf(leaf_index)
        if not verify_inclusion(leaf_bytes, inclusion):
            raise AssertionError(f"product inclusion failure at differential case {case}")
        if not verify_inclusion_wire(leaf_bytes, inclusion.to_bytes()):
            raise AssertionError(f"reference inclusion divergence at case {case}")

        range_start = rng.randrange(len(data))
        range_length = rng.randrange(1, min(4096, len(data) - range_start) + 1)
        range_bytes = data[range_start : range_start + range_length]
        range_proof = index.prove_range(range_start, range_length)
        if not verify_range(range_bytes, range_proof):
            raise AssertionError(f"product range failure at differential case {case}")
        if not verify_range_wire(range_bytes, range_proof.to_bytes()):
            raise AssertionError(f"reference range divergence at case {case}")
        differential_digest.update(
            hashlib.sha256(inclusion.to_bytes()).digest()
            + hashlib.sha256(range_proof.to_bytes()).digest()
        )

    # Bit mutations: accepted changed wires must not verify original bytes.
    inclusion_seed = index.prove_leaf(index.root.leaf_count - 1)
    inclusion_leaf = data[64 * DEFAULT_PROFILE.chunk_size :]
    range_start, range_length = 64 * DEFAULT_PROFILE.chunk_size + 3, 7
    range_seed = index.prove_range(range_start, range_length)
    range_bytes = data[range_start : range_start + range_length]
    seed_cases = (
        ("inclusion", inclusion_seed.to_bytes(), InclusionProofV1.from_bytes),
        ("range", range_seed.to_bytes(), RangeProofV1.from_bytes),
    )
    mutation_digest = hashlib.sha256()
    rejected_mutations = 0
    accepted_invalid_mutations = 0
    for case in range(mutation_cases):
        name, encoded, decoder = seed_cases[case % 2]
        raw = bytearray(encoded)
        position = rng.randrange(len(raw))
        raw[position] ^= 1 << rng.randrange(8)
        mutated = bytes(raw)
        mutation_digest.update(name.encode("ascii") + b"\0" + mutated)
        try:
            parsed = decoder(mutated)
        except (TypeError, ValueError):
            rejected_mutations += 1
            continue

        valid = (
            verify_inclusion(inclusion_leaf, parsed)
            if name == "inclusion"
            else verify_range(range_bytes, parsed)
        )
        independent_valid = (
            verify_inclusion_wire(inclusion_leaf, mutated)
            if name == "inclusion"
            else verify_range_wire(range_bytes, mutated)
        )
        if valid or independent_valid:
            raise AssertionError(f"mutated {name} proof still verifies at case {case}")
        accepted_invalid_mutations += 1

    # Explicit TLV structural mutation coverage.
    structural_mutations = 0
    for _, encoded, decoder in seed_cases:
        for mutated in _schema_mutations(encoded):
            structural_mutations += 1
            try:
                decoder(mutated)
            except (TypeError, ValueError):
                continue
            raise AssertionError("proof codec accepted non-canonical structural TLV mutation")

    # Single-field semantic mutations.
    first_step = inclusion_seed.steps[0]
    corrupted_digest = bytearray(first_step.sibling.digests[0])
    corrupted_digest[0] ^= 1
    corrupted_sibling = replace(
        first_step.sibling,
        digests=(bytes(corrupted_digest), *first_step.sibling.digests[1:]),
    )
    corrupted_inclusion = replace(
        inclusion_seed,
        steps=(
            replace(first_step, sibling=corrupted_sibling),
            *inclusion_seed.steps[1:],
        ),
    )
    if verify_inclusion(inclusion_leaf, corrupted_inclusion):
        raise AssertionError("single-field inclusion sibling mutation verified")

    if not range_seed.witnesses:
        raise AssertionError("range mutation seed unexpectedly has no witnesses")
    witness = range_seed.witnesses[0]
    witness_digest = bytearray(witness.digests[-1])
    witness_digest[-1] ^= 1
    corrupted_witness = replace(
        witness,
        digests=(*witness.digests[:-1], bytes(witness_digest)),
    )
    corrupted_range = replace(
        range_seed,
        witnesses=(corrupted_witness, *range_seed.witnesses[1:]),
    )
    if verify_range(range_bytes, corrupted_range):
        raise AssertionError("single-field range witness mutation verified")

    return {
        "schema": "sigma-tree-st2-gate-v1",
        "passed": True,
        "closure_eligible": True,
        "inclusion_proofs_generated": inclusion_proofs,
        "range_proofs_generated": range_proofs,
        "independent_differential_cases": differential_cases,
        "mutation_cases": mutation_cases,
        "mutation_rejected": rejected_mutations,
        "mutation_accepted_but_invalid": accepted_invalid_mutations,
        "structural_tlv_mutations": structural_mutations,
        "exhaustive_cover_cases": cover_cases,
        "max_inclusion_steps": max_inclusion_steps,
        "max_range_witnesses": max_range_witnesses,
        "cover_stream_sha256": cover_digest.hexdigest(),
        "inclusion_stream_sha256": inclusion_digest.hexdigest(),
        "range_stream_sha256": range_digest.hexdigest(),
        "differential_stream_sha256": differential_digest.hexdigest(),
        "mutation_stream_sha256": mutation_digest.hexdigest(),
        "elapsed_seconds": time.perf_counter() - started,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--inclusion-proofs", type=int, default=MIN_INCLUSION_PROOFS)
    parser.add_argument("--range-proofs", type=int, default=MIN_RANGE_PROOFS)
    parser.add_argument("--differential-cases", type=int, default=MIN_DIFFERENTIAL_CASES)
    parser.add_argument("--mutation-cases", type=int, default=MIN_MUTATION_CASES)
    parser.add_argument("--report", type=Path)
    args = parser.parse_args()
    try:
        report = run_gate(
            inclusion_proofs=args.inclusion_proofs,
            range_proofs=args.range_proofs,
            differential_cases=args.differential_cases,
            mutation_cases=args.mutation_cases,
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
