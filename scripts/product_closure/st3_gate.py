"""Reproducible ST3 closure gate for Sigma Tree V1 portable resume."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import random
import tempfile
import time
from pathlib import Path

import sigma.tree.checkpoint as checkpoint_module
from reference.tree_checkpoint_v1 import checkpoint_wire as reference_checkpoint_wire
from reference.tree_checkpoint_v1 import resume_checkpoint_wire
from reference.tree_v1 import root_wire as reference_root_wire
from sigma.tree import (
    DEFAULT_PROFILE,
    TreeBuilder,
    TreeResumeCheckpointV1,
    TreeSourceHintV1,
    build_tree,
    checkpoint_builder,
    checkpoint_bytes,
    read_checkpoint,
    restore_builder,
    resume_tree,
    write_checkpoint_atomic,
)

MIN_SPLIT_CASES = 100_000
MIN_DIFFERENTIAL_CASES = 500
MIN_CYCLE_CASES = 1_000
MIN_MUTATION_CASES = 20_000


def _raw_fields(encoded: bytes) -> list[tuple[int, bytes]]:
    body_length = int.from_bytes(encoded[10:14], "big")
    if body_length != len(encoded) - 14:
        raise AssertionError("seed checkpoint record length mismatch")
    fields = []
    offset = 14
    while offset < len(encoded):
        if offset + 6 > len(encoded):
            raise AssertionError("truncated checkpoint seed TLV")
        tag = int.from_bytes(encoded[offset : offset + 2], "big")
        length = int.from_bytes(encoded[offset + 2 : offset + 6], "big")
        offset += 6
        end = offset + length
        if end > len(encoded):
            raise AssertionError("truncated checkpoint seed field")
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
    result = []
    for index, field in enumerate(fields):
        result.append(_raw_record(encoded, fields[:index] + fields[index + 1 :]))
        result.append(
            _raw_record(
                encoded,
                fields[: index + 1] + [field] + fields[index + 1 :],
            )
        )
    reordered = list(fields)
    reordered[0], reordered[1] = reordered[1], reordered[0]
    result.append(_raw_record(encoded, reordered))
    result.append(_raw_record(encoded, fields + [(0xFFFF, b"")]))
    return result


def run_gate(
    *,
    split_cases: int,
    differential_cases: int,
    cycle_cases: int,
    mutation_cases: int,
) -> dict[str, object]:
    if split_cases < MIN_SPLIT_CASES:
        raise ValueError(f"ST3 requires at least {MIN_SPLIT_CASES} split cases")
    if differential_cases < MIN_DIFFERENTIAL_CASES:
        raise ValueError(
            f"ST3 requires at least {MIN_DIFFERENTIAL_CASES} independent differential cases"
        )
    if cycle_cases < MIN_CYCLE_CASES:
        raise ValueError(f"ST3 requires at least {MIN_CYCLE_CASES} repeated-resume cycles")
    if mutation_cases < MIN_MUTATION_CASES:
        raise ValueError(f"ST3 requires at least {MIN_MUTATION_CASES} checkpoint mutations")

    started = time.perf_counter()
    rng = random.Random(0x53543347415445)

    chunk = bytes((i * 41 + 13) % 251 for i in range(DEFAULT_PROFILE.chunk_size))
    tail = bytes((i * 23 + 5) % 251 for i in range(4096))
    data = chunk * 4 + tail
    expected_root = build_tree(data)
    expected_wire = expected_root.to_bytes()

    base_builder = TreeBuilder()
    base_builder.update(data[: 4 * DEFAULT_PROFILE.chunk_size])
    base_checkpoint = checkpoint_builder(base_builder)
    base_frontier = base_checkpoint.frontier
    if (
        base_checkpoint.tail
        or base_checkpoint.completed_leaf_count != 4
        or len(base_frontier.nodes) != 1
    ):
        raise AssertionError("unexpected ST3 base checkpoint geometry")

    # 100k random split/resume differential cases on a non-trivial frontier.
    split_digest = hashlib.sha256()
    for case in range(split_cases):
        tail_cut = rng.randrange(len(tail) + 1)
        split = 4 * DEFAULT_PROFILE.chunk_size + tail_cut
        checkpoint = TreeResumeCheckpointV1(
            DEFAULT_PROFILE,
            split,
            4,
            base_frontier,
            tail[:tail_cut],
        )
        got = resume_tree(checkpoint, tail[tail_cut:])
        if got != expected_root:
            raise AssertionError(f"resume divergence at split case {case}")
        split_digest.update(tail_cut.to_bytes(2, "big"))
        if case % 1000 == 0:
            split_digest.update(hashlib.sha256(checkpoint.to_bytes()).digest())

    # Directed splits ensure empty/tail/chunk-boundary semantics outside the main random band.
    directed_offsets = sorted(
        {
            0,
            1,
            DEFAULT_PROFILE.chunk_size - 1,
            DEFAULT_PROFILE.chunk_size,
            DEFAULT_PROFILE.chunk_size + 1,
            2 * DEFAULT_PROFILE.chunk_size - 1,
            2 * DEFAULT_PROFILE.chunk_size,
            2 * DEFAULT_PROFILE.chunk_size + 1,
            3 * DEFAULT_PROFILE.chunk_size,
            4 * DEFAULT_PROFILE.chunk_size - 1,
            4 * DEFAULT_PROFILE.chunk_size,
            len(data) - 1,
            len(data),
        }
    )
    for split in directed_offsets:
        checkpoint = checkpoint_bytes(data[:split])
        if resume_tree(checkpoint, data[split:]) != expected_root:
            raise AssertionError(f"directed resume divergence at split {split}")

    # Independent wire and resume oracle.
    differential_digest = hashlib.sha256()
    for case in range(differential_cases):
        if case < len(directed_offsets):
            split = directed_offsets[case]
        else:
            split = 4 * DEFAULT_PROFILE.chunk_size + rng.randrange(len(tail) + 1)
        prefix = data[:split]
        suffix = data[split:]
        product_checkpoint = checkpoint_bytes(prefix)
        product_wire = product_checkpoint.to_bytes()
        if product_wire != reference_checkpoint_wire(prefix):
            raise AssertionError(f"checkpoint wire divergence at case {case}")
        product_root = resume_tree(product_checkpoint, suffix).to_bytes()
        reference_root = resume_checkpoint_wire(product_wire, suffix)
        if product_root != reference_root or product_root != expected_wire:
            raise AssertionError(f"independent resume divergence at case {case}")
        differential_digest.update(hashlib.sha256(product_wire).digest())

    # Repeated restore/update/checkpoint cycles, all beginning from a non-trivial frontier.
    cycle_digest = hashlib.sha256()
    for case in range(cycle_cases):
        cuts = sorted(
            {
                0,
                len(tail),
                *(rng.randrange(len(tail) + 1) for _ in range(4)),
            }
        )
        checkpoint = base_checkpoint
        position = 0
        for cut in cuts[1:]:
            builder = restore_builder(checkpoint)
            builder.update(tail[position:cut])
            checkpoint = checkpoint_builder(builder)
            position = cut
        got = resume_tree(checkpoint, tail[position:])
        if got != expected_root:
            raise AssertionError(f"repeated checkpoint cycle divergence at case {case}")
        cycle_digest.update(hashlib.sha256(checkpoint.to_bytes()).digest())

    # Source hints are explicitly non-semantic.
    hinted = TreeResumeCheckpointV1(
        base_checkpoint.profile,
        base_checkpoint.completed_bytes,
        base_checkpoint.completed_leaf_count,
        base_checkpoint.frontier,
        base_checkpoint.tail,
        TreeSourceHintV1(len(data), 1, 2, 3),
    )
    differently_hinted = TreeResumeCheckpointV1(
        base_checkpoint.profile,
        base_checkpoint.completed_bytes,
        base_checkpoint.completed_leaf_count,
        base_checkpoint.frontier,
        base_checkpoint.tail,
        TreeSourceHintV1(len(data) + 1, 4, 5, 6),
    )
    if resume_tree(hinted, tail) != resume_tree(differently_hinted, tail):
        raise AssertionError("source hint changed checkpoint semantics")

    # Mutation campaign on a checkpoint with no hint. Any changed accepted
    # checkpoint must fail to reconstruct the original full TreeRoot.
    seed_cut = 4 * DEFAULT_PROFILE.chunk_size + 123
    seed = TreeResumeCheckpointV1(
        DEFAULT_PROFILE,
        seed_cut,
        4,
        base_frontier,
        tail[:123],
    )
    seed_wire = seed.to_bytes()
    seed_suffix = tail[123:]
    mutation_digest = hashlib.sha256()
    rejected_mutations = 0
    accepted_invalid_mutations = 0
    for case in range(mutation_cases):
        raw = bytearray(seed_wire)
        position = rng.randrange(len(raw))
        raw[position] ^= 1 << rng.randrange(8)
        mutated = bytes(raw)
        mutation_digest.update(mutated)
        try:
            parsed = TreeResumeCheckpointV1.from_bytes(mutated)
        except (TypeError, ValueError):
            rejected_mutations += 1
            continue

        product_same = resume_tree(parsed, seed_suffix).to_bytes() == expected_wire
        try:
            reference_same = resume_checkpoint_wire(mutated, seed_suffix) == expected_wire
        except (TypeError, ValueError):
            reference_same = False
        if product_same or reference_same:
            raise AssertionError(f"mutated checkpoint still reconstructs original root at {case}")
        accepted_invalid_mutations += 1

    structural_mutations = 0
    for mutated in _schema_mutations(seed_wire):
        structural_mutations += 1
        try:
            TreeResumeCheckpointV1.from_bytes(mutated)
        except (TypeError, ValueError):
            continue
        raise AssertionError("checkpoint codec accepted structural TLV mutation")

    # Atomic persistence: a failed replace must leave the previous checkpoint intact.
    with tempfile.TemporaryDirectory(prefix="sigma-st3-") as temp:
        path = Path(temp) / "checkpoint.sigma"
        old = checkpoint_bytes(b"old-checkpoint")
        new = checkpoint_bytes(b"new-checkpoint")
        write_checkpoint_atomic(path, old)

        original_replace = checkpoint_module.os.replace

        def fail_replace(src, dst):
            raise OSError("ST3 injected replace failure")

        checkpoint_module.os.replace = fail_replace
        try:
            try:
                write_checkpoint_atomic(path, new)
            except OSError as exc:
                if "injected" not in str(exc):
                    raise
            else:
                raise AssertionError("atomic checkpoint failure injection did not fail")
        finally:
            checkpoint_module.os.replace = original_replace

        if read_checkpoint(path) != old:
            raise AssertionError("failed checkpoint write destroyed previous checkpoint")
        if list(Path(temp).glob(".checkpoint.sigma.*.tmp")):
            raise AssertionError("failed checkpoint write leaked temporary files")

    # Final direct independent root guard.
    if reference_root_wire(data) != expected_wire:
        raise AssertionError("ST0 direct reference root changed")

    return {
        "schema": "sigma-tree-st3-gate-v1",
        "passed": True,
        "closure_eligible": True,
        "split_cases": split_cases,
        "directed_split_cases": len(directed_offsets),
        "independent_differential_cases": differential_cases,
        "repeated_cycle_cases": cycle_cases,
        "mutation_cases": mutation_cases,
        "mutation_rejected": rejected_mutations,
        "mutation_accepted_but_invalid": accepted_invalid_mutations,
        "structural_tlv_mutations": structural_mutations,
        "base_frontier_nodes": len(base_frontier.nodes),
        "tail_band_bytes": len(tail),
        "split_stream_sha256": split_digest.hexdigest(),
        "differential_stream_sha256": differential_digest.hexdigest(),
        "cycle_stream_sha256": cycle_digest.hexdigest(),
        "mutation_stream_sha256": mutation_digest.hexdigest(),
        "expected_root_wire_sha256": hashlib.sha256(expected_wire).hexdigest(),
        "elapsed_seconds": time.perf_counter() - started,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--split-cases", type=int, default=MIN_SPLIT_CASES)
    parser.add_argument("--differential-cases", type=int, default=MIN_DIFFERENTIAL_CASES)
    parser.add_argument("--cycle-cases", type=int, default=MIN_CYCLE_CASES)
    parser.add_argument("--mutation-cases", type=int, default=MIN_MUTATION_CASES)
    parser.add_argument("--report", type=Path)
    args = parser.parse_args()

    try:
        report = run_gate(
            split_cases=args.split_cases,
            differential_cases=args.differential_cases,
            cycle_cases=args.cycle_cases,
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
