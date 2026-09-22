"""Reproducible PX0 closure gate for the persistent Tree index sidecar."""

from __future__ import annotations

import argparse
import hashlib
import json
import random
import tempfile
from pathlib import Path

from reference.persistent_tree_index_v1 import persistent_index_wire
from sigma.artifact import ArtifactProfileV1, create_artifact_v1
from sigma.tree import (
    PersistentSourceValidationV1,
    TreeDeltaIndex,
    TreeEditV1,
    TreePersistentIndexV1,
    TreeProofIndex,
    build_persistent_index,
    build_tree,
    read_persistent_index,
    write_persistent_index_atomic,
)

MIN_INDEX_DIFFERENTIAL_CASES = 500
MIN_PROOF_CASES = 500
MIN_DELTA_CASES = 300
MIN_APPEND_CASES = 300
MIN_MUTATION_CASES = 5_000
MIN_STALE_CASES = 200


def _rechecksum(payload: bytes) -> bytes:
    domain = b"SIGMA-PERSISTENT-TREE-INDEX-V1\x00"
    return payload[:-32] + hashlib.sha256(domain + payload[:-32]).digest()


def _mutate_second_node(encoded: bytes) -> bytes:
    raw = bytearray(encoded)
    offset = 10
    for _ in range(3):
        length = int.from_bytes(raw[offset : offset + 4], "big")
        offset += 4 + length
    node_count = int.from_bytes(raw[offset : offset + 8], "big")
    if node_count < 2:
        raise ValueError("need at least two nodes for structural mutation")
    offset += 8
    first_length = int.from_bytes(raw[offset : offset + 4], "big")
    offset += 4 + first_length
    second_length = int.from_bytes(raw[offset : offset + 4], "big")
    offset += 4
    if second_length < 64:
        raise AssertionError("unexpectedly short TreeNode wire")
    raw[offset + second_length - 1] ^= 1
    return _rechecksum(bytes(raw))


def run_gate(
    *,
    index_cases: int,
    proof_cases: int,
    delta_cases: int,
    append_cases: int,
    mutation_cases: int,
    stale_cases: int,
) -> dict[str, object]:
    if index_cases < MIN_INDEX_DIFFERENTIAL_CASES:
        raise ValueError("PX0 index differential campaign too small")
    if proof_cases < MIN_PROOF_CASES:
        raise ValueError("PX0 proof campaign too small")
    if delta_cases < MIN_DELTA_CASES:
        raise ValueError("PX0 delta campaign too small")
    if append_cases < MIN_APPEND_CASES:
        raise ValueError("PX0 append campaign too small")
    if mutation_cases < MIN_MUTATION_CASES:
        raise ValueError("PX0 mutation campaign too small")
    if stale_cases < MIN_STALE_CASES:
        raise ValueError("PX0 stale-source campaign too small")

    rng = random.Random(0x50583047415445)
    wire_stream = hashlib.sha256()
    proof_stream = hashlib.sha256()
    delta_stream = hashlib.sha256()
    append_stream = hashlib.sha256()
    mutation_rejections = 0
    structural_rejections = 0
    stale_rejections = 0
    artifact_identity_cases = 0

    boundary_sizes = (0, 1, 65_535, 65_536, 65_537, 2 * 65_536 + 19)
    for case in range(index_cases):
        size = (
            boundary_sizes[case]
            if case < len(boundary_sizes)
            else rng.randrange(0, 12 * 65_536 + 257)
        )
        data = rng.randbytes(size)
        index = build_persistent_index(data)
        wire = index.to_bytes()

        if index.root != build_tree(data):
            raise AssertionError(f"PX0 root divergence at case {case}")
        if wire != persistent_index_wire(data):
            raise AssertionError(f"PX0 independent wire divergence at case {case}")
        if TreePersistentIndexV1.from_bytes(wire) != index:
            raise AssertionError(f"PX0 codec round-trip divergence at case {case}")

        artifact_before = create_artifact_v1(
            ArtifactProfileV1.TREE,
            tree_root=build_tree(data),
        )
        artifact_after = create_artifact_v1(
            ArtifactProfileV1.TREE,
            tree_root=index.root,
        )
        if (
            artifact_before.artifact_id != artifact_after.artifact_id
            or artifact_before.to_bytes() != artifact_after.to_bytes()
        ):
            raise AssertionError("PX0 sidecar changed Artifact identity")
        artifact_identity_cases += 1
        wire_stream.update(hashlib.sha256(wire).digest())

    for case in range(proof_cases):
        size = rng.randrange(1, 12 * 65_536 + 257)
        data = rng.randbytes(size)
        persistent = build_persistent_index(data)
        ephemeral = TreeProofIndex(data)
        leaf_index = rng.randrange(persistent.root.leaf_count)
        inclusion = persistent.prove_leaf(leaf_index)
        if inclusion.to_bytes() != ephemeral.prove_leaf(leaf_index).to_bytes():
            raise AssertionError(f"PX0 inclusion proof divergence at case {case}")

        start = rng.randrange(size)
        length = rng.randrange(1, size - start + 1)
        bound = persistent.bind_source(data)
        range_proof = bound.prove_range(start, length)
        if range_proof.to_bytes() != ephemeral.prove_range(start, length).to_bytes():
            raise AssertionError(f"PX0 range proof divergence at case {case}")
        proof_stream.update(
            hashlib.sha256(inclusion.to_bytes()).digest()
            + hashlib.sha256(range_proof.to_bytes()).digest()
        )

    for case in range(delta_cases):
        size = rng.randrange(2 * 65_536, 10 * 65_536 + 257)
        data = rng.randbytes(size)
        edit_length = rng.randrange(1, min(128, size) + 1)
        start = rng.randrange(0, size - edit_length + 1)
        replacement = rng.randbytes(edit_length)
        edit = TreeEditV1(start, edit_length, replacement)

        persistent = build_persistent_index(data)
        result = persistent.bind_source(data).apply_delta([edit])

        direct = TreeDeltaIndex(data)
        direct_result = direct.apply_delta([edit])
        if result.update.root != direct_result.root:
            raise AssertionError(f"PX0 delta ST4 divergence at case {case}")
        if result.data != direct.materialize():
            raise AssertionError(f"PX0 delta materialized bytes divergence at case {case}")
        if result.index.root != build_tree(result.data):
            raise AssertionError(f"PX0 delta full-rebuild divergence at case {case}")
        if result.index.to_bytes() != persistent_index_wire(result.data):
            raise AssertionError(f"PX0 updated sidecar divergence at case {case}")
        delta_stream.update(hashlib.sha256(result.index.to_bytes()).digest())

    for case in range(append_cases):
        size = rng.randrange(0, 8 * 65_536 + 257)
        data = rng.randbytes(size)
        suffix = rng.randbytes(rng.randrange(0, 2 * 65_536 + 257))

        persistent = build_persistent_index(data)
        result = persistent.bind_source(data).append(suffix)

        direct = TreeDeltaIndex(data)
        direct_result = direct.append(suffix)
        if result.update.root != direct_result.root:
            raise AssertionError(f"PX0 append ST4 divergence at case {case}")
        if result.data != direct.materialize():
            raise AssertionError(f"PX0 append materialized bytes divergence at case {case}")
        if result.index.root != build_tree(data + suffix):
            raise AssertionError(f"PX0 append full-rebuild divergence at case {case}")
        if result.index.to_bytes() != persistent_index_wire(data + suffix):
            raise AssertionError(f"PX0 appended sidecar divergence at case {case}")
        append_stream.update(hashlib.sha256(result.index.to_bytes()).digest())

    # Bit corruption without checksum repair must always fail before semantic use.
    base_data = rng.randbytes(8 * 65_536 + 31)
    base_wire = build_persistent_index(base_data).to_bytes()
    mutable_length = len(base_wire) - 32
    for case in range(mutation_cases):
        raw = bytearray(base_wire)
        position = rng.randrange(mutable_length)
        raw[position] ^= 1 << (case % 8)
        try:
            TreePersistentIndexV1.from_bytes(bytes(raw))
        except ValueError:
            mutation_rejections += 1
        else:
            raise AssertionError(f"PX0 corrupted sidecar accepted at mutation {case}")

    # Even with checksum recomputed, an internal node mutation must fail structure.
    for _ in range(200):
        corrupted = _mutate_second_node(base_wire)
        try:
            TreePersistentIndexV1.from_bytes(corrupted)
        except ValueError:
            structural_rejections += 1
        else:
            raise AssertionError("PX0 structurally corrupt sidecar accepted")

    for case in range(stale_cases):
        size = rng.randrange(1, 8 * 65_536 + 257)
        data = rng.randbytes(size)
        stale = bytearray(data)
        stale[case % size] ^= 1
        index = build_persistent_index(data)
        try:
            index.bind_source(bytes(stale))
        except ValueError:
            stale_rejections += 1
        else:
            raise AssertionError("PX0 stale same-length source passed FULL validation")

        preview = index.bind_source(
            data,
            validation=PersistentSourceValidationV1.LENGTH_ONLY,
        )
        if preview.source_verified:
            raise AssertionError("PX0 LENGTH_ONLY binding became trusted implicitly")

    with tempfile.TemporaryDirectory(prefix="sigma-px0-") as temp:
        root = Path(temp)
        sidecar = root / "tree.sigma-index"
        index = build_persistent_index(rng.randbytes(5 * 65_536 + 17))
        write_persistent_index_atomic(sidecar, index)
        if read_persistent_index(sidecar) != index:
            raise AssertionError("PX0 normal file reader divergence")
        if read_persistent_index(sidecar, use_mmap=True) != index:
            raise AssertionError("PX0 mmap file reader divergence")

        old_bytes = sidecar.read_bytes()
        import sigma.tree.persistent as persistent_module

        original_replace = persistent_module.os.replace

        def fail_replace(src, dst):
            raise OSError("PX0 injected replace failure")

        persistent_module.os.replace = fail_replace
        try:
            try:
                write_persistent_index_atomic(
                    sidecar,
                    build_persistent_index(rng.randbytes(7 * 65_536 + 9)),
                )
            except OSError:
                pass
            else:
                raise AssertionError("PX0 atomic failure injection did not fail")
        finally:
            persistent_module.os.replace = original_replace
        if sidecar.read_bytes() != old_bytes:
            raise AssertionError("PX0 atomic failure changed previous sidecar")

    return {
        "schema": "sigma-px0-persistent-tree-index-gate-v1",
        "passed": True,
        "closure_eligible": True,
        "index_differential_cases": index_cases,
        "proof_differential_cases": proof_cases,
        "delta_differential_cases": delta_cases,
        "append_differential_cases": append_cases,
        "corruption_mutations": mutation_cases,
        "corruption_rejections": mutation_rejections,
        "structural_corruption_rejections": structural_rejections,
        "stale_source_cases": stale_cases,
        "stale_source_rejections": stale_rejections,
        "artifact_identity_cases": artifact_identity_cases,
        "wire_stream_sha256": wire_stream.hexdigest(),
        "proof_stream_sha256": proof_stream.hexdigest(),
        "delta_stream_sha256": delta_stream.hexdigest(),
        "append_stream_sha256": append_stream.hexdigest(),
        "mmap_parity": True,
        "atomic_publication_failure_preserves_old_index": True,
        "source_hint_security_evidence": False,
        "persistent_index_part_of_tree_or_artifact_identity": False,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--index-cases", type=int, default=MIN_INDEX_DIFFERENTIAL_CASES)
    parser.add_argument("--proof-cases", type=int, default=MIN_PROOF_CASES)
    parser.add_argument("--delta-cases", type=int, default=MIN_DELTA_CASES)
    parser.add_argument("--append-cases", type=int, default=MIN_APPEND_CASES)
    parser.add_argument("--mutation-cases", type=int, default=MIN_MUTATION_CASES)
    parser.add_argument("--stale-cases", type=int, default=MIN_STALE_CASES)
    parser.add_argument("--report", type=Path)
    args = parser.parse_args()

    report = run_gate(
        index_cases=args.index_cases,
        proof_cases=args.proof_cases,
        delta_cases=args.delta_cases,
        append_cases=args.append_cases,
        mutation_cases=args.mutation_cases,
        stale_cases=args.stale_cases,
    )
    payload = json.dumps(report, indent=2, sort_keys=True) + "\n"
    if args.report is not None:
        args.report.parent.mkdir(parents=True, exist_ok=True)
        args.report.write_text(payload, encoding="utf-8")
    print(payload, end="")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
