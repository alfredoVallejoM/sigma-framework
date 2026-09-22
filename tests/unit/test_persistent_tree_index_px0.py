from __future__ import annotations

import hashlib
from pathlib import Path

import pytest

from sigma.artifact import ArtifactProfileV1, create_artifact_v1
from sigma.tree import (
    PersistentIndexSourceUnverified,
    PersistentSourceValidationV1,
    TreeDeltaIndex,
    TreeEditV1,
    TreePersistentIndexV1,
    TreeProofIndex,
    build_persistent_index,
    build_persistent_index_file,
    build_tree,
    read_persistent_index,
    write_persistent_index_atomic,
)


@pytest.mark.parametrize(
    "size",
    [0, 1, 65_535, 65_536, 65_537, 4 * 65_536 + 19],
)
def test_persistent_index_roundtrip_preserves_tree_root(size: int):
    data = bytes((i * 17 + 3) % 251 for i in range(size))
    index = build_persistent_index(data)
    assert index.root == build_tree(data)
    assert TreePersistentIndexV1.from_bytes(index.to_bytes()) == index

    expected_nodes = 0 if index.root.leaf_count == 0 else 2 * index.root.leaf_count - 1
    assert index.node_count == expected_nodes


def test_detached_inclusion_and_bound_range_match_ephemeral_index():
    data = bytes((i * 11 + 7) % 251 for i in range(9 * 65_536 + 31))
    persistent = build_persistent_index(data)
    ephemeral = TreeProofIndex(data)

    for leaf_index in (0, 1, 4, 8, 9):
        assert persistent.prove_leaf(leaf_index).to_bytes() == ephemeral.prove_leaf(
            leaf_index
        ).to_bytes()

    bound = persistent.bind_source(data)
    for start, length in (
        (0, 1),
        (65_535, 3),
        (65_536 + 7, 101),
        (2 * 65_536 - 9, 2 * 65_536 + 17),
        (0, len(data)),
    ):
        assert bound.prove_range(start, length).to_bytes() == ephemeral.prove_range(
            start, length
        ).to_bytes()


def test_length_only_binding_cannot_drive_trusted_source_operations():
    data = b"x" * (2 * 65_536 + 19)
    persistent = build_persistent_index(data)
    bound = persistent.bind_source(
        data,
        validation=PersistentSourceValidationV1.LENGTH_ONLY,
    )
    assert not bound.source_verified
    with pytest.raises(PersistentIndexSourceUnverified):
        bound.prove_range(0, 1)
    with pytest.raises(PersistentIndexSourceUnverified):
        bound.delta_index()
    assert bound.verify_source()
    assert bound.prove_range(0, 1)


def test_full_binding_rejects_stale_same_length_source():
    data = b"A" * (2 * 65_536 + 11)
    stale = bytearray(data)
    stale[65_536 + 3] ^= 1
    persistent = build_persistent_index(data)
    with pytest.raises(ValueError, match="does not match"):
        persistent.bind_source(bytes(stale))


def test_checksum_detects_random_sidecar_corruption():
    data = b"checksum" * 20_000
    encoded = bytearray(build_persistent_index(data).to_bytes())
    encoded[len(encoded) // 2] ^= 1
    with pytest.raises(ValueError, match="checksum"):
        TreePersistentIndexV1.from_bytes(bytes(encoded))


def _rechecksum(payload: bytes) -> bytes:
    domain = b"SIGMA-PERSISTENT-TREE-INDEX-V1\x00"
    return payload[:-32] + hashlib.sha256(domain + payload[:-32]).digest()


def test_structural_validation_detects_corrupt_node_even_with_recomputed_checksum():
    data = b"node-structure" * 20_000
    encoded = bytearray(build_persistent_index(data).to_bytes())

    # Walk the fixed PX0 framing to the first node payload.
    offset = 10
    for _ in range(3):
        length = int.from_bytes(encoded[offset : offset + 4], "big")
        offset += 4 + length
    node_count = int.from_bytes(encoded[offset : offset + 8], "big")
    assert node_count > 1
    offset += 8
    node_len = int.from_bytes(encoded[offset : offset + 4], "big")
    offset += 4
    assert node_len > 40

    # Mutate a digest byte while leaving TreeNode geometry parseable, then
    # recompute only the sidecar corruption checksum.
    encoded[offset + node_len - 1] ^= 1
    mutated = _rechecksum(bytes(encoded))
    with pytest.raises(ValueError, match="internal node|root node|children"):
        TreePersistentIndexV1.from_bytes(mutated)


def test_file_build_hint_mmap_and_normal_read_are_identical(tmp_path: Path):
    source = tmp_path / "payload.bin"
    source.write_bytes(b"file-index" * 30_000)

    index = build_persistent_index_file(source)
    assert index.source_hint is not None
    assert index.source_hint_matches(source)
    assert index.root == build_tree(source.read_bytes())

    sidecar = tmp_path / "payload.sigma-index"
    write_persistent_index_atomic(sidecar, index)
    normal = read_persistent_index(sidecar)
    mapped = read_persistent_index(sidecar, use_mmap=True)
    assert normal == index
    assert mapped == index

    source.write_bytes(source.read_bytes() + b"x")
    assert not index.source_hint_matches(source)


def test_atomic_write_failure_preserves_previous_sidecar(tmp_path: Path, monkeypatch):
    destination = tmp_path / "state.sigma-index"
    old = build_persistent_index(b"old-data")
    new = build_persistent_index(b"new-data" * 10_000)
    write_persistent_index_atomic(destination, old)
    before = destination.read_bytes()

    import sigma.tree.persistent as persistent_module

    def fail_replace(src, dst):
        raise OSError("injected replace failure")

    monkeypatch.setattr(persistent_module.os, "replace", fail_replace)
    with pytest.raises(OSError, match="injected"):
        persistent_module.write_persistent_index_atomic(destination, new)

    assert destination.read_bytes() == before
    assert read_persistent_index(destination) == old
    assert not list(tmp_path.glob(".state.sigma-index.*.tmp"))


def test_persistent_delta_matches_ephemeral_and_full_rebuild():
    data = bytes((i * 29 + 13) % 251 for i in range(12 * 65_536 + 17))
    edit = TreeEditV1(7 * 65_536 + 31, 4, b"WXYZ")

    persistent = build_persistent_index(data)
    bound = persistent.bind_source(data)
    result = bound.apply_delta([edit])

    direct = TreeDeltaIndex(data)
    direct_result = direct.apply_delta([edit])
    assert result.update.root == direct_result.root
    assert result.data == direct.materialize()
    assert result.index.root == direct_result.root
    assert result.index.root == build_tree(result.data)

    rebound = result.index.bind_source(result.data)
    assert rebound.source_verified


def test_persistent_append_matches_ephemeral_and_full_rebuild():
    data = bytes((i * 31 + 5) % 251 for i in range(6 * 65_536 + 19))
    suffix = b"append" * 20_000

    persistent = build_persistent_index(data)
    result = persistent.bind_source(data).append(suffix)

    direct = TreeDeltaIndex(data)
    direct_result = direct.append(suffix)
    assert result.update.root == direct_result.root
    assert result.data == direct.materialize()
    assert result.index.root == build_tree(data + suffix)


def test_sidecar_does_not_change_artifact_identity():
    data = b"artifact-index-independence"
    root = build_tree(data)
    before = create_artifact_v1(ArtifactProfileV1.TREE, tree_root=root)
    index = build_persistent_index(data)
    after = create_artifact_v1(ArtifactProfileV1.TREE, tree_root=index.root)
    assert before.artifact_id == after.artifact_id
    assert before.to_bytes() == after.to_bytes()


def test_parser_node_limit_is_enforced_before_semantic_use():
    data = b"x" * (8 * 65_536)
    index = build_persistent_index(data)
    assert index.node_count > 3
    with pytest.raises(ValueError, match="node count"):
        TreePersistentIndexV1.from_bytes(index.to_bytes(), max_nodes=3)
