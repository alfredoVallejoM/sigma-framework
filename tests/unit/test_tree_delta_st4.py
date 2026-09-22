from __future__ import annotations

import random

import pytest

from reference.tree_delta_v1 import ancestor_closure as reference_ancestor_closure
from reference.tree_delta_v1 import apply_same_length as reference_apply_same_length
from sigma.tree import (
    RebuildRequired,
    TreeDeltaIndex,
    TreeEditV1,
    build_tree,
    normalize_tree_edits,
)


def _data(leaves: int, tail: int = 0) -> bytes:
    chunk = bytes((i * 17 + 3) % 251 for i in range(65_536))
    return chunk * leaves + bytes((i * 29 + 7) % 251 for i in range(tail))


def test_normalize_overlapping_and_adjacent_edits_canonically():
    edits = [
        TreeEditV1(4, 4, b"EFGH"),
        TreeEditV1(0, 4, b"ABCD"),
        TreeEditV1(2, 4, b"CDEF"),
        TreeEditV1(8, 2, b"IJ"),
    ]
    normalized = normalize_tree_edits(edits, total_bytes=16)
    assert normalized == (TreeEditV1(0, 10, b"ABCDEFGHIJ"),)


def test_normalize_rejects_conflicting_overlap():
    with pytest.raises(ValueError, match="disagree"):
        normalize_tree_edits(
            [TreeEditV1(0, 4, b"AAAA"), TreeEditV1(2, 4, b"BBBB")],
            total_bytes=16,
        )


@pytest.mark.parametrize(
    "edit",
    [
        TreeEditV1(1, 0, b"x"),
        TreeEditV1(1, 2, b"x"),
        TreeEditV1(1, 1, b"xy"),
    ],
)
def test_boundary_shifting_edits_require_rebuild(edit):
    with pytest.raises(RebuildRequired):
        normalize_tree_edits([edit], total_bytes=10)


def test_one_byte_delta_equals_full_rebuild():
    data = _data(8)
    index = TreeDeltaIndex(data)
    edit = TreeEditV1(3 * 65_536 + 17, 1, b"Z")
    result = index.apply_delta([edit])
    expected = reference_apply_same_length(data, [(edit.start, edit.delete_length, edit.data)])
    assert result.root == build_tree(expected)
    assert index.materialize() == expected
    assert result.telemetry.affected_leaves == (3,)
    assert result.telemetry.recomputed_leaf_count == 1


def test_cross_chunk_delta_recomputes_both_leaves():
    data = _data(4)
    index = TreeDeltaIndex(data)
    start = 65_536 - 2
    edit = TreeEditV1(start, 4, b"WXYZ")
    result = index.apply_delta([edit])
    expected = data[:start] + b"WXYZ" + data[start + 4 :]
    assert result.root == build_tree(expected)
    assert result.telemetry.affected_leaves == (0, 1)
    assert result.telemetry.recomputed_leaf_count == 2


def test_multiple_disjoint_edits_equal_full_rebuild():
    data = _data(9, 17)
    edits = [
        TreeEditV1(10, 3, b"abc"),
        TreeEditV1(4 * 65_536 + 7, 5, b"12345"),
        TreeEditV1(len(data) - 3, 3, b"END"),
    ]
    index = TreeDeltaIndex(data)
    result = index.apply_delta(edits)
    expected = reference_apply_same_length(
        data, [(edit.start, edit.delete_length, edit.data) for edit in edits]
    )
    assert result.root == build_tree(expected)
    assert index.materialize() == expected


def test_unaffected_subtree_object_is_preserved():
    data = _data(8)
    index = TreeDeltaIndex(data)
    unaffected = index.node(0, 4)
    result = index.apply_delta([TreeEditV1(6 * 65_536 + 9, 1, b"Q")])
    assert index.node(0, 4) is unaffected
    assert (0, 4) in result.telemetry.reused_nodes


def test_ancestor_closure_is_exact():
    data = _data(11)
    index = TreeDeltaIndex(data)
    edits = [
        TreeEditV1(1 * 65_536 + 3, 1, b"x"),
        TreeEditV1(9 * 65_536 + 5, 1, b"y"),
    ]
    result = index.apply_delta(edits)
    expected = reference_ancestor_closure(index.leaf_count, (1, 9))
    assert result.telemetry.invalidated_nodes == expected
    assert set(result.telemetry.recomputed_nodes) == set(expected)


def test_delta_failure_before_publish_preserves_state(monkeypatch):
    import sigma.tree.delta as delta_module

    data = _data(8)
    index = TreeDeltaIndex(data)
    before_root = index.root
    before_bytes = index.materialize()
    original = delta_module.combine_nodes
    calls = 0

    def fail_once(*args, **kwargs):
        nonlocal calls
        calls += 1
        if calls == 1:
            raise RuntimeError("injected combine failure")
        return original(*args, **kwargs)

    monkeypatch.setattr(delta_module, "combine_nodes", fail_once)
    with pytest.raises(RuntimeError, match="injected"):
        index.apply_delta([TreeEditV1(3 * 65_536 + 1, 1, b"Z")])

    assert index.root == before_root
    assert index.materialize() == before_bytes


def test_append_zero_is_noop():
    data = _data(5, 11)
    index = TreeDeltaIndex(data)
    before = index.root
    result = index.append(b"")
    assert result.root == before
    assert result.telemetry.edit_bytes == 0
    assert index.root == before


@pytest.mark.parametrize("suffix_size", [1, 65_536, 2 * 65_536 + 17])
def test_append_equals_full_rebuild(suffix_size):
    data = _data(7, 19)
    suffix = bytes((i * 11 + 5) % 251 for i in range(suffix_size))
    index = TreeDeltaIndex(data)
    result = index.append(suffix)
    assert result.root == build_tree(data + suffix)
    assert index.materialize() == data + suffix
    assert result.telemetry.frontier_nodes_reused > 0


def test_append_from_exact_chunk_boundary_reuses_old_root():
    data = _data(8)
    index = TreeDeltaIndex(data)
    old_root_node = index.node(0, 8)
    result = index.append(b"tail")
    assert result.root == build_tree(data + b"tail")
    assert (0, 8) in result.telemetry.reused_nodes
    assert result.telemetry.frontier_nodes_reused == 1
    assert index.node(0, 8) is old_root_node


def test_repeated_delta_then_append_then_delta():
    data = _data(6, 17)
    expected = bytearray(data)
    index = TreeDeltaIndex(data)

    first = TreeEditV1(2 * 65_536 + 4, 3, b"ABC")
    index.apply_delta([first])
    expected[first.start : first.end] = first.data

    suffix = b"S" * (65_536 + 9)
    index.append(suffix)
    expected.extend(suffix)

    second = TreeEditV1(len(expected) - 5, 5, b"FINAL")
    index.apply_delta([second])
    expected[second.start : second.end] = second.data

    assert index.root == build_tree(bytes(expected))
    assert index.materialize() == bytes(expected)


def test_random_small_delta_smoke():
    rng = random.Random(0x535434)
    data = rng.randbytes(5 * 65_536 + 127)
    index = TreeDeltaIndex(data)
    expected = bytearray(data)
    for _ in range(25):
        start = rng.randrange(len(expected))
        length = rng.randrange(1, min(64, len(expected) - start) + 1)
        replacement = rng.randbytes(length)
        result = index.apply_delta([TreeEditV1(start, length, replacement)])
        expected[start : start + length] = replacement
        assert result.root == build_tree(bytes(expected))


def test_append_failure_before_publish_preserves_state(monkeypatch):
    import sigma.tree.delta as delta_module

    data = _data(8, 17)
    index = TreeDeltaIndex(data)
    before_root = index.root
    before_bytes = index.materialize()
    original = delta_module.combine_nodes
    calls = 0

    def fail_once(*args, **kwargs):
        nonlocal calls
        calls += 1
        if calls == 1:
            raise RuntimeError("injected append combine failure")
        return original(*args, **kwargs)

    monkeypatch.setattr(delta_module, "combine_nodes", fail_once)
    with pytest.raises(RuntimeError, match="injected append"):
        index.append(b"suffix" * 100)

    assert index.root == before_root
    assert index.materialize() == before_bytes
