from __future__ import annotations

import itertools
import random

from reference.tree_delta_v1 import apply_same_length as reference_apply_same_length
from sigma.tree import TreeDeltaIndex, TreeEditV1, build_tree, normalize_tree_edits


def test_normalization_is_permutation_independent_for_consistent_overlaps():
    edits = (
        TreeEditV1(0, 5, b"ABCDE"),
        TreeEditV1(2, 5, b"CDEFG"),
        TreeEditV1(7, 3, b"HIJ"),
        TreeEditV1(10, 2, b"KL"),
    )
    expected = normalize_tree_edits(list(edits), total_bytes=32)
    for permutation in itertools.permutations(edits):
        assert normalize_tree_edits(list(permutation), total_bytes=32) == expected


def test_random_delta_equivalence_and_work_locality():
    rng = random.Random(0x53543444454C54)
    for _ in range(120):
        leaf_count = rng.randrange(2, 17)
        tail = rng.randrange(0, 257)
        size = leaf_count * 65_536 + tail
        data = rng.randbytes(size)
        index = TreeDeltaIndex(data)

        edits = []
        available_leaves = list(range((size + 65_535) // 65_536))
        rng.shuffle(available_leaves)
        for leaf in available_leaves[: rng.randrange(1, min(6, len(available_leaves) + 1))]:
            leaf_start = leaf * 65_536
            leaf_end = min(leaf_start + 65_536, size)
            start = rng.randrange(leaf_start, leaf_end)
            width = rng.randrange(1, min(128, leaf_end - start) + 1)
            edits.append(TreeEditV1(start, width, rng.randbytes(width)))

        result = index.apply_delta(edits)
        expected = reference_apply_same_length(
            data, [(edit.start, edit.delete_length, edit.data) for edit in edits]
        )
        assert index.materialize() == expected
        assert result.root == build_tree(expected)

        for leaf in result.telemetry.affected_leaves:
            assert (leaf, 1) in result.telemetry.recomputed_nodes
        assert set(result.telemetry.recomputed_nodes) == set(
            result.telemetry.invalidated_nodes
        )


def test_random_append_equivalence_and_frontier_reuse():
    rng = random.Random(0x5354344150504E44)
    for _ in range(120):
        size = rng.randrange(0, 12 * 65_536 + 257)
        data = rng.randbytes(size)
        suffix = rng.randbytes(rng.randrange(0, 3 * 65_536 + 257))
        index = TreeDeltaIndex(data)
        result = index.append(suffix)

        assert index.materialize() == data + suffix
        assert result.root == build_tree(data + suffix)

        if data and suffix:
            full_prefix_leaves = len(data) // 65_536
            if full_prefix_leaves:
                assert result.telemetry.frontier_nodes_reused > 0


def test_random_repeated_mixed_updates():
    rng = random.Random(0x5354344D49584544)
    for _ in range(40):
        data = bytearray(rng.randbytes(4 * 65_536 + rng.randrange(1, 257)))
        index = TreeDeltaIndex(bytes(data))

        for _ in range(12):
            if rng.random() < 0.7:
                start = rng.randrange(len(data))
                width = rng.randrange(1, min(128, len(data) - start) + 1)
                replacement = rng.randbytes(width)
                index.apply_delta([TreeEditV1(start, width, replacement)])
                data[start : start + width] = replacement
            else:
                suffix = rng.randbytes(rng.randrange(0, 4097))
                index.append(suffix)
                data.extend(suffix)
            assert index.root == build_tree(bytes(data))
