from __future__ import annotations

import random

from reference.tree_delta_v1 import (
    ancestor_closure as reference_ancestor_closure,
    append_root_wire,
    delta_root_wire,
)
from sigma.tree import TreeDeltaIndex, TreeEditV1


def test_independent_delta_root_matches_product():
    rng = random.Random(0x53543444494646)
    for _ in range(250):
        size = rng.randrange(1, 10 * 65_536 + 257)
        data = rng.randbytes(size)
        edits = []
        available_leaves = list(range((size + 65_535) // 65_536))
        rng.shuffle(available_leaves)
        for leaf in available_leaves[: rng.randrange(1, min(5, len(available_leaves) + 1))]:
            leaf_start = leaf * 65_536
            leaf_end = min(leaf_start + 65_536, size)
            start = rng.randrange(leaf_start, leaf_end)
            width = rng.randrange(1, min(256, leaf_end - start) + 1)
            edits.append(TreeEditV1(start, width, rng.randbytes(width)))

        index = TreeDeltaIndex(data)
        result = index.apply_delta(edits)
        reference = delta_root_wire(
            data, [(edit.start, edit.delete_length, edit.data) for edit in edits]
        )
        assert result.root.to_bytes() == reference
        assert result.telemetry.invalidated_nodes == reference_ancestor_closure(
            result.root.leaf_count, result.telemetry.affected_leaves
        )


def test_independent_append_root_matches_product():
    rng = random.Random(0x5354344150505246)
    for _ in range(250):
        size = rng.randrange(0, 10 * 65_536 + 257)
        data = rng.randbytes(size)
        suffix = rng.randbytes(rng.randrange(0, 3 * 65_536 + 257))
        index = TreeDeltaIndex(data)
        result = index.append(suffix)
        assert result.root.to_bytes() == append_root_wire(data, suffix)


def test_delta_after_append_still_matches_independent_reference():
    rng = random.Random(0x535434434841494E)
    data = rng.randbytes(7 * 65_536 + 19)
    index = TreeDeltaIndex(data)

    suffix = rng.randbytes(2 * 65_536 + 13)
    index.append(suffix)
    current = data + suffix

    edit = TreeEditV1(6 * 65_536 + 7, 33, rng.randbytes(33))
    result = index.apply_delta([edit])
    assert result.root.to_bytes() == delta_root_wire(
        current, [(edit.start, edit.delete_length, edit.data)]
    )
