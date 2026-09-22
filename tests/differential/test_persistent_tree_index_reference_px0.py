from __future__ import annotations

import random

from reference.persistent_tree_index_v1 import persistent_index_wire
from sigma.tree import (
    TreeProofIndex,
    build_persistent_index,
    build_tree,
)


def test_persistent_index_wire_matches_independent_reference():
    rng = random.Random(0x50583044494646)
    sizes = [0, 1, 65_535, 65_536, 65_537, 2 * 65_536 + 19]
    sizes += [rng.randrange(0, 16 * 65_536 + 257) for _ in range(120)]

    for size in sizes:
        data = rng.randbytes(size)
        index = build_persistent_index(data)
        assert index.root == build_tree(data)
        assert index.to_bytes() == persistent_index_wire(data)


def test_persistent_proofs_match_ephemeral_random_corpus():
    rng = random.Random(0x50583050524F4F46)
    for _ in range(96):
        size = rng.randrange(1, 12 * 65_536 + 257)
        data = rng.randbytes(size)
        persistent = build_persistent_index(data)
        ephemeral = TreeProofIndex(data)

        leaf = rng.randrange(persistent.root.leaf_count)
        assert persistent.prove_leaf(leaf).to_bytes() == ephemeral.prove_leaf(
            leaf
        ).to_bytes()

        start = rng.randrange(size)
        length = rng.randrange(1, size - start + 1)
        bound = persistent.bind_source(data)
        assert bound.prove_range(start, length).to_bytes() == ephemeral.prove_range(
            start,
            length,
        ).to_bytes()
