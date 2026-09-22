from __future__ import annotations

import random

from reference.tree_proof_v1 import verify_inclusion_wire, verify_range_wire
from reference.tree_v1 import root_wire as reference_root_wire
from sigma.tree import (
    TreeProofIndex,
    build_tree,
    prove_leaf_streaming,
    prove_range_streaming,
)


def test_st5_optimized_build_matches_reference_random_corpus():
    rng = random.Random(0x5354354255494C44)
    sizes = [0, 1, 65_535, 65_536, 65_537, 131_071, 131_072, 131_073]
    sizes += [rng.randrange(0, 10 * 65_536 + 257) for _ in range(128)]
    for size in sizes:
        data = rng.randbytes(size)
        assert build_tree(data).to_bytes() == reference_root_wire(data)


def test_st5_streaming_proof_fallback_matches_full_index_random_corpus():
    rng = random.Random(0x53543550524F4F46)
    for _ in range(96):
        size = rng.randrange(1, 10 * 65_536 + 257)
        data = rng.randbytes(size)
        index = TreeProofIndex(data)

        leaf_index = rng.randrange(index.root.leaf_count)
        full_inclusion = index.prove_leaf(leaf_index)
        streaming_inclusion = prove_leaf_streaming(data, leaf_index)
        assert streaming_inclusion.to_bytes() == full_inclusion.to_bytes()
        start = leaf_index * 65_536
        leaf = data[start : min(start + 65_536, size)]
        assert verify_inclusion_wire(leaf, streaming_inclusion.to_bytes())

        range_start = rng.randrange(size)
        range_length = rng.randrange(1, size - range_start + 1)
        full_range = index.prove_range(range_start, range_length)
        streaming_range = prove_range_streaming(data, range_start, range_length)
        assert streaming_range.to_bytes() == full_range.to_bytes()
        assert verify_range_wire(
            data[range_start : range_start + range_length],
            streaming_range.to_bytes(),
        )
