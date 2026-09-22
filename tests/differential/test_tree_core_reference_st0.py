import random

from reference.tree_v1 import build as reference_build
from sigma.tree import build_tree


def test_reference_matches_product_random_corpus():
    rng = random.Random(0x51_47_4D_41)
    sizes = [0, 1, 65_535, 65_536, 65_537, 131_072, 131_073, 7 * 65_536 + 13]
    sizes += [rng.randrange(0, 600_000) for _ in range(128)]
    for size in sizes:
        data = rng.randbytes(size)
        ref_length, ref_leaves, ref_digests = reference_build(data)
        got = build_tree(data)
        assert got.byte_length == ref_length
        assert got.leaf_count == ref_leaves
        assert got.digests == ref_digests
