import random

from sigma.tree import TreeBuilder, TreeFrontier, build_tree, build_tree_chunks


def test_read_partition_invariance_random_corpus():
    rng = random.Random(0x535430)
    for _ in range(250):
        size = rng.randrange(0, 300_001)
        data = rng.randbytes(size)
        chunks = []
        pos = 0
        while pos < size:
            width = rng.randrange(1, 100_001)
            chunks.append(data[pos : pos + width])
            pos += width
        chunks.append(b"")
        assert build_tree_chunks(chunks) == build_tree(data)


def test_frontier_wire_roundtrip_random_prefixes():
    rng = random.Random(0x46524E54)
    for _ in range(250):
        data = rng.randbytes(rng.randrange(0, 200_001))
        builder = TreeBuilder()
        builder.update(data)
        assert TreeFrontier.from_bytes(builder.frontier.to_bytes()) == builder.frontier


def test_prehashed_backend_neutrality_random_corpus():
    from sigma.tree import DEFAULT_PROFILE, TreeBuilder
    from sigma.tree.core import leaf_node

    rng = random.Random(0x4241434B)
    for _ in range(300):
        size = rng.randrange(0, 500_001)
        data = rng.randbytes(size)
        leaves = []
        for index, start in enumerate(range(0, size, DEFAULT_PROFILE.chunk_size)):
            raw = data[start : start + DEFAULT_PROFILE.chunk_size]
            node = leaf_node(DEFAULT_PROFILE, index, start, raw)
            leaves.append((node.digests, len(raw)))
        assert TreeBuilder.from_prehashed_leaves(leaves) == build_tree(data)
