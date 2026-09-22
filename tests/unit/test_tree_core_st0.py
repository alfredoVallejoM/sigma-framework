import pytest

from sigma.tree import (
    DEFAULT_PROFILE,
    TreeDecodeError,
    TreeFrontier,
    TreeNode,
    TreeProfileV1,
    TreeRoot,
    build_tree,
    combine_nodes,
    leaf_node,
)


def test_profile_roundtrip():
    assert TreeProfileV1.from_bytes(DEFAULT_PROFILE.to_bytes()) == DEFAULT_PROFILE


def test_empty_is_canonical():
    a = build_tree(b"")
    b = build_tree(b"")
    assert a == b
    assert a.byte_length == 0
    assert a.leaf_count == 0
    assert TreeRoot.from_bytes(a.to_bytes()) == a


@pytest.mark.parametrize("size", [1, 65_535, 65_536, 65_537])
def test_boundaries_roundtrip(size):
    root = build_tree(bytes([size % 251]) * size)
    assert root.byte_length == size
    assert root.leaf_count == (size + 65_535) // 65_536
    assert TreeRoot.from_bytes(root.to_bytes()) == root


def test_frontier_canonical_order_after_three_leaves():
    from sigma.tree import TreeBuilder

    builder = TreeBuilder()
    builder.update(b"a" * (3 * 65_536))
    frontier = builder.frontier
    assert [n.height for n in frontier.nodes] == [1, 0]
    assert [n.start_leaf for n in frontier.nodes] == [0, 2]
    assert TreeFrontier.from_bytes(frontier.to_bytes()) == frontier


def test_invalid_frontier_rejects_duplicate_height():
    a = leaf_node(DEFAULT_PROFILE, 0, 0, b"a")
    b = leaf_node(DEFAULT_PROFILE, 1, 65_536, b"b")
    with pytest.raises(ValueError):
        TreeFrontier((a, b))


def test_nonadjacent_parent_rejected():
    a = leaf_node(DEFAULT_PROFILE, 0, 0, b"a")
    c = leaf_node(DEFAULT_PROFILE, 2, 2 * 65_536, b"c")
    with pytest.raises(ValueError):
        combine_nodes(DEFAULT_PROFILE, a, c)


def test_node_codec_rejects_trailing_bytes():
    node = leaf_node(DEFAULT_PROFILE, 0, 0, b"a")
    with pytest.raises(TreeDecodeError):
        TreeNode.from_bytes(node.to_bytes() + b"x")


def test_canonical_frontier_heights_exhaustive_100k():
    from sigma.tree import canonical_frontier_heights

    for n in range(100_001):
        heights = canonical_frontier_heights(n)
        assert sum(1 << h for h in heights) == n
        assert all(a > b for a, b in zip(heights, heights[1:]))


def test_prehashed_backend_reducer_matches_direct():
    from sigma.tree import TreeBuilder
    from sigma.tree.core import leaf_node

    data = b"x" * (2 * 65_536) + b"tail"
    leaves = []
    for index, start in enumerate(range(0, len(data), 65_536)):
        raw = data[start : start + 65_536]
        node = leaf_node(DEFAULT_PROFILE, index, start, raw)
        leaves.append((node.digests, len(raw)))
    assert TreeBuilder.from_prehashed_leaves(leaves) == build_tree(data)


def test_prehashed_reducer_rejects_data_after_short_leaf():
    from sigma.tree import TreeBuilder

    digest = (b"a" * 64,) * 4
    with pytest.raises(ValueError):
        TreeBuilder.from_prehashed_leaves(((digest, 1), (digest, 65_536)))
