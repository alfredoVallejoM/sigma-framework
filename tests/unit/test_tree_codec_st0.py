import pytest

from sigma.tree.codec import TreeDecodeError
from sigma.tree.model import DEFAULT_PROFILE, TreeFrontier, TreeNode, TreeRoot
from sigma.tree.core import build_tree, leaf_node


def test_root_rejects_bad_magic_and_version():
    root = build_tree(b"abc").to_bytes()
    with pytest.raises(TreeDecodeError):
        TreeRoot.from_bytes(b"X" + root[1:])
    with pytest.raises(TreeDecodeError):
        TreeRoot.from_bytes(root[:8] + b"\x00\x02" + root[10:])


def test_node_digest_width_enforced():
    node = leaf_node(DEFAULT_PROFILE, 0, 0, b"abc")
    with pytest.raises(ValueError):
        TreeNode(
            node.start_leaf,
            node.leaf_count,
            node.byte_length,
            node.height,
            node.digests[:-1] + (b"x",),
        )


def test_frontier_rejects_gap():
    a = leaf_node(DEFAULT_PROFILE, 0, 0, b"a")
    c = leaf_node(DEFAULT_PROFILE, 2, 2 * 65_536, b"c")
    with pytest.raises(ValueError):
        TreeFrontier((a, c))


def test_profile_rejects_non_four_algorithm_count_before_construction():
    from sigma.tree.codec import record, u16, u32
    from sigma.tree.ids import TREE_PROFILE_MAGIC
    from sigma.tree.model import TreeProfileV1

    malformed = record(
        TREE_PROFILE_MAGIC,
        (
            (1, u16(1)),
            (2, u32(65_536)),
            (3, u16(1) + u16(1)),
        ),
    )
    with pytest.raises(TreeDecodeError, match="exactly four"):
        TreeProfileV1.from_bytes(malformed)


def test_root_rejects_impossible_byte_leaf_relation():
    root = build_tree(b"abc")
    with pytest.raises(ValueError, match="canonical chunking"):
        TreeRoot(root.profile, 65_537, 1, root.digests)
