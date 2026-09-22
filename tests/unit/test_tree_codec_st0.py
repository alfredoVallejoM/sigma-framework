import pytest

from sigma.tree.codec import TreeDecodeError
from sigma.tree.core import build_tree, leaf_node
from sigma.tree.model import DEFAULT_PROFILE, TreeFrontier, TreeNode, TreeRoot


def _top_level_fields(encoded: bytes) -> list[tuple[int, bytes]]:
    body_length = int.from_bytes(encoded[10:14], "big")
    assert body_length == len(encoded) - 14
    fields = []
    offset = 14
    while offset < len(encoded):
        tag = int.from_bytes(encoded[offset : offset + 2], "big")
        length = int.from_bytes(encoded[offset + 2 : offset + 6], "big")
        offset += 6
        fields.append((tag, encoded[offset : offset + length]))
        offset += length
    return fields


def _raw_record(template: bytes, fields: list[tuple[int, bytes]]) -> bytes:
    body = b"".join(
        tag.to_bytes(2, "big") + len(value).to_bytes(4, "big") + value
        for tag, value in fields
    )
    return template[:10] + len(body).to_bytes(4, "big") + body


def test_root_rejects_bad_magic_and_version():
    root = build_tree(b"abc").to_bytes()
    with pytest.raises(TreeDecodeError):
        TreeRoot.from_bytes(b"X" + root[1:])
    with pytest.raises(TreeDecodeError):
        TreeRoot.from_bytes(root[:8] + b"\x00\x02" + root[10:])


def test_root_rejects_missing_duplicate_reordered_and_unknown_fields():
    encoded = build_tree(b"schema-mutation").to_bytes()
    fields = _top_level_fields(encoded)

    mutations = [
        _raw_record(encoded, fields[1:]),
        _raw_record(encoded, fields[:1] + [fields[0]] + fields[1:]),
        _raw_record(encoded, [fields[1], fields[0], *fields[2:]]),
        _raw_record(encoded, [*fields, (0xFFFF, b"")]),
    ]
    for mutated in mutations:
        with pytest.raises(TreeDecodeError):
            TreeRoot.from_bytes(mutated)


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


def test_parser_rejects_oversized_record_before_tlv_walk():
    from sigma.tree.codec import MAX_TREE_RECORD_BYTES

    with pytest.raises(TreeDecodeError, match="total-size limit"):
        TreeRoot.from_bytes(b"X" * (MAX_TREE_RECORD_BYTES + 1))


def test_profile_rejects_integer_algorithm_aliases():
    from sigma.tree.model import TreeProfileV1

    with pytest.raises(TypeError, match="TreeAlgorithmId"):
        TreeProfileV1(algorithms=(1, 2, 3, 4))


def test_digest_and_frontier_containers_are_immutable_tuples():
    root = build_tree(b"abc")
    with pytest.raises(TypeError, match="immutable tuple"):
        TreeRoot(root.profile, root.byte_length, root.leaf_count, list(root.digests))
    with pytest.raises(TypeError, match="immutable tuple"):
        TreeFrontier([])
