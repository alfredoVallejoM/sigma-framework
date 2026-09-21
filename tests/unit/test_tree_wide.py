import io
from dataclasses import replace

import pytest

from sigma.anchors import TreeWide
from sigma.presets import simultaneous_v2_2
from sigma.spec import SigmaContextV2
from sigma.v2 import hash_bytes, hash_chunks, hash_reader, verify_full

LEAF_SIZE = 65536


def tree_context(**kwargs) -> SigmaContextV2:
    return simultaneous_v2_2(**kwargs)


@pytest.mark.parametrize(
    "size",
    [
        0,
        LEAF_SIZE - 1,
        LEAF_SIZE,
        LEAF_SIZE + 1,
        2 * LEAF_SIZE - 1,
        2 * LEAF_SIZE,
        2 * LEAF_SIZE + 1,
    ],
)
def test_tree_is_independent_of_read_partition(size: int) -> None:
    context = tree_context()
    payload = bytes((index * 17) % 256 for index in range(size))
    whole = hash_bytes(payload, context)
    split = hash_chunks(
        (
            payload[:1],
            payload[1:317],
            b"",
            payload[317 : LEAF_SIZE + 9],
            payload[LEAF_SIZE + 9 :],
        ),
        context,
    )
    reader = hash_reader(io.BytesIO(payload), context, read_size=997)
    assert whole == split == reader
    assert verify_full(payload, whole)


def test_empty_tree_has_nonzero_distinct_roots() -> None:
    anchor = TreeWide.compute(tree_context(), ())
    assert anchor.message_length == 0
    assert len(set(anchor.roots)) == 4
    assert all(root != b"\x00" * 64 for root in anchor.roots)


def test_odd_tree_does_not_behave_like_duplicated_last_leaf() -> None:
    context = tree_context()
    three = TreeWide.compute(context, (b"a" * (3 * LEAF_SIZE),))
    four_with_duplicate = TreeWide.compute(
        context,
        (b"a" * (3 * LEAF_SIZE) + b"a" * LEAF_SIZE,),
    )
    assert three.roots != four_with_duplicate.roots
    assert three.message_length == 3 * LEAF_SIZE


def test_tree_frontier_storage_is_logarithmic() -> None:
    context = tree_context()
    engine = TreeWide(context)
    engine.update(b"x" * (33 * LEAF_SIZE))
    # 33 = 32 + 1: two frontier nodes per branch, not 33 retained leaves.
    assert engine.frontier_node_count == 8
    engine.finalize()


def test_tree_suite_rejects_noncanonical_leaf_size() -> None:
    with pytest.raises(ValueError, match="65536"):
        TreeWide(replace(simultaneous_v2_2(), chunk_size=4096))
