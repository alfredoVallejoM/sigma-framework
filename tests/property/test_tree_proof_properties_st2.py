from __future__ import annotations

import random

from sigma.tree import (
    DEFAULT_PROFILE,
    TreeProofIndex,
    TreeRoot,
    inclusion_geometry,
    range_witness_geometry,
    verify_inclusion,
    verify_range,
)


def _dummy_root(leaf_count: int) -> TreeRoot:
    digests = (b"d" * 64,) * 4
    return TreeRoot(
        DEFAULT_PROFILE,
        leaf_count * DEFAULT_PROFILE.chunk_size,
        leaf_count,
        digests,
    )


def _independent_cover(
    leaf_count: int,
    first: int,
    last_exclusive: int,
) -> tuple[tuple[int, int], ...]:
    out: list[tuple[int, int]] = []

    def visit(start: int, count: int) -> None:
        end = start + count
        if end <= first or start >= last_exclusive:
            out.append((start, count))
            return
        if count == 1:
            return
        left = 1 << ((count - 1).bit_length() - 1)
        visit(start, left)
        visit(start + left, count - left)

    visit(0, leaf_count)
    return tuple(out)


def test_range_witness_cover_exhaustive_small_trees():
    for leaf_count in range(1, 65):
        root = _dummy_root(leaf_count)
        for first in range(leaf_count):
            for last in range(first + 1, leaf_count + 1):
                got = range_witness_geometry(root, first, last)
                assert tuple((start, count) for start, count, _ in got) == _independent_cover(
                    leaf_count, first, last
                )

                covered = set(range(first, last))
                for start, count, _ in got:
                    witness = set(range(start, start + count))
                    assert not (witness & covered)
                    covered |= witness
                assert covered == set(range(leaf_count))


def test_inclusion_geometry_has_logarithmic_depth():
    for leaf_count in range(1, 513):
        root = _dummy_root(leaf_count)
        for target in {0, leaf_count // 2, leaf_count - 1}:
            geometry = inclusion_geometry(root, target)
            assert len(geometry) <= leaf_count.bit_length()
            for _, start, count, byte_length in geometry:
                assert count > 0
                assert byte_length == count * DEFAULT_PROFILE.chunk_size
                assert 0 <= start < leaf_count
                assert start + count <= leaf_count


def test_random_inclusion_and_range_properties():
    rng = random.Random(0x53543250524F50)
    for _ in range(100):
        size = rng.randrange(1, 12 * 65_536 + 257)
        data = rng.randbytes(size)
        index = TreeProofIndex(data)

        leaf_index = rng.randrange(index.root.leaf_count)
        leaf_start = leaf_index * DEFAULT_PROFILE.chunk_size
        leaf_end = min(leaf_start + DEFAULT_PROFILE.chunk_size, size)
        proof = index.prove_leaf(leaf_index)
        assert verify_inclusion(data[leaf_start:leaf_end], proof)

        start = rng.randrange(size)
        length = rng.randrange(1, size - start + 1)
        range_proof = index.prove_range(start, length)
        assert verify_range(data[start : start + length], range_proof)


def test_range_witness_count_is_two_boundary_paths_scale():
    for leaf_count in (2, 3, 4, 7, 8, 15, 16, 31, 32, 63, 64, 127, 128, 255):
        root = _dummy_root(leaf_count)
        for first, last in ((0, 1), (leaf_count - 1, leaf_count), (leaf_count // 3, 2 * leaf_count // 3 or 1)):
            if not first < last:
                continue
            witnesses = range_witness_geometry(root, first, last)
            assert len(witnesses) <= 2 * leaf_count.bit_length()
