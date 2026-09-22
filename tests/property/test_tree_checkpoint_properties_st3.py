from __future__ import annotations

import random

from sigma.tree import (
    TreeBuilder,
    TreeResumeCheckpointV1,
    build_tree,
    checkpoint_builder,
    checkpoint_bytes,
    restore_builder,
    resume_tree,
)


def test_random_prefix_suffix_resume_equivalence():
    rng = random.Random(0x53543350524F50)
    for _ in range(500):
        size = rng.randrange(0, 5 * 65_536 + 257)
        data = rng.randbytes(size)
        split = rng.randrange(size + 1)
        checkpoint = checkpoint_bytes(data[:split])
        assert resume_tree(checkpoint, data[split:]) == build_tree(data)


def test_random_checkpoint_wire_roundtrip():
    rng = random.Random(0x53543357495245)
    for _ in range(500):
        size = rng.randrange(0, 5 * 65_536 + 257)
        prefix = rng.randbytes(size)
        checkpoint = checkpoint_bytes(prefix)
        assert TreeResumeCheckpointV1.from_bytes(checkpoint.to_bytes()) == checkpoint


def test_random_repeated_resume_cycles():
    rng = random.Random(0x5354334359434C45)
    for _ in range(200):
        size = rng.randrange(0, 4 * 65_536 + 513)
        data = rng.randbytes(size)
        cuts = sorted({0, size, *(rng.randrange(size + 1) for _ in range(6))})

        builder = TreeBuilder()
        checkpoint = checkpoint_builder(builder)
        position = 0
        for cut in cuts[1:]:
            builder = restore_builder(checkpoint)
            builder.update(data[position:cut])
            checkpoint = checkpoint_builder(builder)
            position = cut
        assert resume_tree(checkpoint, data[position:]) == build_tree(data)


def test_checkpoint_frontier_is_always_full_and_tail_bounded():
    rng = random.Random(0x53543346524E54)
    builder = TreeBuilder()
    data = rng.randbytes(8 * 65_536 + 999)
    position = 0
    while position < len(data):
        width = rng.randrange(1, 100_001)
        builder.update(data[position : position + width])
        position += width
        checkpoint = checkpoint_builder(builder)
        assert checkpoint.frontier.byte_length == checkpoint.completed_leaf_count * 65_536
        assert len(checkpoint.tail) < 65_536
        assert checkpoint.completed_bytes == checkpoint.frontier.byte_length + len(checkpoint.tail)
