from __future__ import annotations

import random

from reference.tree_checkpoint_v1 import checkpoint_wire as reference_checkpoint_wire
from reference.tree_checkpoint_v1 import resume_checkpoint_wire
from reference.tree_v1 import root_wire as reference_root_wire
from sigma.tree import checkpoint_bytes, resume_tree


def test_independent_checkpoint_wire_matches_product():
    rng = random.Random(0x53543343484B50)
    sizes = [
        0,
        1,
        65_535,
        65_536,
        65_537,
        2 * 65_536,
        3 * 65_536 + 19,
    ]
    sizes += [rng.randrange(0, 5 * 65_536 + 257) for _ in range(128)]

    for size in sizes:
        prefix = rng.randbytes(size)
        product = checkpoint_bytes(prefix).to_bytes()
        assert product == reference_checkpoint_wire(prefix)


def test_independent_resume_matches_product_and_direct():
    rng = random.Random(0x53543352455355)
    for _ in range(250):
        size = rng.randrange(0, 5 * 65_536 + 257)
        data = rng.randbytes(size)
        split = rng.randrange(size + 1)
        checkpoint = checkpoint_bytes(data[:split])
        product_root = resume_tree(checkpoint, data[split:]).to_bytes()
        reference_root = resume_checkpoint_wire(checkpoint.to_bytes(), data[split:])
        direct_root = reference_root_wire(data)
        assert product_root == reference_root == direct_root
