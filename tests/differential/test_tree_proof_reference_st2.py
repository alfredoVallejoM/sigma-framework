from __future__ import annotations

import random

from reference.tree_proof_v1 import verify_inclusion_wire, verify_range_wire
from sigma.tree import TreeProofIndex, verify_inclusion, verify_range


def test_independent_inclusion_verifier_matches_product():
    rng = random.Random(0x535432494E434C)
    for _ in range(250):
        size = rng.randrange(1, 10 * 65_536 + 257)
        data = rng.randbytes(size)
        index = TreeProofIndex(data)
        target = rng.randrange(index.root.leaf_count)
        start = target * 65_536
        end = min(start + 65_536, size)
        raw = data[start:end]
        proof = index.prove_leaf(target)
        assert verify_inclusion(raw, proof)
        assert verify_inclusion_wire(raw, proof.to_bytes())


def test_independent_range_verifier_matches_product():
    rng = random.Random(0x53543252414E47)
    for _ in range(250):
        size = rng.randrange(1, 10 * 65_536 + 257)
        data = rng.randbytes(size)
        index = TreeProofIndex(data)
        start = rng.randrange(size)
        length = rng.randrange(1, size - start + 1)
        raw = data[start : start + length]
        proof = index.prove_range(start, length)
        assert verify_range(raw, proof)
        assert verify_range_wire(raw, proof.to_bytes())


def test_independent_verifiers_reject_corrupted_payloads():
    data = b"A" * (3 * 65_536) + b"tail"
    index = TreeProofIndex(data)

    inclusion = index.prove_leaf(1)
    leaf = bytearray(data[65_536 : 2 * 65_536])
    leaf[17] ^= 1
    assert not verify_inclusion_wire(bytes(leaf), inclusion.to_bytes())

    start, length = 65_536 - 5, 65_536 + 17
    range_proof = index.prove_range(start, length)
    target = bytearray(data[start : start + length])
    target[-1] ^= 1
    assert not verify_range_wire(bytes(target), range_proof.to_bytes())
