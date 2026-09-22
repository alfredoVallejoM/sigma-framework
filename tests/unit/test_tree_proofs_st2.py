from __future__ import annotations

from dataclasses import replace

import pytest

from sigma.tree import (
    DEFAULT_PROFILE,
    InclusionProofV1,
    InclusionStepV1,
    ProofSide,
    RangeProofV1,
    TreeProofIndex,
    build_tree,
    prove_leaf,
    prove_range,
    verify_inclusion,
    verify_range,
)
from sigma.tree.ids import TreeProfileId
from sigma.tree.model import TreeProfileV1


def _data(leaves: int, tail: int = 0) -> bytes:
    base = bytes((i * 17 + 3) % 251 for i in range(65_536))
    return base * leaves + bytes((i * 29 + 7) % 251 for i in range(tail))


@pytest.mark.parametrize("leaf_count", [1, 2, 3, 4, 5, 7, 8, 9, 15, 16, 17])
def test_inclusion_roundtrip_for_power_boundaries(leaf_count):
    data = _data(leaf_count)
    index = TreeProofIndex(data)
    for target in {0, leaf_count // 2, leaf_count - 1}:
        proof = index.prove_leaf(target)
        raw = data[target * 65_536 : (target + 1) * 65_536]
        assert verify_inclusion(raw, proof)
        assert InclusionProofV1.from_bytes(proof.to_bytes()) == proof


def test_inclusion_final_short_leaf_roundtrip():
    data = _data(3, 19)
    proof = prove_leaf(data, 3)
    assert proof.leaf_byte_length == 19
    assert verify_inclusion(data[3 * 65_536 :], proof)


def test_inclusion_wrong_leaf_rejects():
    data = _data(3)
    proof = prove_leaf(data, 1)
    leaf = bytearray(data[65_536 : 2 * 65_536])
    leaf[-1] ^= 1
    assert not verify_inclusion(bytes(leaf), proof)


def test_inclusion_position_is_bound():
    data = _data(5)
    proof = prove_leaf(data, 2)
    with pytest.raises(ValueError):
        replace(proof, leaf_index=3)


def test_inclusion_orientation_is_bound():
    data = _data(7)
    proof = prove_leaf(data, 3)
    assert proof.steps
    first = proof.steps[0]
    flipped = ProofSide.LEFT if first.side is ProofSide.RIGHT else ProofSide.RIGHT
    with pytest.raises(ValueError, match="orientation"):
        replace(proof, steps=(InclusionStepV1(flipped, first.sibling), *proof.steps[1:]))


def test_inclusion_sibling_geometry_is_bound():
    data = _data(5)
    proof = prove_leaf(data, 1)
    step = proof.steps[-1]
    sibling = replace(step.sibling, byte_length=step.sibling.byte_length - 1)
    with pytest.raises(ValueError):
        replace(proof, steps=(*proof.steps[:-1], InclusionStepV1(step.side, sibling)))


def test_inclusion_root_length_and_count_are_bound():
    data = _data(3)
    proof = prove_leaf(data, 0)
    with pytest.raises(ValueError):
        replace(proof, root=replace(proof.root, byte_length=proof.root.byte_length - 1))


def test_inclusion_profile_is_bound():
    data = _data(2)
    proof = prove_leaf(data, 0)
    # TreeProfileV1 admits only the frozen profile, so a cross-profile alias cannot
    # be constructed or decoded.
    with pytest.raises(ValueError):
        TreeProfileV1(profile_id=TreeProfileId(2))
    assert proof.profile == DEFAULT_PROFILE


@pytest.mark.parametrize(
    "start,length",
    [
        (0, 1),
        (65_535, 1),
        (65_536, 65_536),
        (65_535, 2),
        (65_536 + 7, 77),
        (2 * 65_536 - 3, 10),
    ],
)
def test_range_boundary_cases(start, length):
    data = _data(4, 23)
    proof = prove_range(data, start, length)
    assert verify_range(data[start : start + length], proof)
    assert RangeProofV1.from_bytes(proof.to_bytes()) == proof


def test_range_full_object():
    data = _data(5, 31)
    proof = prove_range(data, 0, len(data))
    assert proof.prefix == b""
    assert proof.suffix == b""
    assert proof.witnesses == ()
    assert verify_range(data, proof)


def test_range_exact_interval_is_bound():
    data = _data(3)
    proof = prove_range(data, 10, 100)
    assert verify_range(data[10:110], proof)
    assert not verify_range(data[11:111], proof)
    with pytest.raises(ValueError):
        replace(proof, start=11)


def test_range_edge_complements_are_exact():
    data = _data(2, 13)
    proof = prove_range(data, 17, 65_536 + 9)
    assert proof.prefix == data[:17]
    end = 17 + 65_536 + 9
    last_leaf_start = (end - 1) // 65_536 * 65_536
    last_leaf_end = min(last_leaf_start + 65_536, len(data))
    assert proof.suffix == data[end:last_leaf_end]
    assert verify_range(data[17:end], proof)


def test_range_prefix_or_suffix_corruption_rejects():
    data = _data(3)
    proof = prove_range(data, 7, 65_536 + 9)
    prefix = bytearray(proof.prefix)
    prefix[0] ^= 1
    assert not verify_range(data[7 : 7 + 65_536 + 9], replace(proof, prefix=bytes(prefix)))


def test_range_witness_from_other_tree_rejects():
    data_a = _data(5)
    data_b = bytearray(data_a)
    data_b[4 * 65_536 + 10] ^= 1
    proof_a = prove_range(data_a, 65_536 + 3, 100)
    proof_b = prove_range(bytes(data_b), 65_536 + 3, 100)
    assert proof_a.witnesses and proof_b.witnesses
    mixed = replace(proof_a, witnesses=proof_b.witnesses)
    assert not verify_range(data_a[65_536 + 3 : 65_536 + 103], mixed)


@pytest.mark.parametrize(
    "start,length",
    [
        (0, 0),
        (-1, 1),
        (1 << 64, 1),
        (0, 1 << 64),
        (10, (1 << 64) - 5),
    ],
)
def test_range_invalid_bounds_reject_before_hash(monkeypatch, start, length):
    import sigma.tree.proofs as proofs_module

    root = build_tree(b"abc")
    called = False

    def bomb(*args, **kwargs):
        nonlocal called
        called = True
        raise AssertionError("hashing reached")

    monkeypatch.setattr(proofs_module, "leaf_node", bomb)
    with pytest.raises((TypeError, ValueError)):
        RangeProofV1(DEFAULT_PROFILE, root, start, length)
    assert not called


def test_range_verification_uses_no_source_io(monkeypatch):
    import builtins

    data = _data(3, 19)
    start, length = 65_536 - 8, 65_536 + 33
    proof = prove_range(data, start, length)

    def no_open(*args, **kwargs):
        raise AssertionError("range verification attempted source I/O")

    monkeypatch.setattr(builtins, "open", no_open)
    assert verify_range(data[start : start + length], proof)


def test_one_shot_prove_range_rejects_before_index_build(monkeypatch):
    import sigma.tree.proofs as proofs_module

    built = False

    class BombIndex:
        def __init__(self, *args, **kwargs):
            nonlocal built
            built = True
            raise AssertionError("TreeProofIndex constructed")

    monkeypatch.setattr(proofs_module, "TreeProofIndex", BombIndex)
    with pytest.raises(ValueError, match="source byte bounds"):
        proofs_module.prove_range(b"abc", 3, 1)
    assert not built
