from __future__ import annotations

import tracemalloc

import pytest

from reference.tree_proof_v1 import verify_inclusion_wire, verify_range_wire
from reference.tree_v1 import root_wire as reference_root_wire
from sigma.tree import (
    TreeFallbackV1,
    TreeIndexBudgetExceeded,
    TreeIndexedOperationV1,
    TreeIndexModeV1,
    TreeProofIndex,
    TreeScalePolicyV1,
    build_tree,
    delta_index_scaled,
    estimate_index_bytes,
    plan_tree_index,
    prove_leaf_scaled,
    prove_leaf_streaming,
    prove_range_scaled,
    prove_range_streaming,
)


def test_optimized_build_preserves_reference_wire():
    sizes = (0, 1, 65_535, 65_536, 65_537, 3 * 65_536 + 19)
    for size in sizes:
        data = bytes((i * 17 + 3) % 251 for i in range(size))
        assert build_tree(data).to_bytes() == reference_root_wire(data)


def test_proof_index_retains_zero_copy_leaf_views():
    data = bytes((i * 13 + 7) % 251 for i in range(4 * 65_536 + 19))
    index = TreeProofIndex(data)
    assert index._leaves
    assert all(isinstance(leaf, memoryview) for leaf in index._leaves)
    assert all(leaf.obj is data for leaf in index._leaves)


def test_streaming_inclusion_is_byte_identical_to_full_index():
    data = bytes((i * 29 + 5) % 251 for i in range(9 * 65_536 + 17))
    index = TreeProofIndex(data)
    for leaf_index in (0, 1, 4, 8, 9):
        full = index.prove_leaf(leaf_index)
        streaming = prove_leaf_streaming(data, leaf_index)
        assert streaming.to_bytes() == full.to_bytes()
        start = leaf_index * 65_536
        leaf = data[start : min(start + 65_536, len(data))]
        assert verify_inclusion_wire(leaf, streaming.to_bytes())


def test_streaming_range_is_byte_identical_to_full_index():
    data = bytes((i * 31 + 11) % 251 for i in range(7 * 65_536 + 23))
    index = TreeProofIndex(data)
    for start, length in (
        (0, 1),
        (65_535, 3),
        (65_536 + 7, 77),
        (2 * 65_536 - 9, 2 * 65_536 + 17),
        (0, len(data)),
    ):
        full = index.prove_range(start, length)
        streaming = prove_range_streaming(data, start, length)
        assert streaming.to_bytes() == full.to_bytes()
        assert verify_range_wire(data[start : start + length], streaming.to_bytes())


def test_scale_policy_selects_full_streaming_and_reject_explicitly():
    size = 4 * 65_536
    generous = TreeScalePolicyV1(max_index_bytes=1 << 30)
    tiny = TreeScalePolicyV1(max_index_bytes=1)

    assert plan_tree_index(
        size, TreeIndexedOperationV1.PROOF, generous
    ).mode is TreeIndexModeV1.FULL
    assert plan_tree_index(
        size, TreeIndexedOperationV1.PROOF, tiny
    ).mode is TreeIndexModeV1.STREAMING
    assert plan_tree_index(
        size, TreeIndexedOperationV1.DELTA, tiny
    ).mode is TreeIndexModeV1.REJECT


def test_scaled_proof_fallback_preserves_exact_wire():
    data = bytes((i * 7 + 19) % 251 for i in range(5 * 65_536 + 19))
    full_policy = TreeScalePolicyV1(max_index_bytes=1 << 30)
    streaming_policy = TreeScalePolicyV1(max_index_bytes=1)

    full = prove_leaf_scaled(data, 3, policy=full_policy)
    fallback = prove_leaf_scaled(data, 3, policy=streaming_policy)
    assert full.plan.mode is TreeIndexModeV1.FULL
    assert fallback.plan.mode is TreeIndexModeV1.STREAMING
    assert full.proof.to_bytes() == fallback.proof.to_bytes()

    full_range = prove_range_scaled(data, 65_535, 4097, policy=full_policy)
    fallback_range = prove_range_scaled(
        data, 65_535, 4097, policy=streaming_policy
    )
    assert full_range.proof.to_bytes() == fallback_range.proof.to_bytes()


def test_proof_policy_can_reject_instead_of_fallback():
    data = b"x" * 65_536
    policy = TreeScalePolicyV1(
        max_index_bytes=0,
        proof_fallback=TreeFallbackV1.REJECT,
    )
    with pytest.raises(TreeIndexBudgetExceeded):
        prove_leaf_scaled(data, 0, policy=policy)


def test_delta_budget_rejects_before_index_construction(monkeypatch):
    import sigma.tree.scale as scale_module

    built = False

    class BombIndex:
        def __init__(self, *args, **kwargs):
            nonlocal built
            built = True
            raise AssertionError("TreeDeltaIndex should not be constructed")

    monkeypatch.setattr(scale_module, "TreeDeltaIndex", BombIndex)
    policy = TreeScalePolicyV1(max_index_bytes=1)
    with pytest.raises(TreeIndexBudgetExceeded):
        scale_module.delta_index_scaled(b"x" * (2 * 65_536), policy=policy)
    assert not built


def test_index_estimator_is_monotone_and_delta_accounts_for_payload_copy():
    small_proof = estimate_index_bytes(
        65_536, TreeIndexedOperationV1.PROOF
    )
    large_proof = estimate_index_bytes(
        4 * 65_536, TreeIndexedOperationV1.PROOF
    )
    delta = estimate_index_bytes(
        4 * 65_536, TreeIndexedOperationV1.DELTA
    )
    assert large_proof > small_proof
    assert delta > large_proof
    assert delta >= 4 * 65_536


def test_zero_copy_proof_index_has_no_second_payload_sized_allocation():
    data = bytes((i * 5 + 1) % 251 for i in range(8 * 65_536))
    tracemalloc.start()
    index = TreeProofIndex(data)
    _, peak = tracemalloc.get_traced_memory()
    tracemalloc.stop()
    assert index.root == build_tree(data)
    # The old ST2 layout duplicated essentially all B in leaf byte slices.
    # The optimized layout should stay well below another full B allocation.
    assert peak < len(data) // 2
