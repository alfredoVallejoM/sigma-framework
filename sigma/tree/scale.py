"""Resource-aware scale policies for Sigma Tree V1."""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum

from .delta import TreeDeltaIndex
from .model import DEFAULT_PROFILE
from .proofs import (
    InclusionProofV1,
    RangeProofV1,
    TreeProofIndex,
    prove_leaf_streaming,
    prove_range_streaming,
)

_SCALE_FIXED_OVERHEAD = 64 * 1024
_PROOF_INDEX_ESTIMATED_BYTES_PER_LEAF = 4_096
_DELTA_INDEX_ESTIMATED_BYTES_PER_LEAF = 4_608


class TreeIndexedOperationV1(Enum):
    PROOF = "proof"
    DELTA = "delta"


class TreeIndexModeV1(Enum):
    FULL = "full"
    STREAMING = "streaming"
    REJECT = "reject"


class TreeFallbackV1(Enum):
    STREAMING = "streaming"
    REJECT = "reject"


class TreeIndexBudgetExceeded(ValueError):
    """Raised when an operation requires an index forbidden by scale policy."""


@dataclass(frozen=True)
class TreeScalePolicyV1:
    max_index_bytes: int = 256 * 1024 * 1024
    proof_fallback: TreeFallbackV1 = TreeFallbackV1.STREAMING
    delta_fallback: TreeFallbackV1 = TreeFallbackV1.REJECT

    def __post_init__(self) -> None:
        if isinstance(self.max_index_bytes, bool) or not isinstance(self.max_index_bytes, int):
            raise TypeError("max_index_bytes must be int")
        if self.max_index_bytes < 0:
            raise ValueError("max_index_bytes must be non-negative")
        if not isinstance(self.proof_fallback, TreeFallbackV1):
            raise TypeError("proof_fallback must be TreeFallbackV1")
        if not isinstance(self.delta_fallback, TreeFallbackV1):
            raise TypeError("delta_fallback must be TreeFallbackV1")
        if self.delta_fallback is TreeFallbackV1.STREAMING:
            raise ValueError(
                "ST5 does not define streaming delta semantics; delta fallback must reject"
            )


@dataclass(frozen=True)
class TreeIndexPlanV1:
    operation: TreeIndexedOperationV1
    mode: TreeIndexModeV1
    source_bytes: int
    leaf_count: int
    estimated_index_bytes: int
    budget_bytes: int
    reason: str


@dataclass(frozen=True)
class ScaledProofResultV1:
    proof: InclusionProofV1 | RangeProofV1
    plan: TreeIndexPlanV1


def _leaf_count(byte_length: int) -> int:
    if byte_length == 0:
        return 0
    return (byte_length + DEFAULT_PROFILE.chunk_size - 1) // DEFAULT_PROFILE.chunk_size


def estimate_index_bytes(
    byte_length: int,
    operation: TreeIndexedOperationV1,
) -> int:
    """Conservative logical budget estimate, not a CPython RSS claim."""
    if isinstance(byte_length, bool) or not isinstance(byte_length, int):
        raise TypeError("byte_length must be int")
    if not 0 <= byte_length < 1 << 64:
        raise ValueError("byte_length outside Sigma Tree range")
    if not isinstance(operation, TreeIndexedOperationV1):
        raise TypeError("operation must be TreeIndexedOperationV1")

    leaves = _leaf_count(byte_length)
    if operation is TreeIndexedOperationV1.PROOF:
        # ProofIndex keeps the caller bytes plus zero-copy views, leaf summaries,
        # and canonical internal summaries. The caller-owned source is excluded.
        return _SCALE_FIXED_OVERHEAD + leaves * _PROOF_INDEX_ESTIMATED_BYTES_PER_LEAF

    # DeltaIndex intentionally owns mutable leaf payload copies in addition to
    # summaries. That B-sized cost is explicit and therefore budgeted.
    return (
        _SCALE_FIXED_OVERHEAD
        + byte_length
        + leaves * _DELTA_INDEX_ESTIMATED_BYTES_PER_LEAF
    )


def plan_tree_index(
    byte_length: int,
    operation: TreeIndexedOperationV1,
    policy: TreeScalePolicyV1 | None = None,
) -> TreeIndexPlanV1:
    if policy is None:
        policy = TreeScalePolicyV1()
    if not isinstance(policy, TreeScalePolicyV1):
        raise TypeError("policy must be TreeScalePolicyV1")
    estimated = estimate_index_bytes(byte_length, operation)
    leaves = _leaf_count(byte_length)

    if estimated <= policy.max_index_bytes:
        return TreeIndexPlanV1(
            operation,
            TreeIndexModeV1.FULL,
            byte_length,
            leaves,
            estimated,
            policy.max_index_bytes,
            "estimated full index fits policy budget",
        )

    fallback = (
        policy.proof_fallback
        if operation is TreeIndexedOperationV1.PROOF
        else policy.delta_fallback
    )
    if fallback is TreeFallbackV1.STREAMING:
        return TreeIndexPlanV1(
            operation,
            TreeIndexModeV1.STREAMING,
            byte_length,
            leaves,
            estimated,
            policy.max_index_bytes,
            "full index exceeds budget; streaming proof fallback selected",
        )

    return TreeIndexPlanV1(
        operation,
        TreeIndexModeV1.REJECT,
        byte_length,
        leaves,
        estimated,
        policy.max_index_bytes,
        "full index exceeds budget and operation has no permitted fallback",
    )


def prove_leaf_scaled(
    data: bytes,
    leaf_index: int,
    *,
    policy: TreeScalePolicyV1 | None = None,
) -> ScaledProofResultV1:
    if policy is None:
        policy = TreeScalePolicyV1()
    if not isinstance(data, bytes):
        raise TypeError("proof source must be bytes")
    plan = plan_tree_index(len(data), TreeIndexedOperationV1.PROOF, policy)
    if plan.mode is TreeIndexModeV1.FULL:
        proof = TreeProofIndex(data).prove_leaf(leaf_index)
    elif plan.mode is TreeIndexModeV1.STREAMING:
        proof = prove_leaf_streaming(data, leaf_index)
    else:
        raise TreeIndexBudgetExceeded(plan.reason)
    return ScaledProofResultV1(proof, plan)


def prove_range_scaled(
    data: bytes,
    start: int,
    length: int,
    *,
    policy: TreeScalePolicyV1 | None = None,
) -> ScaledProofResultV1:
    if policy is None:
        policy = TreeScalePolicyV1()
    if not isinstance(data, bytes):
        raise TypeError("proof source must be bytes")
    plan = plan_tree_index(len(data), TreeIndexedOperationV1.PROOF, policy)
    if plan.mode is TreeIndexModeV1.FULL:
        proof = TreeProofIndex(data).prove_range(start, length)
    elif plan.mode is TreeIndexModeV1.STREAMING:
        proof = prove_range_streaming(data, start, length)
    else:
        raise TreeIndexBudgetExceeded(plan.reason)
    return ScaledProofResultV1(proof, plan)


def delta_index_scaled(
    data: bytes,
    *,
    policy: TreeScalePolicyV1 | None = None,
) -> tuple[TreeDeltaIndex, TreeIndexPlanV1]:
    if policy is None:
        policy = TreeScalePolicyV1()
    if not isinstance(data, bytes):
        raise TypeError("delta source must be bytes")
    plan = plan_tree_index(len(data), TreeIndexedOperationV1.DELTA, policy)
    if plan.mode is not TreeIndexModeV1.FULL:
        raise TreeIndexBudgetExceeded(plan.reason)
    return TreeDeltaIndex(data), plan
