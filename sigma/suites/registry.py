"""Closed, versioned suite definitions.

A suite fixes the mathematical construction. Runtime execution choices never
appear here and therefore cannot alter its digest.
"""

from dataclasses import dataclass
from typing import Dict, Tuple

from sigma.spec.context import SigmaContextV2
from sigma.spec.ids import (
    AlgorithmId,
    AnchorProfileId,
    OutputProfileId,
    RoundProfileId,
    SuiteId,
)


@dataclass(frozen=True)
class SuiteDescriptor:
    suite_id: SuiteId
    name: str
    anchor_profile: AnchorProfileId
    round_profile: RoundProfileId
    output_profile: OutputProfileId
    branches: Tuple[AlgorithmId, ...]
    state_algorithm: AlgorithmId
    state_size: int
    anchor_component_size: int = 64
    tree_chunk_size: int = 0
    suite_family: str = "v2-2"
    evidence_version: int = 2
    wire_frozen: bool = False
    vectors_frozen: bool = False
    suite_stable: bool = False
    security_reviewed: bool = False
    deprecated: bool = False

    def __post_init__(self) -> None:
        if not self.branches or len(set(self.branches)) != len(self.branches):
            raise ValueError("suite branches must be non-empty and unique")
        if self.anchor_component_size <= 0 or self.state_size <= 0:
            raise ValueError("suite component and state sizes must be positive")
        if self.anchor_profile is AnchorProfileId.TREE_WIDE:
            if self.tree_chunk_size <= 0:
                raise ValueError("TreeWide suites require a positive tree chunk size")
        elif self.tree_chunk_size != 0:
            raise ValueError("non-tree suites must not define a tree chunk size")
        expected_state_size = (
            self.anchor_component_size * len(self.branches)
            if self.round_profile is RoundProfileId.DEEP_VECTOR
            else self.anchor_component_size
        )
        if self.state_size != expected_state_size:
            raise ValueError("suite state size does not match its round profile")

    def validate_context(self, context: SigmaContextV2) -> None:
        expected = {
            "suite_id": self.suite_id,
            "anchor_profile": self.anchor_profile,
            "round_profile": self.round_profile,
            "output_profile": self.output_profile,
            "branches": self.branches,
        }
        for field, value in expected.items():
            if getattr(context, field) != value:
                raise ValueError(f"context {field} does not match suite {self.name}")
        if context.chunk_size != self.tree_chunk_size:
            raise ValueError(
                f"context chunk_size must be {self.tree_chunk_size} for suite {self.name}"
            )


REFERENCE_BRANCHES = (
    AlgorithmId.SHA512,
    AlgorithmId.SHA3_512,
    AlgorithmId.BLAKE2B_512,
    AlgorithmId.SHAKE256_512,
)
LIGHTWEIGHT_BRANCHES = REFERENCE_BRANCHES[:2]

REFERENCE_STREAM_WIDE_V2_2 = SuiteDescriptor(
    suite_id=SuiteId.REFERENCE_STREAM_WIDE_V2_2,
    name="reference-stream-wide-v2-2",
    anchor_profile=AnchorProfileId.STREAM_WIDE,
    round_profile=RoundProfileId.WIDE_ONCE,
    output_profile=OutputProfileId.MULTI_STATE,
    branches=REFERENCE_BRANCHES,
    state_algorithm=AlgorithmId.SHA3_512,
    state_size=64,
    evidence_version=2,
    suite_family="v2-2",
    wire_frozen=True,
    vectors_frozen=True,
    suite_stable=True,
)

LIGHTWEIGHT_STREAM_WIDE_V2_2 = SuiteDescriptor(
    suite_id=SuiteId.LIGHTWEIGHT_STREAM_WIDE_V2_2,
    name="lightweight-stream-wide-v2-2",
    anchor_profile=AnchorProfileId.STREAM_WIDE,
    round_profile=RoundProfileId.WIDE_ONCE,
    output_profile=OutputProfileId.MULTI_STATE,
    branches=LIGHTWEIGHT_BRANCHES,
    state_algorithm=AlgorithmId.SHA3_512,
    state_size=64,
    evidence_version=2,
    suite_family="v2-2",
    wire_frozen=True,
    vectors_frozen=True,
    suite_stable=True,
)

SIMULTANEOUS_TREE_WIDE_V2_2 = SuiteDescriptor(
    suite_id=SuiteId.SIMULTANEOUS_TREE_WIDE_V2_2,
    name="simultaneous-tree-wide-v2-2",
    anchor_profile=AnchorProfileId.TREE_WIDE,
    round_profile=RoundProfileId.WIDE_ONCE,
    output_profile=OutputProfileId.MULTI_STATE,
    branches=REFERENCE_BRANCHES,
    state_algorithm=AlgorithmId.SHA3_512,
    state_size=64,
    tree_chunk_size=65_536,
    evidence_version=2,
    suite_family="v2-2",
    wire_frozen=True,
    vectors_frozen=True,
    suite_stable=True,
)

PARANOID_CROSS_WIDE_V2_2 = SuiteDescriptor(
    suite_id=SuiteId.PARANOID_CROSS_WIDE_V2_2,
    name="paranoid-cross-wide-v2-2",
    anchor_profile=AnchorProfileId.CROSS_WIDE,
    round_profile=RoundProfileId.WIDE_ONCE,
    output_profile=OutputProfileId.MULTI_STATE,
    branches=REFERENCE_BRANCHES,
    state_algorithm=AlgorithmId.SHA3_512,
    state_size=64,
    evidence_version=2,
    suite_family="v2-2",
    wire_frozen=True,
    vectors_frozen=True,
    suite_stable=True,
)

PARANOID_DEEP_V2_2 = SuiteDescriptor(
    suite_id=SuiteId.PARANOID_DEEP_V2_2,
    name="paranoid-deep-v2-2",
    anchor_profile=AnchorProfileId.CROSS_WIDE,
    round_profile=RoundProfileId.DEEP,
    output_profile=OutputProfileId.MULTI_STATE,
    branches=REFERENCE_BRANCHES,
    state_algorithm=AlgorithmId.SHA3_512,
    state_size=64,
    evidence_version=2,
    suite_family="v2-2",
    wire_frozen=True,
    vectors_frozen=True,
    suite_stable=True,
)

PARANOID_DEEP_VECTOR_V2_2 = SuiteDescriptor(
    suite_id=SuiteId.PARANOID_DEEP_VECTOR_V2_2,
    name="paranoid-deep-vector-v2-2",
    anchor_profile=AnchorProfileId.CROSS_WIDE,
    round_profile=RoundProfileId.DEEP_VECTOR,
    output_profile=OutputProfileId.MULTI_STATE,
    branches=REFERENCE_BRANCHES,
    state_algorithm=AlgorithmId.SHA3_512,
    state_size=64 * len(REFERENCE_BRANCHES),
    evidence_version=2,
    suite_family="v2-2",
    wire_frozen=True,
    vectors_frozen=True,
    suite_stable=True,
)

_SUITES: Dict[SuiteId, SuiteDescriptor] = {
    REFERENCE_STREAM_WIDE_V2_2.suite_id: REFERENCE_STREAM_WIDE_V2_2,
    LIGHTWEIGHT_STREAM_WIDE_V2_2.suite_id: LIGHTWEIGHT_STREAM_WIDE_V2_2,
    SIMULTANEOUS_TREE_WIDE_V2_2.suite_id: SIMULTANEOUS_TREE_WIDE_V2_2,
    PARANOID_CROSS_WIDE_V2_2.suite_id: PARANOID_CROSS_WIDE_V2_2,
    PARANOID_DEEP_V2_2.suite_id: PARANOID_DEEP_V2_2,
    PARANOID_DEEP_VECTOR_V2_2.suite_id: PARANOID_DEEP_VECTOR_V2_2,
}


def get_suite(suite_id: SuiteId) -> SuiteDescriptor:
    try:
        return _SUITES[suite_id]
    except KeyError as exc:
        raise ValueError(f"unsupported suite: {suite_id!r}") from exc
