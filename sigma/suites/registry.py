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
    suite_family: str = "v2-1"
    evidence_version: int = 1
    stable: bool = False
    deprecated: bool = False

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
        if (
            self.anchor_profile in (AnchorProfileId.STREAM_WIDE, AnchorProfileId.CROSS_WIDE)
            and context.chunk_size != 0
        ):
            raise ValueError("stream-based suites require chunk_size=0")
        if self.anchor_profile is AnchorProfileId.TREE_WIDE and context.chunk_size != 65536:
            raise ValueError("TreeWide v2-1 requires chunk_size=65536")


REFERENCE_STREAM_WIDE_V2 = SuiteDescriptor(
    suite_id=SuiteId.REFERENCE_STREAM_WIDE_V2,
    name="reference-stream-wide-v2-1",
    anchor_profile=AnchorProfileId.STREAM_WIDE,
    round_profile=RoundProfileId.WIDE_ONCE,
    output_profile=OutputProfileId.MULTI_STATE,
    branches=(
        AlgorithmId.SHA512,
        AlgorithmId.SHA3_512,
        AlgorithmId.BLAKE2B_512,
        AlgorithmId.SHAKE256_512,
    ),
    state_algorithm=AlgorithmId.SHA3_512,
    state_size=64,
    stable=True,
)

PARANOID_CROSS_WIDE_V2 = SuiteDescriptor(
    suite_id=SuiteId.PARANOID_CROSS_WIDE_V2,
    name="paranoid-cross-wide-v2-1",
    anchor_profile=AnchorProfileId.CROSS_WIDE,
    round_profile=RoundProfileId.WIDE_ONCE,
    output_profile=OutputProfileId.MULTI_STATE,
    branches=REFERENCE_STREAM_WIDE_V2.branches,
    state_algorithm=AlgorithmId.SHA3_512,
    state_size=64,
    stable=True,
)

SIMULTANEOUS_TREE_WIDE_V2 = SuiteDescriptor(
    suite_id=SuiteId.SIMULTANEOUS_TREE_WIDE_V2,
    name="simultaneous-tree-wide-v2-1",
    anchor_profile=AnchorProfileId.TREE_WIDE,
    round_profile=RoundProfileId.WIDE_ONCE,
    output_profile=OutputProfileId.MULTI_STATE,
    branches=REFERENCE_STREAM_WIDE_V2.branches,
    state_algorithm=AlgorithmId.SHA3_512,
    state_size=64,
    stable=True,
)

LIGHTWEIGHT_STREAM_WIDE_V2 = SuiteDescriptor(
    suite_id=SuiteId.LIGHTWEIGHT_STREAM_WIDE_V2,
    name="lightweight-stream-wide-v2-1",
    anchor_profile=AnchorProfileId.STREAM_WIDE,
    round_profile=RoundProfileId.WIDE_ONCE,
    output_profile=OutputProfileId.MULTI_STATE,
    branches=(AlgorithmId.SHA512, AlgorithmId.SHA3_512),
    state_algorithm=AlgorithmId.SHA3_512,
    state_size=64,
    stable=True,
)

REALTIME_STREAM_WIDE_V2 = SuiteDescriptor(
    suite_id=SuiteId.REALTIME_STREAM_WIDE_V2,
    name="realtime-stream-wide-v2-1",
    anchor_profile=AnchorProfileId.STREAM_WIDE,
    round_profile=RoundProfileId.WIDE_ONCE,
    output_profile=OutputProfileId.MULTI_STATE,
    branches=(AlgorithmId.SHA512, AlgorithmId.SHA3_512),
    state_algorithm=AlgorithmId.SHA3_512,
    state_size=64,
    stable=True,
    deprecated=True,
)

PARANOID_DEEP_V2 = SuiteDescriptor(
    suite_id=SuiteId.PARANOID_DEEP_V2,
    name="paranoid-deep-v2-1",
    anchor_profile=AnchorProfileId.CROSS_WIDE,
    round_profile=RoundProfileId.DEEP,
    output_profile=OutputProfileId.MULTI_STATE,
    branches=REFERENCE_STREAM_WIDE_V2.branches,
    state_algorithm=AlgorithmId.SHA3_512,
    state_size=64,
    stable=True,
)

REFERENCE_STREAM_WIDE_V2_2 = SuiteDescriptor(
    suite_id=SuiteId.REFERENCE_STREAM_WIDE_V2_2,
    name="reference-stream-wide-v2-2",
    anchor_profile=AnchorProfileId.STREAM_WIDE,
    round_profile=RoundProfileId.WIDE_ONCE,
    output_profile=OutputProfileId.MULTI_STATE,
    branches=REFERENCE_STREAM_WIDE_V2.branches,
    state_algorithm=AlgorithmId.SHA3_512,
    state_size=64,
    evidence_version=2,
    suite_family="v2-2",
)

LIGHTWEIGHT_STREAM_WIDE_V2_2 = SuiteDescriptor(
    suite_id=SuiteId.LIGHTWEIGHT_STREAM_WIDE_V2_2,
    name="lightweight-stream-wide-v2-2",
    anchor_profile=AnchorProfileId.STREAM_WIDE,
    round_profile=RoundProfileId.WIDE_ONCE,
    output_profile=OutputProfileId.MULTI_STATE,
    branches=LIGHTWEIGHT_STREAM_WIDE_V2.branches,
    state_algorithm=AlgorithmId.SHA3_512,
    state_size=64,
    evidence_version=2,
    suite_family="v2-2",
)

SIMULTANEOUS_TREE_WIDE_V2_2 = SuiteDescriptor(
    suite_id=SuiteId.SIMULTANEOUS_TREE_WIDE_V2_2,
    name="simultaneous-tree-wide-v2-2",
    anchor_profile=AnchorProfileId.TREE_WIDE,
    round_profile=RoundProfileId.WIDE_ONCE,
    output_profile=OutputProfileId.MULTI_STATE,
    branches=SIMULTANEOUS_TREE_WIDE_V2.branches,
    state_algorithm=AlgorithmId.SHA3_512,
    state_size=64,
    evidence_version=2,
    suite_family="v2-2",
)

PARANOID_CROSS_WIDE_V2_2 = SuiteDescriptor(
    suite_id=SuiteId.PARANOID_CROSS_WIDE_V2_2,
    name="paranoid-cross-wide-v2-2",
    anchor_profile=AnchorProfileId.CROSS_WIDE,
    round_profile=RoundProfileId.WIDE_ONCE,
    output_profile=OutputProfileId.MULTI_STATE,
    branches=PARANOID_CROSS_WIDE_V2.branches,
    state_algorithm=AlgorithmId.SHA3_512,
    state_size=64,
    evidence_version=2,
    suite_family="v2-2",
)

PARANOID_DEEP_V2_2 = SuiteDescriptor(
    suite_id=SuiteId.PARANOID_DEEP_V2_2,
    name="paranoid-deep-v2-2",
    anchor_profile=AnchorProfileId.CROSS_WIDE,
    round_profile=RoundProfileId.DEEP,
    output_profile=OutputProfileId.MULTI_STATE,
    branches=PARANOID_DEEP_V2.branches,
    state_algorithm=AlgorithmId.SHA3_512,
    state_size=64,
    evidence_version=2,
    suite_family="v2-2",
)

PARANOID_DEEP_VECTOR_V2_2 = SuiteDescriptor(
    suite_id=SuiteId.PARANOID_DEEP_VECTOR_V2_2,
    name="paranoid-deep-vector-v2-2",
    anchor_profile=AnchorProfileId.CROSS_WIDE,
    round_profile=RoundProfileId.DEEP_VECTOR,
    output_profile=OutputProfileId.MULTI_STATE,
    branches=PARANOID_DEEP_V2.branches,
    state_algorithm=AlgorithmId.SHA3_512,
    state_size=64 * len(PARANOID_DEEP_V2.branches),
    evidence_version=2,
    suite_family="v2-2",
)

_SUITES: Dict[SuiteId, SuiteDescriptor] = {
    REFERENCE_STREAM_WIDE_V2.suite_id: REFERENCE_STREAM_WIDE_V2,
    PARANOID_CROSS_WIDE_V2.suite_id: PARANOID_CROSS_WIDE_V2,
    SIMULTANEOUS_TREE_WIDE_V2.suite_id: SIMULTANEOUS_TREE_WIDE_V2,
    LIGHTWEIGHT_STREAM_WIDE_V2.suite_id: LIGHTWEIGHT_STREAM_WIDE_V2,
    REALTIME_STREAM_WIDE_V2.suite_id: REALTIME_STREAM_WIDE_V2,
    PARANOID_DEEP_V2.suite_id: PARANOID_DEEP_V2,
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
