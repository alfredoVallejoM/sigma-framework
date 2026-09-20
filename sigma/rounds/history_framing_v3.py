"""Canonical history-feedback frame builders for Sigma v3 R12.5."""

from __future__ import annotations

from dataclasses import dataclass

from sigma.binding import RoundBindingV3, derive_length_signature_v3
from sigma.layout import (
    HistoryLayoutPlan,
    derive_history_layout_v3,
    iter_placed_round_binding_v3,
)
from sigma.spec.codec_v3 import encode_bytes_sequence
from sigma.spec.context_v3 import SigmaContextV3
from sigma.spec.encoding import encode_uint
from sigma.spec.ids import AlgorithmId
from sigma.spec.ids_v3 import (
    ALGORITHM_OUTPUT_SIZE_V3,
    DomainIdV3,
    RoundProfileIdV3,
    TrajectoryProfileIdV3,
)
from sigma.spec.transcript import encode_transcript


def _validate_context_binding(context: SigmaContextV3, binding: RoundBindingV3) -> None:
    if not isinstance(context, SigmaContextV3):
        raise TypeError("context must be SigmaContextV3")
    if context.trajectory_profile is not TrajectoryProfileIdV3.HISTORY_FEEDBACK:
        raise ValueError("context does not use history feedback")
    if not isinstance(binding, RoundBindingV3):
        raise TypeError("binding must be RoundBindingV3")
    if binding.persistent.anchor.suite_id != context.suite_id:
        raise ValueError("round binding and context suites differ")
    if binding.persistent.length_signature != derive_length_signature_v3(
        context, binding.persistent.cardinality
    ):
        raise ValueError("round binding length signature does not match context")


def _validate_index(index: int) -> None:
    if isinstance(index, bool) or not isinstance(index, int):
        raise TypeError("round_index must be int")
    if not 0 <= index <= (1 << 64) - 1:
        raise ValueError("round_index is out of range")


def _validate_layout(
    context: SigmaContextV3,
    binding: RoundBindingV3,
    layout: HistoryLayoutPlan,
    *,
    round_index: int,
    base_length: int,
) -> None:
    expected = derive_history_layout_v3(
        context,
        binding,
        round_index=round_index,
        base_length=base_length,
    )
    if layout != expected:
        raise ValueError("history layout is not canonical for round binding")


@dataclass(frozen=True)
class HistoryRoundFrame:
    context: SigmaContextV3
    binding: RoundBindingV3
    layout: HistoryLayoutPlan
    round_index: int
    state: bytes

    def __post_init__(self) -> None:
        _validate_context_binding(self.context, self.binding)
        _validate_index(self.round_index)
        if self.binding.history.round_index != self.round_index:
            raise ValueError("history and frame round indices differ")
        if not isinstance(self.state, bytes):
            raise TypeError("state must be bytes")
        if len(self.state) != self.context.state_size:
            raise ValueError("state size does not match context")
        if self.layout.base_length != len(self.state):
            raise ValueError("layout length does not match state")
        _validate_layout(
            self.context,
            self.binding,
            self.layout,
            round_index=self.round_index,
            base_length=len(self.state),
        )

    def to_bytes(self) -> bytes:
        placed = b"".join(iter_placed_round_binding_v3((self.state,), self.binding, self.layout))
        return encode_transcript(
            DomainIdV3.HISTORY_ROUND_FRAME,
            (
                (1, self.context.to_bytes()),
                (2, encode_uint(self.round_index, 8)),
                (3, self.layout.to_bytes()),
                (4, placed),
            ),
        )


@dataclass(frozen=True)
class HistoryVectorRoundFrame:
    context: SigmaContextV3
    binding: RoundBindingV3
    layout: HistoryLayoutPlan
    round_index: int
    vector: bytes

    def __post_init__(self) -> None:
        _validate_context_binding(self.context, self.binding)
        _validate_index(self.round_index)
        if self.binding.history.round_index != self.round_index:
            raise ValueError("history and frame round indices differ")
        if not isinstance(self.vector, bytes) or not self.vector:
            raise ValueError("vector must be non-empty bytes")
        expected = len(self.context.joint_algorithms) * ALGORITHM_OUTPUT_SIZE_V3
        if len(self.vector) != expected:
            raise ValueError("vector width does not match joint algorithms")
        if self.layout.base_length != len(self.vector):
            raise ValueError("layout length does not match vector")
        _validate_layout(
            self.context,
            self.binding,
            self.layout,
            round_index=self.round_index,
            base_length=len(self.vector),
        )

    def to_bytes(self) -> bytes:
        placed = b"".join(iter_placed_round_binding_v3((self.vector,), self.binding, self.layout))
        return encode_transcript(
            DomainIdV3.HISTORY_VECTOR_ROUND_FRAME,
            (
                (1, self.context.to_bytes()),
                (2, encode_uint(self.round_index, 8)),
                (3, self.layout.to_bytes()),
                (4, placed),
            ),
        )


HistoryStateFrameV3 = HistoryRoundFrame | HistoryVectorRoundFrame


@dataclass(frozen=True)
class HistoryDeepBranchFrame:
    context: SigmaContextV3
    round_index: int
    branch_index: int
    algorithm: AlgorithmId
    state_frame: HistoryStateFrameV3

    def __post_init__(self) -> None:
        if not isinstance(self.context, SigmaContextV3):
            raise TypeError("context must be SigmaContextV3")
        _validate_index(self.round_index)
        if isinstance(self.branch_index, bool) or not isinstance(self.branch_index, int):
            raise TypeError("branch_index must be int")
        if not 0 <= self.branch_index < len(self.context.joint_algorithms):
            raise ValueError("branch_index is out of range")
        if not isinstance(self.algorithm, AlgorithmId):
            raise TypeError("algorithm must be AlgorithmId")
        if self.context.joint_algorithms[self.branch_index] is not self.algorithm:
            raise ValueError("branch algorithm does not match context")
        expected_type = (
            HistoryRoundFrame
            if self.context.round_profile is RoundProfileIdV3.DEEP
            else HistoryVectorRoundFrame
        )
        if self.context.round_profile not in (
            RoundProfileIdV3.DEEP,
            RoundProfileIdV3.DEEP_VECTOR,
        ):
            raise ValueError("history branch frame requires a Deep profile")
        if not isinstance(self.state_frame, expected_type):
            raise TypeError(f"state_frame must be {expected_type.__name__}")
        if self.state_frame.context != self.context:
            raise ValueError("state frame context differs from branch context")
        if self.state_frame.round_index != self.round_index:
            raise ValueError("state frame round differs from branch round")

    def to_bytes(self) -> bytes:
        return encode_transcript(
            DomainIdV3.HISTORY_DEEP_BRANCH_FRAME,
            (
                (1, self.context.to_bytes()),
                (2, encode_uint(self.round_index, 8)),
                (3, encode_uint(self.branch_index, 2)),
                (4, encode_uint(self.algorithm, 2)),
                (5, self.state_frame.to_bytes()),
            ),
        )


@dataclass(frozen=True)
class HistoryDeepFoldFrame:
    context: SigmaContextV3
    round_index: int
    branches: tuple[bytes, ...]

    def __post_init__(self) -> None:
        if not isinstance(self.context, SigmaContextV3):
            raise TypeError("context must be SigmaContextV3")
        if self.context.round_profile is not RoundProfileIdV3.DEEP:
            raise ValueError("history fold frame requires Deep scalar profile")
        _validate_index(self.round_index)
        if not isinstance(self.branches, tuple):
            raise TypeError("branches must be tuple")
        if len(self.branches) != len(self.context.joint_algorithms):
            raise ValueError("branches must match joint algorithms")
        if any(
            not isinstance(value, bytes) or len(value) != ALGORITHM_OUTPUT_SIZE_V3
            for value in self.branches
        ):
            raise ValueError("branch width does not match algorithm output size")

    def to_bytes(self) -> bytes:
        return encode_transcript(
            DomainIdV3.HISTORY_DEEP_FOLD,
            (
                (1, self.context.to_bytes()),
                (2, encode_uint(self.round_index, 8)),
                (3, encode_bytes_sequence(self.branches)),
            ),
        )


__all__ = [
    "HistoryDeepBranchFrame",
    "HistoryDeepFoldFrame",
    "HistoryRoundFrame",
    "HistoryStateFrameV3",
    "HistoryVectorRoundFrame",
]
