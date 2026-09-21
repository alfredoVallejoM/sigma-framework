"""Causal history commitments and effective round bindings for Sigma v3 R12.5."""

from __future__ import annotations

from dataclasses import dataclass
from enum import IntEnum

from sigma.binding.types import MAX_U64, PersistentBinding
from sigma.crypto.primitives import hash_bytes
from sigma.spec.codec_v3 import decode_record, encode_record
from sigma.spec.context_v3 import SigmaContextV3
from sigma.spec.encoding import DecodeError, decode_uint, encode_uint
from sigma.spec.ids import AlgorithmId
from sigma.spec.ids_v3 import (
    ALGORITHM_OUTPUT_SIZE_V3,
    DomainIdV3,
    TrajectoryProfileIdV3,
)
from sigma.spec.transcript import encode_transcript

_HISTORY_MAGIC = b"SIG3HIST"
_ROUND_BINDING_MAGIC = b"SIG3RDBD"
HISTORY_ALGORITHM_V3 = AlgorithmId.SHA3_512


class _HistoryField(IntEnum):
    ROUND_INDEX = 1
    DIGEST = 2


class _RoundBindingField(IntEnum):
    PERSISTENT = 1
    HISTORY = 2


@dataclass(frozen=True)
class HistoryCommitmentV3:
    """Commitment to the strict trajectory prefix before one round."""

    round_index: int
    digest: bytes

    def __post_init__(self) -> None:
        if isinstance(self.round_index, bool) or not isinstance(self.round_index, int):
            raise TypeError("round_index must be int")
        if not 0 <= self.round_index <= MAX_U64:
            raise ValueError("round_index is out of range")
        if not isinstance(self.digest, bytes):
            raise TypeError("history digest must be bytes")
        if len(self.digest) != ALGORITHM_OUTPUT_SIZE_V3:
            raise ValueError("history digest must match algorithm output size")

    def to_bytes(self) -> bytes:
        return encode_record(
            _HISTORY_MAGIC,
            (
                (_HistoryField.ROUND_INDEX, encode_uint(self.round_index, 8)),
                (_HistoryField.DIGEST, self.digest),
            ),
        )

    @classmethod
    def from_bytes(cls, data: bytes) -> "HistoryCommitmentV3":
        fields = decode_record(
            data,
            magic=_HISTORY_MAGIC,
            allowed_tags=frozenset(int(field) for field in _HistoryField),
        )
        try:
            return cls(
                decode_uint(fields[_HistoryField.ROUND_INDEX], 8),
                fields[_HistoryField.DIGEST],
            )
        except (KeyError, TypeError, ValueError) as exc:
            raise DecodeError("invalid history commitment") from exc


@dataclass(frozen=True)
class RoundBindingV3:
    """Effective round binding: persistent input identity plus causal history."""

    persistent: PersistentBinding
    history: HistoryCommitmentV3

    def __post_init__(self) -> None:
        if not isinstance(self.persistent, PersistentBinding):
            raise TypeError("persistent must be PersistentBinding")
        if not isinstance(self.history, HistoryCommitmentV3):
            raise TypeError("history must be HistoryCommitmentV3")

    def to_bytes(self) -> bytes:
        return encode_record(
            _ROUND_BINDING_MAGIC,
            (
                (_RoundBindingField.PERSISTENT, self.persistent.to_bytes()),
                (_RoundBindingField.HISTORY, self.history.to_bytes()),
            ),
        )

    @classmethod
    def from_bytes(cls, data: bytes) -> "RoundBindingV3":
        fields = decode_record(
            data,
            magic=_ROUND_BINDING_MAGIC,
            allowed_tags=frozenset(int(field) for field in _RoundBindingField),
        )
        try:
            return cls(
                PersistentBinding.from_bytes(fields[_RoundBindingField.PERSISTENT]),
                HistoryCommitmentV3.from_bytes(fields[_RoundBindingField.HISTORY]),
            )
        except DecodeError:
            raise
        except (KeyError, TypeError, ValueError) as exc:
            raise DecodeError("invalid round binding") from exc


def _validate_history_context(
    context: SigmaContextV3,
    binding: PersistentBinding,
) -> None:
    if not isinstance(context, SigmaContextV3):
        raise TypeError("context must be SigmaContextV3")
    if context.trajectory_profile is not TrajectoryProfileIdV3.HISTORY_FEEDBACK:
        raise ValueError("context does not use history feedback")
    if not isinstance(binding, PersistentBinding):
        raise TypeError("binding must be PersistentBinding")
    if binding.anchor.suite_id != context.suite_id:
        raise ValueError("binding and context suites differ")


def history_seed_v3(
    context: SigmaContextV3,
    binding: PersistentBinding,
) -> HistoryCommitmentV3:
    """Create H_0. No previous state exists at genesis."""

    _validate_history_context(context, binding)
    transcript = encode_transcript(
        DomainIdV3.HISTORY_SEED,
        (
            (1, context.to_bytes()),
            (2, binding.to_bytes()),
        ),
    )
    return HistoryCommitmentV3(
        0,
        hash_bytes(HISTORY_ALGORITHM_V3, DomainIdV3.HISTORY_SEED, transcript),
    )


def history_step_v3(
    context: SigmaContextV3,
    binding: PersistentBinding,
    history: HistoryCommitmentV3,
    round_index: int,
    state: bytes,
) -> HistoryCommitmentV3:
    """Advance H_i to H_(i+1) after round i consumed S_i.

    H_i commits to the strict past S_0..S_(i-1). The update consumes S_i only
    after the round-i binding has already been fixed, avoiding circularity.
    """

    _validate_history_context(context, binding)
    if not isinstance(history, HistoryCommitmentV3):
        raise TypeError("history must be HistoryCommitmentV3")
    if isinstance(round_index, bool) or not isinstance(round_index, int):
        raise TypeError("round_index must be int")
    if not 0 <= round_index < MAX_U64:
        raise ValueError("round_index is out of range")
    if history.round_index != round_index:
        raise ValueError("history does not belong to round_index")
    if not isinstance(state, bytes):
        raise TypeError("state must be bytes")
    if len(state) != context.state_size:
        raise ValueError("state width does not match context")

    transcript = encode_transcript(
        DomainIdV3.HISTORY_STEP,
        (
            (1, context.to_bytes()),
            (2, binding.to_bytes()),
            (3, encode_uint(round_index, 8)),
            (4, history.to_bytes()),
            (5, state),
        ),
    )
    return HistoryCommitmentV3(
        round_index + 1,
        hash_bytes(HISTORY_ALGORITHM_V3, DomainIdV3.HISTORY_STEP, transcript),
    )


__all__ = [
    "HISTORY_ALGORITHM_V3",
    "HistoryCommitmentV3",
    "RoundBindingV3",
    "history_seed_v3",
    "history_step_v3",
]
