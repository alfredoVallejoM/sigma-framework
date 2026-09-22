"""Portable internal trajectory checkpoints for Sigma v3.

This is distinct from sigma.incremental_v3.SigmaCheckpointV3: the latter is a
provisional checkpoint over a source prefix and re-evaluates that prefix. SV1
checkpoints are internal round-state checkpoints after binding/parameters exist.
"""

from __future__ import annotations

import hmac
from dataclasses import dataclass
from enum import IntEnum

from sigma.binding import (
    HistoryCommitmentV3,
    PersistentBinding,
    PublicTrajectoryHeader,
    RoundBindingV3,
    TrajectoryParameters,
    TrajectoryWindow,
    derive_trajectory_parameters,
    history_step_v3,
)
from sigma.crypto.primitives import hash_bytes
from sigma.layout import derive_history_layout_v3, derive_layout_v3
from sigma.outputs.digest_v3 import SigmaDigestV3
from sigma.rounds.deep_v3 import (
    DeepEvaluationV3,
    DeepVectorEvaluationV3,
    next_deep_state_v3,
    next_deep_vector_state_v3,
)
from sigma.rounds.evaluate_v3 import EvaluationV3, evaluate_v3
from sigma.rounds.framing_v3 import RoundFrame
from sigma.rounds.history_framing_v3 import (
    HistoryDeepBranchFrame,
    HistoryDeepFoldFrame,
    HistoryRoundFrame,
    HistoryVectorRoundFrame,
)
from sigma.rounds.history_v3 import (
    HistoryDeepEvaluationV3,
    HistoryDeepVectorEvaluationV3,
    HistoryWideOnceEvaluationV3,
)
from sigma.rounds.wide_once_v3 import WideOnceEvaluationV3
from sigma.sources import CanonicalSource
from sigma.spec.codec_v3 import (
    MAX_SEQUENCE_ITEM_LENGTH,
    MAX_SEQUENCE_ITEMS,
    decode_record,
    encode_record,
)
from sigma.spec.context_v3 import SigmaContextV3
from sigma.spec.encoding import DecodeError, decode_uint, encode_uint
from sigma.spec.ids_v3 import (
    DomainIdV3,
    LayoutKindV3,
    RoundProfileIdV3,
    TrajectoryProfileIdV3,
)

_CHECKPOINT_MAGIC = b"SIG3TCK0"


class _CheckpointField(IntEnum):
    CONTEXT = 1
    BINDING = 2
    PARAMETERS = 3
    ROUND_INDEX = 4
    STATE = 5
    HISTORY = 6
    WINDOW_PREFIX = 7


def _encode_sequence(values: tuple[bytes, ...]) -> bytes:
    if not isinstance(values, tuple):
        raise TypeError("checkpoint sequence must be tuple")
    if len(values) > MAX_SEQUENCE_ITEMS:
        raise ValueError("checkpoint sequence has too many items")
    out = bytearray(encode_uint(len(values), 2))
    for value in values:
        if not isinstance(value, bytes):
            raise TypeError("checkpoint sequence items must be bytes")
        if len(value) > MAX_SEQUENCE_ITEM_LENGTH:
            raise ValueError("checkpoint sequence item is too large")
        out.extend(encode_uint(len(value), 4))
        out.extend(value)
    return bytes(out)


def _decode_sequence(data: bytes) -> tuple[bytes, ...]:
    if not isinstance(data, bytes) or len(data) < 2:
        raise DecodeError("truncated checkpoint sequence")
    count = decode_uint(data[:2], 2)
    if count > MAX_SEQUENCE_ITEMS:
        raise DecodeError("checkpoint sequence has too many items")
    offset = 2
    values: list[bytes] = []
    for _ in range(count):
        if offset + 4 > len(data):
            raise DecodeError("truncated checkpoint sequence length")
        length = decode_uint(data[offset : offset + 4], 4)
        offset += 4
        if length > MAX_SEQUENCE_ITEM_LENGTH or offset + length > len(data):
            raise DecodeError("invalid checkpoint sequence item")
        values.append(data[offset : offset + length])
        offset += length
    if offset != len(data):
        raise DecodeError("trailing checkpoint sequence data")
    return tuple(values)


@dataclass(frozen=True)
class TrajectoryCheckpointV1:
    context: SigmaContextV3
    binding: PersistentBinding
    parameters: TrajectoryParameters
    round_index: int
    state: bytes
    history: HistoryCommitmentV3 | None = None
    window_prefix: tuple[bytes, ...] = ()

    def __post_init__(self) -> None:
        if not isinstance(self.context, SigmaContextV3):
            raise TypeError("checkpoint context must be SigmaContextV3")
        if not isinstance(self.binding, PersistentBinding):
            raise TypeError("checkpoint binding must be PersistentBinding")
        if not isinstance(self.parameters, TrajectoryParameters):
            raise TypeError("checkpoint parameters must be TrajectoryParameters")
        if derive_trajectory_parameters(self.context, self.binding) != self.parameters:
            raise ValueError("checkpoint parameters do not match context/binding")
        if isinstance(self.round_index, bool) or not isinstance(self.round_index, int):
            raise TypeError("checkpoint round_index must be int")
        final_index = self.parameters.target_round + self.parameters.state_count - 1
        if not 0 <= self.round_index <= final_index:
            raise ValueError("checkpoint round_index is outside trajectory")
        if not isinstance(self.state, bytes):
            raise TypeError("checkpoint state must be bytes")
        if len(self.state) != self.context.state_size:
            raise ValueError("checkpoint state width does not match context")
        if not isinstance(self.window_prefix, tuple) or any(
            not isinstance(state, bytes) for state in self.window_prefix
        ):
            raise TypeError("checkpoint window_prefix must be tuple[bytes,...]")
        expected_prefix = max(0, self.round_index - self.parameters.target_round)
        if len(self.window_prefix) != expected_prefix:
            raise ValueError("checkpoint window prefix length is non-canonical")
        if any(len(state) != self.context.state_size for state in self.window_prefix):
            raise ValueError("checkpoint window prefix state width is invalid")

        history_enabled = (
            self.context.trajectory_profile
            is TrajectoryProfileIdV3.HISTORY_FEEDBACK
        )
        if history_enabled:
            if not isinstance(self.history, HistoryCommitmentV3):
                raise ValueError("history checkpoint requires H_i")
            if self.history.round_index != self.round_index:
                raise ValueError("checkpoint history index differs from round_index")
        elif self.history is not None:
            raise ValueError("non-history checkpoint must not contain history")

    @property
    def final_round_index(self) -> int:
        return self.parameters.target_round + self.parameters.state_count - 1

    def to_bytes(self) -> bytes:
        return encode_record(
            _CHECKPOINT_MAGIC,
            (
                (_CheckpointField.CONTEXT, self.context.to_bytes()),
                (_CheckpointField.BINDING, self.binding.to_bytes()),
                (_CheckpointField.PARAMETERS, self.parameters.to_bytes()),
                (_CheckpointField.ROUND_INDEX, encode_uint(self.round_index, 8)),
                (_CheckpointField.STATE, self.state),
                (
                    _CheckpointField.HISTORY,
                    self.history.to_bytes() if self.history is not None else b"",
                ),
                (_CheckpointField.WINDOW_PREFIX, _encode_sequence(self.window_prefix)),
            ),
        )

    @classmethod
    def from_bytes(cls, data: bytes) -> "TrajectoryCheckpointV1":
        fields = decode_record(
            data,
            magic=_CHECKPOINT_MAGIC,
            allowed_tags=frozenset(int(field) for field in _CheckpointField),
        )
        try:
            history = (
                HistoryCommitmentV3.from_bytes(fields[_CheckpointField.HISTORY])
                if fields[_CheckpointField.HISTORY]
                else None
            )
            return cls(
                SigmaContextV3.from_bytes(fields[_CheckpointField.CONTEXT]),
                PersistentBinding.from_bytes(fields[_CheckpointField.BINDING]),
                TrajectoryParameters.from_bytes(fields[_CheckpointField.PARAMETERS]),
                decode_uint(fields[_CheckpointField.ROUND_INDEX], 8),
                fields[_CheckpointField.STATE],
                history,
                _decode_sequence(fields[_CheckpointField.WINDOW_PREFIX]),
            )
        except DecodeError:
            raise
        except (KeyError, TypeError, ValueError) as exc:
            raise DecodeError("invalid Sigma trajectory checkpoint") from exc


@dataclass(frozen=True)
class TrajectoryContinuationV1:
    start_round_index: int
    states: tuple[bytes, ...]
    histories: tuple[bytes, ...]
    digest: SigmaDigestV3

    def __post_init__(self) -> None:
        if isinstance(self.start_round_index, bool) or not isinstance(
            self.start_round_index, int
        ):
            raise TypeError("start_round_index must be int")
        if not isinstance(self.states, tuple) or not self.states:
            raise ValueError("continuation states must be non-empty")
        if any(not isinstance(value, bytes) for value in self.states):
            raise TypeError("continuation states must contain bytes")
        if not isinstance(self.histories, tuple) or any(
            not isinstance(value, bytes) for value in self.histories
        ):
            raise TypeError("continuation histories must contain bytes")
        if self.histories and len(self.histories) != len(self.states):
            raise ValueError("continuation histories must align with states")
        if not isinstance(self.digest, SigmaDigestV3):
            raise TypeError("continuation digest must be SigmaDigestV3")


def _is_history_evaluation(evaluation: EvaluationV3) -> bool:
    return isinstance(
        evaluation,
        (
            HistoryWideOnceEvaluationV3,
            HistoryDeepEvaluationV3,
            HistoryDeepVectorEvaluationV3,
        ),
    )


def checkpoint_from_evaluation_v3(
    evaluation: EvaluationV3,
    round_index: int,
) -> TrajectoryCheckpointV1:
    if not isinstance(
        evaluation,
        (
            WideOnceEvaluationV3,
            DeepEvaluationV3,
            DeepVectorEvaluationV3,
            HistoryWideOnceEvaluationV3,
            HistoryDeepEvaluationV3,
            HistoryDeepVectorEvaluationV3,
        ),
    ):
        raise TypeError("evaluation must be a Sigma v3 evaluation")
    if isinstance(round_index, bool) or not isinstance(round_index, int):
        raise TypeError("round_index must be int")
    if not 0 <= round_index < len(evaluation.states):
        raise ValueError("round_index is outside evaluation trajectory")

    target = evaluation.parameters.target_round
    window_prefix = (
        evaluation.states[target:round_index]
        if round_index > target
        else ()
    )
    history: HistoryCommitmentV3 | None
    if isinstance(
        evaluation,
        (
            HistoryWideOnceEvaluationV3,
            HistoryDeepEvaluationV3,
            HistoryDeepVectorEvaluationV3,
        ),
    ):
        history = evaluation.histories[round_index]
    else:
        history = None
    return TrajectoryCheckpointV1(
        evaluation.context,
        evaluation.prepared.binding,
        evaluation.parameters,
        round_index,
        evaluation.states[round_index],
        history,
        tuple(window_prefix),
    )


def _history_transition(
    checkpoint: TrajectoryCheckpointV1,
) -> tuple[bytes, HistoryCommitmentV3]:
    context = checkpoint.context
    binding = checkpoint.binding
    index = checkpoint.round_index
    state = checkpoint.state
    history = checkpoint.history
    assert history is not None

    round_binding = RoundBindingV3(binding, history)
    layout = derive_history_layout_v3(
        context,
        round_binding,
        round_index=index,
        base_length=len(state),
    )

    if context.round_profile is RoundProfileIdV3.WIDE_ONCE:
        frame = HistoryRoundFrame(context, round_binding, layout, index, state)
        successor = hash_bytes(
            context.state_algorithm,
            DomainIdV3.HISTORY_ROUND_FRAME,
            frame.to_bytes(),
        )
    else:
        state_frame = (
            HistoryVectorRoundFrame(context, round_binding, layout, index, state)
            if context.round_profile is RoundProfileIdV3.DEEP_VECTOR
            else HistoryRoundFrame(context, round_binding, layout, index, state)
        )
        branch_frames = tuple(
            HistoryDeepBranchFrame(
                context,
                index,
                position,
                algorithm,
                state_frame,
            ).to_bytes()
            for position, algorithm in enumerate(context.joint_algorithms)
        )
        branches = tuple(
            hash_bytes(
                algorithm,
                DomainIdV3.HISTORY_DEEP_BRANCH_FRAME,
                frame,
            )
            for algorithm, frame in zip(
                context.joint_algorithms, branch_frames, strict=True
            )
        )
        if context.round_profile is RoundProfileIdV3.DEEP:
            fold = HistoryDeepFoldFrame(context, index, branches)
            successor = hash_bytes(
                context.state_algorithm,
                DomainIdV3.HISTORY_DEEP_FOLD,
                fold.to_bytes(),
            )
        elif context.round_profile is RoundProfileIdV3.DEEP_VECTOR:
            successor = b"".join(branches)
        else:  # pragma: no cover - closed registered profiles
            raise ValueError("unsupported history round profile")

    next_history = history_step_v3(
        context,
        binding,
        history,
        index,
        state,
    )
    return successor, next_history


def _nonhistory_transition(checkpoint: TrajectoryCheckpointV1) -> bytes:
    context = checkpoint.context
    binding = checkpoint.binding
    index = checkpoint.round_index
    state = checkpoint.state

    if context.round_profile is RoundProfileIdV3.WIDE_ONCE:
        layout = derive_layout_v3(
            context,
            binding,
            kind=LayoutKindV3.ROUND,
            round_index=index,
            base_length=len(state),
        )
        frame = RoundFrame(context, binding, layout, index, state)
        return hash_bytes(
            context.state_algorithm,
            DomainIdV3.ROUND_FRAME,
            frame.to_bytes(),
        )
    if context.round_profile is RoundProfileIdV3.DEEP:
        return next_deep_state_v3(context, binding, index, state)
    if context.round_profile is RoundProfileIdV3.DEEP_VECTOR:
        return next_deep_vector_state_v3(context, binding, index, state)
    raise ValueError("unsupported Sigma v3 round profile")  # pragma: no cover


def advance_trajectory_checkpoint_v3(
    checkpoint: TrajectoryCheckpointV1,
    *,
    rounds: int = 1,
) -> TrajectoryCheckpointV1:
    if not isinstance(checkpoint, TrajectoryCheckpointV1):
        raise TypeError("checkpoint must be TrajectoryCheckpointV1")
    if isinstance(rounds, bool) or not isinstance(rounds, int):
        raise TypeError("rounds must be int")
    if rounds < 0:
        raise ValueError("rounds must be non-negative")
    if checkpoint.round_index + rounds > checkpoint.final_round_index:
        raise ValueError("checkpoint advance would skip past final round")

    current = checkpoint
    for _ in range(rounds):
        old_index = current.round_index
        old_state = current.state
        if current.history is not None:
            successor, next_history = _history_transition(current)
        else:
            successor = _nonhistory_transition(current)
            next_history = None

        prefix = current.window_prefix
        if old_index >= current.parameters.target_round:
            prefix = (*prefix, old_state)

        current = TrajectoryCheckpointV1(
            current.context,
            current.binding,
            current.parameters,
            old_index + 1,
            successor,
            next_history,
            tuple(prefix),
        )
    return current


def _digest_from_final_checkpoint(
    final: TrajectoryCheckpointV1,
) -> SigmaDigestV3:
    if final.round_index != final.final_round_index:
        raise ValueError("checkpoint is not at final trajectory state")
    window_states = (*final.window_prefix, final.state)
    if len(window_states) != final.parameters.state_count:
        raise RuntimeError("continued checkpoint did not reconstruct full public window")
    header = PublicTrajectoryHeader(
        final.binding.cardinality,
        final.binding.anchor,
        final.binding.length_signature,
        final.parameters,
    )
    return SigmaDigestV3(
        final.context,
        header,
        TrajectoryWindow(final.parameters, tuple(window_states)),
    )


def finalize_trajectory_checkpoint_v3(
    checkpoint: TrajectoryCheckpointV1,
) -> SigmaDigestV3:
    if not isinstance(checkpoint, TrajectoryCheckpointV1):
        raise TypeError("checkpoint must be TrajectoryCheckpointV1")
    final = advance_trajectory_checkpoint_v3(
        checkpoint,
        rounds=checkpoint.final_round_index - checkpoint.round_index,
    )
    return _digest_from_final_checkpoint(final)


def continue_trajectory_checkpoint_v3(
    checkpoint: TrajectoryCheckpointV1,
) -> TrajectoryContinuationV1:
    if not isinstance(checkpoint, TrajectoryCheckpointV1):
        raise TypeError("checkpoint must be TrajectoryCheckpointV1")
    states = [checkpoint.state]
    histories = (
        [checkpoint.history.to_bytes()]
        if checkpoint.history is not None
        else []
    )
    current = checkpoint
    while current.round_index < current.final_round_index:
        current = advance_trajectory_checkpoint_v3(current)
        states.append(current.state)
        if current.history is not None:
            histories.append(current.history.to_bytes())
    digest = _digest_from_final_checkpoint(current)
    return TrajectoryContinuationV1(
        checkpoint.round_index,
        tuple(states),
        tuple(histories),
        digest,
    )


def verify_trajectory_checkpoint_source_v3(
    source: CanonicalSource,
    checkpoint: TrajectoryCheckpointV1,
) -> bool:
    """Rebind an internal checkpoint to a concrete source by full v3 reevaluation."""

    if not isinstance(source, CanonicalSource):
        raise TypeError("source must be CanonicalSource")
    if not isinstance(checkpoint, TrajectoryCheckpointV1):
        raise TypeError("checkpoint must be TrajectoryCheckpointV1")
    evaluation = evaluate_v3(checkpoint.context, source)
    if checkpoint.round_index >= len(evaluation.states):
        return False
    expected = checkpoint_from_evaluation_v3(evaluation, checkpoint.round_index)
    return hmac.compare_digest(expected.to_bytes(), checkpoint.to_bytes())


__all__ = [
    "TrajectoryCheckpointV1",
    "TrajectoryContinuationV1",
    "advance_trajectory_checkpoint_v3",
    "checkpoint_from_evaluation_v3",
    "continue_trajectory_checkpoint_v3",
    "finalize_trajectory_checkpoint_v3",
    "verify_trajectory_checkpoint_source_v3",
]
