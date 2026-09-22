"""Canonical observational audits for Sigma v3 trajectories.

SV0 is deliberately downstream of evaluation: creating or verifying an audit
never changes evaluate_v3() or SigmaDigestV3 semantics.
"""

from __future__ import annotations

import hmac
from dataclasses import dataclass
from enum import IntEnum

from sigma.binding import (
    HistoryCommitmentV3,
    PersistentBinding,
    RoundBindingV3,
    history_seed_v3,
    history_step_v3,
)
from sigma.crypto.primitives import hash_bytes
from sigma.layout import derive_history_layout_v3, derive_layout_v3
from sigma.outputs.digest_v3 import (
    ExplicitAuditEvidenceV3,
    SigmaDigestV3,
    digest_from_evaluation_v3,
)
from sigma.rounds.deep_v3 import DeepEvaluationV3, DeepVectorEvaluationV3
from sigma.rounds.evaluate_v3 import EvaluationV3, evaluate_v3
from sigma.rounds.framing_v3 import (
    DeepBranchFrame,
    DeepFoldFrame,
    RoundFrame,
    VectorRoundFrame,
)
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

_AUDIT_MAGIC = b"SIG3AUD0"
_ROUND_MAGIC = b"SIG3AUR0"


class TrajectoryAuditModeV3(IntEnum):
    COMPACT = 1
    FULL = 2


class _AuditField(IntEnum):
    MODE = 1
    DIGEST = 2
    BINDING = 3
    INIT_LAYOUT = 4
    STATES = 5
    HISTORIES = 6
    ROUNDS = 7


class _RoundField(IntEnum):
    INDEX = 1
    LAYOUT = 2
    ROUND_BINDING = 3
    STATE_FRAME = 4
    BRANCH_FRAMES = 5
    BRANCH_OUTPUTS = 6
    FOLD_FRAME = 7


def _encode_sequence(values: tuple[bytes, ...]) -> bytes:
    if not isinstance(values, tuple):
        raise TypeError("audit sequences must be tuples")
    if len(values) > MAX_SEQUENCE_ITEMS:
        raise ValueError("audit sequence has too many items")
    output = bytearray(encode_uint(len(values), 2))
    for item in values:
        if not isinstance(item, bytes):
            raise TypeError("audit sequence items must be bytes")
        if len(item) > MAX_SEQUENCE_ITEM_LENGTH:
            raise ValueError("audit sequence item is too large")
        output.extend(encode_uint(len(item), 4))
        output.extend(item)
    return bytes(output)


def _decode_sequence(data: bytes) -> tuple[bytes, ...]:
    if not isinstance(data, bytes) or len(data) < 2:
        raise DecodeError("truncated audit sequence")
    count = decode_uint(data[:2], 2)
    if count > MAX_SEQUENCE_ITEMS:
        raise DecodeError("audit sequence has too many items")
    offset = 2
    output: list[bytes] = []
    for _ in range(count):
        if offset + 4 > len(data):
            raise DecodeError("truncated audit sequence length")
        length = decode_uint(data[offset : offset + 4], 4)
        offset += 4
        if length > MAX_SEQUENCE_ITEM_LENGTH or offset + length > len(data):
            raise DecodeError("invalid audit sequence item length")
        output.append(data[offset : offset + length])
        offset += length
    if offset != len(data):
        raise DecodeError("trailing audit sequence data")
    return tuple(output)


@dataclass(frozen=True)
class TrajectoryRoundAuditV3:
    index: int
    layout: bytes
    round_binding: bytes = b""
    state_frame: bytes = b""
    branch_frames: tuple[bytes, ...] = ()
    branch_outputs: tuple[bytes, ...] = ()
    fold_frame: bytes = b""

    def __post_init__(self) -> None:
        if isinstance(self.index, bool) or not isinstance(self.index, int):
            raise TypeError("audit round index must be int")
        if not 0 <= self.index < (1 << 64):
            raise ValueError("audit round index is out of range")
        for name, value in (
            ("layout", self.layout),
            ("round_binding", self.round_binding),
            ("state_frame", self.state_frame),
            ("fold_frame", self.fold_frame),
        ):
            if not isinstance(value, bytes):
                raise TypeError(f"audit {name} must be bytes")
        if not self.layout:
            raise ValueError("audit round layout must not be empty")
        for name, values in (
            ("branch_frames", self.branch_frames),
            ("branch_outputs", self.branch_outputs),
        ):
            if not isinstance(values, tuple) or any(
                not isinstance(value, bytes) for value in values
            ):
                raise TypeError(f"audit {name} must be tuple[bytes,...]")

    def to_bytes(self) -> bytes:
        return encode_record(
            _ROUND_MAGIC,
            (
                (_RoundField.INDEX, encode_uint(self.index, 8)),
                (_RoundField.LAYOUT, self.layout),
                (_RoundField.ROUND_BINDING, self.round_binding),
                (_RoundField.STATE_FRAME, self.state_frame),
                (_RoundField.BRANCH_FRAMES, _encode_sequence(self.branch_frames)),
                (_RoundField.BRANCH_OUTPUTS, _encode_sequence(self.branch_outputs)),
                (_RoundField.FOLD_FRAME, self.fold_frame),
            ),
        )

    @classmethod
    def from_bytes(cls, data: bytes) -> "TrajectoryRoundAuditV3":
        fields = decode_record(
            data,
            magic=_ROUND_MAGIC,
            allowed_tags=frozenset(int(field) for field in _RoundField),
        )
        try:
            return cls(
                decode_uint(fields[_RoundField.INDEX], 8),
                fields[_RoundField.LAYOUT],
                fields[_RoundField.ROUND_BINDING],
                fields[_RoundField.STATE_FRAME],
                _decode_sequence(fields[_RoundField.BRANCH_FRAMES]),
                _decode_sequence(fields[_RoundField.BRANCH_OUTPUTS]),
                fields[_RoundField.FOLD_FRAME],
            )
        except DecodeError:
            raise
        except (KeyError, TypeError, ValueError) as exc:
            raise DecodeError("invalid Sigma trajectory audit round") from exc


@dataclass(frozen=True)
class TrajectoryAuditV3:
    mode: TrajectoryAuditModeV3
    digest: SigmaDigestV3
    binding: PersistentBinding
    init_layout: bytes
    states: tuple[bytes, ...]
    histories: tuple[bytes, ...]
    rounds: tuple[TrajectoryRoundAuditV3, ...]

    def __post_init__(self) -> None:
        if not isinstance(self.mode, TrajectoryAuditModeV3):
            raise TypeError("audit mode must be TrajectoryAuditModeV3")
        if not isinstance(self.digest, SigmaDigestV3):
            raise TypeError("audit digest must be SigmaDigestV3")
        if not isinstance(self.binding, PersistentBinding):
            raise TypeError("audit binding must be PersistentBinding")
        if not isinstance(self.init_layout, bytes) or not self.init_layout:
            raise ValueError("audit init_layout must be non-empty bytes")
        if not isinstance(self.states, tuple) or not self.states:
            raise ValueError("audit states must be a non-empty tuple")
        if any(not isinstance(state, bytes) for state in self.states):
            raise TypeError("audit states must contain bytes")
        if not isinstance(self.histories, tuple) or any(
            not isinstance(history, bytes) for history in self.histories
        ):
            raise TypeError("audit histories must be tuple[bytes,...]")
        if not isinstance(self.rounds, tuple) or any(
            not isinstance(round_, TrajectoryRoundAuditV3) for round_ in self.rounds
        ):
            raise TypeError("audit rounds must contain TrajectoryRoundAuditV3")

        # Reuse the existing explicit-binding validation without changing its wire.
        ExplicitAuditEvidenceV3(self.digest, self.binding)

        parameters = self.digest.header.parameters
        expected_states = parameters.target_round + parameters.state_count
        if len(self.states) != expected_states:
            raise ValueError("audit state cardinality does not match t+k")
        if len(self.rounds) != len(self.states) - 1:
            raise ValueError("audit requires one round record per state transition")
        if any(len(state) != self.digest.context.state_size for state in self.states):
            raise ValueError("audit state width does not match context")
        if self.digest.window.states != self.states[parameters.target_round :]:
            raise ValueError("audit states do not project to digest public window")

        history_enabled = (
            self.digest.context.trajectory_profile
            is TrajectoryProfileIdV3.HISTORY_FEEDBACK
        )
        if history_enabled:
            if len(self.histories) != len(self.states):
                raise ValueError("history audit requires one H_i per S_i")
            for index, raw in enumerate(self.histories):
                history = HistoryCommitmentV3.from_bytes(raw)
                if history.round_index != index:
                    raise ValueError("history audit indices are non-canonical")
        elif self.histories:
            raise ValueError("non-history audit must not contain histories")

        for index, round_ in enumerate(self.rounds):
            if round_.index != index:
                raise ValueError("audit round indices must be contiguous from zero")

        if self.mode is TrajectoryAuditModeV3.COMPACT:
            for round_ in self.rounds:
                if (
                    round_.round_binding
                    or round_.state_frame
                    or round_.branch_frames
                    or round_.branch_outputs
                    or round_.fold_frame
                ):
                    raise ValueError("COMPACT audit contains FULL-only round evidence")
        else:
            deep = self.digest.context.round_profile in (
                RoundProfileIdV3.DEEP,
                RoundProfileIdV3.DEEP_VECTOR,
            )
            scalar_deep = self.digest.context.round_profile is RoundProfileIdV3.DEEP
            for round_ in self.rounds:
                if not round_.state_frame:
                    raise ValueError("FULL audit must contain every state frame")
                if history_enabled != bool(round_.round_binding):
                    raise ValueError("FULL audit round-binding presence is non-canonical")
                if deep:
                    expected_branches = len(self.digest.context.joint_algorithms)
                    if len(round_.branch_frames) != expected_branches:
                        raise ValueError("FULL Deep audit has wrong branch-frame count")
                    if len(round_.branch_outputs) != expected_branches:
                        raise ValueError("FULL Deep audit has wrong branch-output count")
                elif round_.branch_frames or round_.branch_outputs:
                    raise ValueError("FULL Wide audit must not contain branch evidence")
                if scalar_deep != bool(round_.fold_frame):
                    raise ValueError("FULL fold-frame presence is non-canonical")

    def to_bytes(self) -> bytes:
        return encode_record(
            _AUDIT_MAGIC,
            (
                (_AuditField.MODE, encode_uint(self.mode, 2)),
                (_AuditField.DIGEST, self.digest.to_bytes()),
                (_AuditField.BINDING, self.binding.to_bytes()),
                (_AuditField.INIT_LAYOUT, self.init_layout),
                (_AuditField.STATES, _encode_sequence(self.states)),
                (_AuditField.HISTORIES, _encode_sequence(self.histories)),
                (
                    _AuditField.ROUNDS,
                    _encode_sequence(tuple(round_.to_bytes() for round_ in self.rounds)),
                ),
            ),
        )

    @classmethod
    def from_bytes(cls, data: bytes) -> "TrajectoryAuditV3":
        fields = decode_record(
            data,
            magic=_AUDIT_MAGIC,
            allowed_tags=frozenset(int(field) for field in _AuditField),
        )
        try:
            return cls(
                TrajectoryAuditModeV3(decode_uint(fields[_AuditField.MODE], 2)),
                SigmaDigestV3.from_bytes(fields[_AuditField.DIGEST]),
                PersistentBinding.from_bytes(fields[_AuditField.BINDING]),
                fields[_AuditField.INIT_LAYOUT],
                _decode_sequence(fields[_AuditField.STATES]),
                _decode_sequence(fields[_AuditField.HISTORIES]),
                tuple(
                    TrajectoryRoundAuditV3.from_bytes(raw)
                    for raw in _decode_sequence(fields[_AuditField.ROUNDS])
                ),
            )
        except DecodeError:
            raise
        except (KeyError, TypeError, ValueError) as exc:
            raise DecodeError("invalid Sigma trajectory audit") from exc


def _is_deep(evaluation: EvaluationV3) -> bool:
    return isinstance(
        evaluation,
        (
            DeepEvaluationV3,
            DeepVectorEvaluationV3,
            HistoryDeepEvaluationV3,
            HistoryDeepVectorEvaluationV3,
        ),
    )


def _is_vector(evaluation: EvaluationV3) -> bool:
    return isinstance(
        evaluation,
        (DeepVectorEvaluationV3, HistoryDeepVectorEvaluationV3),
    )


def _is_history(evaluation: EvaluationV3) -> bool:
    return isinstance(
        evaluation,
        (
            HistoryWideOnceEvaluationV3,
            HistoryDeepEvaluationV3,
            HistoryDeepVectorEvaluationV3,
        ),
    )


def _full_round_evidence(
    evaluation: EvaluationV3,
    index: int,
) -> tuple[bytes, tuple[bytes, ...], tuple[bytes, ...], bytes, bytes]:
    context = evaluation.context
    binding = evaluation.prepared.binding
    state = evaluation.states[index]
    layout = evaluation.round_layouts[index]

    if _is_history(evaluation):
        history = evaluation.histories[index]
        round_binding = RoundBindingV3(binding, history)
        if _is_vector(evaluation):
            state_frame = HistoryVectorRoundFrame(
                context, round_binding, layout, index, state
            )
        else:
            state_frame = HistoryRoundFrame(
                context, round_binding, layout, index, state
            )
        round_binding_bytes = round_binding.to_bytes()
    else:
        if _is_vector(evaluation):
            state_frame = VectorRoundFrame(context, binding, layout, index, state)
        else:
            state_frame = RoundFrame(context, binding, layout, index, state)
        round_binding_bytes = b""

    if not _is_deep(evaluation):
        return state_frame.to_bytes(), (), (), b"", round_binding_bytes

    branch_outputs = evaluation.branch_outputs[index]
    if _is_history(evaluation):
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
        fold_frame = (
            HistoryDeepFoldFrame(context, index, branch_outputs).to_bytes()
            if context.round_profile is RoundProfileIdV3.DEEP
            else b""
        )
    else:
        branch_frames = tuple(
            DeepBranchFrame(
                context,
                index,
                position,
                algorithm,
                state_frame,
            ).to_bytes()
            for position, algorithm in enumerate(context.joint_algorithms)
        )
        fold_frame = (
            DeepFoldFrame(context, index, branch_outputs).to_bytes()
            if context.round_profile is RoundProfileIdV3.DEEP
            else b""
        )
    return (
        state_frame.to_bytes(),
        branch_frames,
        branch_outputs,
        fold_frame,
        round_binding_bytes,
    )


def audit_from_evaluation_v3(
    evaluation: EvaluationV3,
    *,
    mode: TrajectoryAuditModeV3 = TrajectoryAuditModeV3.COMPACT,
) -> TrajectoryAuditV3:
    if not isinstance(mode, TrajectoryAuditModeV3):
        raise TypeError("mode must be TrajectoryAuditModeV3")
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

    rounds: list[TrajectoryRoundAuditV3] = []
    for index, layout in enumerate(evaluation.round_layouts):
        if mode is TrajectoryAuditModeV3.FULL:
            (
                state_frame,
                branch_frames,
                branch_outputs,
                fold_frame,
                round_binding,
            ) = _full_round_evidence(evaluation, index)
        else:
            state_frame = b""
            branch_frames = ()
            branch_outputs = ()
            fold_frame = b""
            round_binding = b""
        rounds.append(
            TrajectoryRoundAuditV3(
                index,
                layout.to_bytes(),
                round_binding,
                state_frame,
                branch_frames,
                branch_outputs,
                fold_frame,
            )
        )

    histories = (
        tuple(history.to_bytes() for history in evaluation.histories)
        if _is_history(evaluation)
        else ()
    )
    return TrajectoryAuditV3(
        mode,
        digest_from_evaluation_v3(evaluation),
        evaluation.prepared.binding,
        evaluation.init_layout.to_bytes(),
        evaluation.states,
        histories,
        tuple(rounds),
    )


def evaluate_audit_v3(
    context: SigmaContextV3,
    source: CanonicalSource,
    *,
    mode: TrajectoryAuditModeV3 = TrajectoryAuditModeV3.COMPACT,
) -> TrajectoryAuditV3:
    return audit_from_evaluation_v3(evaluate_v3(context, source), mode=mode)


def project_digest_v3(audit: TrajectoryAuditV3) -> SigmaDigestV3:
    if not isinstance(audit, TrajectoryAuditV3):
        raise TypeError("audit must be TrajectoryAuditV3")
    return audit.digest


def _expected_round_artifacts(
    audit: TrajectoryAuditV3,
    index: int,
) -> tuple[bytes, bytes, tuple[bytes, ...], tuple[bytes, ...], bytes, bytes, bytes]:
    context = audit.digest.context
    binding = audit.binding
    state = audit.states[index]
    history_enabled = (
        context.trajectory_profile is TrajectoryProfileIdV3.HISTORY_FEEDBACK
    )

    if history_enabled:
        history = HistoryCommitmentV3.from_bytes(audit.histories[index])
        round_binding = RoundBindingV3(binding, history)
        layout = derive_history_layout_v3(
            context,
            round_binding,
            round_index=index,
            base_length=len(state),
        )
        if context.round_profile is RoundProfileIdV3.DEEP_VECTOR:
            state_frame = HistoryVectorRoundFrame(
                context, round_binding, layout, index, state
            )
        else:
            state_frame = HistoryRoundFrame(
                context, round_binding, layout, index, state
            )
        round_binding_bytes = round_binding.to_bytes()
        wide_domain = DomainIdV3.HISTORY_ROUND_FRAME
        branch_domain = DomainIdV3.HISTORY_DEEP_BRANCH_FRAME
        fold_domain = DomainIdV3.HISTORY_DEEP_FOLD
    else:
        layout = derive_layout_v3(
            context,
            binding,
            kind=LayoutKindV3.ROUND,
            round_index=index,
            base_length=len(state),
        )
        if context.round_profile is RoundProfileIdV3.DEEP_VECTOR:
            state_frame = VectorRoundFrame(context, binding, layout, index, state)
        else:
            state_frame = RoundFrame(context, binding, layout, index, state)
        round_binding_bytes = b""
        wide_domain = DomainIdV3.ROUND_FRAME
        branch_domain = DomainIdV3.DEEP_BRANCH_FRAME
        fold_domain = DomainIdV3.DEEP_FOLD

    state_frame_bytes = state_frame.to_bytes()

    if context.round_profile is RoundProfileIdV3.WIDE_ONCE:
        successor = hash_bytes(context.state_algorithm, wide_domain, state_frame_bytes)
        return (
            layout.to_bytes(),
            state_frame_bytes,
            (),
            (),
            b"",
            round_binding_bytes,
            successor,
        )

    if history_enabled:
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
    else:
        branch_frames = tuple(
            DeepBranchFrame(
                context,
                index,
                position,
                algorithm,
                state_frame,
            ).to_bytes()
            for position, algorithm in enumerate(context.joint_algorithms)
        )
    branch_outputs = tuple(
        hash_bytes(algorithm, branch_domain, frame)
        for algorithm, frame in zip(
            context.joint_algorithms, branch_frames, strict=True
        )
    )
    if context.round_profile is RoundProfileIdV3.DEEP:
        if history_enabled:
            fold_frame = HistoryDeepFoldFrame(
                context, index, branch_outputs
            ).to_bytes()
        else:
            fold_frame = DeepFoldFrame(context, index, branch_outputs).to_bytes()
        successor = hash_bytes(context.state_algorithm, fold_domain, fold_frame)
    else:
        fold_frame = b""
        successor = b"".join(branch_outputs)

    return (
        layout.to_bytes(),
        state_frame_bytes,
        branch_frames,
        branch_outputs,
        fold_frame,
        round_binding_bytes,
        successor,
    )


def verify_trajectory_audit_structure_v3(audit: TrajectoryAuditV3) -> bool:
    """Verify internal trajectory consistency without claiming message binding."""

    if not isinstance(audit, TrajectoryAuditV3):
        raise TypeError("audit must be TrajectoryAuditV3")
    try:
        context = audit.digest.context
        binding = audit.binding
        expected_init = derive_layout_v3(
            context,
            binding,
            kind=LayoutKindV3.INIT,
            round_index=0,
            base_length=binding.cardinality.byte_length,
        )
        if not hmac.compare_digest(audit.init_layout, expected_init.to_bytes()):
            return False

        if (
            context.trajectory_profile
            is TrajectoryProfileIdV3.HISTORY_FEEDBACK
        ):
            expected_history = history_seed_v3(context, binding)
            if not hmac.compare_digest(
                audit.histories[0], expected_history.to_bytes()
            ):
                return False
        else:
            expected_history = None

        for index, round_ in enumerate(audit.rounds):
            (
                layout,
                state_frame,
                branch_frames,
                branch_outputs,
                fold_frame,
                round_binding,
                successor,
            ) = _expected_round_artifacts(audit, index)
            if not hmac.compare_digest(round_.layout, layout):
                return False
            if not hmac.compare_digest(audit.states[index + 1], successor):
                return False

            if expected_history is not None:
                current = HistoryCommitmentV3.from_bytes(audit.histories[index])
                next_history = history_step_v3(
                    context,
                    binding,
                    current,
                    index,
                    audit.states[index],
                )
                if not hmac.compare_digest(
                    audit.histories[index + 1], next_history.to_bytes()
                ):
                    return False
                expected_history = next_history

            if audit.mode is TrajectoryAuditModeV3.FULL:
                if not hmac.compare_digest(round_.state_frame, state_frame):
                    return False
                if round_.branch_frames != branch_frames:
                    return False
                if round_.branch_outputs != branch_outputs:
                    return False
                if not hmac.compare_digest(round_.fold_frame, fold_frame):
                    return False
                if not hmac.compare_digest(round_.round_binding, round_binding):
                    return False

        return True
    except (DecodeError, TypeError, ValueError):
        return False


def verify_trajectory_audit_full_v3(
    source: CanonicalSource,
    audit: TrajectoryAuditV3,
) -> bool:
    """Verify message binding by recomputing v3, then compare canonical audit bytes."""

    if not isinstance(source, CanonicalSource):
        raise TypeError("source must be CanonicalSource")
    if not isinstance(audit, TrajectoryAuditV3):
        raise TypeError("audit must be TrajectoryAuditV3")
    evaluation = evaluate_v3(audit.digest.context, source)
    expected = audit_from_evaluation_v3(evaluation, mode=audit.mode)
    return hmac.compare_digest(expected.to_bytes(), audit.to_bytes())


__all__ = [
    "TrajectoryAuditModeV3",
    "TrajectoryAuditV3",
    "TrajectoryRoundAuditV3",
    "audit_from_evaluation_v3",
    "evaluate_audit_v3",
    "project_digest_v3",
    "verify_trajectory_audit_full_v3",
    "verify_trajectory_audit_structure_v3",
]
