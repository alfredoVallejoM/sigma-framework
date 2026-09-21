from __future__ import annotations

import dataclasses
import hashlib

import pytest

from sigma.outputs.digest_v3 import SigmaDigestV3, digest_from_evaluation_v3, verify_full_v3
from sigma.rounds.backends_v3 import (
    DeepBranchBackendV3,
    DeepBranchExecutionError,
    DeepBranchResultV3,
    DeepBranchTaskV3,
    ProcessDeepBranchBackendV3,
    ThreadDeepBranchBackendV3,
)
from sigma.rounds.deep_v3 import (
    DeepEvaluationV3,
    DeepVectorEvaluationV3,
    evaluate_deep_bytes_v3,
    evaluate_deep_vector_bytes_v3,
    next_deep_state_v3,
    next_deep_vector_state_v3,
)
from sigma.rounds.framing_v3 import (
    DeepBranchFrame,
    DeepFoldFrame,
    RoundFrame,
    VectorRoundFrame,
)
from sigma.sources import BytesSource
from sigma.spec.context_v3 import SigmaContextV3
from sigma.spec.ids_v3 import ALGORITHM_OUTPUT_SIZE_V3, RoundProfileIdV3, SuiteIdV3


def _context(suite_id: SuiteIdV3) -> SigmaContextV3:
    return SigmaContextV3.for_suite(
        suite_id,
        salt=b"",
        challenge=b"",
        application_context=b"",
    )


@pytest.mark.parametrize(
    ("suite_id", "message", "evaluator", "evaluation_type", "state_size"),
    (
        (SuiteIdV3.DEEP_V3, b"24", evaluate_deep_bytes_v3, DeepEvaluationV3, 64),
        (
            SuiteIdV3.DEEP_VECTOR_V3,
            b"38",
            evaluate_deep_vector_bytes_v3,
            DeepVectorEvaluationV3,
            256,
        ),
    ),
)
def test_deep_backends_are_byte_identical(
    suite_id: SuiteIdV3,
    message: bytes,
    evaluator,
    evaluation_type: type[DeepEvaluationV3] | type[DeepVectorEvaluationV3],
    state_size: int,
) -> None:
    context = _context(suite_id)
    serial = evaluator(context, message)
    threaded = evaluator(context, message, ThreadDeepBranchBackendV3(2))
    processed = evaluator(context, message, ProcessDeepBranchBackendV3(2))

    assert isinstance(serial, evaluation_type)
    assert serial == threaded == processed
    assert all(len(state) == state_size for state in serial.states)
    assert all(
        len(branches) == len(context.joint_algorithms)
        and all(len(branch) == ALGORITHM_OUTPUT_SIZE_V3 for branch in branches)
        for branches in serial.branch_outputs
    )
    assert verify_full_v3(BytesSource(message), digest_from_evaluation_v3(serial))


def test_deep_scalar_folds_and_vector_preserves_all_components() -> None:
    scalar = evaluate_deep_bytes_v3(_context(SuiteIdV3.DEEP_V3), b"24")
    assert scalar.context.round_profile is RoundProfileIdV3.DEEP
    assert all(len(state) == 64 for state in scalar.states)
    assert all(
        successor not in branches
        for successor, branches in zip(scalar.states[1:], scalar.branch_outputs, strict=True)
    )


def test_deep_branch_and_fold_frames_are_profile_typed() -> None:
    scalar = evaluate_deep_bytes_v3(_context(SuiteIdV3.DEEP_V3), b"24")
    scalar_frame = RoundFrame(
        scalar.context,
        scalar.prepared.binding,
        scalar.round_layouts[0],
        0,
        scalar.states[0],
    )
    branch = DeepBranchFrame(
        scalar.context,
        0,
        0,
        scalar.context.joint_algorithms[0],
        scalar_frame,
    )
    assert branch.to_bytes()
    folded = DeepFoldFrame(scalar.context, 0, scalar.branch_outputs[0])
    assert folded.to_bytes()

    vector = evaluate_deep_vector_bytes_v3(_context(SuiteIdV3.DEEP_VECTOR_V3), b"38")
    vector_frame = VectorRoundFrame(
        vector.context,
        vector.prepared.binding,
        vector.round_layouts[0],
        0,
        vector.states[0],
    )
    assert DeepBranchFrame(
        vector.context,
        0,
        0,
        vector.context.joint_algorithms[0],
        vector_frame,
    ).to_bytes()
    with pytest.raises(TypeError, match="RoundFrame"):
        DeepBranchFrame(
            scalar.context,
            0,
            0,
            scalar.context.joint_algorithms[0],
            vector_frame,
        )
    with pytest.raises(ValueError, match="scalar"):
        DeepFoldFrame(vector.context, 0, vector.branch_outputs[0])

    vector = evaluate_deep_vector_bytes_v3(_context(SuiteIdV3.DEEP_VECTOR_V3), b"38")
    assert vector.context.round_profile is RoundProfileIdV3.DEEP_VECTOR
    assert all(
        successor == b"".join(branches)
        for successor, branches in zip(vector.states[1:], vector.branch_outputs, strict=True)
    )


def test_every_vector_successor_component_depends_on_complete_previous_vector() -> None:
    evaluation = evaluate_deep_vector_bytes_v3(_context(SuiteIdV3.DEEP_VECTOR_V3), b"38")
    context = evaluation.context
    binding = evaluation.prepared.binding
    state = evaluation.states[0]
    baseline = next_deep_vector_state_v3(context, binding, 0, state)
    baseline_components = tuple(
        baseline[offset : offset + 64] for offset in range(0, len(baseline), 64)
    )

    for offset in range(0, len(state), 64):
        mutated = bytearray(state)
        mutated[offset] ^= 1
        successor = next_deep_vector_state_v3(context, binding, 0, bytes(mutated))
        components = tuple(successor[index : index + 64] for index in range(0, len(successor), 64))
        assert all(
            changed != original
            for changed, original in zip(components, baseline_components, strict=True)
        )


class _RaisingBackend(DeepBranchBackendV3):
    @property
    def name(self) -> str:
        return "raising"

    def execute(self, tasks: tuple[DeepBranchTaskV3, ...]) -> tuple[DeepBranchResultV3, ...]:
        raise OSError("controlled failure")


class _IncompleteBackend(DeepBranchBackendV3):
    @property
    def name(self) -> str:
        return "incomplete"

    def execute(self, tasks: tuple[DeepBranchTaskV3, ...]) -> tuple[DeepBranchResultV3, ...]:
        return ()


class _DuplicateBackend(DeepBranchBackendV3):
    @property
    def name(self) -> str:
        return "duplicate"

    def execute(self, tasks: tuple[DeepBranchTaskV3, ...]) -> tuple[DeepBranchResultV3, ...]:
        value = b"x" * ALGORITHM_OUTPUT_SIZE_V3
        return tuple(DeepBranchResultV3(0, value) for _ in tasks)


class _WrongWidthBackend(DeepBranchBackendV3):
    @property
    def name(self) -> str:
        return "wrong-width"

    def execute(self, tasks: tuple[DeepBranchTaskV3, ...]) -> tuple[DeepBranchResultV3, ...]:
        return tuple(DeepBranchResultV3(task.position, b"short") for task in tasks)


class _WrongValueBackend(DeepBranchBackendV3):
    @property
    def name(self) -> str:
        return "wrong-value"

    def execute(self, tasks: tuple[DeepBranchTaskV3, ...]) -> tuple[DeepBranchResultV3, ...]:
        value = b"x" * ALGORITHM_OUTPUT_SIZE_V3
        return tuple(DeepBranchResultV3(task.position, value) for task in tasks)


@pytest.mark.parametrize(
    "backend",
    (
        _RaisingBackend(),
        _IncompleteBackend(),
        _DuplicateBackend(),
        _WrongWidthBackend(),
        _WrongValueBackend(),
    ),
)
def test_component_failures_are_controlled(backend: DeepBranchBackendV3) -> None:
    evaluation = evaluate_deep_bytes_v3(_context(SuiteIdV3.DEEP_V3), b"24")
    with pytest.raises(DeepBranchExecutionError):
        next_deep_state_v3(
            evaluation.context,
            evaluation.prepared.binding,
            0,
            evaluation.states[0],
            backend,
        )


def test_profiles_and_evaluations_cannot_be_confused_or_forged() -> None:
    scalar_context = _context(SuiteIdV3.DEEP_V3)
    vector_context = _context(SuiteIdV3.DEEP_VECTOR_V3)
    with pytest.raises(ValueError, match="wrong Deep"):
        evaluate_deep_vector_bytes_v3(scalar_context, b"24")
    with pytest.raises(ValueError, match="wrong Deep"):
        evaluate_deep_bytes_v3(vector_context, b"38")
    with pytest.raises(TypeError, match="created by"):
        DeepEvaluationV3()
    with pytest.raises(TypeError, match="created by"):
        DeepVectorEvaluationV3()

    evaluation = evaluate_deep_bytes_v3(scalar_context, b"24")
    with pytest.raises(TypeError, match="created by"):
        dataclasses.replace(evaluation)


def test_deep_digest_known_answers_and_round_trip() -> None:
    scalar = evaluate_deep_bytes_v3(_context(SuiteIdV3.DEEP_V3), b"24")
    vector = evaluate_deep_vector_bytes_v3(_context(SuiteIdV3.DEEP_VECTOR_V3), b"38")
    scalar_digest = digest_from_evaluation_v3(scalar)
    vector_digest = digest_from_evaluation_v3(vector)

    assert hashlib.sha256(scalar_digest.to_bytes()).hexdigest() == (
        "274b422d0e361d67f28ebf6dad557357c6f73a125670300cb76fe2d8fc74bc30"
    )
    assert hashlib.sha256(vector_digest.to_bytes()).hexdigest() == (
        "9e84c5065b57928c6c226b682a507b1f5d1456c3329fa288ad7345db4d5ac209"
    )
    assert SigmaDigestV3.from_bytes(scalar_digest.to_bytes()) == scalar_digest
    assert SigmaDigestV3.from_bytes(vector_digest.to_bytes()) == vector_digest
