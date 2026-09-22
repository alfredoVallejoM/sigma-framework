from __future__ import annotations

from dataclasses import replace

import pytest

from sigma.binding import HistoryCommitmentV3
from sigma.sources import BytesSource
from sigma.spec.context_v3 import SigmaContextV3
from sigma.spec.ids_v3 import RoundProfileIdV3, SuiteIdV3
from sigma.trajectory import (
    TrajectoryAuditModeV3,
    TrajectoryAuditV3,
    audit_from_evaluation_v3,
    project_digest_v3,
    verify_trajectory_audit_full_v3,
    verify_trajectory_audit_structure_v3,
)
from sigma.v3 import evaluate_v3

ALL_EXECUTABLE_SUITES = (
    SuiteIdV3.REFERENCE_IAP_V3,
    SuiteIdV3.DEEP_V3,
    SuiteIdV3.DEEP_VECTOR_V3,
    SuiteIdV3.REFERENCE_IAP_HISTORY_V3,
    SuiteIdV3.DEEP_HISTORY_V3,
    SuiteIdV3.DEEP_VECTOR_HISTORY_V3,
)

HISTORY_SUITES = (
    SuiteIdV3.REFERENCE_IAP_HISTORY_V3,
    SuiteIdV3.DEEP_HISTORY_V3,
    SuiteIdV3.DEEP_VECTOR_HISTORY_V3,
)


def _evaluation(suite_id: SuiteIdV3, message: bytes = b"trajectory-audit"):
    context = SigmaContextV3.for_suite(
        suite_id,
        salt=b"sv0-salt",
        challenge=b"sv0-challenge",
        application_context=b"tests/sv0",
    )
    return evaluate_v3(context, BytesSource(message))


@pytest.mark.parametrize("suite_id", ALL_EXECUTABLE_SUITES)
@pytest.mark.parametrize(
    "mode", (TrajectoryAuditModeV3.COMPACT, TrajectoryAuditModeV3.FULL)
)
def test_audit_roundtrip_projects_exact_digest_and_replays(
    suite_id: SuiteIdV3,
    mode: TrajectoryAuditModeV3,
):
    evaluation = _evaluation(suite_id)
    audit = audit_from_evaluation_v3(evaluation, mode=mode)
    decoded = TrajectoryAuditV3.from_bytes(audit.to_bytes())

    assert decoded == audit
    assert project_digest_v3(audit).to_bytes() == project_digest_v3(decoded).to_bytes()
    assert project_digest_v3(audit).to_bytes() == audit.digest.to_bytes()
    assert verify_trajectory_audit_structure_v3(audit)
    assert verify_trajectory_audit_full_v3(BytesSource(b"trajectory-audit"), audit)


@pytest.mark.parametrize("suite_id", ALL_EXECUTABLE_SUITES)
def test_compact_and_full_project_same_digest(suite_id: SuiteIdV3):
    evaluation = _evaluation(suite_id)
    compact = audit_from_evaluation_v3(
        evaluation, mode=TrajectoryAuditModeV3.COMPACT
    )
    full = audit_from_evaluation_v3(
        evaluation, mode=TrajectoryAuditModeV3.FULL
    )

    assert compact.digest.to_bytes() == full.digest.to_bytes()
    assert compact.states == full.states
    assert compact.histories == full.histories
    assert tuple(round_.layout for round_ in compact.rounds) == tuple(
        round_.layout for round_ in full.rounds
    )
    assert all(not round_.state_frame for round_ in compact.rounds)
    assert all(round_.state_frame for round_ in full.rounds)


@pytest.mark.parametrize("suite_id", ALL_EXECUTABLE_SUITES)
def test_state_mutation_breaks_structural_replay(suite_id: SuiteIdV3):
    audit = audit_from_evaluation_v3(
        _evaluation(suite_id), mode=TrajectoryAuditModeV3.COMPACT
    )
    mutated = bytearray(audit.states[0])
    mutated[0] ^= 1
    candidate = replace(
        audit,
        states=(bytes(mutated), *audit.states[1:]),
    )
    assert not verify_trajectory_audit_structure_v3(candidate)


@pytest.mark.parametrize("suite_id", HISTORY_SUITES)
def test_history_mutation_breaks_causal_replay(suite_id: SuiteIdV3):
    audit = audit_from_evaluation_v3(
        _evaluation(suite_id), mode=TrajectoryAuditModeV3.COMPACT
    )
    history = HistoryCommitmentV3.from_bytes(audit.histories[1])
    digest = bytearray(history.digest)
    digest[-1] ^= 1
    corrupted = HistoryCommitmentV3(history.round_index, bytes(digest)).to_bytes()
    candidate = replace(
        audit,
        histories=(audit.histories[0], corrupted, *audit.histories[2:]),
    )
    assert not verify_trajectory_audit_structure_v3(candidate)


@pytest.mark.parametrize("suite_id", ALL_EXECUTABLE_SUITES)
def test_layout_mutation_breaks_replay(suite_id: SuiteIdV3):
    audit = audit_from_evaluation_v3(
        _evaluation(suite_id), mode=TrajectoryAuditModeV3.COMPACT
    )
    first = audit.rounds[0]
    layout = bytearray(first.layout)
    layout[-1] ^= 1
    candidate = replace(
        audit,
        rounds=(replace(first, layout=bytes(layout)), *audit.rounds[1:]),
    )
    assert not verify_trajectory_audit_structure_v3(candidate)


@pytest.mark.parametrize("suite_id", ALL_EXECUTABLE_SUITES)
def test_full_frame_mutation_breaks_replay(suite_id: SuiteIdV3):
    audit = audit_from_evaluation_v3(
        _evaluation(suite_id), mode=TrajectoryAuditModeV3.FULL
    )
    first = audit.rounds[0]
    frame = bytearray(first.state_frame)
    frame[-1] ^= 1
    candidate = replace(
        audit,
        rounds=(replace(first, state_frame=bytes(frame)), *audit.rounds[1:]),
    )
    assert not verify_trajectory_audit_structure_v3(candidate)


@pytest.mark.parametrize(
    "suite_id",
    (
        SuiteIdV3.DEEP_V3,
        SuiteIdV3.DEEP_VECTOR_V3,
        SuiteIdV3.DEEP_HISTORY_V3,
        SuiteIdV3.DEEP_VECTOR_HISTORY_V3,
    ),
)
def test_full_branch_output_mutation_breaks_replay(suite_id: SuiteIdV3):
    audit = audit_from_evaluation_v3(
        _evaluation(suite_id), mode=TrajectoryAuditModeV3.FULL
    )
    first = audit.rounds[0]
    output = bytearray(first.branch_outputs[0])
    output[0] ^= 1
    candidate = replace(
        audit,
        rounds=(
            replace(
                first,
                branch_outputs=(bytes(output), *first.branch_outputs[1:]),
            ),
            *audit.rounds[1:],
        ),
    )
    assert not verify_trajectory_audit_structure_v3(candidate)


@pytest.mark.parametrize("suite_id", ALL_EXECUTABLE_SUITES)
def test_round_cardinality_is_exact_t_plus_k_minus_one(suite_id: SuiteIdV3):
    audit = audit_from_evaluation_v3(_evaluation(suite_id))
    parameters = audit.digest.header.parameters
    assert len(audit.states) == parameters.target_round + parameters.state_count
    assert len(audit.rounds) == len(audit.states) - 1

    with pytest.raises(ValueError, match="one round record"):
        replace(audit, rounds=audit.rounds[:-1])


@pytest.mark.parametrize(
    "scalar_suite,vector_suite",
    (
        (SuiteIdV3.DEEP_V3, SuiteIdV3.DEEP_VECTOR_V3),
        (SuiteIdV3.DEEP_HISTORY_V3, SuiteIdV3.DEEP_VECTOR_HISTORY_V3),
    ),
)
def test_deep_and_deep_vector_audits_preserve_distinct_semantics(
    scalar_suite: SuiteIdV3,
    vector_suite: SuiteIdV3,
):
    scalar = audit_from_evaluation_v3(
        _evaluation(scalar_suite), mode=TrajectoryAuditModeV3.FULL
    )
    vector = audit_from_evaluation_v3(
        _evaluation(vector_suite), mode=TrajectoryAuditModeV3.FULL
    )

    assert scalar.digest.context.round_profile is RoundProfileIdV3.DEEP
    assert vector.digest.context.round_profile is RoundProfileIdV3.DEEP_VECTOR
    assert len(scalar.states[0]) == 64
    assert len(vector.states[0]) == 256

    scalar_round = scalar.rounds[0]
    vector_round = vector.rounds[0]
    assert scalar_round.fold_frame
    assert not vector_round.fold_frame
    assert scalar.states[1] != b"".join(scalar_round.branch_outputs)
    assert vector.states[1] == b"".join(vector_round.branch_outputs)


@pytest.mark.parametrize("suite_id", ALL_EXECUTABLE_SUITES)
def test_full_verification_binds_source_not_only_internal_trajectory(
    suite_id: SuiteIdV3,
):
    audit = audit_from_evaluation_v3(
        _evaluation(suite_id, b"message-A"),
        mode=TrajectoryAuditModeV3.COMPACT,
    )
    assert verify_trajectory_audit_full_v3(BytesSource(b"message-A"), audit)
    assert not verify_trajectory_audit_full_v3(BytesSource(b"message-B"), audit)


def test_round_indices_must_be_contiguous():
    audit = audit_from_evaluation_v3(
        _evaluation(SuiteIdV3.REFERENCE_IAP_HISTORY_V3)
    )
    first = audit.rounds[0]
    with pytest.raises(ValueError, match="contiguous"):
        replace(audit, rounds=(replace(first, index=1), *audit.rounds[1:]))


def test_compact_rejects_full_only_evidence():
    audit = audit_from_evaluation_v3(
        _evaluation(SuiteIdV3.REFERENCE_IAP_V3),
        mode=TrajectoryAuditModeV3.COMPACT,
    )
    first = audit.rounds[0]
    with pytest.raises(ValueError, match="FULL-only"):
        replace(
            audit,
            rounds=(replace(first, state_frame=b"not-allowed"), *audit.rounds[1:]),
        )


def test_full_deep_rejects_wrong_branch_count():
    audit = audit_from_evaluation_v3(
        _evaluation(SuiteIdV3.DEEP_V3),
        mode=TrajectoryAuditModeV3.FULL,
    )
    first = audit.rounds[0]
    with pytest.raises(ValueError, match="branch-frame count"):
        replace(
            audit,
            rounds=(
                replace(first, branch_frames=first.branch_frames[:-1]),
                *audit.rounds[1:],
            ),
        )


def test_full_deep_requires_fold_but_vector_forbids_it():
    scalar = audit_from_evaluation_v3(
        _evaluation(SuiteIdV3.DEEP_V3),
        mode=TrajectoryAuditModeV3.FULL,
    )
    first_scalar = scalar.rounds[0]
    with pytest.raises(ValueError, match="fold-frame presence"):
        replace(
            scalar,
            rounds=(replace(first_scalar, fold_frame=b""), *scalar.rounds[1:]),
        )

    vector = audit_from_evaluation_v3(
        _evaluation(SuiteIdV3.DEEP_VECTOR_V3),
        mode=TrajectoryAuditModeV3.FULL,
    )
    first_vector = vector.rounds[0]
    with pytest.raises(ValueError, match="fold-frame presence"):
        replace(
            vector,
            rounds=(
                replace(first_vector, fold_frame=b"unexpected"),
                *vector.rounds[1:],
            ),
        )
