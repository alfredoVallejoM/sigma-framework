from __future__ import annotations

from dataclasses import replace

import pytest

from sigma.binding import HistoryCommitmentV3, TrajectoryParameters
from sigma.sources import BytesSource
from sigma.spec.context_v3 import SigmaContextV3
from sigma.spec.ids_v3 import SuiteIdV3
from sigma.trajectory import (
    TrajectoryCheckpointV1,
    advance_trajectory_checkpoint_v3,
    checkpoint_from_evaluation_v3,
    continue_trajectory_checkpoint_v3,
    finalize_trajectory_checkpoint_v3,
    verify_trajectory_checkpoint_source_v3,
)
from sigma.v3 import evaluate_v3

ALL_SUITES = (
    SuiteIdV3.REFERENCE_IAP_V3,
    SuiteIdV3.DEEP_V3,
    SuiteIdV3.DEEP_VECTOR_V3,
    SuiteIdV3.REFERENCE_IAP_HISTORY_V3,
    SuiteIdV3.DEEP_HISTORY_V3,
    SuiteIdV3.DEEP_VECTOR_HISTORY_V3,
)


def _evaluation(suite_id: SuiteIdV3, message: bytes = b"sv1-checkpoint"):
    context = SigmaContextV3.for_suite(
        suite_id,
        salt=b"sv1-salt",
        challenge=b"sv1-challenge",
        application_context=b"tests/sv1",
    )
    return evaluate_v3(context, BytesSource(message))


@pytest.mark.parametrize("suite_id", ALL_SUITES)
def test_all_checkpoint_indices_continue_to_exact_suffix_and_digest(suite_id):
    evaluation = _evaluation(suite_id)
    expected_digest = evaluation.header, evaluation.window

    for index in range(len(evaluation.states)):
        checkpoint = checkpoint_from_evaluation_v3(evaluation, index)
        decoded = TrajectoryCheckpointV1.from_bytes(checkpoint.to_bytes())
        assert decoded == checkpoint

        continuation = continue_trajectory_checkpoint_v3(decoded)
        assert continuation.states == evaluation.states[index:]
        if hasattr(evaluation, "histories"):
            assert continuation.histories == tuple(
                item.to_bytes() for item in evaluation.histories[index:]
            )
        else:
            assert continuation.histories == ()

        digest = finalize_trajectory_checkpoint_v3(decoded)
        assert digest.header == expected_digest[0]
        assert digest.window == expected_digest[1]


@pytest.mark.parametrize("suite_id", ALL_SUITES)
def test_advance_exactness_matches_next_state_without_skip(suite_id):
    evaluation = _evaluation(suite_id)
    if len(evaluation.states) < 2:
        pytest.skip("trajectory has no transition")

    checkpoint = checkpoint_from_evaluation_v3(evaluation, 0)
    one = advance_trajectory_checkpoint_v3(checkpoint, rounds=1)
    assert one.round_index == 1
    assert one.state == evaluation.states[1]

    with pytest.raises(ValueError, match="past final"):
        advance_trajectory_checkpoint_v3(
            checkpoint, rounds=checkpoint.final_round_index + 1
        )
    with pytest.raises(ValueError, match="non-negative"):
        advance_trajectory_checkpoint_v3(checkpoint, rounds=-1)


@pytest.mark.parametrize("suite_id", ALL_SUITES)
def test_checkpoint_source_rebind_is_distinct_and_exact(suite_id):
    message = b"checkpoint-source-A"
    evaluation = _evaluation(suite_id, message)
    checkpoint = checkpoint_from_evaluation_v3(
        evaluation, len(evaluation.states) // 2
    )

    assert verify_trajectory_checkpoint_source_v3(BytesSource(message), checkpoint)
    assert not verify_trajectory_checkpoint_source_v3(
        BytesSource(b"checkpoint-source-B"), checkpoint
    )


def test_checkpoint_rejects_parameter_mutation():
    evaluation = _evaluation(SuiteIdV3.REFERENCE_IAP_HISTORY_V3)
    checkpoint = checkpoint_from_evaluation_v3(evaluation, 0)
    mutated = TrajectoryParameters(
        checkpoint.parameters.target_round + 1,
        checkpoint.parameters.state_count,
    )
    with pytest.raises(ValueError, match="parameters"):
        replace(checkpoint, parameters=mutated)


def test_checkpoint_rejects_cross_suite_context():
    evaluation = _evaluation(SuiteIdV3.REFERENCE_IAP_HISTORY_V3)
    checkpoint = checkpoint_from_evaluation_v3(evaluation, 0)
    other = SigmaContextV3.for_suite(
        SuiteIdV3.DEEP_HISTORY_V3,
        salt=checkpoint.context.salt,
        challenge=checkpoint.context.challenge,
        application_context=checkpoint.context.application_context,
    )
    with pytest.raises(ValueError):
        replace(checkpoint, context=other)


def test_checkpoint_rejects_wrong_history_index():
    evaluation = _evaluation(SuiteIdV3.REFERENCE_IAP_HISTORY_V3)
    checkpoint = checkpoint_from_evaluation_v3(evaluation, 1)
    assert checkpoint.history is not None
    wrong = HistoryCommitmentV3(0, checkpoint.history.digest)
    with pytest.raises(ValueError, match="history index"):
        replace(checkpoint, history=wrong)


def test_checkpoint_window_prefix_is_minimal_and_exact():
    evaluation = _evaluation(SuiteIdV3.DEEP_VECTOR_HISTORY_V3)
    target = evaluation.parameters.target_round
    late_index = min(len(evaluation.states) - 1, target + 1)
    checkpoint = checkpoint_from_evaluation_v3(evaluation, late_index)
    assert checkpoint.window_prefix == evaluation.states[target:late_index]

    with pytest.raises(ValueError, match="prefix length"):
        replace(checkpoint, window_prefix=())


def test_checkpoint_at_final_index_needs_no_more_rounds():
    evaluation = _evaluation(SuiteIdV3.DEEP_V3)
    index = len(evaluation.states) - 1
    checkpoint = checkpoint_from_evaluation_v3(evaluation, index)
    assert checkpoint.round_index == checkpoint.final_round_index
    assert advance_trajectory_checkpoint_v3(checkpoint, rounds=0) == checkpoint
    continuation = continue_trajectory_checkpoint_v3(checkpoint)
    assert continuation.states == (evaluation.states[-1],)


def _top_level_fields(encoded: bytes) -> list[tuple[int, bytes]]:
    body_length = int.from_bytes(encoded[10:14], "big")
    assert body_length == len(encoded) - 14
    fields = []
    offset = 14
    while offset < len(encoded):
        tag = int.from_bytes(encoded[offset : offset + 2], "big")
        length = int.from_bytes(encoded[offset + 2 : offset + 6], "big")
        offset += 6
        fields.append((tag, encoded[offset : offset + length]))
        offset += length
    return fields


def _rebuild_record(template: bytes, fields: list[tuple[int, bytes]]) -> bytes:
    body = b"".join(
        tag.to_bytes(2, "big") + len(value).to_bytes(4, "big") + value
        for tag, value in fields
    )
    return template[:10] + len(body).to_bytes(4, "big") + body


def test_checkpoint_codec_rejects_missing_duplicate_reordered_unknown_fields():
    evaluation = _evaluation(SuiteIdV3.DEEP_HISTORY_V3)
    encoded = checkpoint_from_evaluation_v3(evaluation, 1).to_bytes()
    fields = _top_level_fields(encoded)

    mutations = []
    for index, field in enumerate(fields):
        mutations.append(_rebuild_record(encoded, fields[:index] + fields[index + 1 :]))
        mutations.append(
            _rebuild_record(
                encoded,
                [*fields[: index + 1], field, *fields[index + 1 :]],
            )
        )
    reordered = list(fields)
    reordered[0], reordered[1] = reordered[1], reordered[0]
    mutations.append(_rebuild_record(encoded, reordered))
    mutations.append(_rebuild_record(encoded, [*fields, (0xFFFF, b"")]))

    for mutated in mutations:
        with pytest.raises(ValueError):
            TrajectoryCheckpointV1.from_bytes(mutated)
