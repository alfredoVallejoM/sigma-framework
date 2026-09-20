from __future__ import annotations

import dataclasses

import pytest

from sigma.binding import (
    HistoryCommitmentV3,
    RoundBindingV3,
    history_seed_v3,
    history_step_v3,
)
from sigma.layout import HistoryLayoutPlan, derive_history_layout_v3
from sigma.outputs.digest_v3 import digest_from_evaluation_v3, verify_full_v3
from sigma.rounds.backends_v3 import ThreadDeepBranchBackendV3
from sigma.rounds.history_framing_v3 import HistoryRoundFrame
from sigma.rounds.history_v3 import (
    HistoryDeepEvaluationV3,
    HistoryDeepVectorEvaluationV3,
    HistoryWideOnceEvaluationV3,
)
from sigma.sources import BytesSource
from sigma.spec.context_v3 import SigmaContextV3
from sigma.spec.ids_v3 import (
    LayoutProfileIdV3,
    RoundBindingFieldIdV3,
    SuiteIdV3,
    TrajectoryProfileIdV3,
)
from sigma.v3 import evaluate_v3

HISTORY_SUITES = (
    SuiteIdV3.REFERENCE_IAP_HISTORY_V3,
    SuiteIdV3.DEEP_HISTORY_V3,
    SuiteIdV3.DEEP_VECTOR_HISTORY_V3,
)


def _context(suite_id: SuiteIdV3) -> SigmaContextV3:
    return SigmaContextV3.for_suite(
        suite_id,
        salt=b"r12.5-history",
        challenge=b"history-challenge",
        application_context=b"tests/unit/history-feedback",
    )


@pytest.mark.parametrize("suite_id", HISTORY_SUITES)
def test_history_suites_use_distinct_registered_profiles(suite_id: SuiteIdV3) -> None:
    context = _context(suite_id)
    assert context.layout_profile is LayoutProfileIdV3.SHAKE256_HISTORY_REJECTION
    assert context.trajectory_profile is TrajectoryProfileIdV3.HISTORY_FEEDBACK


def test_history_commitment_and_round_binding_round_trip() -> None:
    context = _context(SuiteIdV3.REFERENCE_IAP_HISTORY_V3)
    evaluation = evaluate_v3(context, BytesSource(b"round-trip"))
    assert isinstance(evaluation, HistoryWideOnceEvaluationV3)
    seed = evaluation.histories[0]
    assert HistoryCommitmentV3.from_bytes(seed.to_bytes()) == seed
    binding = RoundBindingV3(evaluation.prepared.binding, seed)
    assert RoundBindingV3.from_bytes(binding.to_bytes()) == binding


def test_history_is_causal_and_tracks_strict_past() -> None:
    context = _context(SuiteIdV3.REFERENCE_IAP_HISTORY_V3)
    evaluation = evaluate_v3(context, BytesSource(b"causal-history"))
    assert isinstance(evaluation, HistoryWideOnceEvaluationV3)
    persistent = evaluation.prepared.binding
    assert evaluation.histories[0] == history_seed_v3(context, persistent)
    for index, state in enumerate(evaluation.states[:-1]):
        assert evaluation.histories[index + 1] == history_step_v3(
            context,
            persistent,
            evaluation.histories[index],
            index,
            state,
        )
        assert evaluation.histories[index].round_index == index


def test_same_visible_state_with_different_history_never_has_same_round_frame() -> None:
    context = _context(SuiteIdV3.REFERENCE_IAP_HISTORY_V3)
    evaluation = evaluate_v3(context, BytesSource(b"state-crossing"))
    assert isinstance(evaluation, HistoryWideOnceEvaluationV3)
    state = evaluation.states[0]
    original = evaluation.histories[0]
    changed = bytes((original.digest[0] ^ 1,)) + original.digest[1:]
    alternative = HistoryCommitmentV3(original.round_index, changed)
    first_binding = RoundBindingV3(evaluation.prepared.binding, original)
    second_binding = RoundBindingV3(evaluation.prepared.binding, alternative)
    first_layout = derive_history_layout_v3(
        context, first_binding, round_index=0, base_length=len(state)
    )
    second_layout = derive_history_layout_v3(
        context, second_binding, round_index=0, base_length=len(state)
    )
    first = HistoryRoundFrame(context, first_binding, first_layout, 0, state).to_bytes()
    second = HistoryRoundFrame(context, second_binding, second_layout, 0, state).to_bytes()
    assert first != second


def test_history_layout_contains_all_five_effective_binding_fields() -> None:
    context = _context(SuiteIdV3.REFERENCE_IAP_HISTORY_V3)
    evaluation = evaluate_v3(context, BytesSource(b"five-fields"))
    assert isinstance(evaluation, HistoryWideOnceEvaluationV3)
    plan = evaluation.round_layouts[0]
    assert isinstance(plan, HistoryLayoutPlan)
    assert {item.field for item in plan.placements} == set(RoundBindingFieldIdV3)
    assert len(plan.placements) == 5


def test_history_step_rejects_replay_under_wrong_round_index() -> None:
    context = _context(SuiteIdV3.REFERENCE_IAP_HISTORY_V3)
    evaluation = evaluate_v3(context, BytesSource(b"replay"))
    assert isinstance(evaluation, HistoryWideOnceEvaluationV3)
    with pytest.raises(ValueError, match="round_index"):
        history_step_v3(
            context,
            evaluation.prepared.binding,
            evaluation.histories[0],
            1,
            evaluation.states[0],
        )


@pytest.mark.parametrize(
    ("suite_id", "expected_type"),
    (
        (SuiteIdV3.REFERENCE_IAP_HISTORY_V3, HistoryWideOnceEvaluationV3),
        (SuiteIdV3.DEEP_HISTORY_V3, HistoryDeepEvaluationV3),
        (SuiteIdV3.DEEP_VECTOR_HISTORY_V3, HistoryDeepVectorEvaluationV3),
    ),
)
def test_all_history_families_keep_one_history_per_state(
    suite_id: SuiteIdV3,
    expected_type: type,
) -> None:
    evaluation = evaluate_v3(_context(suite_id), BytesSource(b"all-families"))
    assert isinstance(evaluation, expected_type)
    assert len(evaluation.histories) == len(evaluation.states)
    assert len(evaluation.round_layouts) == len(evaluation.states) - 1


@pytest.mark.parametrize("suite_id", HISTORY_SUITES)
def test_history_digest_full_verification_recomputes_feedback(suite_id: SuiteIdV3) -> None:
    message = b"history-full-verify"
    evaluation = evaluate_v3(_context(suite_id), BytesSource(message))
    digest = digest_from_evaluation_v3(evaluation)
    assert verify_full_v3(BytesSource(message), digest)
    assert not verify_full_v3(BytesSource(message + b"!"), digest)


@pytest.mark.parametrize(
    "suite_id",
    (SuiteIdV3.DEEP_HISTORY_V3, SuiteIdV3.DEEP_VECTOR_HISTORY_V3),
)
def test_history_deep_thread_backend_is_mathematically_identical(
    suite_id: SuiteIdV3,
) -> None:
    context = _context(suite_id)
    serial = evaluate_v3(context, BytesSource(b"backend-equality"))
    threaded = evaluate_v3(
        context,
        BytesSource(b"backend-equality"),
        backend=ThreadDeepBranchBackendV3(2),
    )
    assert digest_from_evaluation_v3(serial).to_bytes() == digest_from_evaluation_v3(
        threaded
    ).to_bytes()
    assert serial.states == threaded.states
    assert serial.histories == threaded.histories


def test_r12_and_r125_are_explicitly_distinct_constructions() -> None:
    message = b"ablation-baseline"
    old_context = SigmaContextV3.for_suite(
        SuiteIdV3.REFERENCE_IAP_V3,
        salt=b"same",
        challenge=b"same",
        application_context=b"same",
    )
    new_context = SigmaContextV3.for_suite(
        SuiteIdV3.REFERENCE_IAP_HISTORY_V3,
        salt=b"same",
        challenge=b"same",
        application_context=b"same",
    )
    old = digest_from_evaluation_v3(evaluate_v3(old_context, BytesSource(message)))
    new = digest_from_evaluation_v3(evaluate_v3(new_context, BytesSource(message)))
    assert old.to_bytes() != new.to_bytes()


def test_history_evaluations_are_factory_only() -> None:
    with pytest.raises(TypeError):
        HistoryWideOnceEvaluationV3()
    evaluation = evaluate_v3(
        _context(SuiteIdV3.REFERENCE_IAP_HISTORY_V3),
        BytesSource(b"factory-only"),
    )
    with pytest.raises(TypeError):
        dataclasses.replace(evaluation)
