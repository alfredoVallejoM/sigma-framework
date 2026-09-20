from __future__ import annotations

from dataclasses import replace

import pytest

from sigma.binding import (
    HistoryCommitmentV3,
    RoundBindingV3,
    history_seed_v3,
    history_step_v3,
)
from sigma.layout import (
    HistoryLayoutPlacement,
    HistoryLayoutPlan,
    derive_history_layout_v3,
    history_placed_length_v3,
    iter_placed_round_binding_v3,
    place_round_binding_v3,
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
from sigma.sources import BytesSource
from sigma.spec.context_v3 import SigmaContextV3
from sigma.spec.encoding import DecodeError
from sigma.spec.ids import AlgorithmId
from sigma.spec.ids_v3 import RoundBindingFieldIdV3, SuiteIdV3
from sigma.v3 import evaluate_v3


def _context(suite_id: SuiteIdV3) -> SigmaContextV3:
    return SigmaContextV3.for_suite(
        suite_id,
        salt=b"negative-history",
        challenge=b"negative-history",
        application_context=b"tests/unit/history-negative",
    )


def _wide() -> HistoryWideOnceEvaluationV3:
    value = evaluate_v3(
        _context(SuiteIdV3.REFERENCE_IAP_HISTORY_V3),
        BytesSource(b"negative-wide"),
    )
    assert isinstance(value, HistoryWideOnceEvaluationV3)
    return value


def _deep() -> HistoryDeepEvaluationV3:
    value = evaluate_v3(
        _context(SuiteIdV3.DEEP_HISTORY_V3),
        BytesSource(b"negative-deep"),
    )
    assert isinstance(value, HistoryDeepEvaluationV3)
    return value


def _vector() -> HistoryDeepVectorEvaluationV3:
    value = evaluate_v3(
        _context(SuiteIdV3.DEEP_VECTOR_HISTORY_V3),
        BytesSource(b"negative-vector"),
    )
    assert isinstance(value, HistoryDeepVectorEvaluationV3)
    return value


@pytest.mark.parametrize(
    ("round_index", "digest", "error"),
    (
        (True, b"x" * 64, TypeError),
        (-1, b"x" * 64, ValueError),
        (0, "bad", TypeError),
        (0, b"x" * 63, ValueError),
    ),
)
def test_history_commitment_rejects_invalid_construction(
    round_index, digest, error: type[Exception]
) -> None:
    with pytest.raises(error):
        HistoryCommitmentV3(round_index, digest)


def test_history_and_round_binding_parsers_reject_malformed_wire() -> None:
    with pytest.raises(DecodeError):
        HistoryCommitmentV3.from_bytes(b"bad")
    with pytest.raises(DecodeError):
        RoundBindingV3.from_bytes(b"bad")


def test_round_binding_rejects_invalid_components() -> None:
    evaluation = _wide()
    history = evaluation.histories[0]
    with pytest.raises(TypeError):
        RoundBindingV3(object(), history)  # type: ignore[arg-type]
    with pytest.raises(TypeError):
        RoundBindingV3(evaluation.prepared.binding, object())  # type: ignore[arg-type]


def test_history_seed_rejects_nonhistory_context_and_suite_mismatch() -> None:
    history_eval = _wide()
    old_context = SigmaContextV3.for_suite(
        SuiteIdV3.REFERENCE_IAP_V3,
        salt=b"",
        challenge=b"",
        application_context=b"",
    )
    with pytest.raises(ValueError, match="history feedback"):
        history_seed_v3(old_context, history_eval.prepared.binding)

    deep = _deep()
    with pytest.raises(ValueError, match="suites differ"):
        history_seed_v3(history_eval.context, deep.prepared.binding)

    with pytest.raises(TypeError):
        history_seed_v3(object(), history_eval.prepared.binding)  # type: ignore[arg-type]


@pytest.mark.parametrize(
    "mutation",
    ("history-type", "index-type", "index-range", "index-mismatch", "state-type", "state-size"),
)
def test_history_step_rejects_malformed_transition(mutation: str) -> None:
    evaluation = _wide()
    context = evaluation.context
    binding = evaluation.prepared.binding
    history = evaluation.histories[0]
    state = evaluation.states[0]

    if mutation == "history-type":
        with pytest.raises(TypeError):
            history_step_v3(context, binding, object(), 0, state)  # type: ignore[arg-type]
    elif mutation == "index-type":
        with pytest.raises(TypeError):
            history_step_v3(context, binding, history, True, state)
    elif mutation == "index-range":
        with pytest.raises(ValueError):
            history_step_v3(context, binding, history, -1, state)
    elif mutation == "index-mismatch":
        with pytest.raises(ValueError, match="round_index"):
            history_step_v3(context, binding, history, 1, state)
    elif mutation == "state-type":
        with pytest.raises(TypeError):
            history_step_v3(context, binding, history, 0, "bad")  # type: ignore[arg-type]
    else:
        with pytest.raises(ValueError, match="state width"):
            history_step_v3(context, binding, history, 0, state[:-1])


@pytest.mark.parametrize(
    ("field", "slot", "error"),
    (
        (1, 0, TypeError),
        (RoundBindingFieldIdV3.ANCHOR, True, TypeError),
        (RoundBindingFieldIdV3.ANCHOR, -1, ValueError),
    ),
)
def test_history_layout_placement_rejects_invalid_values(
    field, slot, error: type[Exception]
) -> None:
    with pytest.raises(error):
        HistoryLayoutPlacement(field, slot)


def test_history_layout_parser_and_plan_invariants_reject_bad_inputs() -> None:
    evaluation = _wide()
    plan = evaluation.round_layouts[0]

    with pytest.raises(DecodeError):
        HistoryLayoutPlan.from_bytes(b"bad")
    with pytest.raises(TypeError):
        HistoryLayoutPlan(True, plan.base_length, plan.placements)
    with pytest.raises(ValueError):
        HistoryLayoutPlan(-1, plan.base_length, plan.placements)
    with pytest.raises(TypeError):
        HistoryLayoutPlan(plan.round_index, plan.base_length, list(plan.placements))  # type: ignore[arg-type]
    with pytest.raises(ValueError, match="every round binding field"):
        HistoryLayoutPlan(plan.round_index, plan.base_length, plan.placements[:-1])

    oversized = replace(plan.placements[0], slot=plan.base_length + 1)
    with pytest.raises(ValueError, match="exceeds"):
        HistoryLayoutPlan(
            plan.round_index,
            plan.base_length,
            (oversized, *plan.placements[1:]),
        )

    if len({item.slot for item in plan.placements}) > 1:
        with pytest.raises(ValueError, match="canonical"):
            HistoryLayoutPlan(plan.round_index, plan.base_length, tuple(reversed(plan.placements)))


def test_history_layout_derivation_rejects_wrong_context_binding_and_indices() -> None:
    evaluation = _wide()
    binding = RoundBindingV3(evaluation.prepared.binding, evaluation.histories[0])
    old_context = SigmaContextV3.for_suite(
        SuiteIdV3.REFERENCE_IAP_V3,
        salt=b"",
        challenge=b"",
        application_context=b"",
    )

    with pytest.raises(TypeError):
        derive_history_layout_v3(object(), binding, round_index=0, base_length=64)  # type: ignore[arg-type]
    with pytest.raises(ValueError, match="history feedback"):
        derive_history_layout_v3(old_context, binding, round_index=0, base_length=64)
    with pytest.raises(TypeError):
        derive_history_layout_v3(evaluation.context, object(), round_index=0, base_length=64)  # type: ignore[arg-type]
    with pytest.raises(TypeError):
        derive_history_layout_v3(evaluation.context, binding, round_index=True, base_length=64)
    with pytest.raises(ValueError):
        derive_history_layout_v3(evaluation.context, binding, round_index=-1, base_length=64)

    wrong_history = HistoryCommitmentV3(1, evaluation.histories[0].digest)
    with pytest.raises(ValueError, match="round indices differ"):
        derive_history_layout_v3(
            evaluation.context,
            RoundBindingV3(evaluation.prepared.binding, wrong_history),
            round_index=0,
            base_length=64,
        )


def test_history_placement_helpers_reject_type_length_and_replay_errors() -> None:
    evaluation = _wide()
    binding = RoundBindingV3(evaluation.prepared.binding, evaluation.histories[0])
    plan = evaluation.round_layouts[0]
    state = evaluation.states[0]

    with pytest.raises(TypeError):
        history_placed_length_v3(object(), plan)  # type: ignore[arg-type]
    with pytest.raises(TypeError):
        history_placed_length_v3(binding, object())  # type: ignore[arg-type]
    with pytest.raises(TypeError):
        b"".join(iter_placed_round_binding_v3((), object(), plan))  # type: ignore[arg-type]
    with pytest.raises(TypeError):
        b"".join(iter_placed_round_binding_v3((), binding, object()))  # type: ignore[arg-type]

    wrong_history = HistoryCommitmentV3(1, evaluation.histories[0].digest)
    with pytest.raises(ValueError, match="round indices differ"):
        b"".join(
            iter_placed_round_binding_v3(
                (state,),
                RoundBindingV3(evaluation.prepared.binding, wrong_history),
                plan,
            )
        )

    with pytest.raises(TypeError, match="chunks"):
        b"".join(iter_placed_round_binding_v3(("bad",), binding, plan))  # type: ignore[arg-type]
    with pytest.raises(ValueError, match="longer"):
        b"".join(iter_placed_round_binding_v3((state + b"x",), binding, plan))
    with pytest.raises(ValueError, match="shorter"):
        b"".join(iter_placed_round_binding_v3((state[:-1],), binding, plan))
    with pytest.raises(TypeError):
        place_round_binding_v3("bad", binding, plan)  # type: ignore[arg-type]
    with pytest.raises(ValueError, match="too large"):
        place_round_binding_v3(b"x" * ((1 << 20) + 1), binding, plan)


def test_history_round_frame_rejects_bad_state_history_and_layout() -> None:
    evaluation = _wide()
    binding = RoundBindingV3(evaluation.prepared.binding, evaluation.histories[0])
    plan = evaluation.round_layouts[0]
    state = evaluation.states[0]

    with pytest.raises(ValueError, match="round indices differ"):
        HistoryRoundFrame(
            evaluation.context,
            RoundBindingV3(
                evaluation.prepared.binding,
                HistoryCommitmentV3(1, evaluation.histories[0].digest),
            ),
            plan,
            0,
            state,
        )
    with pytest.raises(TypeError):
        HistoryRoundFrame(evaluation.context, binding, plan, 0, "bad")  # type: ignore[arg-type]
    with pytest.raises(ValueError, match="state size"):
        HistoryRoundFrame(evaluation.context, binding, plan, 0, state[:-1])
    with pytest.raises(ValueError, match="layout length"):
        HistoryRoundFrame(
            evaluation.context,
            binding,
            replace(plan, base_length=plan.base_length + 1),
            0,
            state,
        )


def test_history_vector_frame_rejects_empty_and_wrong_width_vectors() -> None:
    evaluation = _vector()
    binding = RoundBindingV3(evaluation.prepared.binding, evaluation.histories[0])
    plan = evaluation.round_layouts[0]
    vector = evaluation.states[0]

    with pytest.raises(ValueError, match="non-empty"):
        HistoryVectorRoundFrame(evaluation.context, binding, plan, 0, b"")
    with pytest.raises(ValueError, match="vector width"):
        HistoryVectorRoundFrame(evaluation.context, binding, plan, 0, vector[:-1])


def test_history_deep_branch_frame_rejects_bad_position_algorithm_and_profile() -> None:
    evaluation = _deep()
    round_binding = RoundBindingV3(evaluation.prepared.binding, evaluation.histories[0])
    state_frame = HistoryRoundFrame(
        evaluation.context,
        round_binding,
        evaluation.round_layouts[0],
        0,
        evaluation.states[0],
    )

    with pytest.raises(ValueError, match="branch_index"):
        HistoryDeepBranchFrame(
            evaluation.context,
            0,
            -1,
            AlgorithmId.SHA512,
            state_frame,
        )
    with pytest.raises(ValueError, match="algorithm"):
        HistoryDeepBranchFrame(
            evaluation.context,
            0,
            0,
            AlgorithmId.SHA3_512,
            state_frame,
        )

    wide = _wide()
    wide_binding = RoundBindingV3(wide.prepared.binding, wide.histories[0])
    wide_frame = HistoryRoundFrame(
        wide.context,
        wide_binding,
        wide.round_layouts[0],
        0,
        wide.states[0],
    )
    with pytest.raises(ValueError, match="Deep profile"):
        HistoryDeepBranchFrame(
            wide.context,
            0,
            0,
            AlgorithmId.SHA512,
            wide_frame,
        )


def test_history_deep_fold_frame_rejects_wrong_profile_and_branch_shape() -> None:
    deep = _deep()
    branches = deep.branch_outputs[0]
    vector = _vector()

    with pytest.raises(ValueError, match="Deep scalar"):
        HistoryDeepFoldFrame(vector.context, 0, vector.branch_outputs[0])
    with pytest.raises(TypeError):
        HistoryDeepFoldFrame(deep.context, 0, list(branches))  # type: ignore[arg-type]
    with pytest.raises(ValueError, match="match joint algorithms"):
        HistoryDeepFoldFrame(deep.context, 0, branches[:-1])
    with pytest.raises(ValueError, match="branch width"):
        HistoryDeepFoldFrame(
            deep.context,
            0,
            (branches[0][:-1], *branches[1:]),
        )
