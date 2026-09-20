from __future__ import annotations

import ast
from pathlib import Path

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st

from reference.independent_v3 import evaluate_suite
from sigma.binding import RoundBindingV3
from sigma.outputs.digest_v3 import digest_from_evaluation_v3
from sigma.rounds.history_framing_v3 import (
    HistoryDeepBranchFrame,
    HistoryDeepFoldFrame,
    HistoryRoundFrame,
    HistoryVectorRoundFrame,
)
from sigma.rounds.history_v3 import (
    HistoryDeepEvaluationV3,
    HistoryDeepVectorEvaluationV3,
)
from sigma.sources import BytesSource
from sigma.spec.context_v3 import SigmaContextV3
from sigma.spec.ids_v3 import SuiteIdV3
from sigma.v3 import evaluate_v3

HISTORY_SUITES = (
    SuiteIdV3.REFERENCE_IAP_HISTORY_V3,
    SuiteIdV3.DEEP_HISTORY_V3,
    SuiteIdV3.DEEP_VECTOR_HISTORY_V3,
)


def _assert_equal(
    suite_id: SuiteIdV3,
    message: bytes,
    salt: bytes,
    challenge: bytes,
    application_context: bytes,
) -> None:
    context = SigmaContextV3.for_suite(
        suite_id,
        salt=salt,
        challenge=challenge,
        application_context=application_context,
    )
    actual = evaluate_v3(context, BytesSource(message))
    expected = evaluate_suite(
        message,
        suite_id=int(suite_id),
        salt=salt,
        challenge=challenge,
        application_context=application_context,
    )
    binding = actual.prepared.binding

    assert expected["history_enabled"] is True
    assert context.to_bytes() == expected["context"]
    assert binding.to_bytes() == expected["binding"]
    assert tuple(item.to_bytes() for item in actual.histories) == expected["histories"]
    assert (
        tuple(RoundBindingV3(binding, item).to_bytes() for item in actual.histories[:-1])
        == expected["round_bindings"]
    )
    assert tuple(layout.to_bytes() for layout in actual.round_layouts) == expected["round_layouts"]
    assert (
        tuple(
            tuple((int(item.field), item.slot) for item in layout.placements)
            for layout in actual.round_layouts
        )
        == expected["round_placements"]
    )

    frames: list[bytes] = []
    branch_frames: list[tuple[bytes, ...]] = []
    fold_frames: list[bytes] = []
    for index, (layout, history, state) in enumerate(
        zip(actual.round_layouts, actual.histories[:-1], actual.states[:-1], strict=True)
    ):
        round_binding = RoundBindingV3(binding, history)
        if isinstance(actual, HistoryDeepVectorEvaluationV3):
            state_frame: HistoryRoundFrame | HistoryVectorRoundFrame = HistoryVectorRoundFrame(
                context, round_binding, layout, index, state
            )
        else:
            state_frame = HistoryRoundFrame(context, round_binding, layout, index, state)
        frames.append(state_frame.to_bytes())
        if isinstance(actual, (HistoryDeepEvaluationV3, HistoryDeepVectorEvaluationV3)):
            current = tuple(
                HistoryDeepBranchFrame(
                    context,
                    index,
                    position,
                    algorithm,
                    state_frame,
                ).to_bytes()
                for position, algorithm in enumerate(context.joint_algorithms)
            )
            branch_frames.append(current)
            if isinstance(actual, HistoryDeepEvaluationV3):
                fold_frames.append(
                    HistoryDeepFoldFrame(context, index, actual.branch_outputs[index]).to_bytes()
                )
        else:
            branch_frames.append(())

    assert tuple(frames) == expected["round_frames"]
    assert tuple(branch_frames) == expected["branch_frames"]
    assert tuple(fold_frames) == expected["fold_frames"]
    if isinstance(actual, (HistoryDeepEvaluationV3, HistoryDeepVectorEvaluationV3)):
        assert actual.branch_outputs == expected["branch_outputs"]
    assert actual.states == expected["states"]
    assert actual.header.to_bytes() == expected["header"]
    assert actual.window.to_bytes() == expected["window"]
    assert digest_from_evaluation_v3(actual).to_bytes() == expected["digest"]


@pytest.mark.parametrize("suite_id", HISTORY_SUITES)
@pytest.mark.parametrize("message", [b"", b"history-r12.5", bytes(range(32))])
def test_independent_reference_matches_history_suites(
    suite_id: SuiteIdV3,
    message: bytes,
) -> None:
    _assert_equal(
        suite_id,
        message,
        b"r125-differential",
        b"challenge",
        b"tests/differential/history",
    )


@settings(max_examples=12, deadline=None)
@given(
    suite_id=st.sampled_from(HISTORY_SUITES),
    message=st.binary(max_size=48),
    salt=st.binary(max_size=8),
    challenge=st.binary(max_size=8),
    application_context=st.binary(max_size=8),
)
def test_generated_history_differential(
    suite_id: SuiteIdV3,
    message: bytes,
    salt: bytes,
    challenge: bytes,
    application_context: bytes,
) -> None:
    _assert_equal(suite_id, message, salt, challenge, application_context)


def test_independent_reference_still_never_imports_sigma() -> None:
    path = Path(__file__).parents[2] / "reference" / "independent_v3.py"
    tree = ast.parse(path.read_text(encoding="utf-8"))
    imported = {
        alias.name
        for node in ast.walk(tree)
        if isinstance(node, (ast.Import, ast.ImportFrom))
        for alias in node.names
    }
    assert not any(name == "sigma" or name.startswith("sigma.") for name in imported)
