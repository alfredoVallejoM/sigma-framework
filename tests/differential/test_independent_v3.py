from __future__ import annotations

import ast
from pathlib import Path

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st

from reference.independent_v3 import evaluate_suite
from sigma.outputs.digest_v3 import digest_from_evaluation_v3
from sigma.rounds.deep_v3 import DeepEvaluationV3, DeepVectorEvaluationV3
from sigma.rounds.framing_v3 import (
    DeepBranchFrame,
    DeepFoldFrame,
    InitFrame,
    RoundFrame,
    VectorRoundFrame,
)
from sigma.rounds.wide_once_v3 import WideOnceEvaluationV3
from sigma.sources import BytesSource
from sigma.spec.context_v3 import SigmaContextV3
from sigma.spec.ids_v3 import SuiteIdV3
from sigma.v3 import evaluate_v3

EXECUTABLE_SUITES = (
    SuiteIdV3.REFERENCE_IAP_V3,
    SuiteIdV3.DEEP_V3,
    SuiteIdV3.DEEP_VECTOR_V3,
)


def _assert_independent_equal(
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
    assert isinstance(actual, (WideOnceEvaluationV3, DeepEvaluationV3, DeepVectorEvaluationV3))
    expected = evaluate_suite(
        message,
        suite_id=int(suite_id),
        salt=salt,
        challenge=challenge,
        application_context=application_context,
    )
    binding = actual.prepared.binding

    assert context.to_bytes() == expected["context"]
    assert binding.cardinality.to_bytes() == expected["cardinality"]
    assert binding.anchor.to_bytes() == expected["anchor"]
    assert binding.anchor.components == expected["anchor_components"]
    assert binding.length_signature.to_bytes() == expected["length_signature"]
    assert binding.joint_signature.to_bytes() == expected["joint"]
    assert binding.joint_signature.components == expected["joint_components"]
    assert binding.to_bytes() == expected["binding"]
    assert actual.parameters.target_round == expected["target_round"]
    assert actual.parameters.state_count == expected["state_count"]
    assert actual.parameters.to_bytes() == expected["parameters"]
    assert actual.init_layout.to_bytes() == expected["init_layout"]
    assert (
        tuple((int(item.field), item.slot) for item in actual.init_layout.placements)
        == expected["init_placements"]
    )
    assert tuple(layout.to_bytes() for layout in actual.round_layouts) == expected["round_layouts"]
    assert (
        tuple(
            tuple((int(item.field), item.slot) for item in layout.placements)
            for layout in actual.round_layouts
        )
        == expected["round_placements"]
    )

    init_frame = InitFrame(
        context,
        actual.prepared,
        actual.init_layout,
        BytesSource(message),
    ).to_bytes()
    assert init_frame == expected["init_frame"]
    round_frames: list[bytes] = []
    branch_frames: list[tuple[bytes, ...]] = []
    fold_frames: list[bytes] = []
    for index, layout in enumerate(actual.round_layouts):
        prior = actual.states[index]
        state_frame: RoundFrame | VectorRoundFrame
        if isinstance(actual, DeepVectorEvaluationV3):
            state_frame = VectorRoundFrame(context, binding, layout, index, prior)
        else:
            state_frame = RoundFrame(context, binding, layout, index, prior)
        round_frames.append(state_frame.to_bytes())
        if isinstance(actual, (DeepEvaluationV3, DeepVectorEvaluationV3)):
            frames = tuple(
                DeepBranchFrame(context, index, position, algorithm, state_frame).to_bytes()
                for position, algorithm in enumerate(context.joint_algorithms)
            )
            branch_frames.append(frames)
            if isinstance(actual, DeepEvaluationV3):
                fold_frames.append(
                    DeepFoldFrame(context, index, actual.branch_outputs[index]).to_bytes()
                )
        else:
            branch_frames.append(())

    assert tuple(round_frames) == expected["round_frames"]
    assert tuple(branch_frames) == expected["branch_frames"]
    assert tuple(fold_frames) == expected["fold_frames"]
    if isinstance(actual, (DeepEvaluationV3, DeepVectorEvaluationV3)):
        assert actual.branch_outputs == expected["branch_outputs"]
    else:
        assert expected["branch_outputs"] == tuple(() for _ in actual.round_layouts)
    assert actual.states == expected["states"]
    assert actual.header.to_bytes() == expected["header"]
    assert actual.window.to_bytes() == expected["window"]
    assert digest_from_evaluation_v3(actual).to_bytes() == expected["digest"]


@pytest.mark.parametrize("suite_id", EXECUTABLE_SUITES)
@pytest.mark.parametrize("message", [b"", b"Sigma v3 R12 corpus", bytes(range(64))])
def test_independent_v3_matches_every_executable_suite(
    suite_id: SuiteIdV3,
    message: bytes,
) -> None:
    _assert_independent_equal(
        suite_id,
        message,
        b"R12-differential-salt",
        b"R12-differential-challenge",
        b"tests/differential/independent-v3",
    )


@settings(max_examples=12, deadline=None)
@given(
    suite_id=st.sampled_from(EXECUTABLE_SUITES),
    message=st.binary(max_size=48),
    salt=st.binary(max_size=8),
    challenge=st.binary(max_size=8),
    application_context=st.binary(max_size=8),
)
def test_independent_v3_generated_differential(
    suite_id: SuiteIdV3,
    message: bytes,
    salt: bytes,
    challenge: bytes,
    application_context: bytes,
) -> None:
    _assert_independent_equal(
        suite_id,
        message,
        salt,
        challenge,
        application_context,
    )


def test_independent_v3_never_imports_sigma() -> None:
    path = Path(__file__).parents[2] / "reference" / "independent_v3.py"
    tree = ast.parse(path.read_text(encoding="utf-8"))
    imported = {
        alias.name
        for node in ast.walk(tree)
        if isinstance(node, (ast.Import, ast.ImportFrom))
        for alias in node.names
    }
    assert not any(name == "sigma" or name.startswith("sigma.") for name in imported)
