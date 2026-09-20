from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any

from scripts.generate_v3_r12_corpus import render_corpus
from sigma.outputs.digest_v3 import digest_from_evaluation_v3
from sigma.rounds.deep_v3 import DeepEvaluationV3, DeepVectorEvaluationV3
from sigma.rounds.framing_v3 import (
    DeepBranchFrame,
    DeepFoldFrame,
    InitFrame,
    RoundFrame,
    VectorRoundFrame,
)
from sigma.sources import BytesSource
from sigma.spec.context_v3 import SigmaContextV3
from sigma.spec.ids_v3 import SuiteIdV3
from sigma.v3 import evaluate_v3

CORPUS_PATH = (
    Path(__file__).parents[2] / "specification" / "test-vectors" / "conformance-v3-r12.json"
)


def _bytes(value: str) -> bytes:
    return bytes.fromhex(value)


def _placements(layout: Any) -> list[dict[str, int]]:
    return [{"field_id": int(item.field), "slot": item.slot} for item in layout.placements]


def test_v3_r12_corpus_is_reproducible_from_independent_reference() -> None:
    assert CORPUS_PATH.read_text(encoding="utf-8") == render_corpus()


def test_v3_r12_corpus_covers_every_executable_suite() -> None:
    document = json.loads(CORPUS_PATH.read_text(encoding="utf-8"))
    assert document["schema"] == "sigma-v3-conformance-r12"
    assert document["record_version"] == 3
    assert {case["suite_id"] for case in document["cases"]} == {
        "0x0301",
        "0x0303",
        "0x0304",
    }


def test_v3_r12_corpus_matches_production_byte_for_byte() -> None:
    document = json.loads(CORPUS_PATH.read_text(encoding="utf-8"))
    for case in document["cases"]:
        _assert_case(case)


def _assert_case(case: dict[str, Any]) -> None:
    suite_id = SuiteIdV3(int(case["suite_id"], 16))
    message = _bytes(case["message_hex"])
    context = SigmaContextV3.for_suite(
        suite_id,
        salt=_bytes(case["salt_hex"]),
        challenge=_bytes(case["challenge_hex"]),
        application_context=_bytes(case["application_context_hex"]),
    )
    evaluation = evaluate_v3(context, BytesSource(message))
    binding = evaluation.prepared.binding

    assert context.to_bytes().hex() == case["context_hex"]
    assert binding.cardinality.to_bytes().hex() == case["kappa_hex"]
    assert binding.anchor.to_bytes().hex() == case["anchor_hex"]
    assert [value.hex() for value in binding.anchor.components] == case["anchor_components_hex"]
    assert binding.length_signature.to_bytes().hex() == case["lambda_hex"]
    assert binding.joint_signature.to_bytes().hex() == case["joint_hex"]
    assert [value.hex() for value in binding.joint_signature.components] == case[
        "joint_components_hex"
    ]
    assert binding.to_bytes().hex() == case["binding_hex"]
    assert evaluation.parameters.target_round == case["t"]
    assert evaluation.parameters.state_count == case["k"]
    assert evaluation.parameters.to_bytes().hex() == case["parameters_hex"]

    assert evaluation.init_layout.to_bytes().hex() == case["init_layout"]["wire_hex"]
    assert _placements(evaluation.init_layout) == case["init_layout"]["placements"]
    assert [
        {
            "round_index": layout.round_index,
            "wire_hex": layout.to_bytes().hex(),
            "placements": _placements(layout),
        }
        for layout in evaluation.round_layouts
    ] == case["round_layouts"]

    init_frame = InitFrame(
        context,
        evaluation.prepared,
        evaluation.init_layout,
        BytesSource(message),
    ).to_bytes()
    assert init_frame.hex() == case["init_frame_hex"]

    round_frames: list[bytes] = []
    branch_frames: list[tuple[bytes, ...]] = []
    fold_frames: list[bytes] = []
    for index, layout in enumerate(evaluation.round_layouts):
        prior = evaluation.states[index]
        state_frame: RoundFrame | VectorRoundFrame
        if isinstance(evaluation, DeepVectorEvaluationV3):
            state_frame = VectorRoundFrame(context, binding, layout, index, prior)
        else:
            state_frame = RoundFrame(context, binding, layout, index, prior)
        round_frames.append(state_frame.to_bytes())
        if isinstance(evaluation, (DeepEvaluationV3, DeepVectorEvaluationV3)):
            branch_frames.append(
                tuple(
                    DeepBranchFrame(
                        context,
                        index,
                        position,
                        algorithm,
                        state_frame,
                    ).to_bytes()
                    for position, algorithm in enumerate(context.joint_algorithms)
                )
            )
            if isinstance(evaluation, DeepEvaluationV3):
                fold_frames.append(
                    DeepFoldFrame(
                        context,
                        index,
                        evaluation.branch_outputs[index],
                    ).to_bytes()
                )
        else:
            branch_frames.append(())

    assert [value.hex() for value in round_frames] == case["round_frames_hex"]
    assert [[value.hex() for value in group] for group in branch_frames] == case[
        "branch_frames_hex"
    ]
    if isinstance(evaluation, (DeepEvaluationV3, DeepVectorEvaluationV3)):
        branch_outputs = evaluation.branch_outputs
    else:
        branch_outputs = tuple(() for _ in evaluation.round_layouts)
    assert [[value.hex() for value in group] for group in branch_outputs] == case[
        "branch_outputs_hex"
    ]
    assert [value.hex() for value in fold_frames] == case["fold_frames_hex"]
    assert [value.hex() for value in evaluation.states] == case["states_hex"]
    assert evaluation.header.to_bytes().hex() == case["header_hex"]
    assert evaluation.window.to_bytes().hex() == case["window_hex"]
    digest = digest_from_evaluation_v3(evaluation).to_bytes()
    assert digest.hex() == case["digest_hex"]
    assert hashlib.sha256(digest).hexdigest() == case["digest_sha256"]
