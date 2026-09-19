from __future__ import annotations

import ast
import hashlib
import io
from dataclasses import replace
from pathlib import Path

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st

from reference.independent_v3 import evaluate as independent_evaluate
from sigma.binding import TrajectoryParameters
from sigma.crypto.primitives import domain_tag_v3
from sigma.rounds.framing_v3 import InitFrame, RoundFrame
from sigma.sources import BytesSource, SpoolingStreamSource, StableFileSource
from sigma.spec.context_v3 import SigmaContextV3
from sigma.spec.ids_v3 import DomainIdV3
from sigma.v3 import evaluate_wide_once_bytes_v3, evaluate_wide_once_v3


def _context() -> SigmaContextV3:
    return SigmaContextV3.reference(
        salt=b"R7-salt",
        challenge=b"R7-challenge",
        application_context=b"tests/v3/wide-once",
    )


def test_wide_once_is_deterministic_and_window_is_exact_tail() -> None:
    first = evaluate_wide_once_bytes_v3(_context(), b"trajectory")
    second = evaluate_wide_once_bytes_v3(_context(), b"trajectory")

    assert first == second
    start = first.parameters.target_round
    stop = start + first.parameters.state_count
    assert first.window.states == first.states[start:stop]
    assert len(first.states) == stop
    assert first.header.parameters == first.parameters
    assert first.header.cardinality == first.prepared.binding.cardinality


def test_wide_once_matches_direct_standard_library_state_hashing() -> None:
    message = b"independent-state-check"
    evaluation = evaluate_wide_once_bytes_v3(_context(), message)
    init_frame = InitFrame(
        evaluation.context,
        evaluation.prepared,
        evaluation.init_layout,
        BytesSource(message),
    ).to_bytes()
    state = hashlib.sha512(domain_tag_v3(DomainIdV3.INIT_FRAME) + init_frame).digest()
    assert state == evaluation.states[0]

    for index, layout in enumerate(evaluation.round_layouts):
        frame = RoundFrame(
            evaluation.context,
            evaluation.prepared.binding,
            layout,
            index,
            state,
        ).to_bytes()
        state = hashlib.sha512(domain_tag_v3(DomainIdV3.ROUND_FRAME) + frame).digest()
        assert state == evaluation.states[index + 1]


def test_wide_once_is_source_independent_and_input_sensitive(tmp_path) -> None:
    message = b"same canonical source" * 50
    path = tmp_path / "message.bin"
    path.write_bytes(message)
    expected = evaluate_wide_once_v3(_context(), BytesSource(message))
    from_file = evaluate_wide_once_v3(_context(), StableFileSource(path))
    with SpoolingStreamSource(
        io.BytesIO(message), max_memory_bytes=32, max_spool_bytes=len(message)
    ) as stream:
        from_stream = evaluate_wide_once_v3(_context(), stream)

    assert from_file == expected == from_stream
    changed = evaluate_wide_once_bytes_v3(_context(), message[:-1] + b"X")
    assert changed.prepared.binding != expected.prepared.binding
    assert changed.states != expected.states
    assert changed.window != expected.window


def test_wide_once_known_answer() -> None:
    evaluation = evaluate_wide_once_bytes_v3(_context(), b"Sigma v3 R7 KAT")

    assert evaluation.parameters.to_bytes().hex() == (
        "5349474d4133545000030000001c00010000000800000000000000180002000000080000000000000004"
    )
    assert hashlib.sha256(b"".join(evaluation.states)).hexdigest() == (
        "3de50932b9ad73aae2c67db432ec2da1b6128d702284152867dc89d707fb595e"
    )
    assert hashlib.sha256(evaluation.header.to_bytes()).hexdigest() == (
        "9c3e289dc563c45392363ab07474a1b2ea2bd725169f68ccad85c059b734f3bd"
    )
    assert hashlib.sha256(evaluation.window.to_bytes()).hexdigest() == (
        "4acb47ee8bb869dcaf1502740912d24dfb3cd7feacf7c2140d9c4c3f7db4d7af"
    )


def test_wide_once_matches_fully_independent_reference() -> None:
    message = b"independent-full-pipeline"
    context = _context()
    actual = evaluate_wide_once_bytes_v3(context, message)
    expected = independent_evaluate(
        message,
        salt=context.salt,
        challenge=context.challenge,
        application_context=context.application_context,
    )
    binding = actual.prepared.binding
    init_frame = InitFrame(
        context, actual.prepared, actual.init_layout, BytesSource(message)
    ).to_bytes()
    round_frames = tuple(
        RoundFrame(context, binding, layout, index, actual.states[index]).to_bytes()
        for index, layout in enumerate(actual.round_layouts)
    )

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
    assert tuple(item.to_bytes() for item in actual.round_layouts) == expected["round_layouts"]
    assert init_frame == expected["init_frame"]
    assert round_frames == expected["round_frames"]
    assert actual.states == expected["states"]
    assert actual.header.to_bytes() == expected["header"]
    assert actual.window.to_bytes() == expected["window"]

    reference_path = Path(__file__).parents[2] / "reference" / "independent_v3.py"
    tree = ast.parse(reference_path.read_text(encoding="utf-8"))
    imported_modules = {
        alias.name
        for node in ast.walk(tree)
        if isinstance(node, ast.Import)
        for alias in node.names
    } | {node.module or "" for node in ast.walk(tree) if isinstance(node, ast.ImportFrom)}
    assert not any(name == "sigma" or name.startswith("sigma.") for name in imported_modules)


@settings(max_examples=40, deadline=None)
@given(
    message=st.binary(max_size=64),
    salt=st.binary(max_size=8),
    challenge=st.binary(max_size=8),
    application_context=st.binary(max_size=8),
)
def test_wide_once_matches_independent_reference_over_generated_inputs(
    message: bytes,
    salt: bytes,
    challenge: bytes,
    application_context: bytes,
) -> None:
    context = SigmaContextV3.reference(
        salt=salt,
        challenge=challenge,
        application_context=application_context,
    )
    actual = evaluate_wide_once_bytes_v3(context, message)
    expected = independent_evaluate(
        message,
        salt=salt,
        challenge=challenge,
        application_context=application_context,
    )

    assert actual.prepared.binding.to_bytes() == expected["binding"]
    assert actual.parameters.to_bytes() == expected["parameters"]
    assert actual.init_layout.to_bytes() == expected["init_layout"]
    assert tuple(layout.to_bytes() for layout in actual.round_layouts) == expected["round_layouts"]
    assert actual.states == expected["states"]
    assert actual.header.to_bytes() == expected["header"]
    assert actual.window.to_bytes() == expected["window"]


def test_evaluation_rejects_cross_message_artifacts() -> None:
    first = evaluate_wide_once_bytes_v3(_context(), b"A")
    second = evaluate_wide_once_bytes_v3(_context(), b"BB")
    with pytest.raises(ValueError, match="header"):
        replace(first, header=second.header)
    with pytest.raises(ValueError, match="parameters"):
        replace(
            first,
            parameters=TrajectoryParameters(
                2 if first.parameters.target_round != 2 else 3,
                first.parameters.state_count,
            ),
        )
    with pytest.raises(ValueError, match="layout"):
        replace(first, init_layout=second.init_layout)


def test_context_component_mutation_matrix_changes_trajectory() -> None:
    message = b"context-sensitive"
    base = _context()
    contexts = (
        replace(base, salt=base.salt + b"x"),
        replace(base, challenge=base.challenge + b"x"),
        replace(base, application_context=base.application_context + b"x"),
    )
    original = evaluate_wide_once_bytes_v3(base, message)
    for context in contexts:
        changed = evaluate_wide_once_bytes_v3(context, message)
        assert changed.prepared.binding != original.prepared.binding
        assert changed.states != original.states
        assert changed.header != original.header
