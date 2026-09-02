import gc
import hashlib
import json
import statistics
import tracemalloc
from pathlib import Path

import pytest

from sigma.anchors import CrossWide
from sigma.presets import paranoid_deep_v2_2, paranoid_deep_vector_v2_2
from sigma.rounds import DeepVector, TraceConfig, TracePolicy
from sigma.spec.ids import DomainId, RoundProfileId
from sigma.v2 import hash_bytes, trace_bytes, verify_full


def test_deep_vector_is_a_distinct_wide_state_suite() -> None:
    context = paranoid_deep_vector_v2_2(target_round=2, state_count=3)
    digest = hash_bytes(b"vector", context)
    assert context.round_profile is RoundProfileId.DEEP_VECTOR
    assert len(digest.states) == 3
    assert all(len(vector) == len(context.branches) * 64 for vector in digest.states)
    assert digest != hash_bytes(b"vector", paranoid_deep_v2_2(target_round=2, state_count=3))
    assert verify_full(b"vector", digest)


def test_every_next_component_consumes_the_complete_previous_vector(monkeypatch) -> None:
    context = paranoid_deep_vector_v2_2()
    anchor = CrossWide.compute(context, (b"dependency",))
    engine = DeepVector(context)
    vector = engine._initial_state(anchor)
    captured = []

    def capture(algorithm, data):
        captured.append(data)
        return b"x" * 64

    monkeypatch.setattr("sigma.rounds.deep_vector.hash_once", capture)
    engine.next_state(anchor, 0, vector)
    assert len(captured) == len(context.branches)
    assert all(vector in framed for framed in captured)
    assert all(
        framed.startswith(b"SIGMADST" + int(DomainId.VECTOR_ROUND).to_bytes(2, "big"))
        for framed in captured
    )


def test_deep_vector_trace_publishes_components_without_a_fold() -> None:
    context = paranoid_deep_vector_v2_2(target_round=2, state_count=2)
    transcript = trace_bytes(b"trace", context)
    assert len(transcript.states) == 4
    assert len(transcript.branch_outputs) == 4
    for vector, components in zip(transcript.states, transcript.branch_outputs, strict=True):
        assert vector == b"".join(components)


def test_deep_vector_rolling_matches_trace_and_none_retains_nothing() -> None:
    context = paranoid_deep_vector_v2_2(target_round=5, state_count=2)
    anchor = CrossWide.compute(context, (b"rolling",))
    engine = DeepVector(context)
    rolling = engine.evaluate_digest(anchor)
    traced, transcript = engine.evaluate(anchor)
    assert rolling == traced
    assert rolling.states == transcript.states[-2:]
    none_digest, none = engine.evaluate_trace(anchor, TraceConfig(TracePolicy.NONE))
    assert none_digest == rolling
    assert none.states == none.branch_outputs == ()


def _rolling_peak(target_round: int) -> int:
    context = paranoid_deep_vector_v2_2(target_round=target_round, state_count=2)
    anchor = CrossWide.compute(context, (b"memory",))
    peaks = []
    for _ in range(3):
        gc.collect()
        tracemalloc.start()
        DeepVector(context).evaluate_digest(anchor)
        _, peak = tracemalloc.get_traced_memory()
        tracemalloc.stop()
        peaks.append(peak)
    return int(statistics.median(peaks))


def test_deep_vector_rolling_memory_is_bounded_in_depth() -> None:
    assert _rolling_peak(512) <= _rolling_peak(16) + 24 * 1024


def test_deep_vector_rejects_wrong_anchor_and_vector_width() -> None:
    context = paranoid_deep_vector_v2_2()
    engine = DeepVector(context)
    anchor = CrossWide.compute(context, (b"width",))
    with pytest.raises(ValueError, match="exactly"):
        engine.next_state(anchor, 0, b"short")
    with pytest.raises(TypeError, match="CrossWide"):
        engine.evaluate_digest(object())  # type: ignore[arg-type]


def test_deep_vector_frozen_intermediate_vector() -> None:
    vector = json.loads(
        Path("specification/test-vectors/paranoid-deep-vector-v2-2.json").read_text(
            encoding="utf-8"
        )
    )
    context = paranoid_deep_vector_v2_2(target_round=2, state_count=2)
    anchor = CrossWide.compute(context, (bytes.fromhex(vector["message_hex"]),))
    digest, transcript = DeepVector(context).evaluate(anchor)

    def sha256(value: bytes) -> str:
        return hashlib.sha256(value).hexdigest()

    assert context.to_bytes().hex() == vector["context_hex"]
    assert sha256(anchor.to_bytes()) == vector["evidence_sha256"]
    assert [sha256(root) for root in anchor.roots] == vector["root_sha256"]
    assert [sha256(root) for root in anchor.cross_roots] == vector["cross_root_sha256"]
    assert [sha256(state) for state in transcript.states] == vector["vector_sha256"]
    assert [[sha256(item) for item in row] for row in transcript.branch_outputs] == vector[
        "component_sha256"
    ]
    assert sha256(digest.to_bytes()) == vector["digest_sha256"]
