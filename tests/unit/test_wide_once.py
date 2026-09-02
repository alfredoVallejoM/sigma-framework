import gc
import statistics
import tracemalloc

import pytest

from sigma.anchors import StreamWide
from sigma.rounds import TraceConfig, TracePolicy, WideOnce
from sigma.spec import SigmaContextV2


@pytest.mark.parametrize("target_round,state_count", [(0, 1), (0, 2), (1, 2), (2, 3)])
def test_selected_states_are_consecutive(target_round: int, state_count: int) -> None:
    context = SigmaContextV2(target_round=target_round, state_count=state_count)
    anchor = StreamWide.compute(context, [b"abc"])
    digest, transcript = WideOnce(context).evaluate(anchor)
    assert digest.states == transcript.states[target_round : target_round + state_count]
    assert len(transcript.states) == target_round + state_count
    assert all(len(state) == 64 for state in digest.states)


def test_anchor_is_reinjected_after_state_collision() -> None:
    context = SigmaContextV2()
    engine = WideOnce(context)
    anchor_a = StreamWide.compute(context, [b"a"])
    anchor_b = StreamWide.compute(context, [b"b"])
    colliding_state = b"\x55" * 64
    assert engine.next_state(anchor_a, 3, colliding_state) != engine.next_state(
        anchor_b, 3, colliding_state
    )


def test_round_index_and_context_are_bound() -> None:
    context = SigmaContextV2()
    anchor = StreamWide.compute(context, [b"abc"])
    state = b"\x42" * 64
    assert WideOnce(context).next_state(anchor, 0, state) != WideOnce(context).next_state(
        anchor, 1, state
    )

    other_context = SigmaContextV2(application_context=b"other")
    other_anchor = StreamWide.compute(other_context, [b"abc"])
    assert WideOnce(context).next_state(anchor, 0, state) != WideOnce(other_context).next_state(
        other_anchor, 0, state
    )


def test_engine_rejects_wrong_state_size() -> None:
    context = SigmaContextV2()
    anchor = StreamWide.compute(context, [b"abc"])
    with pytest.raises(ValueError, match="64 bytes"):
        WideOnce(context).next_state(anchor, 0, b"short")


def test_rolling_evaluation_matches_full_trace_without_retaining_history() -> None:
    context = SigmaContextV2(target_round=128, state_count=3)
    anchor = StreamWide.compute(context, [b"abc"])
    engine = WideOnce(context)
    rolling = engine.evaluate_digest(anchor)
    traced, transcript = engine.evaluate(anchor)
    assert rolling == traced
    assert rolling.states == transcript.states[-context.state_count :]


def test_trace_policies_capture_only_requested_state_indices() -> None:
    context = SigmaContextV2(target_round=8, state_count=2)
    anchor = StreamWide.compute(context, [b"abc"])
    engine = WideOnce(context)
    digest, no_trace = engine.evaluate_trace(anchor, TraceConfig(TracePolicy.NONE))
    assert no_trace.states == ()
    assert no_trace.state_indices == ()
    assert digest == engine.evaluate_digest(anchor)

    _, selected = engine.evaluate_trace(
        anchor,
        TraceConfig(TracePolicy.SELECTED, selected_indices=(0, 3, 9)),
    )
    assert selected.state_indices == (0, 3, 9)

    _, sampled = engine.evaluate_trace(
        anchor,
        TraceConfig(TracePolicy.EVERY_N, every_n=4),
    )
    assert sampled.state_indices == (0, 4, 8)


def test_trace_budget_is_rejected_before_evaluation() -> None:
    context = SigmaContextV2(target_round=8, state_count=2)
    anchor = StreamWide.compute(context, [b"abc"])
    with pytest.raises(ValueError, match="max_entries"):
        WideOnce(context).evaluate_trace(
            anchor,
            TraceConfig(TracePolicy.FULL, max_entries=3),
        )


def _rolling_peak(target_round: int) -> int:
    context = SigmaContextV2(target_round=target_round, state_count=3)
    anchor = StreamWide.compute(context, [b"memory-regression"])
    peaks = []
    for _ in range(3):
        gc.collect()
        tracemalloc.start()
        WideOnce(context).evaluate_digest(anchor)
        _, peak = tracemalloc.get_traced_memory()
        tracemalloc.stop()
        peaks.append(peak)
    return int(statistics.median(peaks))


def test_rolling_evaluation_memory_does_not_scale_with_target_round() -> None:
    short_peak = _rolling_peak(16)
    long_peak = _rolling_peak(4096)
    # A former implementation retained 4,099 complete 64-byte states. Permit
    # allocator noise, but reject any return to storage proportional to t.
    assert long_peak <= short_peak + 16 * 1024
