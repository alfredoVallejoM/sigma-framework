import gc
import statistics
import tracemalloc

from sigma.anchors import CrossWide
from sigma.presets import paranoid_deep_v2, paranoid_wide_v2
from sigma.rounds import Deep, TraceConfig, TracePolicy
from sigma.v2 import hash_bytes, trace_bytes, verify_full


def test_deep_evaluates_every_branch_at_every_transition() -> None:
    context = paranoid_deep_v2(target_round=2, state_count=3)
    transcript = trace_bytes(b"abc", context)
    assert len(transcript.states) == 5
    assert len(transcript.branch_outputs) == 4
    assert all(len(outputs) == len(context.branches) for outputs in transcript.branch_outputs)
    assert all(len(output) == 64 for outputs in transcript.branch_outputs for output in outputs)


def test_deep_reinjects_cross_anchor() -> None:
    context = paranoid_deep_v2()
    engine = Deep(context)
    anchor_a = CrossWide.compute(context, (b"a",))
    anchor_b = CrossWide.compute(context, (b"b",))
    collision = b"\x5a" * 64
    assert engine.next_state(anchor_a, 0, collision) != engine.next_state(anchor_b, 0, collision)


def test_deep_and_wide_are_separate_suites_and_verify_fully() -> None:
    deep = hash_bytes(b"abc", paranoid_deep_v2(target_round=2))
    wide = hash_bytes(b"abc", paranoid_wide_v2(target_round=2))
    assert deep != wide
    assert verify_full(b"abc", deep)
    assert not verify_full(b"abd", deep)


def test_deep_rolling_evaluation_matches_full_trace() -> None:
    context = paranoid_deep_v2(target_round=8, state_count=3)
    anchor = CrossWide.compute(context, (b"abc",))
    engine = Deep(context)
    rolling = engine.evaluate_digest(anchor)
    traced, transcript = engine.evaluate(anchor)
    assert rolling == traced
    assert rolling.states == transcript.states[-context.state_count :]

    no_trace_digest, transcript = engine.evaluate_trace(anchor, TraceConfig(TracePolicy.NONE))
    assert no_trace_digest == rolling
    assert transcript.states == ()
    assert transcript.branch_outputs == ()


def _deep_rolling_peak(target_round: int) -> int:
    context = paranoid_deep_v2(target_round=target_round, state_count=3)
    anchor = CrossWide.compute(context, (b"memory-regression",))
    peaks = []
    for _ in range(3):
        gc.collect()
        tracemalloc.start()
        Deep(context).evaluate_digest(anchor)
        _, peak = tracemalloc.get_traced_memory()
        tracemalloc.stop()
        peaks.append(peak)
    return int(statistics.median(peaks))


def test_deep_rolling_memory_does_not_retain_round_branches() -> None:
    assert _deep_rolling_peak(512) <= _deep_rolling_peak(16) + 16 * 1024
