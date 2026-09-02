from sigma.anchors import CrossWide
from sigma.presets import paranoid_deep_v2, paranoid_wide_v2
from sigma.rounds import Deep
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
