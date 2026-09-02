import pytest

from sigma.anchors import StreamWide
from sigma.rounds import WideOnce
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
