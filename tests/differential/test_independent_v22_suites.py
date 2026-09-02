import pytest

from reference.independent_v22 import ALGORITHMS, LIGHT_ALGORITHMS, sequential_suite, tree_suite
from sigma.anchors import CrossWide, StreamWide, TreeWide
from sigma.presets import (
    lightweight_v2_2,
    paranoid_deep_v2_2,
    paranoid_wide_v2_2,
    simultaneous_v2_2,
)
from sigma.rounds import Deep, WideOnce
from sigma.spec import SigmaContextV2
from sigma.spec.ids import AnchorProfileId, RoundProfileId, SuiteId
from sigma.suites.registry import get_suite


def _reference_context(
    *,
    target_round: int,
    state_count: int,
    salt: bytes,
    challenge: bytes,
    application_context: bytes,
) -> SigmaContextV2:
    suite_id = SuiteId.REFERENCE_STREAM_WIDE_V2_2
    return SigmaContextV2(
        suite_id=suite_id,
        anchor_profile=AnchorProfileId.STREAM_WIDE,
        round_profile=RoundProfileId.WIDE_ONCE,
        branches=get_suite(suite_id).branches,
        target_round=target_round,
        state_count=state_count,
        salt=salt,
        challenge=challenge,
        application_context=application_context,
    )


SEQUENTIAL_CASES = (
    (0x0101, 1, 1, ALGORITHMS, _reference_context, StreamWide, WideOnce),
    (0x0102, 1, 1, LIGHT_ALGORITHMS, lightweight_v2_2, StreamWide, WideOnce),
    (0x0104, 3, 1, ALGORITHMS, paranoid_wide_v2_2, CrossWide, WideOnce),
    (0x0105, 3, 2, ALGORITHMS, paranoid_deep_v2_2, CrossWide, Deep),
)


@pytest.mark.parametrize(
    "suite_id,anchor_profile,round_profile,algorithms,context_factory,anchor_type,round_type",
    SEQUENTIAL_CASES,
)
@pytest.mark.parametrize("size", [0, 1, 63, 64, 65, 1025])
@pytest.mark.parametrize("target_round,state_count", [(0, 1), (1, 2), (3, 2)])
def test_independent_sequential_suites_match_every_intermediate(
    suite_id,
    anchor_profile,
    round_profile,
    algorithms,
    context_factory,
    anchor_type,
    round_type,
    size: int,
    target_round: int,
    state_count: int,
) -> None:
    message = bytes((size + 29 * index) % 256 for index in range(size))
    context = context_factory(
        target_round=target_round,
        state_count=state_count,
        salt=b"salt",
        challenge=b"challenge",
        application_context=b"differential",
    )
    anchor = anchor_type.compute(context, (message,))
    digest, transcript = round_type(context).evaluate(anchor)
    independent = sequential_suite(
        message,
        suite_id,
        anchor_profile,
        round_profile,
        algorithms=algorithms,
        target_round=target_round,
        state_count=state_count,
        salt=b"salt",
        challenge=b"challenge",
        application_context=b"differential",
    )
    assert independent["context"] == context.to_bytes()
    assert independent["roots"] == list(anchor.roots)
    assert independent["cross_roots"] == list(getattr(anchor, "cross_roots", ()))
    assert independent["evidence"] == anchor.to_bytes()
    assert independent["states"] == list(transcript.states)
    assert independent["branch_outputs"] == [list(row) for row in transcript.branch_outputs]
    assert independent["digest"] == digest.to_bytes()


@pytest.mark.parametrize("size", [0, 1, 65535, 65536, 65537, 3 * 65536 + 17])
@pytest.mark.parametrize("target_round,state_count", [(0, 1), (1, 2), (3, 2)])
def test_independent_tree_suite_matches_every_intermediate(
    size: int, target_round: int, state_count: int
) -> None:
    message = bytes((size + 17 * index) % 256 for index in range(size))
    context = simultaneous_v2_2(
        target_round=target_round,
        state_count=state_count,
        salt=b"salt",
        challenge=b"challenge",
        application_context=b"tree-differential",
    )
    anchor = TreeWide.compute(context, (message,))
    digest, transcript = WideOnce(context).evaluate(anchor)
    independent = tree_suite(
        message,
        target_round=target_round,
        state_count=state_count,
        salt=b"salt",
        challenge=b"challenge",
        application_context=b"tree-differential",
    )
    assert independent["context"] == context.to_bytes()
    assert independent["roots"] == list(anchor.roots)
    assert independent["evidence"] == anchor.to_bytes()
    assert independent["states"] == list(transcript.states)
    assert independent["digest"] == digest.to_bytes()
