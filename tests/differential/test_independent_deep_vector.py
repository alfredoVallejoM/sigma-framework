import pytest

from reference.independent_v22 import deep_vector
from sigma.anchors import CrossWide
from sigma.presets import paranoid_deep_vector_v2_2
from sigma.rounds import DeepVector


@pytest.mark.parametrize("size", [0, 1, 63, 64, 65, 1024, 1025])
@pytest.mark.parametrize("target_round,state_count", [(0, 1), (1, 2), (2, 3), (4, 1)])
def test_independent_deep_vector_matches_every_intermediate(
    size: int, target_round: int, state_count: int
) -> None:
    message = bytes((size + 31 * index) % 256 for index in range(size))
    context = paranoid_deep_vector_v2_2(
        target_round=target_round,
        state_count=state_count,
        salt=b"salt",
        challenge=b"challenge",
        application_context=b"differential",
    )
    anchor = CrossWide.compute(context, (message,))
    digest, transcript = DeepVector(context).evaluate(anchor)
    independent = deep_vector(
        message,
        target_round,
        state_count,
        salt=b"salt",
        challenge=b"challenge",
        application_context=b"differential",
    )
    assert independent["context"] == context.to_bytes()
    assert independent["roots"] == list(anchor.roots)
    assert independent["cross_roots"] == list(anchor.cross_roots)
    assert independent["evidence"] == anchor.to_bytes()
    assert independent["vectors"] == list(transcript.states)
    assert independent["components"] == [list(row) for row in transcript.branch_outputs]
    assert independent["digest"] == digest.to_bytes()
