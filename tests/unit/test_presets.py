import pytest

from sigma.backends import MultiprocessingTreeBackend
from sigma.incremental import IncrementalSigmaV2
from sigma.presets import (
    get_preset,
    lightweight_v2_2,
    paranoid_deep_v2_2,
    paranoid_deep_vector_v2_2,
    paranoid_wide_v2_2,
    reference_v2_2,
    simultaneous_v2_2,
)
from sigma.spec.ids import AnchorProfileId, RoundProfileId
from sigma.suites.registry import get_suite
from sigma.v2 import hash_bytes


def test_active_presets_are_exact_and_produce_distinct_digests() -> None:
    contexts = (
        reference_v2_2(),
        lightweight_v2_2(),
        simultaneous_v2_2(),
        paranoid_wide_v2_2(),
        paranoid_deep_v2_2(),
        paranoid_deep_vector_v2_2(),
    )
    assert len({context.suite_id for context in contexts}) == len(contexts)
    digests = {hash_bytes(b"same message", context).to_bytes() for context in contexts}
    assert len(digests) == len(contexts)


def test_preset_semantics_match_names() -> None:
    assert lightweight_v2_2().anchor_profile is AnchorProfileId.STREAM_WIDE
    assert simultaneous_v2_2().anchor_profile is AnchorProfileId.TREE_WIDE
    assert simultaneous_v2_2().chunk_size == 65536
    assert paranoid_wide_v2_2().anchor_profile is AnchorProfileId.CROSS_WIDE
    assert paranoid_deep_v2_2().round_profile is RoundProfileId.DEEP


def test_simultaneous_backend_is_an_execution_choice() -> None:
    context = simultaneous_v2_2(target_round=2)
    payload = b"x" * 70000
    assert hash_bytes(payload, context) == hash_bytes(
        payload, context, MultiprocessingTreeBackend(3)
    )


def test_stream_preset_supports_explicit_finalization() -> None:
    context = lightweight_v2_2()
    stream = IncrementalSigmaV2(context)
    stream.update(b"a")
    stream.update(b"bc")
    assert stream.finalize() == hash_bytes(b"abc", context)


def test_unknown_preset_is_rejected() -> None:
    with pytest.raises(ValueError, match="unknown"):
        get_preset("imaginary-v2")


def test_reference_v22_preset_exposes_the_registered_reference_suite() -> None:
    context = reference_v2_2()
    assert get_preset("reference-v2-2") == context
    assert context.anchor_profile is AnchorProfileId.STREAM_WIDE
    assert context.round_profile is RoundProfileId.WIDE_ONCE


def test_deep_vector_preset_has_its_own_wide_state_suite() -> None:
    context = paranoid_deep_vector_v2_2()
    assert context.suite_id not in {
        paranoid_deep_v2_2().suite_id,
    }
    assert len(hash_bytes(b"vector", context).states[0]) == 256


@pytest.mark.parametrize(
    "context",
    [
        reference_v2_2(),
        lightweight_v2_2(),
        simultaneous_v2_2(),
        paranoid_wide_v2_2(),
        paranoid_deep_v2_2(),
        paranoid_deep_vector_v2_2(),
    ],
)
def test_v22_mathematical_sizes_are_owned_by_suite_descriptor(context) -> None:
    suite = get_suite(context.suite_id)
    assert context.chunk_size == suite.tree_chunk_size
    expected_state_size = (
        suite.anchor_component_size * len(suite.branches)
        if context.round_profile is RoundProfileId.DEEP_VECTOR
        else suite.anchor_component_size
    )
    assert suite.state_size == expected_state_size
