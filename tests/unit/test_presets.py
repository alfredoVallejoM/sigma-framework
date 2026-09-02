import pytest

from sigma.backends import MultiprocessingTreeBackend
from sigma.incremental import IncrementalSigmaV2
from sigma.presets import (
    get_preset,
    lightweight_v2,
    paranoid_deep_v2,
    paranoid_wide_v2,
    realtime_v2,
    simultaneous_v2,
)
from sigma.spec.ids import AnchorProfileId, RoundProfileId
from sigma.v2 import hash_bytes


def test_presets_are_exact_and_produce_distinct_digests() -> None:
    contexts = (
        lightweight_v2(),
        simultaneous_v2(),
        realtime_v2(),
        paranoid_wide_v2(),
        paranoid_deep_v2(),
    )
    assert len({context.suite_id for context in contexts}) == len(contexts)
    digests = {hash_bytes(b"same message", context).to_bytes() for context in contexts}
    assert len(digests) == len(contexts)


def test_preset_semantics_match_names() -> None:
    assert lightweight_v2().anchor_profile is AnchorProfileId.STREAM_WIDE
    assert simultaneous_v2().anchor_profile is AnchorProfileId.TREE_WIDE
    assert simultaneous_v2().chunk_size == 65536
    assert realtime_v2().anchor_profile is AnchorProfileId.STREAM_WIDE
    assert paranoid_wide_v2().anchor_profile is AnchorProfileId.CROSS_WIDE
    assert paranoid_deep_v2().round_profile is RoundProfileId.DEEP


def test_simultaneous_backend_is_an_execution_choice() -> None:
    context = simultaneous_v2(target_round=2)
    payload = b"x" * 70000
    assert hash_bytes(payload, context) == hash_bytes(
        payload, context, MultiprocessingTreeBackend(3)
    )


def test_realtime_preset_supports_explicit_finalization() -> None:
    context = realtime_v2()
    stream = IncrementalSigmaV2(context)
    stream.update(b"a")
    stream.update(b"bc")
    assert stream.finalize() == hash_bytes(b"abc", context)


def test_unknown_preset_is_rejected() -> None:
    with pytest.raises(ValueError, match="unknown"):
        get_preset("imaginary-v2")
