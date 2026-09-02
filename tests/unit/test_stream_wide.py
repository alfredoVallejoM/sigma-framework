import pytest

from sigma.anchors import StreamWide
from sigma.spec import SigmaContextV2


def test_anchor_is_independent_of_api_chunk_boundaries() -> None:
    context = SigmaContextV2()
    one_chunk = StreamWide.compute(context, [b"abcdefghijk"])
    many_chunks = StreamWide.compute(context, [b"", b"a", b"bc", b"defg", b"hijk", b""])
    assert many_chunks == one_chunk
    assert one_chunk.message_length == 11
    assert one_chunk.physical_width_bits == 2048


def test_empty_anchor_is_not_zero_and_has_all_roots() -> None:
    anchor = StreamWide.compute(SigmaContextV2(), [])
    assert len(anchor.roots) == 4
    assert all(len(root) == 64 and root != b"\x00" * 64 for root in anchor.roots)


def test_message_and_context_are_bound() -> None:
    base = StreamWide.compute(SigmaContextV2(), [b"message"])
    changed_message = StreamWide.compute(SigmaContextV2(), [b"messagf"])
    changed_context = StreamWide.compute(SigmaContextV2(application_context=b"other"), [b"message"])
    assert base.roots != changed_message.roots
    assert base.roots != changed_context.roots


def test_suite_rejects_mismatched_profiles() -> None:
    from sigma.spec.ids import AnchorProfileId

    with pytest.raises(ValueError, match="anchor_profile"):
        StreamWide(SigmaContextV2(anchor_profile=AnchorProfileId.CROSS_WIDE))


def test_stream_finalization_is_single_use() -> None:
    stream = StreamWide(SigmaContextV2())
    stream.finalize()
    with pytest.raises(RuntimeError, match="finalized"):
        stream.finalize()
    with pytest.raises(RuntimeError, match="finalized"):
        stream.update(b"late")
