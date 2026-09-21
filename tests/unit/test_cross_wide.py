from sigma.anchors import CrossWide, StreamWide
from sigma.presets import paranoid_wide_v2_2
from sigma.rounds import WideOnce
from sigma.spec import SigmaContextV2
from sigma.v2 import hash_bytes, verify_full


def cross_context(**kwargs) -> SigmaContextV2:
    return paranoid_wide_v2_2(**kwargs)


def test_cross_wide_retains_roots_and_adds_connections() -> None:
    context = cross_context()
    base = StreamWide.compute(context, (b"abc",))
    cross = CrossWide.compute(context, (b"abc",))
    assert cross.roots == base.roots
    assert len(cross.cross_roots) == len(cross.roots) == 4
    assert cross.physical_width_bits == 4096
    for root in cross.roots:
        assert root in cross.to_bytes()


def test_every_cross_connection_depends_on_complete_root_vector() -> None:
    context = cross_context()
    original = CrossWide.compute(context, (b"abc",))
    changed = CrossWide.compute(context, (b"abd",))
    assert original.roots != changed.roots
    assert all(
        left != right
        for left, right in zip(original.cross_roots, changed.cross_roots, strict=False)
    )


def test_cross_wide_is_chunk_boundary_independent() -> None:
    context = cross_context(target_round=2)
    one = hash_bytes(b"abcdefgh", context)
    split = CrossWide.compute(context, (b"a", b"bc", b"", b"defgh"))
    from_split, _ = WideOnce(context).evaluate(split)
    assert from_split == one
    assert verify_full(b"abcdefgh", one)


def test_cross_suite_digest_differs_from_stream_suite() -> None:
    assert hash_bytes(b"abc", cross_context()) != hash_bytes(b"abc", SigmaContextV2())
