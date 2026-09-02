import io

import pytest

from sigma.anchors import StreamWide
from sigma.outputs import SigmaDigestV2
from sigma.rounds import WideOnce
from sigma.spec import SigmaContextV2
from sigma.spec.encoding import DecodeError
from sigma.v2 import (
    hash_bytes,
    hash_chunks,
    hash_reader,
    hash_text,
    verify_adjacent_only,
    verify_full,
)


def test_all_streaming_entry_points_are_canonical() -> None:
    context = SigmaContextV2(target_round=2, state_count=2)
    payload = b"the same bytes through every adapter"
    expected = hash_bytes(payload, context)
    assert hash_chunks((payload[:1], payload[1:7], payload[7:]), context) == expected
    assert hash_reader(io.BytesIO(payload), context, read_size=3) == expected
    assert hash_reader(io.BytesIO(payload), context, read_size=65536) == expected


def test_hash_text_is_explicit_utf8() -> None:
    assert hash_text("Σigma").to_bytes() == hash_bytes("Σigma".encode("utf-8")).to_bytes()


def test_full_verification_binds_message_and_context() -> None:
    digest = hash_bytes(b"message", SigmaContextV2(application_context=b"test"))
    assert verify_full(b"message", digest)
    assert not verify_full(b"changed", digest)

    changed_context = SigmaContextV2(application_context=b"changed")
    forged = SigmaDigestV2(changed_context, digest.states)
    assert not verify_full(b"message", forged)


def test_corrupted_state_fails_full_verification() -> None:
    digest = hash_bytes(b"message")
    corrupted = bytes([digest.states[0][0] ^ 1]) + digest.states[0][1:]
    tampered = SigmaDigestV2(digest.context, (corrupted, digest.states[1]))
    assert not verify_full(b"message", tampered)


def test_every_digest_byte_is_parser_or_verifier_bound() -> None:
    message = b"binding audit"
    encoded = hash_bytes(message).to_bytes()
    for offset in range(len(encoded)):
        corrupted = bytearray(encoded)
        corrupted[offset] ^= 1
        try:
            parsed = SigmaDigestV2.from_bytes(bytes(corrupted))
        except DecodeError:
            continue
        assert not verify_full(message, parsed), f"unbound digest byte at offset {offset}"


def test_adjacent_verification_is_explicitly_local() -> None:
    context = SigmaContextV2(target_round=1, state_count=2)
    anchor = StreamWide.compute(context, (b"message",))
    digest, transcript = WideOnce(context).evaluate(anchor)
    assert digest.states == transcript.states[1:3]
    assert verify_adjacent_only(context, anchor, 1, digest.states[0], digest.states[1])
    assert not verify_adjacent_only(context, anchor, 1, b"x" * 64, digest.states[1])


@pytest.mark.parametrize("read_size", [0, -1, True])
def test_reader_rejects_invalid_buffer_size(read_size: int) -> None:
    with pytest.raises(ValueError, match="positive"):
        hash_reader(io.BytesIO(b"abc"), read_size=read_size)
