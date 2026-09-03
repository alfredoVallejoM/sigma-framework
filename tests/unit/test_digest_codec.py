import pytest

from sigma.outputs import SigmaDigestV2
from sigma.spec import SigmaContextV2
from sigma.spec.encoding import DecodeError
from sigma.spec.ids import DIGEST_MAGIC


def make_digest() -> SigmaDigestV2:
    return SigmaDigestV2(SigmaContextV2(), (b"a" * 64, b"b" * 64))


def test_digest_round_trip_preserves_complete_states() -> None:
    digest = make_digest()
    assert SigmaDigestV2.from_bytes(digest.to_bytes()) == digest
    assert bytes.fromhex(digest.hex()) == digest.to_bytes()
    assert SigmaDigestV2.from_json(digest.to_json()) == digest


def test_digest_json_is_a_strict_presentation_wrapper() -> None:
    digest = make_digest()
    encoded = digest.to_json()
    assert '"format":"sigma-v2"' in encoded
    assert digest.hex() in encoded

    invalid = (
        "{}",
        '{"binary":"00","format":"unknown"}',
        '{"binary":"AA","format":"sigma-v2"}',
        '{"binary":"0","format":"sigma-v2"}',
        '{"binary":1,"format":"sigma-v2"}',
        '{"binary":"00","format":"sigma-v2","extra":false}',
        '{"binary":"00","binary":"00","format":"sigma-v2"}',
    )
    for value in invalid:
        with pytest.raises(DecodeError):
            SigmaDigestV2.from_json(value)


def test_digest_metadata_is_complete_and_non_ambiguous() -> None:
    metadata = make_digest().metadata()
    assert metadata["format"] == "sigma-v2"
    assert metadata["suite_name"] == "reference-stream-wide-v2-2"
    assert metadata["wire_frozen"] is True
    assert metadata["vectors_frozen"] is True
    assert metadata["suite_stable"] is True
    assert metadata["security_reviewed"] is False
    assert metadata["target_round"] == 1
    assert metadata["state_count"] == 2
    assert metadata["state_size"] == 64
    assert len(metadata["states_hex"]) == 2


def test_digest_requires_context_state_count() -> None:
    with pytest.raises(ValueError, match="state_count"):
        SigmaDigestV2(SigmaContextV2(), (b"a" * 64,))


def test_digest_requires_equal_nonempty_states() -> None:
    with pytest.raises(ValueError, match="exactly 64 bytes"):
        SigmaDigestV2(SigmaContextV2(), (b"a", b"bb"))
    with pytest.raises(ValueError, match="exactly 64 bytes"):
        SigmaDigestV2(SigmaContextV2(), (b"", b""))


@pytest.mark.parametrize("state_size", [0, 1, 63, 65, 1024, 1025])
def test_digest_constructor_rejects_non_suite_state_width(state_size: int) -> None:
    with pytest.raises(ValueError, match="exactly 64 bytes"):
        SigmaDigestV2(SigmaContextV2(), (b"a" * state_size, b"b" * state_size))


def test_digest_constructor_accepts_suite_state_width() -> None:
    SigmaDigestV2(SigmaContextV2(), (b"a" * 64, b"b" * 64))


@pytest.mark.parametrize("state_size", [0, 1, 63, 65, 1024, 1025])
def test_digest_parser_rejects_non_suite_state_width(state_size: int) -> None:
    context = SigmaContextV2().to_bytes()
    malformed = (
        DIGEST_MAGIC
        + len(context).to_bytes(4, "big")
        + context
        + (2).to_bytes(2, "big")
        + state_size.to_bytes(2, "big")
        + b"a" * state_size
        + state_size.to_bytes(2, "big")
        + b"b" * state_size
    )
    with pytest.raises(DecodeError, match="exactly 64 bytes"):
        SigmaDigestV2.from_bytes(malformed)


def test_digest_parser_rejects_count_downgrade() -> None:
    encoded = bytearray(make_digest().to_bytes())
    context_length = int.from_bytes(encoded[len(DIGEST_MAGIC) : len(DIGEST_MAGIC) + 4], "big")
    count_offset = len(DIGEST_MAGIC) + 4 + context_length
    encoded[count_offset : count_offset + 2] = b"\x00\x01"
    with pytest.raises(DecodeError, match="differs"):
        SigmaDigestV2.from_bytes(bytes(encoded))


@pytest.mark.parametrize("suffix", [b"\x00", b"garbage"])
def test_digest_parser_rejects_trailing_bytes(suffix: bytes) -> None:
    with pytest.raises(DecodeError, match="trailing"):
        SigmaDigestV2.from_bytes(make_digest().to_bytes() + suffix)


def test_digest_parser_rejects_corrupted_magic() -> None:
    encoded = make_digest().to_bytes()
    with pytest.raises(DecodeError, match="magic"):
        SigmaDigestV2.from_bytes(b"X" + encoded[1:])


def test_every_truncated_digest_prefix_is_rejected() -> None:
    encoded = make_digest().to_bytes()
    for end in range(len(encoded)):
        with pytest.raises(DecodeError):
            SigmaDigestV2.from_bytes(encoded[:end])
