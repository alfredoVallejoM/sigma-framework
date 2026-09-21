import pytest

from scripts.fuzz_codecs import canonical_codec_cases
from sigma.spec.encoding import DecodeError, decode_uint

TLV_OFFSETS = {
    "context": len(b"SIGMACTX") + 6,
    "evidence-wide": len(b"SIGMAAE") + 10,
    "evidence-cross": len(b"SIGMAAE") + 10,
    "pow": len(b"SIGMAPOW3"),
    "kdf": len(b"SIGMAKDF2"),
    "kdf-record": len(b"SIGMAKVR2"),
    "signed": len(b"SIGMASIG") + 2,
}
TLV_CODEC_CASES = tuple(case for case in canonical_codec_cases() if case[0] in TLV_OFFSETS)


@pytest.mark.parametrize("name,encoded,parser", canonical_codec_cases())
def test_every_public_codec_rejects_all_truncated_prefixes(name, encoded, parser) -> None:
    for end in range(len(encoded)):
        with pytest.raises(DecodeError):
            parser(encoded[:end])


@pytest.mark.parametrize("name,encoded,parser", canonical_codec_cases())
def test_every_public_codec_rejects_trailing_bytes(name, encoded, parser) -> None:
    with pytest.raises(DecodeError):
        parser(encoded + b"\x00")


@pytest.mark.parametrize("name,encoded,parser", canonical_codec_cases())
def test_every_public_codec_rejects_wrong_magic(name, encoded, parser) -> None:
    corrupted = bytes((encoded[0] ^ 1,)) + encoded[1:]
    with pytest.raises(DecodeError):
        parser(corrupted)


@pytest.mark.parametrize("name,encoded,parser", TLV_CODEC_CASES)
def test_every_tlv_schema_rejects_unknown_and_duplicate_tags(name, encoded, parser) -> None:
    offset = TLV_OFFSETS[name]
    unknown = bytearray(encoded)
    unknown[offset : offset + 2] = b"\xff\xff"
    with pytest.raises(DecodeError, match="unknown"):
        parser(bytes(unknown))

    first_length = int.from_bytes(encoded[offset + 2 : offset + 6], "big")
    second_offset = offset + 6 + first_length
    duplicate = bytearray(encoded)
    duplicate[second_offset : second_offset + 2] = encoded[offset : offset + 2]
    with pytest.raises(DecodeError, match=r"order|duplicated"):
        parser(bytes(duplicate))


@pytest.mark.parametrize("width", [0, 3, 5, 16])
def test_integer_decoder_rejects_unregistered_widths(width: int) -> None:
    with pytest.raises(ValueError, match="width"):
        decode_uint(b"", width)


@pytest.mark.parametrize("value", [bytearray(b"\x00"), memoryview(b"\x00"), "\x00"])
def test_integer_decoder_rejects_non_bytes(value: object) -> None:
    with pytest.raises(TypeError, match="bytes"):
        decode_uint(value, 1)  # type: ignore[arg-type]
