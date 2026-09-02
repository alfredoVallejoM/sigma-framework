from dataclasses import replace

import pytest

from sigma.anchors import AnchorEvidence, CrossWide, CrossWideEvidence, StreamWide, TreeWide
from sigma.presets import (
    lightweight_v2,
    lightweight_v2_2,
    paranoid_deep_v2_2,
    paranoid_wide_v2_2,
    simultaneous_v2_2,
)
from sigma.rounds import WideOnce
from sigma.spec.encoding import DecodeError
from sigma.spec.ids import EVIDENCE_MAGIC, EVIDENCE_VERSION, EvidenceType
from sigma.v2 import hash_bytes, verify_full


def _evidence(context):
    if context.anchor_profile.name == "STREAM_WIDE":
        return StreamWide.compute(context, (b"evidence",))
    if context.anchor_profile.name == "TREE_WIDE":
        return TreeWide.compute(context, (b"evidence",))
    return CrossWide.compute(context, (b"evidence",))


@pytest.mark.parametrize(
    "context",
    [
        lightweight_v2_2(),
        simultaneous_v2_2(),
        paranoid_wide_v2_2(),
        paranoid_deep_v2_2(),
    ],
)
def test_v22_evidence_round_trip_is_strict_and_suite_bound(context) -> None:
    evidence = _evidence(context)
    encoded = evidence.to_bytes()
    assert encoded.startswith(EVIDENCE_MAGIC)
    assert evidence.evidence_version == EVIDENCE_VERSION
    assert type(evidence).from_bytes(encoded, context) == evidence
    assert type(evidence).from_bytes(encoded, context).to_bytes() == encoded


def test_evidence_types_are_explicit_and_distinct() -> None:
    wide = _evidence(lightweight_v2_2())
    cross = _evidence(paranoid_wide_v2_2())
    assert isinstance(wide, AnchorEvidence)
    assert isinstance(cross, CrossWideEvidence)
    assert wide.evidence_type is EvidenceType.WIDE_ROOTS
    assert cross.evidence_type is EvidenceType.CROSS_WIDE
    assert wide.to_bytes()[:11] != cross.to_bytes()[:11]


def test_v21_evidence_encoding_remains_historical() -> None:
    evidence = StreamWide.compute(lightweight_v2(), (b"evidence",))
    assert evidence.evidence_version == 1
    assert not evidence.to_bytes().startswith(EVIDENCE_MAGIC)
    with pytest.raises(DecodeError, match="legacy"):
        AnchorEvidence.from_bytes(evidence.to_bytes(), lightweight_v2())


def test_v22_digest_round_trip_and_verification() -> None:
    for context in (lightweight_v2_2(), paranoid_wide_v2_2(), paranoid_deep_v2_2()):
        digest = hash_bytes(b"v2-2", context)
        assert verify_full(b"v2-2", digest)
        assert type(digest).from_bytes(digest.to_bytes()) == digest


def test_v22_rounds_reject_legacy_or_cross_suite_evidence() -> None:
    context = lightweight_v2_2()
    evidence = _evidence(context)
    with pytest.raises(ValueError, match="exact context suite"):
        WideOnce(context).evaluate_digest(replace(evidence, suite_id=None))
    with pytest.raises(ValueError, match="evidence suite"):
        replace(evidence, suite_id=simultaneous_v2_2().suite_id)


def test_every_truncated_evidence_prefix_is_rejected() -> None:
    context = paranoid_wide_v2_2()
    encoded = _evidence(context).to_bytes()
    for end in range(len(encoded)):
        with pytest.raises(DecodeError):
            CrossWideEvidence.from_bytes(encoded[:end], context)


@pytest.mark.parametrize(
    "offset,replacement,match",
    [
        (0, b"X", "magic"),
        (len(EVIDENCE_MAGIC), b"\x00\x03", "version"),
        (len(EVIDENCE_MAGIC) + 2, b"\x00\x63", "identifier"),
        (len(EVIDENCE_MAGIC) + 4, b"\x01\x03", "suite"),
    ],
)
def test_evidence_header_mutations_are_rejected(
    offset: int, replacement: bytes, match: str
) -> None:
    context = lightweight_v2_2()
    encoded = bytearray(_evidence(context).to_bytes())
    encoded[offset : offset + len(replacement)] = replacement
    with pytest.raises(DecodeError, match=match):
        AnchorEvidence.from_bytes(bytes(encoded), context)


def test_evidence_rejects_trailing_and_tlv_confusion() -> None:
    context = lightweight_v2_2()
    encoded = _evidence(context).to_bytes()
    with pytest.raises(DecodeError, match="length mismatch"):
        AnchorEvidence.from_bytes(encoded + b"\x00", context)

    body_offset = len(EVIDENCE_MAGIC) + 10
    second_tag_offset = body_offset + 6 + 8
    duplicate = bytearray(encoded)
    duplicate[second_tag_offset : second_tag_offset + 2] = b"\x00\x01"
    with pytest.raises(DecodeError, match="duplicated"):
        AnchorEvidence.from_bytes(bytes(duplicate), context)

    unknown = bytearray(encoded)
    unknown[second_tag_offset : second_tag_offset + 2] = b"\x00\x63"
    with pytest.raises(DecodeError, match="unknown"):
        AnchorEvidence.from_bytes(bytes(unknown), context)


def test_evidence_rejects_unknown_algorithm_and_component_length() -> None:
    context = lightweight_v2_2()
    encoded = _evidence(context).to_bytes()
    body_offset = len(EVIDENCE_MAGIC) + 10
    components_offset = body_offset + (6 + 8) + 6
    first_algorithm = components_offset + 2

    unknown_algorithm = bytearray(encoded)
    unknown_algorithm[first_algorithm : first_algorithm + 2] = b"\xff\xff"
    with pytest.raises(DecodeError, match="algorithm"):
        AnchorEvidence.from_bytes(bytes(unknown_algorithm), context)

    wrong_length = bytearray(encoded)
    wrong_length[first_algorithm + 2 : first_algorithm + 4] = b"\x00\x3f"
    with pytest.raises(DecodeError):
        AnchorEvidence.from_bytes(bytes(wrong_length), context)
