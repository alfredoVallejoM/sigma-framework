from __future__ import annotations

import hashlib

import pytest

from sigma.binding import JointSignature, PersistentBinding, derive_trajectory_parameters
from sigma.crypto.primitives import domain_tag_v3
from sigma.outputs.digest_v3 import (
    ExplicitAuditEvidenceV3,
    SigmaDigestV3,
    digest_from_evaluation_v3,
    verify_explicit_full_v3,
    verify_full_v3,
    verify_prepared_v3,
    verify_structure_v3,
)
from sigma.sources import BytesSource
from sigma.spec.context_v3 import SigmaContextV3
from sigma.spec.encoding import DecodeError, encode_tlv_field, encode_uint
from sigma.spec.ids_v3 import DomainIdV3, OutputProfileIdV3, SuiteIdV3
from sigma.suites.registry_v3 import get_evidence_envelope_v3, get_suite_v3
from sigma.v3 import evaluate_wide_once_bytes_v3


def _context() -> SigmaContextV3:
    return SigmaContextV3.reference(
        salt=b"R8-salt",
        challenge=b"R8-challenge",
        application_context=b"tests/v3/digest",
    )


def _digest(message: bytes = b"digest-message"):
    evaluation = evaluate_wide_once_bytes_v3(_context(), message)
    return evaluation, digest_from_evaluation_v3(evaluation)


def _fields(encoded: bytes) -> list[bytes]:
    result = []
    offset = 14
    while offset < len(encoded):
        length = int.from_bytes(encoded[offset + 2 : offset + 6], "big")
        end = offset + 6 + length
        result.append(encoded[offset:end])
        offset = end
    assert offset == len(encoded)
    return result


def _with_fields(encoded: bytes, fields: list[bytes]) -> bytes:
    body = b"".join(fields)
    return encoded[:10] + encode_uint(len(body), 4) + body


def test_digest_round_trip_and_structure_makes_no_binding_claim() -> None:
    evaluation, digest = _digest()
    encoded = digest.to_bytes()

    assert SigmaDigestV3.from_bytes(encoded) == digest
    structure = verify_structure_v3(encoded)
    assert structure.evidence == digest
    assert structure.structure_valid
    assert not structure.message_binding_verified
    assert verify_prepared_v3(evaluation, digest)


def test_digest_rejects_header_bound_to_another_context() -> None:
    evaluation, digest = _digest()
    other_context = SigmaContextV3.reference(
        salt=digest.context.salt + b"x",
        challenge=digest.context.challenge,
        application_context=digest.context.application_context,
    )

    with pytest.raises(ValueError, match="length signature"):
        SigmaDigestV3(other_context, evaluation.header, evaluation.window)


def test_full_verification_recomputes_header_and_entire_window() -> None:
    message = b"fully-bound"
    _, digest = _digest(message)

    assert verify_full_v3(BytesSource(message), digest)
    assert not verify_full_v3(BytesSource(b"fully-bounD"), digest)
    _, other = _digest(b"other-message")
    assert not verify_full_v3(BytesSource(message), other)


def test_implicit_digest_excludes_j_and_explicit_envelope_is_separate() -> None:
    evaluation, digest = _digest()
    binding = evaluation.prepared.binding
    implicit = digest.to_bytes()
    explicit = ExplicitAuditEvidenceV3(digest, binding)

    assert binding.joint_signature.to_bytes() not in implicit
    assert binding.to_bytes() in explicit.to_bytes()
    assert ExplicitAuditEvidenceV3.from_bytes(explicit.to_bytes()) == explicit
    assert explicit.to_bytes()[:8] != implicit[:8]
    assert verify_explicit_full_v3(BytesSource(b"digest-message"), explicit)


def test_explicit_envelope_rejects_joint_signature_with_different_parameters() -> None:
    evaluation, digest = _digest(b"explicit-j")
    binding = evaluation.prepared.binding
    mutated = None
    for delta in range(1, 256):
        component = (
            bytes((binding.joint_signature.components[0][0] ^ delta,))
            + binding.joint_signature.components[0][1:]
        )
        joint = JointSignature(
            binding.joint_signature.algorithms,
            (component, *binding.joint_signature.components[1:]),
        )
        candidate = PersistentBinding(
            binding.anchor,
            binding.cardinality,
            binding.length_signature,
            joint,
        )
        if derive_trajectory_parameters(digest.context, candidate) != digest.header.parameters:
            mutated = candidate
            break
    assert mutated is not None
    with pytest.raises(ValueError, match="different trajectory"):
        ExplicitAuditEvidenceV3(digest, mutated)


def test_explicit_full_rejects_mutated_j_even_when_parameters_collide() -> None:
    message = b"explicit-parameter-collision"
    evaluation, digest = _digest(message)
    binding = evaluation.prepared.binding
    colliding = None
    original_component = binding.joint_signature.components[0]
    for position in range(len(original_component)):
        for delta in range(1, 256):
            changed = bytearray(original_component)
            changed[position] ^= delta
            candidate = PersistentBinding(
                binding.anchor,
                binding.cardinality,
                binding.length_signature,
                JointSignature(
                    binding.joint_signature.algorithms,
                    (bytes(changed), *binding.joint_signature.components[1:]),
                ),
            )
            if derive_trajectory_parameters(digest.context, candidate) == digest.header.parameters:
                colliding = candidate
                break
        if colliding is not None:
            break
    assert colliding is not None
    forged = ExplicitAuditEvidenceV3(digest, colliding)
    assert ExplicitAuditEvidenceV3.from_bytes(forged.to_bytes()) == forged
    assert not verify_explicit_full_v3(BytesSource(message), forged)
    assert not verify_explicit_full_v3(BytesSource(message + b"x"), forged)


def test_digest_parser_rejects_unknown_duplicate_order_and_downgrade() -> None:
    _, digest = _digest()
    encoded = digest.to_bytes()
    fields = _fields(encoded)

    with pytest.raises(DecodeError):
        SigmaDigestV3.from_bytes(_with_fields(encoded, [*fields, encode_tlv_field(6, b"")]))
    with pytest.raises(DecodeError):
        SigmaDigestV3.from_bytes(_with_fields(encoded, [fields[0], fields[0], *fields[1:]]))
    with pytest.raises(DecodeError):
        SigmaDigestV3.from_bytes(_with_fields(encoded, [fields[1], fields[0], *fields[2:]]))

    downgraded = bytearray(encoded)
    downgraded[20:22] = encode_uint(0x0302, 2)
    with pytest.raises(DecodeError):
        SigmaDigestV3.from_bytes(bytes(downgraded))


def test_invalid_digest_profile_is_rejected_before_full_body_slice() -> None:
    class TrackingBytes(bytes):
        slices: list[slice]

        def __new__(cls, value: bytes):
            instance = super().__new__(cls, value)
            instance.slices = []
            return instance

        def __getitem__(self, key):
            if isinstance(key, slice):
                self.slices.append(key)
            return super().__getitem__(key)

    _, digest = _digest()
    fields = _fields(digest.to_bytes())
    oversized_but_bounded = _with_fields(
        digest.to_bytes(),
        [
            encode_tlv_field(1, encode_uint(OutputProfileIdV3.EXPLICIT_BINDING, 2)),
            fields[1],
            encode_tlv_field(3, b"x" * 900_000),
            *fields[3:],
        ],
    )
    tracked = TrackingBytes(oversized_but_bounded)

    with pytest.raises(DecodeError, match="discriminator"):
        SigmaDigestV3.from_bytes(tracked)
    assert not any(item.start == 14 and item.stop is None for item in tracked.slices)


def test_explicit_wire_rejects_malformed_discriminators_and_tlv() -> None:
    evaluation, digest = _digest(b"explicit-negative-wire")
    encoded = ExplicitAuditEvidenceV3(digest, evaluation.prepared.binding).to_bytes()
    fields = _fields(encoded)

    malformed = [
        _with_fields(encoded, [*fields, encode_tlv_field(6, b"")]),
        _with_fields(encoded, [fields[0], fields[0], *fields[1:]]),
        _with_fields(encoded, [fields[1], fields[0], *fields[2:]]),
        encoded + b"\x00",
        _with_fields(
            encoded,
            [
                encode_tlv_field(1, encode_uint(SuiteIdV3.REFERENCE_IAP_V3, 2)),
                *fields[1:],
            ],
        ),
        _with_fields(
            encoded,
            [
                fields[0],
                encode_tlv_field(2, encode_uint(OutputProfileIdV3.IMPLICIT_J, 2)),
                *fields[2:],
            ],
        ),
        _with_fields(
            encoded,
            [
                *fields[:2],
                encode_tlv_field(3, domain_tag_v3(DomainIdV3.EVIDENCE)),
                *fields[3:],
            ],
        ),
    ]
    bad_length = bytearray(encoded)
    bad_length[10:14] = encode_uint(len(encoded) - 13, 4)
    malformed.append(bytes(bad_length))

    for candidate in malformed:
        with pytest.raises(DecodeError):
            ExplicitAuditEvidenceV3.from_bytes(candidate)


def test_explicit_wire_has_registered_suite_and_distinct_domain() -> None:
    evaluation, digest = _digest(b"explicit-suite-domain")
    encoded = ExplicitAuditEvidenceV3(digest, evaluation.prepared.binding).to_bytes()
    fields = _fields(encoded)

    assert fields[0] == encode_tlv_field(1, encode_uint(SuiteIdV3.EXPLICIT_AUDIT_V3, 2))
    assert fields[2] == encode_tlv_field(3, domain_tag_v3(DomainIdV3.EXPLICIT_EVIDENCE))
    descriptor = get_evidence_envelope_v3(SuiteIdV3.EXPLICIT_AUDIT_V3)
    assert descriptor.output_profile is (OutputProfileIdV3.EXPLICIT_BINDING)
    assert descriptor.inner_output_profile is OutputProfileIdV3.IMPLICIT_J
    with pytest.raises(ValueError, match="unregistered Sigma v3 suite"):
        get_suite_v3(SuiteIdV3.EXPLICIT_AUDIT_V3)
    with pytest.raises(ValueError, match="unregistered Sigma v3 suite"):
        SigmaContextV3.for_suite(
            SuiteIdV3.EXPLICIT_AUDIT_V3,
            salt=b"",
            challenge=b"",
            application_context=b"",
        )


def test_explicit_evidence_known_answer() -> None:
    evaluation, digest = _digest(b"Sigma v3 R8 explicit KAT")
    explicit = ExplicitAuditEvidenceV3(digest, evaluation.prepared.binding)
    assert hashlib.sha256(explicit.to_bytes()).hexdigest() == (
        "6f0243f6b85797807fcfab190ebad66449c79e78f9e97a9f7460b285ad22e51b"
    )


def test_digest_known_answer() -> None:
    _, digest = _digest(b"Sigma v3 R8 KAT")
    assert hashlib.sha256(digest.to_bytes()).hexdigest() == (
        "21641e96fe4c58961761a911447524108805e84d21d74cd5113d316f57c730eb"
    )
