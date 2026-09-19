from __future__ import annotations

import hashlib

import pytest

from sigma.binding import JointSignature, PersistentBinding, derive_trajectory_parameters
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
    with pytest.raises(DecodeError, match="invalid"):
        SigmaDigestV3.from_bytes(bytes(downgraded))


def test_digest_known_answer() -> None:
    _, digest = _digest(b"Sigma v3 R8 KAT")
    assert hashlib.sha256(digest.to_bytes()).hexdigest() == (
        "21641e96fe4c58961761a911447524108805e84d21d74cd5113d316f57c730eb"
    )
