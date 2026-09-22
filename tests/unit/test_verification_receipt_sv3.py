from __future__ import annotations

from dataclasses import replace

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from reference.verification_receipt_v1 import receipt_signing_input, receipt_wire
from sigma.sources import BytesSource
from sigma.spec.context_v3 import SigmaContextV3
from sigma.spec.ids_v3 import SuiteIdV3
from sigma.trajectory import (
    ReceiptSignatureStatusV1,
    TrajectoryAuditModeV3,
    VerificationDecisionCodeV1,
    VerificationDecisionKindV1,
    VerificationEvidenceKindV1,
    VerificationPolicyV1,
    VerificationReceiptV1,
    audit_from_evaluation_v3,
    receipt_from_decision_v1,
    sign_receipt_ed25519_v1,
    verify_receipt_signature_v1,
    verify_with_policy_v1,
)
from sigma.v3 import evaluate_v3


def _accepted_decision():
    message = b"sv3-receipt"
    context = SigmaContextV3.for_suite(
        SuiteIdV3.REFERENCE_IAP_HISTORY_V3,
        salt=b"sv3",
        challenge=b"receipt",
        application_context=b"tests/sv3",
    )
    audit = audit_from_evaluation_v3(
        evaluate_v3(context, BytesSource(message)),
        mode=TrajectoryAuditModeV3.COMPACT,
    )
    policy = VerificationPolicyV1(require_audit=True)
    decision = verify_with_policy_v1(audit, policy=policy, source=message)
    assert decision.accepted
    return policy, decision


def _raw_public_key(seed: bytes) -> bytes:
    private = Ed25519PrivateKey.from_private_bytes(seed)
    return private.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )


def _reference_kwargs(receipt: VerificationReceiptV1) -> dict[str, object]:
    return {
        "artifact_identity": receipt.artifact_identity,
        "policy_id": receipt.policy_id,
        "verifier_package": receipt.verifier_package,
        "verifier_version": receipt.verifier_version,
        "verifier_build": receipt.verifier_build,
        "evidence_kind": None if receipt.evidence_kind is None else receipt.evidence_kind.value,
        "evidence_id": receipt.evidence_id,
        "decision_kind": receipt.decision_kind.value,
        "decision_code": receipt.decision_code.value,
        "decision_reason": receipt.decision_reason,
        "structure_valid": receipt.structure_valid,
        "message_binding_verified": receipt.message_binding_verified,
        "evidence_hashes": receipt.evidence_hashes,
        "claimed_unix_time": receipt.claimed_unix_time,
        "signature_status": int(receipt.signature_status),
        "signature_algorithm": (
            None if receipt.signature_algorithm is None else int(receipt.signature_algorithm)
        ),
        "public_key_id": receipt.public_key_id,
        "signature": receipt.signature,
    }


def test_unsigned_receipt_roundtrip_projects_exact_decision():
    policy, decision = _accepted_decision()
    receipt = receipt_from_decision_v1(
        b"artifact:sv3:001",
        policy,
        decision,
        verifier_build=b"commit-abc",
        claimed_unix_time=1_800_000_000,
    )

    assert receipt.signature_status is ReceiptSignatureStatusV1.UNSIGNED
    assert not receipt.is_signed
    assert receipt.signature_algorithm is None
    assert receipt.public_key_id == b""
    assert receipt.signature == b""
    assert receipt.decision_projection() == decision
    assert receipt.policy_id == policy.policy_id
    assert decision.evidence_id in receipt.evidence_hashes

    encoded = receipt.to_bytes()
    assert VerificationReceiptV1.from_bytes(encoded) == receipt
    assert encoded == receipt_wire(**_reference_kwargs(receipt))


def test_receipt_signature_covers_full_canonical_record():
    policy, decision = _accepted_decision()
    unsigned = receipt_from_decision_v1(
        b"artifact:sv3:002",
        policy,
        decision,
        verifier_build=b"build-A",
        claimed_unix_time=1_800_000_001,
    )
    seed = bytes(range(32))
    public_key = _raw_public_key(seed)
    signed = sign_receipt_ed25519_v1(unsigned, seed, b"test-key")

    assert signed.is_signed
    assert verify_receipt_signature_v1(
        signed,
        public_key,
        expected_public_key_id=b"test-key",
    )
    assert signed.signing_input() == receipt_signing_input(**_reference_kwargs(signed))

    mutations = [
        replace(signed, artifact_identity=b"artifact:sv3:003"),
        replace(signed, policy_id=bytes([signed.policy_id[0] ^ 1]) + signed.policy_id[1:]),
        replace(signed, verifier_package="sigma-framework-alt"),
        replace(signed, verifier_version="3.0.0a2"),
        replace(signed, verifier_build=b"build-B"),
        replace(signed, evidence_kind=VerificationEvidenceKindV1.V3_DIGEST),
        replace(signed, decision_kind=VerificationDecisionKindV1.REJECTED),
        replace(signed, decision_code=VerificationDecisionCodeV1.VERIFICATION_FAILED),
        replace(signed, decision_reason="different canonical reason"),
        replace(signed, structure_valid=False),
        replace(signed, message_binding_verified=False),
        replace(
            signed,
            evidence_hashes=tuple(sorted((*signed.evidence_hashes, bytes.fromhex("11" * 32)))),
        ),
        replace(signed, claimed_unix_time=1_800_000_002),
        replace(signed, public_key_id=b"other-key"),
    ]
    for mutated in mutations:
        assert not verify_receipt_signature_v1(mutated, public_key)


def test_unsigned_receipt_never_verifies_as_signed():
    policy, decision = _accepted_decision()
    receipt = receipt_from_decision_v1(b"artifact:unsigned", policy, decision)
    assert not verify_receipt_signature_v1(receipt, bytes(32))
    with pytest.raises(ValueError, match="signing input"):
        receipt.signing_input()


def test_receipt_builder_rejects_policy_decision_mismatch():
    policy, decision = _accepted_decision()
    other_policy = VerificationPolicyV1(max_input_bytes=1024)
    assert other_policy.policy_id != decision.policy_id
    with pytest.raises(ValueError, match="policy_id"):
        receipt_from_decision_v1(b"artifact:mismatch", other_policy, decision)


def test_receipt_evidence_hashes_must_bind_primary_evidence_id():
    policy, decision = _accepted_decision()
    assert decision.evidence_id is not None
    with pytest.raises(ValueError, match="include evidence_id"):
        receipt_from_decision_v1(
            b"artifact:hashes",
            policy,
            decision,
            evidence_hashes=(bytes.fromhex("22" * 32),),
        )


def test_signed_receipt_cannot_be_signed_again():
    policy, decision = _accepted_decision()
    seed = bytes(range(32))
    receipt = receipt_from_decision_v1(b"artifact:resign", policy, decision)
    signed = sign_receipt_ed25519_v1(receipt, seed, b"key")
    with pytest.raises(ValueError, match="already signed"):
        sign_receipt_ed25519_v1(signed, seed, b"key")


def _record_fields(encoded: bytes) -> list[tuple[int, bytes]]:
    body_length = int.from_bytes(encoded[10:14], "big")
    assert body_length == len(encoded) - 14
    fields = []
    offset = 14
    while offset < len(encoded):
        tag = int.from_bytes(encoded[offset : offset + 2], "big")
        length = int.from_bytes(encoded[offset + 2 : offset + 6], "big")
        offset += 6
        fields.append((tag, encoded[offset : offset + length]))
        offset += length
    return fields


def _rebuild_record(template: bytes, fields: list[tuple[int, bytes]]) -> bytes:
    body = b"".join(
        tag.to_bytes(2, "big") + len(value).to_bytes(4, "big") + value
        for tag, value in fields
    )
    return template[:10] + len(body).to_bytes(4, "big") + body


def test_receipt_codec_rejects_missing_duplicate_reordered_unknown_fields():
    policy, decision = _accepted_decision()
    encoded = receipt_from_decision_v1(
        b"artifact:codec",
        policy,
        decision,
    ).to_bytes()
    fields = _record_fields(encoded)
    mutations = []
    for index, field in enumerate(fields):
        mutations.append(_rebuild_record(encoded, [*fields[:index], *fields[index + 1 :]]))
        mutations.append(
            _rebuild_record(
                encoded,
                [*fields[: index + 1], field, *fields[index + 1 :]],
            )
        )
    reordered = list(fields)
    reordered[0], reordered[1] = reordered[1], reordered[0]
    mutations.append(_rebuild_record(encoded, reordered))
    mutations.append(_rebuild_record(encoded, [*fields, (0xFFFF, b"")]))

    for mutated in mutations:
        with pytest.raises(ValueError):
            VerificationReceiptV1.from_bytes(mutated)
