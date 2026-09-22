from __future__ import annotations

from dataclasses import replace

import pytest

from sigma.sources import BytesSource
from sigma.spec.context_v3 import SigmaContextV3
from sigma.spec.ids_v3 import SuiteIdV3
from sigma.trajectory import (
    PolicySymlinkModeV1,
    TrajectoryAuditModeV3,
    VerificationCapabilitiesV1,
    VerificationDecisionCodeV1,
    VerificationDecisionKindV1,
    VerificationPolicyV1,
    audit_from_evaluation_v3,
    parse_verification_evidence_v1,
    policy_is_stricter_or_equal_v1,
    verify_with_policy_v1,
)
from sigma.v2 import hash_bytes as hash_bytes_v22
from sigma.v3 import evaluate_v3


def _history_audit(message: bytes = b"sv2-policy"):
    context = SigmaContextV3.for_suite(
        SuiteIdV3.REFERENCE_IAP_HISTORY_V3,
        salt=b"sv2",
        challenge=b"policy",
        application_context=b"tests/sv2",
    )
    evaluation = evaluate_v3(context, BytesSource(message))
    return audit_from_evaluation_v3(
        evaluation,
        mode=TrajectoryAuditModeV3.COMPACT,
    )


def _r12_digest(message: bytes = b"sv2-r12"):
    context = SigmaContextV3.for_suite(
        SuiteIdV3.REFERENCE_IAP_V3,
        salt=b"sv2",
        challenge=b"policy",
        application_context=b"tests/sv2",
    )
    evaluation = evaluate_v3(context, BytesSource(message))
    return evaluation, audit_from_evaluation_v3(evaluation).digest


def test_policy_codec_and_identity_are_canonical():
    policy = VerificationPolicyV1()
    encoded = policy.to_bytes()
    assert VerificationPolicyV1.from_bytes(encoded) == policy
    assert VerificationPolicyV1.from_bytes(encoded).policy_id == policy.policy_id

    changed = replace(policy, max_input_bytes=policy.max_input_bytes - 1)
    assert changed.policy_id != policy.policy_id


def test_parse_validity_is_separate_from_policy_acceptance():
    _, digest = _r12_digest()
    parsed = parse_verification_evidence_v1(digest.to_bytes())
    assert parsed.value == digest

    decision = verify_with_policy_v1(
        parsed,
        policy=VerificationPolicyV1(),
        source=b"sv2-r12",
    )
    assert decision.kind is VerificationDecisionKindV1.REJECTED
    assert decision.code is VerificationDecisionCodeV1.SUITE_NOT_ALLOWED


def test_four_way_decisions_are_explicit():
    audit = _history_audit()

    accepted = verify_with_policy_v1(
        audit,
        policy=VerificationPolicyV1(require_audit=True),
        source=b"sv2-policy",
    )
    assert accepted.kind is VerificationDecisionKindV1.ACCEPTED
    assert accepted.accepted

    rejected = verify_with_policy_v1(
        audit,
        policy=VerificationPolicyV1(max_input_bytes=1),
        source=b"sv2-policy",
    )
    assert rejected.kind is VerificationDecisionKindV1.REJECTED
    assert rejected.code is VerificationDecisionCodeV1.INPUT_TOO_LARGE

    inconclusive = verify_with_policy_v1(
        audit,
        policy=VerificationPolicyV1(require_audit=True),
    )
    assert inconclusive.kind is VerificationDecisionKindV1.INCONCLUSIVE
    assert inconclusive.code is VerificationDecisionCodeV1.SOURCE_REQUIRED

    unsupported = verify_with_policy_v1(b"FUTURE00" + b"\x00" * 32)
    assert unsupported.kind is VerificationDecisionKindV1.UNSUPPORTED
    assert unsupported.code is VerificationDecisionCodeV1.UNSUPPORTED_EVIDENCE


def test_known_malformed_wire_is_rejected_not_unsupported():
    decision = verify_with_policy_v1(b"SIGMA3DG" + b"\x00" * 12)
    assert decision.kind is VerificationDecisionKindV1.REJECTED
    assert decision.code is VerificationDecisionCodeV1.MALFORMED_EVIDENCE


def test_cheap_policy_rejection_happens_before_full_verification(monkeypatch):
    import sigma.trajectory.policy_v1 as policy_module

    audit = _history_audit()
    called = False

    def bomb(*args, **kwargs):
        nonlocal called
        called = True
        raise AssertionError("expensive verifier reached")

    monkeypatch.setattr(policy_module, "verify_trajectory_audit_structure_v3", bomb)
    monkeypatch.setattr(policy_module, "verify_trajectory_audit_full_v3", bomb)

    decision = policy_module.verify_with_policy_v1(
        audit,
        policy=VerificationPolicyV1(max_input_bytes=1),
        source=b"sv2-policy",
    )
    assert decision.code is VerificationDecisionCodeV1.INPUT_TOO_LARGE
    assert not called


def test_policy_decision_is_deterministic():
    audit = _history_audit()
    policy = VerificationPolicyV1(require_audit=True)
    first = verify_with_policy_v1(audit, policy=policy, source=b"sv2-policy")
    second = verify_with_policy_v1(audit, policy=policy, source=b"sv2-policy")
    assert first == second


def test_normalized_strict_policy_acceptance_implies_weak_acceptance():
    audit = _history_audit()
    strict = VerificationPolicyV1(
        allowed_v3_suites=(SuiteIdV3.REFERENCE_IAP_HISTORY_V3,),
        require_history_feedback=True,
        require_message_binding=True,
        require_audit=True,
        max_input_bytes=1024,
        max_trajectory_rounds=64,
        allowed_artifact_metadata_profiles=(1,),
        symlink_mode=PolicySymlinkModeV1.REJECT,
    )
    weak = VerificationPolicyV1(
        allowed_v3_suites=(
            SuiteIdV3.REFERENCE_IAP_V3,
            SuiteIdV3.DEEP_V3,
            SuiteIdV3.DEEP_VECTOR_V3,
            SuiteIdV3.REFERENCE_IAP_HISTORY_V3,
            SuiteIdV3.DEEP_HISTORY_V3,
            SuiteIdV3.DEEP_VECTOR_HISTORY_V3,
        ),
        require_history_feedback=False,
        allow_legacy_v22=True,
        require_message_binding=False,
        require_audit=False,
        allow_tree_only_artifacts=True,
        max_input_bytes=1 << 20,
        max_trajectory_rounds=1024,
        allowed_artifact_metadata_profiles=(1, 2),
        symlink_mode=PolicySymlinkModeV1.TEXT,
    )
    assert policy_is_stricter_or_equal_v1(strict, weak)

    strict_result = verify_with_policy_v1(
        audit,
        policy=strict,
        source=b"sv2-policy",
    )
    weak_result = verify_with_policy_v1(
        audit,
        policy=weak,
        source=b"sv2-policy",
    )
    assert strict_result.accepted
    assert weak_result.accepted


def test_legacy_v22_requires_explicit_opt_in():
    message = b"legacy-v22"
    digest = hash_bytes_v22(message)

    default = verify_with_policy_v1(
        digest,
        policy=VerificationPolicyV1(),
        source=message,
    )
    assert default.kind is VerificationDecisionKindV1.REJECTED
    assert default.code is VerificationDecisionCodeV1.LEGACY_DISABLED

    opted_in = VerificationPolicyV1(
        allowed_v3_suites=(),
        require_history_feedback=False,
        allow_legacy_v22=True,
        require_message_binding=True,
    )
    accepted = verify_with_policy_v1(
        digest,
        policy=opted_in,
        source=message,
    )
    assert accepted.kind is VerificationDecisionKindV1.ACCEPTED


def test_dual_signature_provenance_and_symlink_requirements_are_explicit():
    audit = _history_audit()

    dual_policy = VerificationPolicyV1(
        require_tree_evidence=True,
        require_dual_evidence=True,
    )
    dual_missing = verify_with_policy_v1(
        audit,
        policy=dual_policy,
        source=b"sv2-policy",
    )
    assert dual_missing.code is VerificationDecisionCodeV1.DUAL_REQUIRED

    signature_policy = VerificationPolicyV1(require_signature=True)
    signature_missing = verify_with_policy_v1(
        audit,
        policy=signature_policy,
        source=b"sv2-policy",
    )
    assert signature_missing.code is VerificationDecisionCodeV1.SIGNATURE_REQUIRED

    provenance_policy = VerificationPolicyV1(require_provenance=True)
    provenance_missing = verify_with_policy_v1(
        audit,
        policy=provenance_policy,
        source=b"sv2-policy",
    )
    assert provenance_missing.code is VerificationDecisionCodeV1.PROVENANCE_REQUIRED

    symlink = verify_with_policy_v1(
        audit,
        policy=VerificationPolicyV1(),
        source=b"sv2-policy",
        capabilities=VerificationCapabilitiesV1(contains_symlink=True),
    )
    assert symlink.code is VerificationDecisionCodeV1.SYMLINK_NOT_ALLOWED


def test_missing_resource_estimate_can_be_inconclusive():
    audit = _history_audit()
    policy = VerificationPolicyV1(max_memory_bytes=1024)
    decision = verify_with_policy_v1(
        audit,
        policy=policy,
        source=b"sv2-policy",
    )
    assert decision.kind is VerificationDecisionKindV1.INCONCLUSIVE
    assert decision.code is VerificationDecisionCodeV1.MEMORY_ESTIMATE_UNKNOWN


def test_wrong_source_is_rejected_after_policy_checks():
    audit = _history_audit(b"source-A")
    decision = verify_with_policy_v1(
        audit,
        policy=VerificationPolicyV1(require_audit=True),
        source=b"source-B",
    )
    assert decision.kind is VerificationDecisionKindV1.REJECTED
    assert decision.code is VerificationDecisionCodeV1.VERIFICATION_FAILED


def _policy_fields(encoded: bytes) -> list[tuple[int, bytes]]:
    body_length = int.from_bytes(encoded[10:14], "big")
    assert body_length == len(encoded) - 14
    offset = 14
    fields = []
    while offset < len(encoded):
        tag = int.from_bytes(encoded[offset : offset + 2], "big")
        length = int.from_bytes(encoded[offset + 2 : offset + 6], "big")
        offset += 6
        fields.append((tag, encoded[offset : offset + length]))
        offset += length
    return fields


def _policy_record(template: bytes, fields: list[tuple[int, bytes]]) -> bytes:
    body = b"".join(
        tag.to_bytes(2, "big") + len(value).to_bytes(4, "big") + value
        for tag, value in fields
    )
    return template[:10] + len(body).to_bytes(4, "big") + body


def test_policy_codec_rejects_missing_duplicate_reordered_unknown_fields():
    encoded = VerificationPolicyV1().to_bytes()
    fields = _policy_fields(encoded)
    mutations = []
    for index, field in enumerate(fields):
        mutations.append(_policy_record(encoded, fields[:index] + fields[index + 1 :]))
        mutations.append(
            _policy_record(
                encoded,
                [*fields[: index + 1], field, *fields[index + 1 :]],
            )
        )
    reordered = list(fields)
    reordered[0], reordered[1] = reordered[1], reordered[0]
    mutations.append(_policy_record(encoded, reordered))
    mutations.append(_policy_record(encoded, [*fields, (0xFFFF, b"")]))

    for mutated in mutations:
        with pytest.raises(ValueError):
            VerificationPolicyV1.from_bytes(mutated)
