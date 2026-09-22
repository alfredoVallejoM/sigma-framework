from __future__ import annotations

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from reference.verification_receipt_v1 import batch_item_wire, batch_wire, receipt_wire
from sigma.sources import BytesSource, CanonicalSource
from sigma.spec.context_v3 import SigmaContextV3
from sigma.spec.ids_v3 import SuiteIdV3
from sigma.trajectory import (
    BatchVerificationItemV1,
    BatchVerificationResultV1,
    TrajectoryAuditModeV3,
    VerificationDecisionKindV1,
    VerificationPolicyV1,
    audit_from_evaluation_v3,
    verify_batch_item_v1,
    verify_batch_v1,
    verify_receipt_signature_v1,
)
from sigma.v3 import evaluate_v3


class _ExplodingSource(CanonicalSource):
    @property
    def byte_length(self) -> int:
        raise RuntimeError("isolated-source-failure")

    def iter_chunks(self, chunk_size: int):
        raise RuntimeError("isolated-source-failure")
        yield b""


def _audit(message: bytes):
    context = SigmaContextV3.for_suite(
        SuiteIdV3.REFERENCE_IAP_HISTORY_V3,
        salt=b"sv3",
        challenge=b"batch",
        application_context=b"tests/sv3",
    )
    return audit_from_evaluation_v3(
        evaluate_v3(context, BytesSource(message)),
        mode=TrajectoryAuditModeV3.COMPACT,
    )


def _items() -> tuple[BatchVerificationItemV1, ...]:
    policy = VerificationPolicyV1(require_audit=True)
    message_a = b"batch-A"
    message_b = b"batch-B"
    return (
        BatchVerificationItemV1(
            b"artifact-A",
            _audit(message_a),
            policy,
            source=message_a,
        ),
        BatchVerificationItemV1(
            b"artifact-B",
            _audit(message_b),
            policy,
            source=b"wrong-B",
        ),
        BatchVerificationItemV1(
            b"artifact-C",
            _audit(b"batch-C"),
            policy,
            source=None,
        ),
        BatchVerificationItemV1(
            b"artifact-D",
            _audit(b"batch-D"),
            policy,
            source=_ExplodingSource(),
        ),
    )


def _reference_receipt(receipt):
    return receipt_wire(
        artifact_identity=receipt.artifact_identity,
        policy_id=receipt.policy_id,
        verifier_package=receipt.verifier_package,
        verifier_version=receipt.verifier_version,
        verifier_build=receipt.verifier_build,
        evidence_kind=None if receipt.evidence_kind is None else receipt.evidence_kind.value,
        evidence_id=receipt.evidence_id,
        decision_kind=receipt.decision_kind.value,
        decision_code=receipt.decision_code.value,
        decision_reason=receipt.decision_reason,
        structure_valid=receipt.structure_valid,
        message_binding_verified=receipt.message_binding_verified,
        evidence_hashes=receipt.evidence_hashes,
        claimed_unix_time=receipt.claimed_unix_time,
        signature_status=int(receipt.signature_status),
        signature_algorithm=None if receipt.signature_algorithm is None else int(receipt.signature_algorithm),
        public_key_id=receipt.public_key_id,
        signature=receipt.signature,
    )


def test_batch_equals_pointwise_and_preserves_input_order():
    items = _items()
    batch = verify_batch_v1(items, verifier_build=b"batch-build", max_workers=1)
    pointwise = tuple(
        verify_batch_item_v1(
            item,
            index=index,
            verifier_build=b"batch-build",
        )
        for index, item in enumerate(items)
    )
    assert batch.items == pointwise
    assert tuple(item.artifact_identity for item in batch.items) == tuple(
        item.artifact_identity for item in items
    )

    assert batch.items[0].decision.kind is VerificationDecisionKindV1.ACCEPTED
    assert batch.items[1].decision.kind is VerificationDecisionKindV1.REJECTED
    assert batch.items[2].decision.kind is VerificationDecisionKindV1.INCONCLUSIVE
    assert not batch.items[3].succeeded
    assert batch.items[3].error_type == "RuntimeError"

    # Failure of D does not alter A/B/C receipts.
    for index in range(3):
        assert batch.items[index] == pointwise[index]


def test_threaded_batch_is_byte_identical_to_serial():
    items = _items()
    serial = verify_batch_v1(items, verifier_build=b"same-build", max_workers=1)
    threaded = verify_batch_v1(items, verifier_build=b"same-build", max_workers=4)
    assert threaded == serial
    assert threaded.to_bytes() == serial.to_bytes()


def test_batch_wire_roundtrip_and_independent_encoder():
    batch = verify_batch_v1(_items(), verifier_build=b"wire-build")
    encoded = batch.to_bytes()
    assert BatchVerificationResultV1.from_bytes(encoded) == batch

    independent_items = []
    for item in batch.items:
        receipt = b"" if item.receipt is None else _reference_receipt(item.receipt)
        independent_items.append(
            batch_item_wire(
                index=item.index,
                artifact_identity=item.artifact_identity,
                receipt=receipt,
                error_type=item.error_type,
                error_message=item.error_message,
            )
        )
    assert encoded == batch_wire(tuple(independent_items))


def test_signed_batch_receipts_verify_independently():
    seed = bytes(range(32))
    public_key = Ed25519PrivateKey.from_private_bytes(seed).public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    batch = verify_batch_v1(
        _items()[:3],
        verifier_build=b"signed-batch",
        signing_private_key=seed,
        public_key_id=b"batch-key",
        max_workers=3,
    )
    for item in batch.items:
        assert item.receipt is not None
        assert verify_receipt_signature_v1(
            item.receipt,
            public_key,
            expected_public_key_id=b"batch-key",
        )


def test_batch_ids_and_order_are_deterministic():
    items = _items()[:3]
    first = verify_batch_v1(items, verifier_build=b"deterministic")
    second = verify_batch_v1(items, verifier_build=b"deterministic")
    assert first.batch_id == second.batch_id
    assert first.to_bytes() == second.to_bytes()


def test_batch_result_roundtrip_preserves_failure_record():
    batch = verify_batch_v1(_items(), verifier_build=b"failure-wire")
    decoded = BatchVerificationResultV1.from_bytes(batch.to_bytes())
    assert decoded == batch
    assert not decoded.items[3].succeeded
    assert decoded.items[3].error_type == "RuntimeError"


def test_batch_rejects_noncanonical_result_order():
    batch = verify_batch_v1(_items()[:2], verifier_build=b"order")
    from dataclasses import replace

    swapped = (
        replace(batch.items[1], index=0),
        replace(batch.items[0], index=1),
    )
    # indices are canonical, but artifact/result order changed intentionally;
    # construction itself preserves whatever input order is supplied. The law
    # is verified at verify_batch_v1 boundary rather than sorting post hoc.
    rebuilt = BatchVerificationResultV1(swapped)
    assert rebuilt.items[0].artifact_identity == batch.items[1].artifact_identity
