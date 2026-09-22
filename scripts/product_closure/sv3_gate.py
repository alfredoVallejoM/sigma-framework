"""Reproducible SV3 closure gate for receipts and batch verification."""

from __future__ import annotations

import argparse
import hashlib
import json
import random
from dataclasses import replace
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from reference.verification_receipt_v1 import (
    batch_item_wire,
    batch_wire,
    receipt_wire,
)
from sigma.sources import BytesSource, CanonicalSource
from sigma.spec.context_v3 import SigmaContextV3
from sigma.spec.ids_v3 import SuiteIdV3
from sigma.trajectory import (
    BatchVerificationItemV1,
    ReceiptSignatureStatusV1,
    TrajectoryAuditModeV3,
    VerificationDecisionKindV1,
    VerificationPolicyV1,
    VerificationReceiptV1,
    audit_from_evaluation_v3,
    receipt_from_decision_v1,
    sign_receipt_ed25519_v1,
    verify_batch_item_v1,
    verify_batch_v1,
    verify_receipt_signature_v1,
    verify_with_policy_v1,
)
from sigma.v3 import evaluate_v3

MIN_RECEIPT_CASES = 200
MIN_SIGNATURE_MUTATIONS = 1_000
MIN_BATCH_CASES = 100
MIN_FAILURE_ISOLATION_CASES = 100

_HISTORY_SUITES = (
    SuiteIdV3.REFERENCE_IAP_HISTORY_V3,
    SuiteIdV3.DEEP_HISTORY_V3,
    SuiteIdV3.DEEP_VECTOR_HISTORY_V3,
)


class _ExplodingSource(CanonicalSource):
    @property
    def byte_length(self) -> int:
        raise RuntimeError("sv3-isolated-source-failure")

    def iter_chunks(self, chunk_size: int):
        raise RuntimeError("sv3-isolated-source-failure")
        yield b""


def _audit(
    suite_id: SuiteIdV3,
    message: bytes,
    *,
    salt: bytes,
    challenge: bytes,
    application_context: bytes,
):
    context = SigmaContextV3.for_suite(
        suite_id,
        salt=salt,
        challenge=challenge,
        application_context=application_context,
    )
    return audit_from_evaluation_v3(
        evaluate_v3(context, BytesSource(message)),
        mode=TrajectoryAuditModeV3.COMPACT,
    )


def _reference_receipt(receipt: VerificationReceiptV1) -> bytes:
    return receipt_wire(
        artifact_identity=receipt.artifact_identity,
        policy_id=receipt.policy_id,
        verifier_package=receipt.verifier_package,
        verifier_version=receipt.verifier_version,
        verifier_build=receipt.verifier_build,
        evidence_kind=(
            None if receipt.evidence_kind is None else receipt.evidence_kind.value
        ),
        evidence_id=receipt.evidence_id,
        decision_kind=receipt.decision_kind.value,
        decision_code=receipt.decision_code.value,
        decision_reason=receipt.decision_reason,
        structure_valid=receipt.structure_valid,
        message_binding_verified=receipt.message_binding_verified,
        evidence_hashes=receipt.evidence_hashes,
        claimed_unix_time=receipt.claimed_unix_time,
        signature_status=int(receipt.signature_status),
        signature_algorithm=(
            None
            if receipt.signature_algorithm is None
            else int(receipt.signature_algorithm)
        ),
        public_key_id=receipt.public_key_id,
        signature=receipt.signature,
    )


def _reference_batch(batch) -> bytes:
    item_wires = []
    for item in batch.items:
        item_wires.append(
            batch_item_wire(
                index=item.index,
                artifact_identity=item.artifact_identity,
                receipt=(
                    b"" if item.receipt is None else _reference_receipt(item.receipt)
                ),
                error_type=item.error_type,
                error_message=item.error_message,
            )
        )
    return batch_wire(tuple(item_wires))


def run_gate(
    *,
    receipt_cases: int,
    signature_mutations: int,
    batch_cases: int,
    failure_isolation_cases: int,
) -> dict[str, object]:
    if receipt_cases < MIN_RECEIPT_CASES:
        raise ValueError(f"SV3 requires at least {MIN_RECEIPT_CASES} receipt cases")
    if signature_mutations < MIN_SIGNATURE_MUTATIONS:
        raise ValueError(
            f"SV3 requires at least {MIN_SIGNATURE_MUTATIONS} signature mutations"
        )
    if batch_cases < MIN_BATCH_CASES:
        raise ValueError(f"SV3 requires at least {MIN_BATCH_CASES} batch cases")
    if failure_isolation_cases < MIN_FAILURE_ISOLATION_CASES:
        raise ValueError(
            "SV3 requires at least "
            f"{MIN_FAILURE_ISOLATION_CASES} failure-isolation cases"
        )

    rng = random.Random(0x53563347415445)
    seed = bytes(range(32))
    private = Ed25519PrivateKey.from_private_bytes(seed)
    public_key = private.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )

    receipt_stream = hashlib.sha256()
    signed_receipt_stream = hashlib.sha256()
    batch_stream = hashlib.sha256()
    mutation_count = 0

    for case in range(receipt_cases):
        suite_id = _HISTORY_SUITES[case % len(_HISTORY_SUITES)]
        message = rng.randbytes(rng.randrange(0, 65))
        salt = rng.randbytes(rng.randrange(0, 9))
        challenge = rng.randbytes(rng.randrange(0, 9))
        app = rng.randbytes(rng.randrange(1, 17))
        audit = _audit(
            suite_id,
            message,
            salt=salt,
            challenge=challenge,
            application_context=app,
        )
        policy = VerificationPolicyV1(
            allowed_v3_suites=(suite_id,),
            require_history_feedback=True,
            require_message_binding=True,
            require_audit=True,
        )
        decision = verify_with_policy_v1(audit, policy=policy, source=message)
        if not decision.accepted:
            raise AssertionError("SV3 receipt fixture did not verify")

        artifact_identity = b"artifact:" + case.to_bytes(4, "big")
        receipt = receipt_from_decision_v1(
            artifact_identity,
            policy,
            decision,
            verifier_build=b"sv3-gate",
            claimed_unix_time=1_800_000_000 + case,
        )
        if receipt.signature_status is not ReceiptSignatureStatusV1.UNSIGNED:
            raise AssertionError("SV3 unsigned receipt is not explicitly unsigned")
        if receipt.decision_projection() != decision:
            raise AssertionError("SV3 receipt decision projection drift")
        if receipt.to_bytes() != _reference_receipt(receipt):
            raise AssertionError("SV3 receipt independent-wire divergence")
        if VerificationReceiptV1.from_bytes(receipt.to_bytes()) != receipt:
            raise AssertionError("SV3 receipt codec round-trip divergence")

        signed = sign_receipt_ed25519_v1(
            receipt,
            seed,
            b"sv3-gate-key",
        )
        if not verify_receipt_signature_v1(
            signed,
            public_key,
            expected_public_key_id=b"sv3-gate-key",
        ):
            raise AssertionError("SV3 signed receipt failed verification")
        if signed.to_bytes() != _reference_receipt(signed):
            raise AssertionError("SV3 signed receipt independent-wire divergence")

        candidates = (
            replace(signed, artifact_identity=artifact_identity + b"x"),
            replace(
                signed,
                policy_id=bytes([signed.policy_id[0] ^ 1]) + signed.policy_id[1:],
            ),
            replace(signed, verifier_version="3.0.0a1+mutated"),
            replace(signed, decision_reason="mutated decision reason"),
            replace(signed, claimed_unix_time=1_900_000_000 + case),
        )
        for mutated in candidates:
            if verify_receipt_signature_v1(mutated, public_key):
                raise AssertionError("SV3 receipt signature missed a bound-field mutation")
            mutation_count += 1

        receipt_stream.update(hashlib.sha256(receipt.to_bytes()).digest())
        signed_receipt_stream.update(hashlib.sha256(signed.to_bytes()).digest())

    if mutation_count < signature_mutations:
        raise AssertionError(
            f"SV3 signature mutation campaign too small: {mutation_count}"
        )

    isolation_count = 0
    for case in range(batch_cases):
        suite_id = _HISTORY_SUITES[case % len(_HISTORY_SUITES)]
        salt = b"batch-salt-" + case.to_bytes(2, "big")
        challenge = b"batch-challenge"
        app = b"scripts/product_closure/sv3_gate"
        messages = (
            b"A" + case.to_bytes(4, "big"),
            b"B" + case.to_bytes(4, "big"),
            b"C" + case.to_bytes(4, "big"),
        )
        audits = tuple(
            _audit(
                suite_id,
                message,
                salt=salt,
                challenge=challenge,
                application_context=app,
            )
            for message in messages
        )
        policy = VerificationPolicyV1(
            allowed_v3_suites=(suite_id,),
            require_history_feedback=True,
            require_message_binding=True,
            require_audit=True,
        )
        items = (
            BatchVerificationItemV1(
                b"batch-A:" + case.to_bytes(4, "big"),
                audits[0],
                policy,
                source=messages[0],
            ),
            BatchVerificationItemV1(
                b"batch-B:" + case.to_bytes(4, "big"),
                audits[1],
                policy,
                source=b"wrong-source",
            ),
            BatchVerificationItemV1(
                b"batch-C:" + case.to_bytes(4, "big"),
                audits[2],
                policy,
                source=None,
            ),
            BatchVerificationItemV1(
                b"batch-D:" + case.to_bytes(4, "big"),
                audits[0],
                policy,
                source=_ExplodingSource(),
            ),
        )
        serial = verify_batch_v1(items, verifier_build=b"sv3-batch", max_workers=1)
        threaded = verify_batch_v1(items, verifier_build=b"sv3-batch", max_workers=4)
        pointwise = tuple(
            verify_batch_item_v1(
                item,
                index=index,
                verifier_build=b"sv3-batch",
            )
            for index, item in enumerate(items)
        )

        if serial.items != pointwise:
            raise AssertionError("SV3 batch != pointwise verification")
        if threaded.to_bytes() != serial.to_bytes():
            raise AssertionError("SV3 threaded batch changed deterministic result")
        if serial.to_bytes() != _reference_batch(serial):
            raise AssertionError("SV3 batch independent-wire divergence")
        if tuple(item.index for item in serial.items) != (0, 1, 2, 3):
            raise AssertionError("SV3 batch result ordering drift")
        if serial.items[0].decision is None or (
            serial.items[0].decision.kind is not VerificationDecisionKindV1.ACCEPTED
        ):
            raise AssertionError("SV3 accepted batch item drift")
        if serial.items[1].decision is None or (
            serial.items[1].decision.kind is not VerificationDecisionKindV1.REJECTED
        ):
            raise AssertionError("SV3 rejected batch item drift")
        if serial.items[2].decision is None or (
            serial.items[2].decision.kind
            is not VerificationDecisionKindV1.INCONCLUSIVE
        ):
            raise AssertionError("SV3 inconclusive batch item drift")
        if serial.items[3].succeeded or serial.items[3].error_type != "RuntimeError":
            raise AssertionError("SV3 injected item failure was not isolated")
        if any(not serial.items[index].succeeded for index in (0, 1, 2)):
            raise AssertionError("SV3 failing item contaminated neighbors")
        isolation_count += 1
        batch_stream.update(hashlib.sha256(serial.to_bytes()).digest())

    if isolation_count < failure_isolation_cases:
        raise AssertionError(
            f"SV3 isolation campaign too small: {isolation_count}"
        )

    return {
        "schema": "sigma-sv3-receipt-batch-gate-v1",
        "passed": True,
        "closure_eligible": True,
        "receipt_cases": receipt_cases,
        "signature_mutations": mutation_count,
        "batch_cases": batch_cases,
        "failure_isolation_cases": isolation_count,
        "receipt_stream_sha256": receipt_stream.hexdigest(),
        "signed_receipt_stream_sha256": signed_receipt_stream.hexdigest(),
        "batch_stream_sha256": batch_stream.hexdigest(),
        "pointwise_equivalence": True,
        "threaded_equivalence": True,
        "unsigned_receipt_explicit": True,
        "opaque_provenance_truth_claim": False,
        "empirical_performance_claims": False,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--receipt-cases", type=int, default=MIN_RECEIPT_CASES)
    parser.add_argument(
        "--signature-mutations",
        type=int,
        default=MIN_SIGNATURE_MUTATIONS,
    )
    parser.add_argument("--batch-cases", type=int, default=MIN_BATCH_CASES)
    parser.add_argument(
        "--failure-isolation-cases",
        type=int,
        default=MIN_FAILURE_ISOLATION_CASES,
    )
    parser.add_argument("--report", type=Path)
    args = parser.parse_args()

    report = run_gate(
        receipt_cases=args.receipt_cases,
        signature_mutations=args.signature_mutations,
        batch_cases=args.batch_cases,
        failure_isolation_cases=args.failure_isolation_cases,
    )
    payload = json.dumps(report, indent=2, sort_keys=True) + "\n"
    if args.report is not None:
        args.report.parent.mkdir(parents=True, exist_ok=True)
        args.report.write_text(payload, encoding="utf-8")
    print(payload, end="")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
