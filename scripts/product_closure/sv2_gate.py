"""Reproducible SV2 semantic gate for VerificationPolicy V1."""

from __future__ import annotations

import argparse
import hashlib
import json
import random
from pathlib import Path

from sigma.sources import BytesSource, CanonicalSource
from sigma.spec.context_v3 import SigmaContextV3
from sigma.spec.ids_v3 import SuiteIdV3
from sigma.trajectory import (
    PolicySymlinkModeV1,
    TrajectoryAuditModeV3,
    VerificationCapabilitiesV1,
    VerificationDecisionKindV1,
    VerificationPolicyV1,
    audit_from_evaluation_v3,
    policy_is_stricter_or_equal_v1,
    verify_with_policy_v1,
)
from sigma.v2 import hash_bytes as hash_bytes_v22
from sigma.v3 import evaluate_v3

MIN_DECISION_CASES = 400
MIN_MONOTONIC_CASES = 100
MIN_CHEAP_REJECT_CASES = 100


class _BombSource(CanonicalSource):
    def __init__(self, byte_length: int) -> None:
        self._byte_length = byte_length
        self.iterated = False

    @property
    def byte_length(self) -> int:
        return self._byte_length

    def iter_chunks(self, chunk_size: int):
        self.iterated = True
        raise AssertionError("SV2 expensive source replay reached")
        yield b""  # pragma: no cover


def _audit(message: bytes, suite_id: SuiteIdV3):
    context = SigmaContextV3.for_suite(
        suite_id,
        salt=b"sv2-gate",
        challenge=b"policy",
        application_context=b"scripts/product_closure/sv2_gate",
    )
    evaluation = evaluate_v3(context, BytesSource(message))
    return audit_from_evaluation_v3(
        evaluation,
        mode=TrajectoryAuditModeV3.COMPACT,
    )


def run_gate(
    *,
    decision_cases: int,
    monotonic_cases: int,
    cheap_reject_cases: int,
) -> dict[str, object]:
    if decision_cases < MIN_DECISION_CASES:
        raise ValueError(
            f"SV2 requires at least {MIN_DECISION_CASES} decision cases"
        )
    if monotonic_cases < MIN_MONOTONIC_CASES:
        raise ValueError(
            f"SV2 requires at least {MIN_MONOTONIC_CASES} monotonic cases"
        )
    if cheap_reject_cases < MIN_CHEAP_REJECT_CASES:
        raise ValueError(
            f"SV2 requires at least {MIN_CHEAP_REJECT_CASES} cheap-reject cases"
        )

    history_message = b"sv2-history-evidence"
    history_audit = _audit(
        history_message,
        SuiteIdV3.REFERENCE_IAP_HISTORY_V3,
    )
    r12_message = b"sv2-r12-evidence"
    r12_audit = _audit(r12_message, SuiteIdV3.REFERENCE_IAP_V3)
    r12_digest = r12_audit.digest

    four_way = {
        verify_with_policy_v1(
            history_audit,
            source=history_message,
        ).kind,
        verify_with_policy_v1(
            r12_digest,
            source=r12_message,
        ).kind,
        verify_with_policy_v1(history_audit).kind,
        verify_with_policy_v1(b"FUTURE00" + b"\x00" * 32).kind,
    }
    expected_four_way = {
        VerificationDecisionKindV1.ACCEPTED,
        VerificationDecisionKindV1.REJECTED,
        VerificationDecisionKindV1.INCONCLUSIVE,
        VerificationDecisionKindV1.UNSUPPORTED,
    }
    if four_way != expected_four_way:
        raise AssertionError("SV2 four-way decision coverage incomplete")

    rng = random.Random(0x53563247415445)
    decision_stream = hashlib.sha256()
    policy_stream = hashlib.sha256()

    suites_all = (
        SuiteIdV3.REFERENCE_IAP_V3,
        SuiteIdV3.DEEP_V3,
        SuiteIdV3.DEEP_VECTOR_V3,
        SuiteIdV3.REFERENCE_IAP_HISTORY_V3,
        SuiteIdV3.DEEP_HISTORY_V3,
        SuiteIdV3.DEEP_VECTOR_HISTORY_V3,
    )

    for case in range(decision_cases):
        require_binding = bool(rng.getrandbits(1))
        require_audit = bool(rng.getrandbits(1))
        require_history = bool(rng.getrandbits(1))
        allowed = tuple(
            suite for suite in suites_all if rng.getrandbits(1)
        )
        allowed = tuple(sorted(allowed, key=int))
        policy = VerificationPolicyV1(
            allowed_v3_suites=allowed,
            require_history_feedback=require_history,
            require_message_binding=require_binding,
            require_audit=require_audit,
            max_input_bytes=rng.choice((8, 64, 1024, 1 << 20)),
            max_trajectory_rounds=rng.choice((1, 8, 64, 1024)),
            symlink_mode=rng.choice(
                (PolicySymlinkModeV1.REJECT, PolicySymlinkModeV1.TEXT)
            ),
        )
        encoded = policy.to_bytes()
        decoded = VerificationPolicyV1.from_bytes(encoded)
        if decoded != policy or decoded.policy_id != policy.policy_id:
            raise AssertionError("SV2 policy codec/identity drift")

        evidence = history_audit if case % 2 == 0 else r12_digest
        source = history_message if case % 2 == 0 else r12_message
        first = verify_with_policy_v1(
            evidence,
            policy=policy,
            source=source if require_binding else None,
        )
        second = verify_with_policy_v1(
            evidence,
            policy=decoded,
            source=source if require_binding else None,
        )
        if first != second:
            raise AssertionError("SV2 decision is non-deterministic")
        decision_stream.update(
            first.kind.value.encode("ascii")
            + b"\0"
            + first.code.value.encode("ascii")
        )
        policy_stream.update(policy.policy_id)

    # Defined normalized partial-order subset.
    weak = VerificationPolicyV1(
        allowed_v3_suites=suites_all,
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
    for case in range(monotonic_cases):
        suite_id = rng.choice(
            (
                SuiteIdV3.REFERENCE_IAP_HISTORY_V3,
                SuiteIdV3.DEEP_HISTORY_V3,
                SuiteIdV3.DEEP_VECTOR_HISTORY_V3,
            )
        )
        message = f"sv2-monotone-{case}".encode()
        evidence = _audit(message, suite_id)
        strict = VerificationPolicyV1(
            allowed_v3_suites=(suite_id,),
            require_history_feedback=True,
            require_message_binding=True,
            require_audit=True,
            max_input_bytes=1024,
            max_trajectory_rounds=64,
            allowed_artifact_metadata_profiles=(1,),
            symlink_mode=PolicySymlinkModeV1.REJECT,
        )
        if not policy_is_stricter_or_equal_v1(strict, weak):
            raise AssertionError("SV2 normalized strict/weak relation failed")
        strict_result = verify_with_policy_v1(
            evidence,
            policy=strict,
            source=message,
        )
        weak_result = verify_with_policy_v1(
            evidence,
            policy=weak,
            source=message,
        )
        if strict_result.accepted and not weak_result.accepted:
            raise AssertionError("SV2 monotonic acceptance law violated")

    # Cheap policy rejection before source replay.
    for case in range(cheap_reject_cases):
        message = b"x" * (32 + case % 16)
        evidence = _audit(
            message,
            SuiteIdV3.REFERENCE_IAP_HISTORY_V3,
        )
        source = _BombSource(len(message))
        decision = verify_with_policy_v1(
            evidence,
            policy=VerificationPolicyV1(max_input_bytes=1),
            source=source,
        )
        if decision.kind is not VerificationDecisionKindV1.REJECTED:
            raise AssertionError("SV2 oversized input did not reject")
        if source.iterated:
            raise AssertionError("SV2 cheap check reached source replay")

    # Legacy is denied by default and works only after explicit opt-in.
    legacy_message = b"sv2-legacy-v22"
    legacy_digest = hash_bytes_v22(legacy_message)
    if verify_with_policy_v1(
        legacy_digest,
        source=legacy_message,
    ).kind is not VerificationDecisionKindV1.REJECTED:
        raise AssertionError("SV2 default policy accepted legacy v2.2")
    legacy_policy = VerificationPolicyV1(
        allowed_v3_suites=(),
        require_history_feedback=False,
        allow_legacy_v22=True,
        require_message_binding=True,
    )
    if not verify_with_policy_v1(
        legacy_digest,
        policy=legacy_policy,
        source=legacy_message,
    ).accepted:
        raise AssertionError("SV2 explicit legacy opt-in did not accept valid v2.2")

    # Future Artifact requirements are explicit through capabilities.
    dual_policy = VerificationPolicyV1(
        require_tree_evidence=True,
        require_dual_evidence=True,
        require_signature=True,
        require_provenance=True,
    )
    missing = verify_with_policy_v1(
        history_audit,
        policy=dual_policy,
        source=history_message,
    )
    if missing.kind is not VerificationDecisionKindV1.REJECTED:
        raise AssertionError("SV2 missing DUAL capabilities did not reject")

    satisfied = verify_with_policy_v1(
        history_audit,
        policy=dual_policy,
        source=history_message,
        capabilities=VerificationCapabilitiesV1(
            has_tree_evidence=True,
            has_signature=True,
            has_provenance=True,
            tree_proof_bytes=128,
            artifact_metadata_profile=1,
            contains_symlink=False,
        ),
    )
    if not satisfied.accepted:
        raise AssertionError("SV2 satisfied DUAL capabilities were not accepted")

    return {
        "schema": "sigma-sv2-verification-policy-gate-v1",
        "passed": True,
        "closure_eligible": True,
        "decision_cases": decision_cases,
        "monotonic_cases": monotonic_cases,
        "cheap_reject_cases": cheap_reject_cases,
        "decision_stream_sha256": decision_stream.hexdigest(),
        "policy_id_stream_sha256": policy_stream.hexdigest(),
        "four_way_coverage": sorted(kind.value for kind in four_way),
        "legacy_default": "rejected",
        "legacy_opt_in": "accepted",
        "empirical_performance_claims": False,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--decision-cases", type=int, default=MIN_DECISION_CASES)
    parser.add_argument(
        "--monotonic-cases", type=int, default=MIN_MONOTONIC_CASES
    )
    parser.add_argument(
        "--cheap-reject-cases", type=int, default=MIN_CHEAP_REJECT_CASES
    )
    parser.add_argument("--report", type=Path)
    args = parser.parse_args()

    report = run_gate(
        decision_cases=args.decision_cases,
        monotonic_cases=args.monotonic_cases,
        cheap_reject_cases=args.cheap_reject_cases,
    )
    payload = json.dumps(report, indent=2, sort_keys=True) + "\n"
    if args.report is not None:
        args.report.parent.mkdir(parents=True, exist_ok=True)
        args.report.write_text(payload, encoding="utf-8")
    print(payload, end="")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
