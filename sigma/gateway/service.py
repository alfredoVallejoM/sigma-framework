"""PX4 in-process verification gateway with exact local-API delegation."""

from __future__ import annotations

import threading
import time
from dataclasses import dataclass
from pathlib import Path
from typing import BinaryIO, Callable

from sigma.artifact import (
    ArtifactPolicyCodeV1,
    ArtifactSideResultV1,
    ArtifactStoreCorruptionError,
    ArtifactStoreNotFound,
    ArtifactVerificationResultV1,
    LocalArtifactStoreV1,
    SigmaArtifactV1,
    verify_artifact_v1,
)
from sigma.outputs.digest_v3 import SigmaDigestV3
from sigma.sources import CanonicalSource
from sigma.trajectory import (
    BatchItemResultV1,
    BatchVerificationItemV1,
    BatchVerificationResultV1,
    ParsedVerificationEvidenceV1,
    TrajectoryAuditV3,
    VerificationDecisionCodeV1,
    VerificationDecisionV1,
    VerificationEvidenceKindV1,
    VerificationPolicyV1,
    parse_verification_evidence_v1,
    receipt_from_decision_v1,
    verify_batch_item_v1,
    verify_with_policy_v1,
)
from sigma.tree import (
    InclusionProofV1,
    RangeProofV1,
    verify_inclusion,
    verify_range,
)
from sigma.version import PACKAGE_VERSION

from .protocol import (
    ARTIFACT_VERIFY_MEDIA_TYPE,
    ARTIFACT_WIRE_MEDIA_TYPE,
    BATCH_RESULT_MEDIA_TYPE,
    BATCH_VERIFY_MEDIA_TYPE,
    INCLUSION_VERIFY_MEDIA_TYPE,
    POLICY_EVALUATE_MEDIA_TYPE,
    RANGE_VERIFY_MEDIA_TYPE,
    GatewayBodyReaderV1,
    read_artifact_verify_metadata_v1,
    read_batch_header_v1,
    read_batch_item_metadata_v1,
    read_inclusion_verify_head_v1,
    read_policy_evaluate_metadata_v1,
    read_range_verify_head_v1,
)
from .runtime import (
    GatewayAuditRecordV1,
    GatewayAuditSinkV1,
    GatewayBusyError,
    GatewayCancellationTokenV1,
    GatewayCancelledError,
    GatewayError,
    GatewayErrorCodeV1,
    GatewayLimitsV1,
    GatewayNotFoundError,
    GatewayResponseV1,
    GatewaySourceTooLargeError,
    GatewayTimeoutError,
    NullGatewayAuditSinkV1,
    canonical_json_bytes,
    error_response_v1,
    health_response_v1,
    version_response_v1,
)

_ARTIFACT_RESULT_SCHEMA = "sigma-gateway-artifact-verification-v1"
_POLICY_RESULT_SCHEMA = "sigma-gateway-policy-evaluation-v1"
_PROOF_RESULT_SCHEMA = "sigma-gateway-proof-verification-v1"
_PARENTS_RESULT_SCHEMA = "sigma-gateway-artifact-parents-v1"
_BATCH_RESULT_BUDGET_PER_ITEM = 16 << 10


class _SpoolBudgetV1:
    def __init__(self, limit: int) -> None:
        self.limit = limit
        self.used = 0
        self._lock = threading.Lock()

    def acquire(self, amount: int) -> bool:
        if amount < 0:
            raise ValueError("spool reservation must be non-negative")
        with self._lock:
            if self.used + amount > self.limit:
                return False
            self.used += amount
            return True

    def release(self, amount: int) -> None:
        if amount < 0:
            raise ValueError("spool release must be non-negative")
        with self._lock:
            if amount > self.used:
                raise RuntimeError("spool budget release exceeds reservation")
            self.used -= amount


class _DeclaredLengthSourceV1(CanonicalSource):
    """Preflight-only source whose bytes must never be requested."""

    def __init__(self, byte_length: int) -> None:
        self._byte_length = byte_length

    @property
    def byte_length(self) -> int:
        return self._byte_length

    def iter_chunks(self, chunk_size: int):
        raise AssertionError("declared-length preflight attempted to read source bytes")


@dataclass(frozen=True)
class _GatewayOutcomeV1:
    response: GatewayResponseV1
    artifact_id_hex: str = ""
    policy_id_hex: str = ""
    decision: str = ""


def _side_object(value: ArtifactSideResultV1) -> dict[str, object]:
    return {
        "actual_wire": None if value.actual_wire is None else value.actual_wire.hex(),
        "code": value.code.value,
        "expected_wire": (
            None if value.expected_wire is None else value.expected_wire.hex()
        ),
        "reason": value.reason,
        "status": value.status.value,
        "verified": value.verified,
    }


def artifact_result_json_v1(
    value: ArtifactVerificationResultV1,
) -> bytes:
    if not isinstance(value, ArtifactVerificationResultV1):
        raise TypeError("value must be ArtifactVerificationResultV1")
    return canonical_json_bytes(
        {
            "accepted": value.accepted,
            "artifact_id": value.artifact_id.hex(),
            "dual_conjunction": value.dual_conjunction,
            "failure_sides": list(value.failure_sides),
            "policy": {
                "accepted": value.policy.accepted,
                "code": value.policy.code.value,
                "kind": value.policy.kind.value,
                "policy_id": value.policy.policy_id.hex(),
                "reason": value.policy.reason,
            },
            "profile": value.profile.name.lower(),
            "schema": _ARTIFACT_RESULT_SCHEMA,
            "trajectory": _side_object(value.trajectory),
            "tree": _side_object(value.tree),
        }
    )


def decision_result_json_v1(
    decision: VerificationDecisionV1,
    *,
    receipt_wire: bytes,
    receipt_id: bytes,
) -> bytes:
    if not isinstance(decision, VerificationDecisionV1):
        raise TypeError("decision must be VerificationDecisionV1")
    if not isinstance(receipt_wire, bytes):
        raise TypeError("receipt_wire must be bytes")
    if not isinstance(receipt_id, bytes) or len(receipt_id) != 32:
        raise ValueError("receipt_id must contain exactly 32 bytes")
    return canonical_json_bytes(
        {
            "decision": {
                "accepted": decision.accepted,
                "code": decision.code.value,
                "evidence_id": (
                    None
                    if decision.evidence_id is None
                    else decision.evidence_id.hex()
                ),
                "evidence_kind": (
                    None
                    if decision.evidence_kind is None
                    else decision.evidence_kind.value
                ),
                "kind": decision.kind.value,
                "message_binding_verified": decision.message_binding_verified,
                "policy_id": decision.policy_id.hex(),
                "reason": decision.reason,
                "structure_valid": decision.structure_valid,
            },
            "receipt_id": receipt_id.hex(),
            "receipt_wire": receipt_wire.hex(),
            "schema": _POLICY_RESULT_SCHEMA,
        }
    )


def _proof_result_json(verified: bool) -> bytes:
    return canonical_json_bytes(
        {
            "schema": _PROOF_RESULT_SCHEMA,
            "verified": verified,
        }
    )


def _artifact_committed_bytes(artifact: SigmaArtifactV1) -> int:
    if artifact.tree_root is not None:
        return artifact.tree_root.byte_length
    if artifact.trajectory_digest is None:
        raise RuntimeError("canonical artifact has no primary evidence")
    return artifact.trajectory_digest.header.cardinality.byte_length


def _artifact_rounds(artifact: SigmaArtifactV1) -> int:
    digest = artifact.trajectory_digest
    if digest is None:
        return 0
    return (
        digest.header.parameters.target_round
        + digest.header.parameters.state_count
        - 1
    )


def _evidence_rounds(parsed: ParsedVerificationEvidenceV1) -> int:
    if parsed.kind is VerificationEvidenceKindV1.TRAJECTORY_AUDIT:
        assert isinstance(parsed.value, TrajectoryAuditV3)
        digest = parsed.value.digest
    elif parsed.kind is VerificationEvidenceKindV1.V3_DIGEST:
        assert isinstance(parsed.value, SigmaDigestV3)
        digest = parsed.value
    else:
        return 0
    return (
        digest.header.parameters.target_round
        + digest.header.parameters.state_count
        - 1
    )


def _expected_content_type(value: str, expected: str) -> None:
    media_type = value.split(";", 1)[0].strip().lower()
    if media_type != expected:
        raise GatewayError(
            status=415,
            code=GatewayErrorCodeV1.UNSUPPORTED_MEDIA_TYPE,
            safe_message="request Content-Type is unsupported",
        )


class GatewayServiceV1:
    """In-process PX4 gateway; the HTTP daemon is a thin transport adapter."""

    def __init__(
        self,
        store: LocalArtifactStoreV1,
        *,
        limits: GatewayLimitsV1 | None = None,
        audit_sink: GatewayAuditSinkV1 | None = None,
        verifier_build: bytes = b"",
        spool_temp_dir: str | Path | None = None,
        monotonic: Callable[[], float] = time.monotonic,
    ) -> None:
        if not isinstance(store, LocalArtifactStoreV1):
            raise TypeError("store must be LocalArtifactStoreV1")
        self.store = store
        self.limits = GatewayLimitsV1() if limits is None else limits
        if not isinstance(self.limits, GatewayLimitsV1):
            raise TypeError("limits must be GatewayLimitsV1")
        selected_sink = NullGatewayAuditSinkV1() if audit_sink is None else audit_sink
        if not isinstance(selected_sink, GatewayAuditSinkV1):
            raise TypeError("audit_sink must implement GatewayAuditSinkV1")
        if not isinstance(verifier_build, bytes) or len(verifier_build) > 255:
            raise ValueError("verifier_build must be bytes of length <=255")
        self.audit_sink = selected_sink
        self.verifier_build = verifier_build
        self._spool_temp_dir = (
            None if spool_temp_dir is None else Path(spool_temp_dir)
        )
        if self._spool_temp_dir is not None:
            self._spool_temp_dir.mkdir(parents=True, exist_ok=True)
        self._spool_budget = _SpoolBudgetV1(
            self.limits.max_total_spool_bytes
        )
        self._monotonic = monotonic
        self._semaphore = threading.BoundedSemaphore(
            self.limits.max_concurrent_requests
        )
        self._sequence = 0
        self._sequence_lock = threading.Lock()

    def _next_sequence(self) -> int:
        with self._sequence_lock:
            self._sequence += 1
            return self._sequence

    def audit_transport_rejection(
        self,
        *,
        method: str,
        path: str,
        response: GatewayResponseV1,
        error_code: GatewayErrorCodeV1,
    ) -> None:
        if not isinstance(method, str) or not isinstance(path, str):
            raise TypeError("method and path must be str")
        if not isinstance(response, GatewayResponseV1):
            raise TypeError("response must be GatewayResponseV1")
        if not isinstance(error_code, GatewayErrorCodeV1):
            raise TypeError("error_code must be GatewayErrorCodeV1")
        record = GatewayAuditRecordV1(
            sequence=self._next_sequence(),
            method=self._audit_method(method),
            endpoint=self._audit_endpoint(path),
            status=response.status,
            error_code=error_code.value,
            artifact_id_hex="",
            policy_id_hex="",
            decision="",
            bytes_in=0,
            bytes_out=len(response.body),
            elapsed_milliseconds=0,
            timed_out=False,
            cancelled=False,
        )
        try:
            self.audit_sink.emit(record)
        except Exception:
            pass

    def _spool_source(
        self,
        reader: GatewayBodyReaderV1,
        length: int,
        *,
        effective_max_source_bytes: int,
    ) -> tuple[CanonicalSource, int]:
        if not self._spool_budget.acquire(length):
            raise GatewayBusyError(
                safe_message="gateway temporary spool budget exhausted"
            )
        try:
            source = reader.spool_source(
                length,
                effective_max_source_bytes=effective_max_source_bytes,
                temp_dir=self._spool_temp_dir,
            )
        except BaseException:
            self._spool_budget.release(length)
            raise
        return source, length

    def _release_spool(self, reserved: int) -> None:
        self._spool_budget.release(reserved)

    def _operational_artifact_preflight(
        self,
        artifact: SigmaArtifactV1,
    ) -> None:
        if _artifact_committed_bytes(artifact) > self.limits.max_source_bytes:
            raise GatewaySourceTooLargeError()
        if _artifact_rounds(artifact) > self.limits.max_trajectory_rounds:
            raise GatewayError(
                status=413,
                code=GatewayErrorCodeV1.POLICY_LIMIT,
                safe_message="artifact trajectory rounds exceed gateway limit",
            )

    def _operational_evidence_preflight(
        self,
        evidence_wire: bytes,
    ) -> ParsedVerificationEvidenceV1 | None:
        try:
            parsed = parse_verification_evidence_v1(evidence_wire)
        except Exception:
            return None
        if _evidence_rounds(parsed) > self.limits.max_trajectory_rounds:
            raise GatewayError(
                status=413,
                code=GatewayErrorCodeV1.POLICY_LIMIT,
                safe_message="evidence trajectory rounds exceed gateway limit",
            )
        return parsed

    def _artifact_from_metadata(
        self,
        artifact_id: bytes,
        artifact_wire: bytes,
    ) -> SigmaArtifactV1:
        if artifact_wire:
            try:
                artifact = SigmaArtifactV1.from_bytes(artifact_wire)
            except (TypeError, ValueError) as exc:
                raise GatewayError(
                    code=GatewayErrorCodeV1.MALFORMED_ARTIFACT,
                    safe_message="artifact wire is malformed",
                ) from exc
            if artifact.to_bytes() != artifact_wire:
                raise GatewayError(
                    code=GatewayErrorCodeV1.MALFORMED_ARTIFACT,
                    safe_message="artifact wire is non-canonical",
                )
            if artifact.artifact_id != artifact_id:
                raise GatewayError(
                    status=409,
                    code=GatewayErrorCodeV1.ARTIFACT_ID_MISMATCH,
                    safe_message="artifact wire does not match requested ArtifactId",
                )
            return artifact
        try:
            return self.store.get_artifact(artifact_id)
        except ArtifactStoreNotFound as exc:
            raise GatewayNotFoundError() from exc
        except ArtifactStoreCorruptionError as exc:
            raise GatewayError(
                status=500,
                code=GatewayErrorCodeV1.INTERNAL,
                safe_message="stored artifact failed integrity validation",
            ) from exc

    def _artifact_verify(
        self,
        reader: GatewayBodyReaderV1,
        token: GatewayCancellationTokenV1,
    ) -> _GatewayOutcomeV1:
        metadata = read_artifact_verify_metadata_v1(reader)
        artifact = self._artifact_from_metadata(
            metadata.artifact_id,
            metadata.artifact_wire,
        )
        self._operational_artifact_preflight(artifact)
        policy = metadata.policy
        caps = metadata.capabilities

        preflight = verify_artifact_v1(
            None,
            artifact,
            policy=policy,
            capabilities=caps,
        )
        if not metadata.source_present:
            reader.require_consumed()
            response = GatewayResponseV1(
                200,
                "application/json",
                artifact_result_json_v1(preflight),
            )
            return _GatewayOutcomeV1(
                response,
                artifact.artifact_id.hex(),
                policy.policy_id.hex(),
                preflight.policy.kind.value,
            )

        if preflight.policy.code is not ArtifactPolicyCodeV1.SOURCE_REQUIRED:
            response = GatewayResponseV1(
                200,
                "application/json",
                artifact_result_json_v1(preflight),
            )
            return _GatewayOutcomeV1(
                response,
                artifact.artifact_id.hex(),
                policy.policy_id.hex(),
                preflight.policy.kind.value,
            )

        if metadata.source_length > self.limits.max_source_bytes:
            raise GatewaySourceTooLargeError()

        if metadata.source_length > policy.max_input_bytes:
            declared = _DeclaredLengthSourceV1(metadata.source_length)
            result = verify_artifact_v1(
                declared,
                artifact,
                policy=policy,
                capabilities=caps,
            )
            response = GatewayResponseV1(
                200,
                "application/json",
                artifact_result_json_v1(result),
            )
            return _GatewayOutcomeV1(
                response,
                artifact.artifact_id.hex(),
                policy.policy_id.hex(),
                result.policy.kind.value,
            )

        source, reserved = self._spool_source(
            reader,
            metadata.source_length,
            effective_max_source_bytes=policy.max_input_bytes,
        )
        try:
            result = verify_artifact_v1(
                source,
                artifact,
                policy=policy,
                capabilities=caps,
            )
            token.check()
        finally:
            try:
                source.close()
            finally:
                self._release_spool(reserved)
        reader.require_consumed()
        response = GatewayResponseV1(
            200,
            "application/json",
            artifact_result_json_v1(result),
        )
        return _GatewayOutcomeV1(
            response,
            artifact.artifact_id.hex(),
            policy.policy_id.hex(),
            result.policy.kind.value,
        )

    def _policy_receipt_outcome(
        self,
        *,
        artifact_identity: bytes,
        policy: VerificationPolicyV1,
        decision: VerificationDecisionV1,
    ) -> _GatewayOutcomeV1:
        receipt = receipt_from_decision_v1(
            artifact_identity,
            policy,
            decision,
            verifier_package="sigma-framework",
            verifier_version=PACKAGE_VERSION,
            verifier_build=self.verifier_build,
            claimed_unix_time=None,
        )
        wire = receipt.to_bytes()
        response = GatewayResponseV1(
            200,
            "application/json",
            decision_result_json_v1(
                decision,
                receipt_wire=wire,
                receipt_id=receipt.receipt_id,
            ),
        )
        return _GatewayOutcomeV1(
            response,
            "",
            policy.policy_id.hex(),
            decision.kind.value,
        )

    def _policy_evaluate(
        self,
        reader: GatewayBodyReaderV1,
        token: GatewayCancellationTokenV1,
    ) -> _GatewayOutcomeV1:
        metadata = read_policy_evaluate_metadata_v1(reader)
        parsed = self._operational_evidence_preflight(metadata.evidence_wire)
        policy = metadata.policy
        caps = metadata.capabilities

        preflight = verify_with_policy_v1(
            metadata.evidence_wire,
            policy=policy,
            source=None,
            capabilities=caps,
        )
        if not metadata.source_present:
            reader.require_consumed()
            return self._policy_receipt_outcome(
                artifact_identity=metadata.artifact_identity,
                policy=policy,
                decision=preflight,
            )

        if preflight.code is not VerificationDecisionCodeV1.SOURCE_REQUIRED:
            return self._policy_receipt_outcome(
                artifact_identity=metadata.artifact_identity,
                policy=policy,
                decision=preflight,
            )

        if metadata.source_length > self.limits.max_source_bytes:
            raise GatewaySourceTooLargeError()

        if metadata.source_length > policy.max_input_bytes:
            decision = verify_with_policy_v1(
                metadata.evidence_wire if parsed is None else parsed,
                policy=policy,
                source=_DeclaredLengthSourceV1(metadata.source_length),
                capabilities=caps,
            )
            return self._policy_receipt_outcome(
                artifact_identity=metadata.artifact_identity,
                policy=policy,
                decision=decision,
            )

        source, reserved = self._spool_source(
            reader,
            metadata.source_length,
            effective_max_source_bytes=policy.max_input_bytes,
        )
        try:
            decision = verify_with_policy_v1(
                metadata.evidence_wire if parsed is None else parsed,
                policy=policy,
                source=source,
                capabilities=caps,
            )
            token.check()
        finally:
            source.close()
            self._release_spool(reserved)
        reader.require_consumed()
        return self._policy_receipt_outcome(
            artifact_identity=metadata.artifact_identity,
            policy=policy,
            decision=decision,
        )

    def _batch_verify(
        self,
        reader: GatewayBodyReaderV1,
        token: GatewayCancellationTokenV1,
    ) -> _GatewayOutcomeV1:
        count = read_batch_header_v1(reader)
        if count * _BATCH_RESULT_BUDGET_PER_ITEM > self.limits.max_response_bytes:
            raise GatewayError(
                status=413,
                code=GatewayErrorCodeV1.REQUEST_TOO_LARGE,
                safe_message="batch result budget exceeds gateway response limit",
            )
        results: list[BatchItemResultV1] = []
        total_source_bytes = 0

        for index in range(count):
            token.check()
            metadata = read_batch_item_metadata_v1(reader)
            total_source_bytes += metadata.source_length
            if total_source_bytes > self.limits.max_batch_total_source_bytes:
                raise GatewaySourceTooLargeError(
                    safe_message="batch source bytes exceed gateway limit"
                )

            self._operational_evidence_preflight(metadata.evidence_wire)
            preflight = verify_with_policy_v1(
                metadata.evidence_wire,
                policy=metadata.policy,
                source=None,
                capabilities=metadata.capabilities,
            )

            source: CanonicalSource | bytes | None = None
            close_source = False
            reserved = 0
            if metadata.source_present:
                if preflight.code is VerificationDecisionCodeV1.SOURCE_REQUIRED:
                    if metadata.source_length > self.limits.max_source_bytes:
                        raise GatewaySourceTooLargeError()
                    if metadata.source_length > metadata.policy.max_input_bytes:
                        source = _DeclaredLengthSourceV1(metadata.source_length)
                        reader.discard_exact(metadata.source_length)
                    else:
                        source, reserved = self._spool_source(
                            reader,
                            metadata.source_length,
                            effective_max_source_bytes=metadata.policy.max_input_bytes,
                        )
                        close_source = True
                else:
                    reader.discard_exact(metadata.source_length)

            try:
                item = BatchVerificationItemV1(
                    artifact_identity=metadata.artifact_identity,
                    evidence=metadata.evidence_wire,
                    policy=metadata.policy,
                    source=source,
                    capabilities=metadata.capabilities,
                    claimed_unix_time=None,
                )
                result = verify_batch_item_v1(
                    item,
                    index=index,
                    verifier_package="sigma-framework",
                    verifier_version=PACKAGE_VERSION,
                    verifier_build=self.verifier_build,
                )
                token.check()
                results.append(result)
            finally:
                if close_source and isinstance(source, CanonicalSource):
                    try:
                        source.close()
                    finally:
                        self._release_spool(reserved)

        reader.require_consumed()
        batch = BatchVerificationResultV1(tuple(results))
        wire = batch.to_bytes()
        return _GatewayOutcomeV1(
            GatewayResponseV1(
                200,
                BATCH_RESULT_MEDIA_TYPE,
                wire,
            ),
            decision=f"batch:{batch.accepted_count}/{len(batch.items)}",
        )

    def _inclusion_verify(
        self,
        reader: GatewayBodyReaderV1,
        token: GatewayCancellationTokenV1,
    ) -> _GatewayOutcomeV1:
        head = read_inclusion_verify_head_v1(reader)
        try:
            proof = InclusionProofV1.from_bytes(head.proof_wire)
        except (TypeError, ValueError) as exc:
            raise GatewayError(
                code=GatewayErrorCodeV1.MALFORMED_PROOF,
                safe_message="inclusion proof is malformed",
            ) from exc
        token.check()
        if head.leaf_length != proof.leaf_byte_length:
            return _GatewayOutcomeV1(
                GatewayResponseV1(
                    200,
                    "application/json",
                    _proof_result_json(False),
                ),
                decision="rejected",
            )
        leaf = reader.read_exact(head.leaf_length)
        reader.require_consumed()
        verified = verify_inclusion(leaf, proof)
        token.check()
        return _GatewayOutcomeV1(
            GatewayResponseV1(
                200,
                "application/json",
                _proof_result_json(verified),
            ),
            decision="verified" if verified else "rejected",
        )

    def _range_verify(
        self,
        reader: GatewayBodyReaderV1,
        token: GatewayCancellationTokenV1,
    ) -> _GatewayOutcomeV1:
        head = read_range_verify_head_v1(reader)
        try:
            proof = RangeProofV1.from_bytes(head.proof_wire)
        except (TypeError, ValueError) as exc:
            raise GatewayError(
                code=GatewayErrorCodeV1.MALFORMED_PROOF,
                safe_message="range proof is malformed",
            ) from exc
        token.check()
        if head.value_length != proof.length:
            return _GatewayOutcomeV1(
                GatewayResponseV1(
                    200,
                    "application/json",
                    _proof_result_json(False),
                ),
                decision="rejected",
            )
        range_bytes = reader.read_exact(head.value_length)
        reader.require_consumed()
        verified = verify_range(range_bytes, proof)
        token.check()
        return _GatewayOutcomeV1(
            GatewayResponseV1(
                200,
                "application/json",
                _proof_result_json(verified),
            ),
            decision="verified" if verified else "rejected",
        )

    def _get_artifact(self, artifact_id: bytes) -> _GatewayOutcomeV1:
        try:
            payload = self.store.get_artifact_bytes(artifact_id)
        except ArtifactStoreNotFound as exc:
            raise GatewayNotFoundError() from exc
        except ArtifactStoreCorruptionError as exc:
            raise GatewayError(
                status=500,
                code=GatewayErrorCodeV1.INTERNAL,
                safe_message="stored artifact failed integrity validation",
            ) from exc
        return _GatewayOutcomeV1(
            GatewayResponseV1(
                200,
                ARTIFACT_WIRE_MEDIA_TYPE,
                payload,
            ),
            artifact_id.hex(),
        )

    def _get_parents(self, artifact_id: bytes) -> _GatewayOutcomeV1:
        try:
            artifact = self.store.get_artifact(artifact_id)
        except ArtifactStoreNotFound as exc:
            raise GatewayNotFoundError() from exc
        except ArtifactStoreCorruptionError as exc:
            raise GatewayError(
                status=500,
                code=GatewayErrorCodeV1.INTERNAL,
                safe_message="stored artifact failed integrity validation",
            ) from exc
        body = canonical_json_bytes(
            {
                "artifact_id": artifact.artifact_id.hex(),
                "parents": [
                    value.hex() for value in artifact.parent_artifact_ids
                ],
                "schema": _PARENTS_RESULT_SCHEMA,
            }
        )
        return _GatewayOutcomeV1(
            GatewayResponseV1(200, "application/json", body),
            artifact.artifact_id.hex(),
        )

    @staticmethod
    def _audit_method(method: str) -> str:
        value = method.upper()
        if value in {"GET", "POST", "HEAD", "PUT", "DELETE", "PATCH", "OPTIONS"}:
            return value
        return "<other>"

    @classmethod
    def _audit_endpoint(cls, path: str) -> str:
        clean = path.split("?", 1)[0].split("#", 1)[0]
        if clean in (
            "/health",
            "/version",
            "/v1/artifacts/verify",
            "/v1/policies/evaluate",
            "/v1/batch/verify",
            "/v1/proofs/inclusion/verify",
            "/v1/proofs/range/verify",
        ):
            return clean
        if cls._path_artifact_id(clean, suffix="/parents") is not None:
            return "/v1/artifacts/{id}/parents"
        if cls._path_artifact_id(clean) is not None:
            return "/v1/artifacts/{id}"
        return "<unmatched>"

    @staticmethod
    def _path_artifact_id(path: str, *, suffix: str = "") -> bytes | None:
        prefix = "/v1/artifacts/"
        if not path.startswith(prefix):
            return None
        value = path[len(prefix) :]
        if suffix:
            if not value.endswith(suffix):
                return None
            value = value[: -len(suffix)]
        if "/" in value or len(value) != 64:
            return None
        if value != value.lower() or any(
            character not in "0123456789abcdef" for character in value
        ):
            return None
        try:
            raw = bytes.fromhex(value)
        except ValueError:
            return None
        return raw if len(raw) == 32 else None

    def _dispatch(
        self,
        method: str,
        path: str,
        content_type: str,
        reader: GatewayBodyReaderV1,
        token: GatewayCancellationTokenV1,
    ) -> _GatewayOutcomeV1:
        token.check()
        if "?" in path or "#" in path:
            raise GatewayError(
                code=GatewayErrorCodeV1.BAD_REQUEST,
                safe_message="query strings and fragments are not accepted",
            )
        if method == "GET" and path == "/health":
            if reader.content_length:
                raise GatewayFramingError()
            return _GatewayOutcomeV1(health_response_v1(), decision="ok")
        if method == "GET" and path == "/version":
            if reader.content_length:
                raise GatewayFramingError()
            return _GatewayOutcomeV1(version_response_v1(), decision="ok")

        if method == "GET":
            artifact_id = self._path_artifact_id(path, suffix="/parents")
            if artifact_id is not None:
                if reader.content_length:
                    raise GatewayFramingError()
                return self._get_parents(artifact_id)
            artifact_id = self._path_artifact_id(path)
            if artifact_id is not None:
                if reader.content_length:
                    raise GatewayFramingError()
                return self._get_artifact(artifact_id)

        if method == "POST" and path == "/v1/artifacts/verify":
            _expected_content_type(content_type, ARTIFACT_VERIFY_MEDIA_TYPE)
            return self._artifact_verify(reader, token)
        if method == "POST" and path == "/v1/policies/evaluate":
            _expected_content_type(content_type, POLICY_EVALUATE_MEDIA_TYPE)
            return self._policy_evaluate(reader, token)
        if method == "POST" and path == "/v1/batch/verify":
            _expected_content_type(content_type, BATCH_VERIFY_MEDIA_TYPE)
            return self._batch_verify(reader, token)
        if method == "POST" and path == "/v1/proofs/inclusion/verify":
            _expected_content_type(content_type, INCLUSION_VERIFY_MEDIA_TYPE)
            return self._inclusion_verify(reader, token)
        if method == "POST" and path == "/v1/proofs/range/verify":
            _expected_content_type(content_type, RANGE_VERIFY_MEDIA_TYPE)
            return self._range_verify(reader, token)

        raise GatewayNotFoundError()

    def handle(
        self,
        *,
        method: str,
        path: str,
        content_type: str,
        body_stream: BinaryIO,
        content_length: int,
        token: GatewayCancellationTokenV1 | None = None,
    ) -> GatewayResponseV1:
        if not isinstance(method, str) or not isinstance(path, str):
            raise TypeError("method and path must be str")
        if not isinstance(content_type, str):
            raise TypeError("content_type must be str")
        audit_endpoint = self._audit_endpoint(path)

        if not self._semaphore.acquire(blocking=False):
            response = error_response_v1(GatewayBusyError())
            sequence = self._next_sequence()
            try:
                self.audit_sink.emit(
                    GatewayAuditRecordV1(
                        sequence=sequence,
                        method=self._audit_method(method),
                        endpoint=audit_endpoint,
                        status=response.status,
                        error_code=GatewayErrorCodeV1.BUSY.value,
                        artifact_id_hex="",
                        policy_id_hex="",
                        decision="",
                        bytes_in=0,
                        bytes_out=len(response.body),
                        elapsed_milliseconds=0,
                        timed_out=False,
                        cancelled=False,
                    )
                )
            except Exception:
                pass
            return response

        selected_token = (
            GatewayCancellationTokenV1(
                timeout_seconds=self.limits.request_timeout_seconds,
                monotonic=self._monotonic,
            )
            if token is None
            else token
        )
        sequence = self._next_sequence()
        started = self._monotonic()
        reader: GatewayBodyReaderV1 | None = None
        outcome: _GatewayOutcomeV1 | None = None
        error_code = ""
        timed_out = False
        cancelled = False

        try:
            reader = GatewayBodyReaderV1(
                body_stream,
                content_length=content_length,
                limits=self.limits,
                token=selected_token,
            )
            outcome = self._dispatch(
                method.upper(),
                path,
                content_type,
                reader,
                selected_token,
            )
            if len(outcome.response.body) > self.limits.max_response_bytes:
                raise GatewayError(
                    status=500,
                    code=GatewayErrorCodeV1.INTERNAL,
                    safe_message="gateway response exceeds configured limit",
                )
            response = outcome.response
        except GatewayTimeoutError as exc:
            timed_out = True
            error_code = exc.code.value
            response = error_response_v1(exc)
        except GatewayCancelledError as exc:
            cancelled = True
            error_code = exc.code.value
            response = error_response_v1(exc)
        except GatewayError as exc:
            error_code = exc.code.value
            response = error_response_v1(exc)
        except Exception:
            error = GatewayError(
                status=500,
                code=GatewayErrorCodeV1.INTERNAL,
                safe_message="internal gateway error",
            )
            error_code = error.code.value
            response = error_response_v1(error)
        finally:
            elapsed = max(
                0,
                int((self._monotonic() - started) * 1000),
            )
            bytes_in = 0 if reader is None else reader.bytes_read
            record = GatewayAuditRecordV1(
                sequence=sequence,
                method=method.upper(),
                endpoint=audit_endpoint,
                status=(500 if "response" not in locals() else response.status),
                error_code=error_code,
                artifact_id_hex=(
                    "" if outcome is None else outcome.artifact_id_hex
                ),
                policy_id_hex=(
                    "" if outcome is None else outcome.policy_id_hex
                ),
                decision="" if outcome is None else outcome.decision,
                bytes_in=bytes_in,
                bytes_out=(
                    0 if "response" not in locals() else len(response.body)
                ),
                elapsed_milliseconds=elapsed,
                timed_out=timed_out,
                cancelled=cancelled,
            )
            self._semaphore.release()
            try:
                self.audit_sink.emit(record)
            except Exception:
                pass

        return response


__all__ = [
    "GatewayServiceV1",
    "artifact_result_json_v1",
    "decision_result_json_v1",
]
