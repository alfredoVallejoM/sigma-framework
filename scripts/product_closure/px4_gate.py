"""Reproducible PX4 closure gate for the verification gateway/daemon."""

from __future__ import annotations

import argparse
import hashlib
import http.client
import io
import json
import random
import socket
import sqlite3
import tempfile
import threading
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

from sigma.artifact import (
    ArtifactDescriptorV1,
    ArtifactProfileV1,
    LocalArtifactStoreV1,
    create_artifact_v1,
    verify_artifact_v1,
)
from sigma.gateway import (
    ARTIFACT_VERIFY_MEDIA_TYPE,
    BATCH_RESULT_MEDIA_TYPE,
    BATCH_VERIFY_MEDIA_TYPE,
    INCLUSION_VERIFY_MEDIA_TYPE,
    POLICY_EVALUATE_MEDIA_TYPE,
    RANGE_VERIFY_MEDIA_TYPE,
    GatewayCancellationTokenV1,
    GatewayLimitsV1,
    GatewayServiceV1,
    MemoryGatewayAuditSinkV1,
    artifact_result_json_v1,
    canonical_json_bytes,
    create_gateway_http_server_v1,
    decision_result_json_v1,
    encode_artifact_verify_request_v1,
    encode_batch_verify_request_v1,
    encode_inclusion_verify_request_v1,
    encode_policy_evaluate_request_v1,
    encode_range_verify_request_v1,
)
from sigma.outputs.digest_v3 import digest_from_evaluation_v3
from sigma.sources import BytesSource
from sigma.spec.context_v3 import SigmaContextV3
from sigma.spec.ids_v3 import SuiteIdV3
from sigma.trajectory import (
    BatchVerificationItemV1,
    VerificationCapabilitiesV1,
    VerificationPolicyV1,
    receipt_from_decision_v1,
    verify_batch_v1,
    verify_with_policy_v1,
)
from sigma.tree import build_tree, prove_leaf, prove_range, verify_inclusion, verify_range
from sigma.v3 import evaluate_v3
from sigma.version import PACKAGE_VERSION

MIN_ARTIFACT_CASES = 300
MIN_POLICY_RECEIPT_CASES = 300
MIN_BATCH_CASES = 100
MIN_PROOF_CASES = 300
MIN_CHEAP_REJECT_CASES = 200
MIN_CONCURRENCY_CASES = 100
MIN_ERROR_SCHEMA_CASES = 100
MIN_HTTP_CASES = 40


def _tree_artifact(data: bytes, case: int):
    parent_count = case % 4
    parents = tuple(
        sorted(
            hashlib.sha256(
                b"PX4-PARENT"
                + case.to_bytes(8, "big")
                + index.to_bytes(2, "big")
            ).digest()
            for index in range(parent_count)
        )
    )
    return create_artifact_v1(
        ArtifactProfileV1.TREE,
        descriptor=ArtifactDescriptorV1(
            logical_name=f"px4-{case}.bin",
            media_type="application/octet-stream",
        ),
        tree_root=build_tree(data),
        parent_artifact_ids=parents,
    )


def _tree_policy(*, max_input_bytes: int) -> VerificationPolicyV1:
    return VerificationPolicyV1(
        allow_tree_only_artifacts=True,
        max_input_bytes=max_input_bytes,
    )


def _v3_digest(data: bytes, case: int):
    context = SigmaContextV3.for_suite(
        SuiteIdV3.REFERENCE_IAP_HISTORY_V3,
        salt=b"px4-gate-" + case.to_bytes(4, "big"),
        challenge=b"gateway",
        application_context=b"scripts/product_closure/px4",
    )
    return digest_from_evaluation_v3(
        evaluate_v3(context, BytesSource(data))
    )


def _json_body(response) -> dict[str, object]:
    return json.loads(response.body.decode("ascii"))


class _BombStream:
    def read(self, size: int) -> bytes:
        raise AssertionError("PX4 gate body read crossed cheap-preflight boundary")


class _PrefixThenBombStream:
    def __init__(self, prefix: bytes) -> None:
        self._prefix = io.BytesIO(prefix)

    def read(self, size: int) -> bytes:
        value = self._prefix.read(size)
        if value:
            return value
        raise AssertionError(
            "PX4 gate read disclosed proof value after metadata rejection"
        )


class _CancelOnRead(io.BytesIO):
    def __init__(self, payload: bytes, token: GatewayCancellationTokenV1):
        super().__init__(payload)
        self.token = token
        self.read_count = 0

    def read(self, size: int = -1) -> bytes:
        value = super().read(size)
        self.read_count += 1
        if self.read_count == 1:
            self.token.cancel()
        return value


class _AdvancingClock:
    def __init__(self) -> None:
        self.calls = 0

    def __call__(self) -> float:
        self.calls += 1
        return 0.0 if self.calls <= 2 else 2.0


def run_gate(
    *,
    artifact_cases: int,
    policy_receipt_cases: int,
    batch_cases: int,
    proof_cases: int,
    cheap_reject_cases: int,
    concurrency_cases: int,
    error_schema_cases: int,
    http_cases: int,
) -> dict[str, object]:
    for name, value, minimum in (
        ("artifact", artifact_cases, MIN_ARTIFACT_CASES),
        ("policy_receipt", policy_receipt_cases, MIN_POLICY_RECEIPT_CASES),
        ("batch", batch_cases, MIN_BATCH_CASES),
        ("proof", proof_cases, MIN_PROOF_CASES),
        ("cheap_reject", cheap_reject_cases, MIN_CHEAP_REJECT_CASES),
        ("concurrency", concurrency_cases, MIN_CONCURRENCY_CASES),
        ("error_schema", error_schema_cases, MIN_ERROR_SCHEMA_CASES),
        ("http", http_cases, MIN_HTTP_CASES),
    ):
        if value < minimum:
            raise ValueError(f"PX4 {name} campaign too small")

    rng = random.Random(0x50583447415445)
    artifact_stream = hashlib.sha256()
    receipt_stream = hashlib.sha256()
    batch_stream = hashlib.sha256()
    proof_stream = hashlib.sha256()
    error_stream = hashlib.sha256()
    http_stream = hashlib.sha256()

    artifact_parity = 0
    policy_receipt_parity = 0
    batch_parity = 0
    proof_parity = 0
    cheap_rejects = 0
    cancelled_isolated = 0
    timeout_isolated = 0
    deterministic_errors = 0
    http_parity = 0
    audit_secret_cases = 0

    with tempfile.TemporaryDirectory(prefix="sigma-px4-gate-") as temp:
        root = Path(temp)
        store = LocalArtifactStoreV1(root / "store")
        audit = MemoryGatewayAuditSinkV1()
        build = b"px4-gate"
        service = GatewayServiceV1(
            store,
            audit_sink=audit,
            verifier_build=build,
            limits=GatewayLimitsV1(
                max_concurrent_requests=8,
                max_response_bytes=32 << 20,
            ),
        )

        for case in range(artifact_cases):
            size = rng.randrange(0, 3 * 65_536 + 257)
            data = rng.randbytes(size)
            artifact = _tree_artifact(data, case)
            store.put_artifact(artifact)
            accepted_policy = case % 4 != 0
            max_input = size if accepted_policy else max(0, size - 1)
            policy = _tree_policy(max_input_bytes=max_input)
            caps = VerificationCapabilitiesV1()

            local = verify_artifact_v1(
                data,
                artifact,
                policy=policy,
                capabilities=caps,
            )
            payload = encode_artifact_verify_request_v1(
                artifact_id=artifact.artifact_id,
                policy=policy,
                capabilities=caps,
                source=data,
            )
            response = service.handle(
                method="POST",
                path="/v1/artifacts/verify",
                content_type=ARTIFACT_VERIFY_MEDIA_TYPE,
                body_stream=io.BytesIO(payload),
                content_length=len(payload),
            )
            expected = artifact_result_json_v1(local)
            if response.status != 200 or response.body != expected:
                raise AssertionError(
                    f"PX4 artifact/local parity divergence at case {case}"
                )
            artifact_stream.update(
                artifact.artifact_id
                + hashlib.sha256(response.body).digest()
            )
            artifact_parity += 1

        for case in range(policy_receipt_cases):
            size = rng.randrange(1, 65_537)
            original = rng.randbytes(size)
            digest = _v3_digest(original, case)
            supplied = original
            if case % 5 == 0:
                mutated = bytearray(original)
                mutated[case % len(mutated)] ^= 1
                supplied = bytes(mutated)
            policy = VerificationPolicyV1()
            caps = VerificationCapabilitiesV1()
            identity = b"px4-" + case.to_bytes(8, "big")

            local_decision = verify_with_policy_v1(
                digest.to_bytes(),
                policy=policy,
                source=supplied,
                capabilities=caps,
            )
            local_receipt = receipt_from_decision_v1(
                identity,
                policy,
                local_decision,
                verifier_package="sigma-framework",
                verifier_version=PACKAGE_VERSION,
                verifier_build=build,
                claimed_unix_time=None,
            )
            payload = encode_policy_evaluate_request_v1(
                artifact_identity=identity,
                evidence_wire=digest.to_bytes(),
                policy=policy,
                capabilities=caps,
                source=supplied,
            )
            response = service.handle(
                method="POST",
                path="/v1/policies/evaluate",
                content_type=POLICY_EVALUATE_MEDIA_TYPE,
                body_stream=io.BytesIO(payload),
                content_length=len(payload),
            )
            expected = decision_result_json_v1(
                local_decision,
                receipt_wire=local_receipt.to_bytes(),
                receipt_id=local_receipt.receipt_id,
            )
            if response.status != 200 or response.body != expected:
                raise AssertionError(
                    f"PX4 policy/receipt parity divergence at case {case}"
                )
            receipt_stream.update(
                local_receipt.receipt_id
                + hashlib.sha256(response.body).digest()
            )
            policy_receipt_parity += 1

        for case in range(batch_cases):
            count = 2 + case % 5
            policy = VerificationPolicyV1()
            caps = VerificationCapabilitiesV1()
            local_items: list[BatchVerificationItemV1] = []
            wire_items = []
            for item_index in range(count):
                data = rng.randbytes(rng.randrange(1, 16_385))
                digest = _v3_digest(data, case * 16 + item_index)
                identity = (
                    b"b"
                    + case.to_bytes(4, "big")
                    + item_index.to_bytes(2, "big")
                )
                local_items.append(
                    BatchVerificationItemV1(
                        identity,
                        digest.to_bytes(),
                        policy,
                        source=data,
                        capabilities=caps,
                    )
                )
                wire_items.append(
                    (identity, digest.to_bytes(), policy, caps, data)
                )
            local = verify_batch_v1(
                tuple(local_items),
                verifier_build=build,
                max_workers=1,
            )
            payload = encode_batch_verify_request_v1(tuple(wire_items))
            response = service.handle(
                method="POST",
                path="/v1/batch/verify",
                content_type=BATCH_VERIFY_MEDIA_TYPE,
                body_stream=io.BytesIO(payload),
                content_length=len(payload),
            )
            if (
                response.status != 200
                or response.content_type != BATCH_RESULT_MEDIA_TYPE
                or response.body != local.to_bytes()
            ):
                raise AssertionError(
                    f"PX4 batch parity divergence at case {case}"
                )
            batch_stream.update(
                local.batch_id + hashlib.sha256(response.body).digest()
            )
            batch_parity += 1

        for case in range(proof_cases):
            size = rng.randrange(1, 5 * 65_536 + 257)
            data = rng.randbytes(size)
            leaf_count = (size + 65_535) // 65_536
            leaf_index = rng.randrange(leaf_count)
            inclusion = prove_leaf(data, leaf_index)
            leaf_start = leaf_index * 65_536
            leaf = data[
                leaf_start : leaf_start + inclusion.leaf_byte_length
            ]
            inclusion_payload = encode_inclusion_verify_request_v1(
                inclusion.to_bytes(),
                leaf,
            )
            inclusion_response = service.handle(
                method="POST",
                path="/v1/proofs/inclusion/verify",
                content_type=INCLUSION_VERIFY_MEDIA_TYPE,
                body_stream=io.BytesIO(inclusion_payload),
                content_length=len(inclusion_payload),
            )
            inclusion_expected = canonical_json_bytes(
                {
                    "schema": "sigma-gateway-proof-verification-v1",
                    "verified": verify_inclusion(leaf, inclusion),
                }
            )
            if inclusion_response.body != inclusion_expected:
                raise AssertionError(
                    f"PX4 inclusion parity divergence at case {case}"
                )

            start = rng.randrange(size)
            length = rng.randrange(1, size - start + 1)
            range_proof = prove_range(data, start, length)
            range_bytes = data[start : start + length]
            range_payload = encode_range_verify_request_v1(
                range_proof.to_bytes(),
                range_bytes,
            )
            range_response = service.handle(
                method="POST",
                path="/v1/proofs/range/verify",
                content_type=RANGE_VERIFY_MEDIA_TYPE,
                body_stream=io.BytesIO(range_payload),
                content_length=len(range_payload),
            )
            range_expected = canonical_json_bytes(
                {
                    "schema": "sigma-gateway-proof-verification-v1",
                    "verified": verify_range(range_bytes, range_proof),
                }
            )
            if range_response.body != range_expected:
                raise AssertionError(
                    f"PX4 range parity divergence at case {case}"
                )
            proof_stream.update(
                hashlib.sha256(inclusion_response.body).digest()
                + hashlib.sha256(range_response.body).digest()
            )
            proof_parity += 2

        for case in range(cheap_reject_cases):
            if case % 2 == 0:
                limited = GatewayServiceV1(
                    store,
                    limits=GatewayLimitsV1(max_request_bytes=64),
                )
                response = limited.handle(
                    method="POST",
                    path="/v1/artifacts/verify",
                    content_type=ARTIFACT_VERIFY_MEDIA_TYPE,
                    body_stream=_BombStream(),
                    content_length=65,
                )
                if (
                    response.status != 413
                    or _json_body(response)["code"] != "request-too-large"
                ):
                    raise AssertionError("PX4 Content-Length preflight diverged")
            else:
                data = rng.randbytes(2048)
                artifact = _tree_artifact(
                    data,
                    100_000 + case,
                )
                store.put_artifact(artifact)
                policy = _tree_policy(max_input_bytes=1)
                payload = encode_artifact_verify_request_v1(
                    artifact_id=artifact.artifact_id,
                    policy=policy,
                    source=data,
                )
                before = len(audit.records)
                response = service.handle(
                    method="POST",
                    path="/v1/artifacts/verify",
                    content_type=ARTIFACT_VERIFY_MEDIA_TYPE,
                    body_stream=io.BytesIO(payload),
                    content_length=len(payload),
                )
                if _json_body(response)["policy"]["code"] != "input-too-large":
                    raise AssertionError("PX4 policy cheap reject diverged")
                record = audit.records[before]
                if record.bytes_in >= len(payload):
                    raise AssertionError(
                        "PX4 policy reject consumed source body"
                    )
            cheap_rejects += 1

        spool_data = b"px4-spool-budget" * 100
        spool_artifact = _tree_artifact(spool_data, 150_000)
        store.put_artifact(spool_artifact)
        spool_policy = _tree_policy(max_input_bytes=len(spool_data))
        spool_payload = encode_artifact_verify_request_v1(
            artifact_id=spool_artifact.artifact_id,
            policy=spool_policy,
            source=spool_data,
        )
        spool_prefix = spool_payload[: -len(spool_data)]
        spool_service = GatewayServiceV1(
            store,
            limits=GatewayLimitsV1(
                max_source_bytes=len(spool_data) + 1,
                max_total_spool_bytes=len(spool_data) - 1,
            ),
            spool_temp_dir=root / "spool-budget",
        )
        spool_response = spool_service.handle(
            method="POST",
            path="/v1/artifacts/verify",
            content_type=ARTIFACT_VERIFY_MEDIA_TYPE,
            body_stream=_PrefixThenBombStream(spool_prefix),
            content_length=len(spool_payload),
        )
        if (
            spool_response.status != 503
            or _json_body(spool_response)["code"] != "busy"
        ):
            raise AssertionError("PX4 global spool budget did not fail closed")
        if spool_service._spool_budget.used != 0:
            raise AssertionError("PX4 spool reservation leaked after rejection")
        spool_budget_cheap_reject = True

        malformed_disclosed = b"x" * (1 << 20)
        malformed_proof_payload = encode_inclusion_verify_request_v1(
            b"not-a-proof",
            malformed_disclosed,
        )
        malformed_prefix = malformed_proof_payload[: -len(malformed_disclosed)]
        malformed_response = service.handle(
            method="POST",
            path="/v1/proofs/inclusion/verify",
            content_type=INCLUSION_VERIFY_MEDIA_TYPE,
            body_stream=_PrefixThenBombStream(malformed_prefix),
            content_length=len(malformed_proof_payload),
        )
        if (
            malformed_response.status != 400
            or _json_body(malformed_response)["code"] != "malformed-proof"
        ):
            raise AssertionError(
                "PX4 malformed proof did not reject before disclosed value"
            )
        proof_metadata_cheap_reject = True

        concurrency_payload_data = b"px4-concurrency" * 80
        concurrency_artifact = _tree_artifact(
            concurrency_payload_data,
            200_000,
        )
        store.put_artifact(concurrency_artifact)
        concurrency_policy = _tree_policy(
            max_input_bytes=len(concurrency_payload_data)
        )
        concurrency_payload = encode_artifact_verify_request_v1(
            artifact_id=concurrency_artifact.artifact_id,
            policy=concurrency_policy,
            source=concurrency_payload_data,
        )

        for case in range(concurrency_cases):
            token = GatewayCancellationTokenV1(timeout_seconds=30)

            def cancelled_call():
                return service.handle(
                    method="POST",
                    path="/v1/artifacts/verify",
                    content_type=ARTIFACT_VERIFY_MEDIA_TYPE,
                    body_stream=_CancelOnRead(
                        concurrency_payload,
                        token,
                    ),
                    content_length=len(concurrency_payload),
                    token=token,
                )

            def healthy_call():
                return service.handle(
                    method="POST",
                    path="/v1/artifacts/verify",
                    content_type=ARTIFACT_VERIFY_MEDIA_TYPE,
                    body_stream=io.BytesIO(concurrency_payload),
                    content_length=len(concurrency_payload),
                )

            with ThreadPoolExecutor(max_workers=2) as executor:
                left = executor.submit(cancelled_call)
                right = executor.submit(healthy_call)
                cancelled_response = left.result()
                healthy_response = right.result()

            if (
                cancelled_response.status != 409
                or _json_body(cancelled_response)["code"] != "cancelled"
                or healthy_response.status != 200
                or not _json_body(healthy_response)["accepted"]
            ):
                raise AssertionError(
                    f"PX4 cancellation isolation divergence at case {case}"
                )
            cancelled_isolated += 1

            timeout_token = GatewayCancellationTokenV1(
                timeout_seconds=1.0,
                monotonic=_AdvancingClock(),
            )
            timeout_response = service.handle(
                method="POST",
                path="/v1/artifacts/verify",
                content_type=ARTIFACT_VERIFY_MEDIA_TYPE,
                body_stream=io.BytesIO(concurrency_payload),
                content_length=len(concurrency_payload),
                token=timeout_token,
            )
            if (
                timeout_response.status != 408
                or _json_body(timeout_response)["code"] != "timeout"
            ):
                raise AssertionError(
                    f"PX4 timeout isolation divergence at case {case}"
                )
            timeout_isolated += 1

        for case in range(error_schema_cases):
            malformed = (
                b"BADMAGIC"
                + case.to_bytes(2, "big")
                + rng.randbytes(case % 23)
            )
            first = service.handle(
                method="POST",
                path="/v1/artifacts/verify",
                content_type=ARTIFACT_VERIFY_MEDIA_TYPE,
                body_stream=io.BytesIO(malformed),
                content_length=len(malformed),
            )
            second = service.handle(
                method="POST",
                path="/v1/artifacts/verify",
                content_type=ARTIFACT_VERIFY_MEDIA_TYPE,
                body_stream=io.BytesIO(malformed),
                content_length=len(malformed),
            )
            if (
                first.status != second.status
                or first.body != second.body
                or _json_body(first)["schema"] != "sigma-gateway-error-v1"
            ):
                raise AssertionError(
                    f"PX4 deterministic error schema divergence at case {case}"
                )
            error_stream.update(hashlib.sha256(first.body).digest())
            deterministic_errors += 1

        # PX1 mutable parent index must never become gateway authority.
        store_check = LocalArtifactStoreV1(root / "store-index-check")
        store_parent = _tree_artifact(b"px4-store-parent", 240_000)
        store_child = create_artifact_v1(
            ArtifactProfileV1.TREE,
            tree_root=build_tree(b"px4-store-child"),
            parent_artifact_ids=(store_parent.artifact_id,),
        )
        store_check.put_artifact(store_parent)
        store_check.put_artifact(store_child)
        connection = sqlite3.connect(store_check.database_path)
        try:
            connection.execute(
                "DELETE FROM artifact_parents WHERE child_id=?",
                (store_child.artifact_id,),
            )
            connection.execute(
                "INSERT INTO artifact_parents(child_id, parent_id) VALUES(?, ?)",
                (store_child.artifact_id, bytes.fromhex("55" * 32)),
            )
            connection.commit()
        finally:
            connection.close()
        store_response = GatewayServiceV1(store_check).handle(
            method="GET",
            path=f"/v1/artifacts/{store_child.artifact_id.hex()}/parents",
            content_type="",
            body_stream=io.BytesIO(b""),
            content_length=0,
        )
        if (
            store_response.status != 500
            or _json_body(store_response)["code"] != "internal"
        ):
            raise AssertionError(
                "PX4 exposed mutable parent index instead of canonical artifact"
            )
        canonical_store_authority_enforced = True

        # Canonical routing and audit-field normalization.
        route_artifact = _tree_artifact(b"px4-route-canonicality", 250_000)
        store.put_artifact(route_artifact)
        uppercase_route = service.handle(
            method="GET",
            path=f"/v1/artifacts/{route_artifact.artifact_id.hex().upper()}",
            content_type="",
            body_stream=io.BytesIO(b""),
            content_length=0,
        )
        if (
            uppercase_route.status != 404
            or _json_body(uppercase_route)["code"] != "not-found"
        ):
            raise AssertionError("PX4 accepted non-canonical ArtifactId path alias")
        canonical_artifact_route_enforced = True

        secret_method = "SECRET-METHOD-TOKEN"
        before_audit = len(audit.records)
        secret_method_response = service.handle(
            method=secret_method,
            path="/health",
            content_type="",
            body_stream=io.BytesIO(b""),
            content_length=0,
        )
        if secret_method_response.status != 404:
            raise AssertionError("PX4 arbitrary method fixture status diverged")
        method_record = audit.records[before_audit]
        if method_record.method != "<other>" or secret_method.encode() in method_record.to_json_bytes():
            raise AssertionError("PX4 arbitrary HTTP method leaked into audit")
        audit_method_normalized = True

        # Actual localhost HTTP adapter campaign.
        http_audit = MemoryGatewayAuditSinkV1()
        http_service = GatewayServiceV1(
            store,
            audit_sink=http_audit,
            verifier_build=build,
        )
        server = create_gateway_http_server_v1(
            "127.0.0.1",
            0,
            http_service,
        )
        thread = threading.Thread(
            target=server.serve_forever,
            daemon=True,
        )
        thread.start()
        try:
            host, port = server.server_address
            for case in range(http_cases):
                data = rng.randbytes(rng.randrange(0, 8193))
                artifact = _tree_artifact(
                    data,
                    300_000 + case,
                )
                store.put_artifact(artifact)
                policy = _tree_policy(max_input_bytes=len(data))
                payload = encode_artifact_verify_request_v1(
                    artifact_id=artifact.artifact_id,
                    policy=policy,
                    source=data,
                )
                local = verify_artifact_v1(
                    data,
                    artifact,
                    policy=policy,
                )
                connection = http.client.HTTPConnection(
                    host,
                    port,
                    timeout=10,
                )
                connection.request(
                    "POST",
                    "/v1/artifacts/verify",
                    body=payload,
                    headers={
                        "Authorization": f"Bearer secret-{case}",
                        "Cookie": f"session=secret-cookie-{case}",
                        "Content-Type": ARTIFACT_VERIFY_MEDIA_TYPE,
                    },
                )
                response = connection.getresponse()
                body = response.read()
                connection.close()
                if (
                    response.status != 200
                    or body != artifact_result_json_v1(local)
                ):
                    raise AssertionError(
                        f"PX4 HTTP/local parity divergence at case {case}"
                    )
                http_stream.update(
                    artifact.artifact_id
                    + hashlib.sha256(body).digest()
                )
                http_parity += 1

                connection = http.client.HTTPConnection(
                    host,
                    port,
                    timeout=10,
                )
                secret = f"query-secret-{case}"
                connection.request(
                    "GET",
                    f"/health?token={secret}",
                    headers={
                        "Authorization": f"Bearer auth-secret-{case}",
                        "Cookie": f"session=cookie-secret-{case}",
                    },
                )
                rejected = connection.getresponse()
                rejected.read()
                connection.close()
                if rejected.status != 400:
                    raise AssertionError("PX4 query-bearing HTTP request not rejected")
                record = http_audit.records[-1]
                serialized = record.to_json_bytes()
                for forbidden in (
                    secret.encode(),
                    f"auth-secret-{case}".encode(),
                    f"cookie-secret-{case}".encode(),
                ):
                    if forbidden in serialized:
                        raise AssertionError(
                            "PX4 structured audit leaked request secret"
                        )
                if record.endpoint != "/health":
                    raise AssertionError(
                        "PX4 audit endpoint was not normalized"
                    )
                audit_secret_cases += 1
            # Header credentials are transport-only: the exact receipt must equal
            # the local library result under different Authorization/Cookie values.
            receipt_data = b"px4-http-receipt-independence"
            receipt_digest = _v3_digest(receipt_data, 999_999)
            receipt_policy = VerificationPolicyV1()
            receipt_identity = b"px4-http-receipt"
            receipt_payload = encode_policy_evaluate_request_v1(
                artifact_identity=receipt_identity,
                evidence_wire=receipt_digest.to_bytes(),
                policy=receipt_policy,
                source=receipt_data,
            )
            receipt_decision = verify_with_policy_v1(
                receipt_digest.to_bytes(),
                policy=receipt_policy,
                source=receipt_data,
            )
            receipt_local = receipt_from_decision_v1(
                receipt_identity,
                receipt_policy,
                receipt_decision,
                verifier_package="sigma-framework",
                verifier_version=PACKAGE_VERSION,
                verifier_build=build,
                claimed_unix_time=None,
            )
            receipt_expected = decision_result_json_v1(
                receipt_decision,
                receipt_wire=receipt_local.to_bytes(),
                receipt_id=receipt_local.receipt_id,
            )
            receipt_bodies = []
            for secret in ("secret-a", "secret-b"):
                connection = http.client.HTTPConnection(
                    host,
                    port,
                    timeout=10,
                )
                connection.request(
                    "POST",
                    "/v1/policies/evaluate",
                    body=receipt_payload,
                    headers={
                        "Authorization": f"Bearer {secret}",
                        "Cookie": f"session={secret}",
                        "Content-Type": POLICY_EVALUATE_MEDIA_TYPE,
                    },
                )
                response = connection.getresponse()
                receipt_bodies.append(response.read())
                if response.status != 200:
                    raise AssertionError(
                        "PX4 credential receipt HTTP status diverged"
                    )
                connection.close()
            if receipt_bodies != [receipt_expected, receipt_expected]:
                raise AssertionError(
                    "PX4 credentials changed policy receipt bytes"
                )
            credential_receipt_independent = True

            # Raw HTTP framing hardening: these cases are outside the ordinary
            # high-level client path and must still use canonical PX4 JSON.
            def raw_request(payload: bytes) -> bytes:
                with socket.create_connection((host, port), timeout=10) as sock:
                    sock.sendall(payload)
                    chunks = []
                    while True:
                        part = sock.recv(4096)
                        if not part:
                            break
                        chunks.append(part)
                return b"".join(chunks)

            duplicate_length = raw_request(
                (
                    "POST /v1/artifacts/verify HTTP/1.1\r\n"
                    f"Host: {host}:{port}\r\n"
                    f"Content-Type: {ARTIFACT_VERIFY_MEDIA_TYPE}\r\n"
                    "Content-Length: 0\r\n"
                    "Content-Length: 1\r\n"
                    "Connection: close\r\n"
                    "\r\n"
                ).encode("ascii")
            )
            if not duplicate_length.startswith(b"HTTP/1.1 400"):
                raise AssertionError("PX4 duplicate Content-Length was not rejected")
            if b"sigma-gateway-error-v1" not in duplicate_length:
                raise AssertionError("PX4 transport error escaped canonical JSON schema")

            header_lines = "".join(
                f"X-PX4-{index}: " + ("x" * 9000) + "\r\n"
                for index in range(8)
            )
            oversized_headers = raw_request(
                (
                    "GET /health HTTP/1.1\r\n"
                    f"Host: {host}:{port}\r\n"
                    + header_lines
                    + "Connection: close\r\n\r\n"
                ).encode("ascii")
            )
            if not oversized_headers.startswith(b"HTTP/1.1 431"):
                raise AssertionError("PX4 preparse header budget did not reject")
            if b"sigma-gateway-error-v1" not in oversized_headers:
                raise AssertionError("PX4 header reject escaped canonical JSON schema")

            expect_oversize = raw_request(
                (
                    "POST /v1/artifacts/verify HTTP/1.1\r\n"
                    f"Host: {host}:{port}\r\n"
                    f"Content-Type: {ARTIFACT_VERIFY_MEDIA_TYPE}\r\n"
                    f"Content-Length: {http_service.limits.max_request_bytes + 1}\r\n"
                    "Expect: 100-continue\r\n"
                    "Connection: close\r\n"
                    "\r\n"
                ).encode("ascii")
            )
            if not expect_oversize.startswith(b"HTTP/1.1 413"):
                raise AssertionError("PX4 Expect preflight did not reject oversized body")
            if expect_oversize.startswith(b"HTTP/1.1 100"):
                raise AssertionError("PX4 sent 100 Continue before size admission")

            noncanonical_length = raw_request(
                (
                    "POST /v1/artifacts/verify HTTP/1.1\r\n"
                    f"Host: {host}:{port}\r\n"
                    f"Content-Type: {ARTIFACT_VERIFY_MEDIA_TYPE}\r\n"
                    "Content-Length: +1\r\n"
                    "Connection: close\r\n"
                    "\r\n"
                ).encode("ascii")
            )
            if not noncanonical_length.startswith(b"HTTP/1.1 400"):
                raise AssertionError("PX4 accepted noncanonical Content-Length")

            unsupported_expect = raw_request(
                (
                    "POST /v1/artifacts/verify HTTP/1.1\r\n"
                    f"Host: {host}:{port}\r\n"
                    f"Content-Type: {ARTIFACT_VERIFY_MEDIA_TYPE}\r\n"
                    "Content-Length: 0\r\n"
                    "Expect: nonsense\r\n"
                    "Connection: close\r\n"
                    "\r\n"
                ).encode("ascii")
            )
            if not unsupported_expect.startswith(b"HTTP/1.1 417"):
                raise AssertionError("PX4 accepted unsupported Expect header")
            if b"expectation-failed" not in unsupported_expect:
                raise AssertionError("PX4 unsupported Expect error code diverged")

            http_framing_hardening = True

        finally:
            server.shutdown()
            server.server_close()
            thread.join(timeout=10)

        # Bound connection threads before request parsing/service admission.
        connection_service = GatewayServiceV1(
            store,
            limits=GatewayLimitsV1(max_http_connections=1),
        )
        connection_server = create_gateway_http_server_v1(
            "127.0.0.1",
            0,
            connection_service,
        )
        connection_thread = threading.Thread(
            target=connection_server.serve_forever,
            daemon=True,
        )
        connection_thread.start()
        if not connection_server._connection_slots.acquire(blocking=False):
            raise AssertionError("PX4 connection-slot fixture could not reserve slot")
        try:
            connection_host, connection_port = connection_server.server_address
            connection = http.client.HTTPConnection(
                connection_host,
                connection_port,
                timeout=10,
            )
            connection.request("GET", "/health")
            response = connection.getresponse()
            body = response.read()
            connection.close()
            if (
                response.status != 503
                or json.loads(body.decode("ascii"))["code"] != "busy"
            ):
                raise AssertionError(
                    "PX4 HTTP connection admission did not fail closed"
                )
            http_connection_limit_rejected = True
        finally:
            connection_server._connection_slots.release()
            connection_server.shutdown()
            connection_server.server_close()
            connection_thread.join(timeout=10)


    return {
        "schema": "sigma-px4-verification-gateway-gate-v1",
        "passed": True,
        "closure_eligible": True,
        "artifact_cases": artifact_cases,
        "artifact_local_parity": artifact_parity,
        "policy_receipt_cases": policy_receipt_cases,
        "policy_receipt_parity": policy_receipt_parity,
        "batch_cases": batch_cases,
        "batch_wire_parity": batch_parity,
        "proof_cases": proof_cases,
        "proof_results_checked": proof_parity,
        "cheap_reject_cases": cheap_reject_cases,
        "cheap_rejects": cheap_rejects,
        "proof_metadata_cheap_reject": proof_metadata_cheap_reject,
        "spool_budget_cheap_reject": spool_budget_cheap_reject,
        "concurrency_cases": concurrency_cases,
        "cancelled_requests_isolated": cancelled_isolated,
        "timeout_requests_isolated": timeout_isolated,
        "error_schema_cases": error_schema_cases,
        "deterministic_error_cases": deterministic_errors,
        "canonical_store_authority_enforced": canonical_store_authority_enforced,
        "canonical_artifact_route_enforced": canonical_artifact_route_enforced,
        "audit_method_normalized": audit_method_normalized,
        "http_cases": http_cases,
        "http_local_parity": http_parity,
        "audit_secret_cases": audit_secret_cases,
        "credential_receipt_independent": credential_receipt_independent,
        "http_framing_hardening": http_framing_hardening,
        "http_connection_limit_rejected": http_connection_limit_rejected,
        "artifact_stream_sha256": artifact_stream.hexdigest(),
        "receipt_stream_sha256": receipt_stream.hexdigest(),
        "batch_stream_sha256": batch_stream.hexdigest(),
        "proof_stream_sha256": proof_stream.hexdigest(),
        "error_stream_sha256": error_stream.hexdigest(),
        "http_stream_sha256": http_stream.hexdigest(),
        "gateway_reimplements_crypto": False,
        "raw_request_headers_in_audit_schema": False,
        "query_strings_in_audit_schema": False,
        "github_actions_required": False,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--artifact-cases", type=int, default=MIN_ARTIFACT_CASES)
    parser.add_argument(
        "--policy-receipt-cases",
        type=int,
        default=MIN_POLICY_RECEIPT_CASES,
    )
    parser.add_argument("--batch-cases", type=int, default=MIN_BATCH_CASES)
    parser.add_argument("--proof-cases", type=int, default=MIN_PROOF_CASES)
    parser.add_argument(
        "--cheap-reject-cases",
        type=int,
        default=MIN_CHEAP_REJECT_CASES,
    )
    parser.add_argument(
        "--concurrency-cases",
        type=int,
        default=MIN_CONCURRENCY_CASES,
    )
    parser.add_argument(
        "--error-schema-cases",
        type=int,
        default=MIN_ERROR_SCHEMA_CASES,
    )
    parser.add_argument("--http-cases", type=int, default=MIN_HTTP_CASES)
    parser.add_argument("--report", type=Path)
    args = parser.parse_args()

    report = run_gate(
        artifact_cases=args.artifact_cases,
        policy_receipt_cases=args.policy_receipt_cases,
        batch_cases=args.batch_cases,
        proof_cases=args.proof_cases,
        cheap_reject_cases=args.cheap_reject_cases,
        concurrency_cases=args.concurrency_cases,
        error_schema_cases=args.error_schema_cases,
        http_cases=args.http_cases,
    )
    payload = json.dumps(report, indent=2, sort_keys=True) + "\n"
    if args.report is not None:
        args.report.parent.mkdir(parents=True, exist_ok=True)
        args.report.write_text(payload, encoding="utf-8")
    print(payload, end="")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
