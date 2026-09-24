from __future__ import annotations

import http.client
import io
import json
import socket
import sqlite3
import threading
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

import pytest

from sigma.artifact import (
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
    GatewayResponseV1,
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
from sigma.gateway.cli import build_parser_v1, main as gateway_cli_main
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
from sigma.tree import (
    build_tree,
    prove_leaf,
    prove_range,
    verify_inclusion,
    verify_range,
)
from sigma.v3 import evaluate_v3
from sigma.version import PACKAGE_VERSION


def _tree_artifact(data: bytes):
    return create_artifact_v1(
        ArtifactProfileV1.TREE,
        tree_root=build_tree(data),
    )


def _tree_policy(**overrides):
    values = {"allow_tree_only_artifacts": True}
    values.update(overrides)
    return VerificationPolicyV1(**values)


def _v3_digest(data: bytes):
    context = SigmaContextV3.for_suite(
        SuiteIdV3.REFERENCE_IAP_HISTORY_V3,
        salt=b"px4",
        challenge=b"gateway",
        application_context=b"tests/px4",
    )
    evaluation = evaluate_v3(context, BytesSource(data))
    return digest_from_evaluation_v3(evaluation)


def _json(response):
    return json.loads(response.body.decode("ascii"))



def _raw_http_request(host: str, port: int, payload: bytes) -> bytes:
    with socket.create_connection((host, port), timeout=5) as connection:
        connection.sendall(payload)
        chunks = []
        while True:
            part = connection.recv(4096)
            if not part:
                break
            chunks.append(part)
    return b"".join(chunks)


def test_px4_response_type_rejects_header_injection():
    with pytest.raises(ValueError, match="content_type"):
        GatewayResponseV1(
            200,
            "application/json\r\nX-Evil: 1",
            b"{}",
        )
    with pytest.raises(ValueError, match="headers"):
        GatewayResponseV1(
            200,
            "application/json",
            b"{}",
            (("X-Test", "ok\r\nX-Evil: 1"),),
        )

def test_px4_artifact_gateway_exactly_matches_local_api(tmp_path: Path):
    data = b"px4-artifact-parity" * 100
    artifact = _tree_artifact(data)
    policy = _tree_policy()
    caps = VerificationCapabilitiesV1()

    store = LocalArtifactStoreV1(tmp_path / "store")
    store.put_artifact(artifact)
    service = GatewayServiceV1(store)

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

    assert response.status == 200
    assert response.body == artifact_result_json_v1(local)


def test_px4_embedded_artifact_parity_and_id_mismatch(tmp_path: Path):
    data = b"embedded-artifact"
    artifact = _tree_artifact(data)
    policy = _tree_policy()

    service = GatewayServiceV1(LocalArtifactStoreV1(tmp_path / "store"))

    payload = encode_artifact_verify_request_v1(
        artifact_id=artifact.artifact_id,
        artifact_wire=artifact.to_bytes(),
        policy=policy,
        source=data,
    )
    response = service.handle(
        method="POST",
        path="/v1/artifacts/verify",
        content_type=ARTIFACT_VERIFY_MEDIA_TYPE,
        body_stream=io.BytesIO(payload),
        content_length=len(payload),
    )
    assert response.body == artifact_result_json_v1(
        verify_artifact_v1(data, artifact, policy=policy)
    )

    wrong = bytes([artifact.artifact_id[0] ^ 1]) + artifact.artifact_id[1:]
    mismatch = encode_artifact_verify_request_v1(
        artifact_id=wrong,
        artifact_wire=artifact.to_bytes(),
        policy=policy,
        source=data,
    )
    rejected = service.handle(
        method="POST",
        path="/v1/artifacts/verify",
        content_type=ARTIFACT_VERIFY_MEDIA_TYPE,
        body_stream=io.BytesIO(mismatch),
        content_length=len(mismatch),
    )
    assert rejected.status == 409
    assert _json(rejected)["code"] == "artifact-id-mismatch"


def test_px4_policy_decision_and_receipt_are_byte_exact_local_parity(tmp_path: Path):
    data = b"px4-policy-evidence" * 40
    digest = _v3_digest(data)
    policy = VerificationPolicyV1()
    caps = VerificationCapabilitiesV1()
    identity = b"px4-policy-case"
    build = b"test-build"

    local_decision = verify_with_policy_v1(
        digest.to_bytes(),
        policy=policy,
        source=data,
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


    service = GatewayServiceV1(
        LocalArtifactStoreV1(tmp_path / "store"),
        verifier_build=build,
    )
    payload = encode_policy_evaluate_request_v1(
        artifact_identity=identity,
        evidence_wire=digest.to_bytes(),
        policy=policy,
        capabilities=caps,
        source=data,
    )
    response = service.handle(
        method="POST",
        path="/v1/policies/evaluate",
        content_type=POLICY_EVALUATE_MEDIA_TYPE,
        body_stream=io.BytesIO(payload),
        content_length=len(payload),
    )

    assert response.status == 200
    assert response.body == decision_result_json_v1(
        local_decision,
        receipt_wire=local_receipt.to_bytes(),
        receipt_id=local_receipt.receipt_id,
    )


def test_px4_batch_result_wire_matches_sv3_local_batch_exactly(tmp_path: Path):
    data_a = b"batch-a" * 30
    data_b = b"batch-b" * 50
    digest_a = _v3_digest(data_a)
    digest_b = _v3_digest(data_b)
    policy = VerificationPolicyV1()
    caps = VerificationCapabilitiesV1()
    build = b"px4-batch"

    local_items = (
        BatchVerificationItemV1(
            b"batch-a",
            digest_a.to_bytes(),
            policy,
            source=data_a,
            capabilities=caps,
        ),
        BatchVerificationItemV1(
            b"batch-b",
            digest_b.to_bytes(),
            policy,
            source=data_b,
            capabilities=caps,
        ),
    )
    local = verify_batch_v1(
        local_items,
        verifier_build=build,
        max_workers=1,
    )


    service = GatewayServiceV1(
        LocalArtifactStoreV1(tmp_path / "store"),
        verifier_build=build,
    )
    payload = encode_batch_verify_request_v1(
        (
            (b"batch-a", digest_a.to_bytes(), policy, caps, data_a),
            (b"batch-b", digest_b.to_bytes(), policy, caps, data_b),
        )
    )
    response = service.handle(
        method="POST",
        path="/v1/batch/verify",
        content_type=BATCH_VERIFY_MEDIA_TYPE,
        body_stream=io.BytesIO(payload),
        content_length=len(payload),
    )
    assert response.status == 200
    assert response.content_type == BATCH_RESULT_MEDIA_TYPE
    assert response.body == local.to_bytes()


def test_px4_proof_endpoints_match_local_verifiers(tmp_path: Path):
    data = bytes((index * 17 + 5) % 251 for index in range(3 * 65_536 + 101))
    inclusion = prove_leaf(data, 1)
    leaf_start = inclusion.leaf_index * inclusion.profile.chunk_size
    leaf = data[leaf_start : leaf_start + inclusion.leaf_byte_length]

    range_start = 65_536 - 11
    range_length = 65_536 + 53
    range_proof = prove_range(data, range_start, range_length)
    range_bytes = data[range_start : range_start + range_length]


    service = GatewayServiceV1(LocalArtifactStoreV1(tmp_path / "store"))

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
    assert inclusion_response.body == canonical_json_bytes(
        {
            "schema": "sigma-gateway-proof-verification-v1",
            "verified": verify_inclusion(leaf, inclusion),
        }
    )

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
    assert range_response.body == canonical_json_bytes(
        {
            "schema": "sigma-gateway-proof-verification-v1",
            "verified": verify_range(range_bytes, range_proof),
        }
    )



def test_px4_malformed_proof_rejects_before_disclosed_value_read(tmp_path: Path):
    service = GatewayServiceV1(LocalArtifactStoreV1(tmp_path / "store"))
    disclosed = b"x" * (1 << 20)
    payload = encode_inclusion_verify_request_v1(b"not-a-proof", disclosed)
    prefix = payload[: -len(disclosed)]

    response = service.handle(
        method="POST",
        path="/v1/proofs/inclusion/verify",
        content_type=INCLUSION_VERIFY_MEDIA_TYPE,
        body_stream=PrefixThenBombStream(prefix),
        content_length=len(payload),
    )
    assert response.status == 400
    assert _json(response)["code"] == "malformed-proof"


def test_px4_proof_length_mismatch_matches_local_false_without_value_read(
    tmp_path: Path,
):
    data = b"proof-cheap-length" * 5000
    proof = prove_leaf(data, 0)
    disclosed_length = proof.leaf_byte_length + 1
    disclosed = b"x" * disclosed_length
    payload = encode_inclusion_verify_request_v1(proof.to_bytes(), disclosed)
    prefix = payload[: -disclosed_length]

    response = GatewayServiceV1(
        LocalArtifactStoreV1(tmp_path / "store")
    ).handle(
        method="POST",
        path="/v1/proofs/inclusion/verify",
        content_type=INCLUSION_VERIFY_MEDIA_TYPE,
        body_stream=PrefixThenBombStream(prefix),
        content_length=len(payload),
    )
    assert response.status == 200
    assert _json(response) == {
        "schema": "sigma-gateway-proof-verification-v1",
        "verified": False,
    }


def test_px4_range_length_mismatch_returns_false_without_value_read(tmp_path: Path):
    data = b"range-cheap-length" * 6000
    proof = prove_range(data, 17, min(5000, len(data) - 17))
    disclosed_length = proof.length + 1
    disclosed = b"x" * disclosed_length
    payload = encode_range_verify_request_v1(proof.to_bytes(), disclosed)
    prefix = payload[: -disclosed_length]

    response = GatewayServiceV1(
        LocalArtifactStoreV1(tmp_path / "store")
    ).handle(
        method="POST",
        path="/v1/proofs/range/verify",
        content_type=RANGE_VERIFY_MEDIA_TYPE,
        body_stream=PrefixThenBombStream(prefix),
        content_length=len(payload),
    )
    assert response.status == 200
    assert _json(response)["verified"] is False

def test_px4_get_artifact_and_parents_use_canonical_artifact_bytes(tmp_path: Path):

    store = LocalArtifactStoreV1(tmp_path / "store")
    parent = _tree_artifact(b"parent")
    child = create_artifact_v1(
        ArtifactProfileV1.TREE,
        tree_root=build_tree(b"child"),
        parent_artifact_ids=(parent.artifact_id,),
    )
    store.put_artifact(parent)
    store.put_artifact(child)
    service = GatewayServiceV1(store)

    get_artifact = service.handle(
        method="GET",
        path=f"/v1/artifacts/{child.artifact_id.hex()}",
        content_type="",
        body_stream=io.BytesIO(b""),
        content_length=0,
    )
    assert get_artifact.body == child.to_bytes()

    parents = service.handle(
        method="GET",
        path=f"/v1/artifacts/{child.artifact_id.hex()}/parents",
        content_type="",
        body_stream=io.BytesIO(b""),
        content_length=0,
    )
    assert _json(parents) == {
        "artifact_id": child.artifact_id.hex(),
        "parents": [parent.artifact_id.hex()],
        "schema": "sigma-gateway-artifact-parents-v1",
    }




def test_px4_parent_get_fails_closed_on_mutable_index_divergence(tmp_path: Path):
    store = LocalArtifactStoreV1(tmp_path / "store")
    parent = _tree_artifact(b"canonical-parent")
    child = create_artifact_v1(
        ArtifactProfileV1.TREE,
        tree_root=build_tree(b"canonical-child"),
        parent_artifact_ids=(parent.artifact_id,),
    )
    store.put_artifact(parent)
    store.put_artifact(child)

    connection = sqlite3.connect(store.database_path)
    try:
        connection.execute(
            "DELETE FROM artifact_parents WHERE child_id=?",
            (child.artifact_id,),
        )
        connection.execute(
            "INSERT INTO artifact_parents(child_id, parent_id) VALUES(?, ?)",
            (child.artifact_id, bytes.fromhex("44" * 32)),
        )
        connection.commit()
    finally:
        connection.close()

    response = GatewayServiceV1(store).handle(
        method="GET",
        path=f"/v1/artifacts/{child.artifact_id.hex()}/parents",
        content_type="",
        body_stream=io.BytesIO(b""),
        content_length=0,
    )
    assert response.status == 500
    assert _json(response)["code"] == "internal"

def test_px4_artifact_route_rejects_noncanonical_uppercase_id(tmp_path: Path):
    store = LocalArtifactStoreV1(tmp_path / "store")
    artifact = _tree_artifact(b"canonical-route")
    store.put_artifact(artifact)
    upper = artifact.artifact_id.hex().upper()
    assert upper != artifact.artifact_id.hex()

    response = GatewayServiceV1(store).handle(
        method="GET",
        path=f"/v1/artifacts/{upper}",
        content_type="",
        body_stream=io.BytesIO(b""),
        content_length=0,
    )
    assert response.status == 404
    assert _json(response)["code"] == "not-found"

def test_px4_policy_preflight_rejects_without_hashing_or_reading_source(
    tmp_path: Path,
    monkeypatch,
):
    data = b"x" * 4096
    artifact = _tree_artifact(data)
    policy = _tree_policy(max_input_bytes=1)

    store = LocalArtifactStoreV1(tmp_path / "store")
    store.put_artifact(artifact)
    audit = MemoryGatewayAuditSinkV1()
    service = GatewayServiceV1(store, audit_sink=audit)

    import sigma.artifact.verify as verify_module

    class BombTreeBuilder:
        def __init__(self, *args, **kwargs):
            raise AssertionError("expensive Tree hashing started after policy preflight")

    monkeypatch.setattr(verify_module, "TreeBuilder", BombTreeBuilder)

    payload = encode_artifact_verify_request_v1(
        artifact_id=artifact.artifact_id,
        policy=policy,
        source=data,
    )
    response = service.handle(
        method="POST",
        path="/v1/artifacts/verify",
        content_type=ARTIFACT_VERIFY_MEDIA_TYPE,
        body_stream=io.BytesIO(payload),
        content_length=len(payload),
    )
    body = _json(response)
    assert body["policy"]["code"] == "input-too-large"
    assert audit.records[-1].bytes_in < len(payload)


class BombStream:
    def read(self, size: int) -> bytes:
        raise AssertionError("body was read despite Content-Length preflight")


class PrefixThenBombStream:
    def __init__(self, prefix: bytes) -> None:
        self._prefix = io.BytesIO(prefix)

    def read(self, size: int) -> bytes:
        value = self._prefix.read(size)
        if value:
            return value
        raise AssertionError("gateway read disclosed proof value after cheap rejection")


def test_px4_request_length_limit_rejects_before_any_body_read(tmp_path: Path):

    limits = GatewayLimitsV1(max_request_bytes=64)
    service = GatewayServiceV1(
        LocalArtifactStoreV1(tmp_path / "store"),
        limits=limits,
    )
    response = service.handle(
        method="POST",
        path="/v1/artifacts/verify",
        content_type=ARTIFACT_VERIFY_MEDIA_TYPE,
        body_stream=BombStream(),
        content_length=65,
    )
    assert response.status == 413
    assert _json(response)["code"] == "request-too-large"


class CancelAfterFirstRead(io.BytesIO):
    def __init__(self, payload: bytes, token: GatewayCancellationTokenV1):
        super().__init__(payload)
        self.token = token
        self.reads = 0

    def read(self, size: int = -1) -> bytes:
        value = super().read(size)
        self.reads += 1
        if self.reads == 1:
            self.token.cancel()
        return value



def test_px4_global_spool_budget_rejects_before_source_read(tmp_path: Path):
    data = b"spool-budget" * 100
    artifact = _tree_artifact(data)
    policy = _tree_policy(max_input_bytes=len(data))
    store = LocalArtifactStoreV1(tmp_path / "store")
    store.put_artifact(artifact)
    service = GatewayServiceV1(
        store,
        limits=GatewayLimitsV1(
            max_source_bytes=len(data) + 1,
            max_total_spool_bytes=len(data) - 1,
        ),
        spool_temp_dir=tmp_path / "spool",
    )
    payload = encode_artifact_verify_request_v1(
        artifact_id=artifact.artifact_id,
        policy=policy,
        source=data,
    )
    prefix = payload[: -len(data)]

    response = service.handle(
        method="POST",
        path="/v1/artifacts/verify",
        content_type=ARTIFACT_VERIFY_MEDIA_TYPE,
        body_stream=PrefixThenBombStream(prefix),
        content_length=len(payload),
    )
    assert response.status == 503
    assert _json(response)["code"] == "busy"
    assert service._spool_budget.used == 0

def test_px4_cancelled_request_does_not_affect_concurrent_request(tmp_path: Path):

    data = b"concurrency" * 100
    artifact = _tree_artifact(data)
    policy = _tree_policy()
    store = LocalArtifactStoreV1(tmp_path / "store")
    store.put_artifact(artifact)
    service = GatewayServiceV1(
        store,
        limits=GatewayLimitsV1(max_concurrent_requests=2),
    )
    payload = encode_artifact_verify_request_v1(
        artifact_id=artifact.artifact_id,
        policy=policy,
        source=data,
    )
    cancel_token = GatewayCancellationTokenV1(timeout_seconds=60)

    def cancelled():
        return service.handle(
            method="POST",
            path="/v1/artifacts/verify",
            content_type=ARTIFACT_VERIFY_MEDIA_TYPE,
            body_stream=CancelAfterFirstRead(payload, cancel_token),
            content_length=len(payload),
            token=cancel_token,
        )

    def healthy():
        return service.handle(
            method="POST",
            path="/v1/artifacts/verify",
            content_type=ARTIFACT_VERIFY_MEDIA_TYPE,
            body_stream=io.BytesIO(payload),
            content_length=len(payload),
        )

    with ThreadPoolExecutor(max_workers=2) as executor:
        cancelled_future = executor.submit(cancelled)
        healthy_future = executor.submit(healthy)
        cancelled_response = cancelled_future.result()
        healthy_response = healthy_future.result()

    assert cancelled_response.status == 409
    assert _json(cancelled_response)["code"] == "cancelled"
    assert healthy_response.status == 200
    assert _json(healthy_response)["accepted"]


class AdvancingClock:
    def __init__(self):
        self.value = 0.0
        self.calls = 0

    def __call__(self):
        self.calls += 1
        if self.calls > 2:
            self.value = 2.0
        return self.value


def test_px4_timeout_is_request_local_and_audited(tmp_path: Path):

    data = b"timeout" * 100
    artifact = _tree_artifact(data)
    policy = _tree_policy()
    store = LocalArtifactStoreV1(tmp_path / "store")
    store.put_artifact(artifact)
    audit = MemoryGatewayAuditSinkV1()
    service = GatewayServiceV1(store, audit_sink=audit)

    payload = encode_artifact_verify_request_v1(
        artifact_id=artifact.artifact_id,
        policy=policy,
        source=data,
    )
    token = GatewayCancellationTokenV1(
        timeout_seconds=1.0,
        monotonic=AdvancingClock(),
    )
    response = service.handle(
        method="POST",
        path="/v1/artifacts/verify",
        content_type=ARTIFACT_VERIFY_MEDIA_TYPE,
        body_stream=io.BytesIO(payload),
        content_length=len(payload),
        token=token,
    )
    assert response.status == 408
    assert _json(response)["code"] == "timeout"
    assert audit.records[-1].timed_out


def test_px4_concurrency_limit_fails_closed_without_touching_body(tmp_path: Path):

    service = GatewayServiceV1(
        LocalArtifactStoreV1(tmp_path / "store"),
        limits=GatewayLimitsV1(max_concurrent_requests=1),
    )
    assert service._semaphore.acquire(blocking=False)
    try:
        response = service.handle(
            method="POST",
            path="/v1/artifacts/verify",
            content_type=ARTIFACT_VERIFY_MEDIA_TYPE,
            body_stream=BombStream(),
            content_length=10,
        )
    finally:
        service._semaphore.release()
    assert response.status == 503
    assert _json(response)["code"] == "busy"



def test_px4_audit_normalizes_arbitrary_http_method(tmp_path: Path):
    audit = MemoryGatewayAuditSinkV1()
    service = GatewayServiceV1(
        LocalArtifactStoreV1(tmp_path / "store"),
        audit_sink=audit,
    )
    secret_method = "SECRET-BEARER-METHOD"
    response = service.handle(
        method=secret_method,
        path="/health",
        content_type="",
        body_stream=io.BytesIO(b""),
        content_length=0,
    )
    assert response.status == 404
    assert audit.records[-1].method == "<other>"
    assert secret_method.encode() not in audit.records[-1].to_json_bytes()

def test_px4_http_daemon_redacts_query_and_headers_from_audit(tmp_path: Path):

    audit = MemoryGatewayAuditSinkV1()
    service = GatewayServiceV1(
        LocalArtifactStoreV1(tmp_path / "store"),
        audit_sink=audit,
    )
    server = create_gateway_http_server_v1("127.0.0.1", 0, service)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        host, port = server.server_address
        connection = http.client.HTTPConnection(host, port, timeout=5)
        connection.request(
            "GET",
            "/health?token=supersecret-query",
            headers={
                "Authorization": "Bearer supersecret-auth",
                "Cookie": "session=supersecret-cookie",
            },
        )
        response = connection.getresponse()
        body = response.read()
        connection.close()
        assert response.status == 400
        assert json.loads(body.decode("ascii"))["code"] == "bad-request"
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)

    assert audit.records
    record = audit.records[-1]
    assert record.endpoint == "/health"
    serialized = record.to_json_bytes()
    assert b"supersecret-query" not in serialized
    assert b"supersecret-auth" not in serialized
    assert b"supersecret-cookie" not in serialized


def test_px4_http_health_version_and_stored_artifact(tmp_path: Path):

    store = LocalArtifactStoreV1(tmp_path / "store")
    artifact = _tree_artifact(b"http-get")
    store.put_artifact(artifact)
    server = create_gateway_http_server_v1(
        "127.0.0.1",
        0,
        GatewayServiceV1(store),
    )
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        host, port = server.server_address
        for path, expected in (
            ("/health", 200),
            ("/version", 200),
            (f"/v1/artifacts/{artifact.artifact_id.hex()}", 200),
        ):
            connection = http.client.HTTPConnection(host, port, timeout=5)
            connection.request("GET", path)
            response = connection.getresponse()
            body = response.read()
            connection.close()
            assert response.status == expected
            if path.startswith("/v1/artifacts/"):
                assert body == artifact.to_bytes()
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)



def test_px4_http_authorization_never_changes_policy_receipt(tmp_path: Path):
    data = b"receipt-header-independence" * 20
    digest = _v3_digest(data)
    policy = VerificationPolicyV1()
    identity = b"header-independent-receipt"
    payload = encode_policy_evaluate_request_v1(
        artifact_identity=identity,
        evidence_wire=digest.to_bytes(),
        policy=policy,
        source=data,
    )
    local_decision = verify_with_policy_v1(
        digest.to_bytes(),
        policy=policy,
        source=data,
    )
    local_receipt = receipt_from_decision_v1(
        identity,
        policy,
        local_decision,
        verifier_package="sigma-framework",
        verifier_version=PACKAGE_VERSION,
        verifier_build=b"",
        claimed_unix_time=None,
    )
    expected = decision_result_json_v1(
        local_decision,
        receipt_wire=local_receipt.to_bytes(),
        receipt_id=local_receipt.receipt_id,
    )

    server = create_gateway_http_server_v1(
        "127.0.0.1",
        0,
        GatewayServiceV1(LocalArtifactStoreV1(tmp_path / "store")),
    )
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        host, port = server.server_address
        bodies = []
        for secret in ("alpha-secret", "beta-secret"):
            connection = http.client.HTTPConnection(host, port, timeout=5)
            connection.request(
                "POST",
                "/v1/policies/evaluate",
                body=payload,
                headers={
                    "Content-Type": POLICY_EVALUATE_MEDIA_TYPE,
                    "Authorization": f"Bearer {secret}",
                    "Cookie": f"session={secret}",
                },
            )
            response = connection.getresponse()
            bodies.append(response.read())
            assert response.status == 200
            connection.close()
        assert bodies == [expected, expected]
        assert b"alpha-secret" not in expected
        assert b"beta-secret" not in expected
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)


def test_px4_http_rejects_duplicate_content_length(tmp_path: Path):
    service = GatewayServiceV1(LocalArtifactStoreV1(tmp_path / "store"))
    server = create_gateway_http_server_v1("127.0.0.1", 0, service)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        host, port = server.server_address
        request = (
            "POST /v1/artifacts/verify HTTP/1.1\r\n"
            f"Host: {host}:{port}\r\n"
            f"Content-Type: {ARTIFACT_VERIFY_MEDIA_TYPE}\r\n"
            "Content-Length: 0\r\n"
            "Content-Length: 1\r\n"
            "Connection: close\r\n"
            "\r\n"
        ).encode("ascii")
        response = _raw_http_request(host, port, request)
        assert response.startswith(b"HTTP/1.1 400")
        assert b"multiple Content-Length" in response

        request = (
            "POST /v1/artifacts/verify HTTP/1.1\r\n"
            f"Host: {host}:{port}\r\n"
            f"Content-Type: {ARTIFACT_VERIFY_MEDIA_TYPE}\r\n"
            "Content-Length: +1\r\n"
            "Connection: close\r\n"
            "\r\n"
        ).encode("ascii")
        response = _raw_http_request(host, port, request)
        assert response.startswith(b"HTTP/1.1 400")
        assert b"Content-Length is invalid" in response

        request = (
            "POST /v1/artifacts/verify HTTP/1.1\r\n"
            f"Host: {host}:{port}\r\n"
            f"Content-Type: {ARTIFACT_VERIFY_MEDIA_TYPE}\r\n"
            "Content-Length: 0\r\n"
            "Expect: nonsense\r\n"
            "Connection: close\r\n"
            "\r\n"
        ).encode("ascii")
        response = _raw_http_request(host, port, request)
        assert response.startswith(b"HTTP/1.1 417")
        assert b"expectation-failed" in response
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)


def test_px4_declared_source_length_must_match_request_remainder(tmp_path: Path):
    data = b"framing-geometry"
    artifact = _tree_artifact(data)
    policy = _tree_policy()
    store = LocalArtifactStoreV1(tmp_path / "store")
    store.put_artifact(artifact)
    payload = bytearray(
        encode_artifact_verify_request_v1(
            artifact_id=artifact.artifact_id,
            policy=policy,
            source=data,
        )
    )
    declared = int.from_bytes(payload[56:64], "big")
    payload[56:64] = (declared + 1).to_bytes(8, "big")
    response = GatewayServiceV1(store).handle(
        method="POST",
        path="/v1/artifacts/verify",
        content_type=ARTIFACT_VERIFY_MEDIA_TYPE,
        body_stream=io.BytesIO(bytes(payload)),
        content_length=len(payload),
    )
    assert response.status == 400
    assert _json(response)["code"] == "bad-request"


def test_px4_cli_requires_explicit_nonlocal_bind_acknowledgement(tmp_path: Path):
    with pytest.raises(SystemExit) as exc:
        gateway_cli_main(
            [
                "--store",
                str(tmp_path / "store"),
                "--host",
                "0.0.0.0",
            ]
        )
    assert exc.value.code == 2

    parsed = build_parser_v1().parse_args(
        [
            "--store",
            str(tmp_path / "store"),
            "--max-header-bytes",
            "4096",
            "--max-response-bytes",
            "8192",
            "--max-concurrent-requests",
            "3",
            "--max-http-connections",
            "5",
            "--max-total-spool-bytes",
            "16384",
            "--spool-temp-dir",
            str(tmp_path / "spool"),
        ]
    )
    assert parsed.host == "127.0.0.1"
    assert parsed.max_header_bytes == 4096
    assert parsed.max_response_bytes == 8192
    assert parsed.max_concurrent_requests == 3
    assert parsed.max_http_connections == 5
    assert parsed.max_total_spool_bytes == 16384
    assert parsed.spool_temp_dir == tmp_path / "spool"


def test_px4_http_connection_limit_rejects_before_handler_thread(tmp_path: Path):
    service = GatewayServiceV1(
        LocalArtifactStoreV1(tmp_path / "store"),
        limits=GatewayLimitsV1(max_http_connections=1),
    )
    server = create_gateway_http_server_v1("127.0.0.1", 0, service)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    assert server._connection_slots.acquire(blocking=False)
    try:
        host, port = server.server_address
        connection = http.client.HTTPConnection(host, port, timeout=5)
        connection.request("GET", "/health")
        response = connection.getresponse()
        body = response.read()
        connection.close()
        assert response.status == 503
        assert json.loads(body.decode("ascii"))["code"] == "busy"
    finally:
        server._connection_slots.release()
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)

def test_px4_http_header_limit_and_chunked_requests_fail_closed(tmp_path: Path):

    limits = GatewayLimitsV1(max_header_bytes=512)
    service = GatewayServiceV1(
        LocalArtifactStoreV1(tmp_path / "store"),
        limits=limits,
    )
    server = create_gateway_http_server_v1("127.0.0.1", 0, service)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        host, port = server.server_address
        connection = http.client.HTTPConnection(host, port, timeout=5)
        connection.request(
            "POST",
            "/v1/artifacts/verify",
            body=b"",
            headers={
                "Content-Type": ARTIFACT_VERIFY_MEDIA_TYPE,
                "X-Large": "x" * 2048,
            },
        )
        response = connection.getresponse()
        assert response.status == 431
        response.read()
        connection.close()

        connection = http.client.HTTPConnection(host, port, timeout=5)
        connection.putrequest("POST", "/v1/artifacts/verify")
        connection.putheader("Content-Type", ARTIFACT_VERIFY_MEDIA_TYPE)
        connection.putheader("Transfer-Encoding", "chunked")
        connection.endheaders()
        connection.send(b"0\r\n\r\n")
        response = connection.getresponse()
        assert response.status == 400
        response.read()
        connection.close()
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)
