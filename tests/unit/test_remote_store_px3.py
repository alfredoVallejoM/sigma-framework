from __future__ import annotations

import base64
import hashlib
import urllib.parse
from pathlib import Path

import pytest

from sigma.artifact import (
    ArtifactProfileV1,
    Boto3S3ClientAdapterV1,
    HttpReadOnlyMirrorBackendV1,
    HttpResponseV1,
    OciRegistryBackendV1,
    RemoteArtifactRepositoryV1,
    RemoteCheckpointError,
    RemoteConflictError,
    RemoteDownloadCheckpointV1,
    RemoteIntegrityError,
    RemoteNotFoundError,
    RemoteObjectInfoV1,
    RemoteReadChunkV1,
    RemoteReadOnlyError,
    RemoteRetryableError,
    RemoteSessionExpiredError,
    RemoteStoreError,
    RemoteTransferPolicyV1,
    RemoteTransferSourceV1,
    RemoteUploadCheckpointV1,
    RemoteUploadSessionV1,
    S3CompatibleBackendV1,
    S3ObjectHeadV1,
    S3RangeResultV1,
    S3UploadedPartV1,
    VerifiedRemoteArtifactCacheV1,
    artifact_remote_key_v1,
    create_artifact_v1,
)
from sigma.artifact.store import LocalArtifactStoreV1
from sigma.tree import build_tree


def _artifact(payload: bytes):
    return create_artifact_v1(
        ArtifactProfileV1.TREE,
        tree_root=build_tree(payload),
    )


class MemoryRemoteBackend:
    def __init__(self, *, identity: str = "memory-v1") -> None:
        self._fingerprint = identity
        self.objects: dict[str, bytes] = {}
        self.sessions: dict[str, dict[str, object]] = {}
        self.next_token = 1
        self.fail_upload_retryable_after_accept_at: int | None = None
        self.fail_upload_fatal_after_accept_at: int | None = None
        self.fail_download_once_at: int | None = None

    @property
    def fingerprint(self) -> str:
        return self._fingerprint

    @property
    def read_only(self) -> bool:
        return False

    @staticmethod
    def _info(key: str, payload: bytes) -> RemoteObjectInfoV1:
        digest = hashlib.sha256(payload).digest()
        return RemoteObjectInfoV1(
            key=key,
            size=len(payload),
            revision="rev-" + digest.hex(),
            wire_sha256=digest,
            provider_locator="memory://" + key,
        )

    def seed(self, key: str, payload: bytes) -> None:
        self.objects[key] = payload

    def head(self, key: str) -> RemoteObjectInfoV1 | None:
        payload = self.objects.get(key)
        return None if payload is None else self._info(key, payload)

    def read_range(
        self,
        key: str,
        *,
        start: int,
        max_bytes: int,
    ) -> RemoteReadChunkV1:
        if self.fail_download_once_at == start:
            self.fail_download_once_at = None
            raise RemoteStoreError("injected download interruption")
        if key not in self.objects:
            raise RemoteNotFoundError(key)
        payload = self.objects[key]
        end = min(len(payload), start + max_bytes)
        info = self._info(key, payload)
        return RemoteReadChunkV1(
            key=key,
            start=start,
            data=payload[start:end],
            total_size=len(payload),
            revision=info.revision,
            wire_sha256=info.wire_sha256,
        )

    def begin_upload(
        self,
        key: str,
        *,
        total_size: int,
        wire_sha256: bytes,
        preferred_chunk_size: int,
    ) -> RemoteUploadSessionV1:
        token = f"u{self.next_token}"
        self.next_token += 1
        self.sessions[token] = {
            "key": key,
            "data": bytearray(),
            "total_size": total_size,
            "wire_sha256": wire_sha256,
            "chunk_size": preferred_chunk_size,
        }
        return RemoteUploadSessionV1(
            backend_fingerprint=self.fingerprint,
            key=key,
            total_size=total_size,
            wire_sha256=wire_sha256,
            token=token,
            accepted_offset=0,
            chunk_size=preferred_chunk_size,
        )

    def _state(self, session: RemoteUploadSessionV1) -> dict[str, object]:
        state = self.sessions.get(session.token)
        if state is None:
            raise RemoteSessionExpiredError("session expired")
        return state

    def resume_upload(
        self,
        session: RemoteUploadSessionV1,
    ) -> RemoteUploadSessionV1:
        state = self._state(session)
        data = state["data"]
        assert isinstance(data, bytearray)
        return RemoteUploadSessionV1(
            backend_fingerprint=self.fingerprint,
            key=session.key,
            total_size=session.total_size,
            wire_sha256=session.wire_sha256,
            token=session.token,
            accepted_offset=len(data),
            chunk_size=session.chunk_size,
        )

    def upload_chunk(
        self,
        session: RemoteUploadSessionV1,
        data: bytes,
    ) -> RemoteUploadSessionV1:
        state = self._state(session)
        current = state["data"]
        assert isinstance(current, bytearray)
        start = session.accepted_offset

        # Idempotent recovery if a previous request was accepted but its response
        # was lost and the caller retries with the stale session offset.
        if len(current) > start:
            end = start + len(data)
            if len(current) == end and bytes(current[start:end]) == data:
                return self.resume_upload(session)
            raise RemoteConflictError("stale upload offset conflicts with accepted bytes")
        if len(current) != start:
            raise RemoteConflictError("non-contiguous upload")
        current.extend(data)

        if self.fail_upload_retryable_after_accept_at == start:
            self.fail_upload_retryable_after_accept_at = None
            raise RemoteRetryableError("response lost after accepted chunk")
        if self.fail_upload_fatal_after_accept_at == start:
            self.fail_upload_fatal_after_accept_at = None
            raise RemoteStoreError("process interrupted after accepted chunk")
        return self.resume_upload(session)

    def complete_upload(
        self,
        session: RemoteUploadSessionV1,
    ) -> RemoteObjectInfoV1:
        state = self._state(session)
        current = state["data"]
        assert isinstance(current, bytearray)
        payload = bytes(current)
        if len(payload) != session.total_size:
            raise RemoteConflictError("incomplete upload")
        if hashlib.sha256(payload).digest() != session.wire_sha256:
            raise RemoteIntegrityError("assembled upload digest mismatch")
        self.objects[session.key] = payload
        del self.sessions[session.token]
        return self._info(session.key, payload)

    def abort_upload(self, session: RemoteUploadSessionV1) -> None:
        self.sessions.pop(session.token, None)


class StaticMirrorTransport:
    def __init__(self, base_url: str, objects: dict[str, bytes], *, ignore_range=False):
        self.base_url = base_url.rstrip("/") + "/"
        self.objects = objects
        self.ignore_range = ignore_range

    def request(self, method, url, *, headers=None, body=None, timeout=30.0):
        path = urllib.parse.unquote(
            urllib.parse.urlsplit(url).path.lstrip("/")
        )
        base_path = urllib.parse.urlsplit(self.base_url).path.lstrip("/")
        if base_path and path.startswith(base_path):
            path = path[len(base_path) :].lstrip("/")
        payload = self.objects.get(path)
        if payload is None:
            return HttpResponseV1(404, (), b"", url)
        digest = hashlib.sha256(payload).hexdigest()
        common = (
            ("Content-Length", str(len(payload))),
            ("ETag", '"mirror-rev"'),
            ("X-Sigma-Wire-SHA256", digest),
        )
        if method == "HEAD":
            return HttpResponseV1(200, common, b"", url)
        if method != "GET":
            return HttpResponseV1(405, (), b"", url)
        range_header = (headers or {}).get("Range")
        if self.ignore_range or range_header is None:
            return HttpResponseV1(200, common, payload, url)
        spec = range_header.removeprefix("bytes=")
        start_text, end_text = spec.split("-", 1)
        start, end = int(start_text), min(int(end_text), len(payload) - 1)
        part = payload[start : end + 1]
        return HttpResponseV1(
            206,
            (
                ("Content-Range", f"bytes {start}-{end}/{len(payload)}"),
                ("Content-Length", str(len(part))),
                ("ETag", '"mirror-rev"'),
                ("X-Sigma-Wire-SHA256", digest),
            ),
            part,
            url,
        )


class FakeS3Client:
    def __init__(self):
        self.objects: dict[tuple[str, str], tuple[bytes, dict[str, str], str]] = {}
        self.uploads: dict[str, dict[str, object]] = {}
        self.next_upload = 1

    def head_object(self, bucket, key):
        value = self.objects.get((bucket, key))
        if value is None:
            return None
        data, metadata, etag = value
        return S3ObjectHeadV1(
            len(data),
            etag,
            tuple(sorted(metadata.items())),
        )

    def get_object_range(self, bucket, key, *, start, end_exclusive):
        value = self.objects.get((bucket, key))
        if value is None:
            raise RemoteNotFoundError(key)
        data, metadata, etag = value
        return S3RangeResultV1(
            data[start:end_exclusive],
            len(data),
            etag,
            tuple(sorted(metadata.items())),
        )

    def create_multipart_upload(self, bucket, key, *, metadata):
        upload_id = f"m{self.next_upload}"
        self.next_upload += 1
        self.uploads[upload_id] = {
            "bucket": bucket,
            "key": key,
            "metadata": dict(metadata),
            "parts": {},
        }
        return upload_id

    def list_parts(self, bucket, key, upload_id):
        state = self.uploads.get(upload_id)
        if state is None:
            raise RemoteSessionExpiredError("expired")
        parts = state["parts"]
        assert isinstance(parts, dict)
        return tuple(parts[number] for number in sorted(parts))

    def upload_part(
        self,
        bucket,
        key,
        upload_id,
        *,
        part_number,
        data,
        checksum_sha256_b64,
    ):
        state = self.uploads[upload_id]
        expected = base64.b64encode(hashlib.sha256(data).digest()).decode("ascii")
        assert checksum_sha256_b64 == expected
        part = S3UploadedPartV1(
            part_number,
            len(data),
            f'"etag-{part_number}-{hashlib.sha256(data).hexdigest()[:8]}"',
            expected,
        )
        state["parts"][part_number] = part
        state.setdefault("payloads", {})[part_number] = data
        return part

    def complete_multipart_upload(self, bucket, key, upload_id, *, parts):
        state = self.uploads[upload_id]
        payloads = state["payloads"]
        data = b"".join(payloads[part.part_number] for part in parts)
        etag = '"complete-' + hashlib.sha256(data).hexdigest()[:12] + '"'
        self.objects[(bucket, key)] = (
            data,
            dict(state["metadata"]),
            etag,
        )
        del self.uploads[upload_id]
        return self.head_object(bucket, key)

    def abort_multipart_upload(self, bucket, key, upload_id):
        self.uploads.pop(upload_id, None)


class FakeOciTransport:
    def __init__(self, base_url="https://registry.example/"):
        self.base_url = base_url.rstrip("/") + "/"
        self.blobs: dict[str, bytes] = {}
        self.manifests: dict[str, bytes] = {}
        self.uploads: dict[str, bytearray] = {}
        self.next_upload = 1

    @staticmethod
    def _headers(**values):
        return tuple((key, value) for key, value in values.items())

    def request(self, method, url, *, headers=None, body=None, timeout=30.0):
        headers = dict(headers or {})
        body = b"" if body is None else body
        parsed = urllib.parse.urlsplit(url)
        path = parsed.path
        query = dict(urllib.parse.parse_qsl(parsed.query))

        marker = "/v2/demo/manifests/"
        if marker in path:
            tag = urllib.parse.unquote(path.split(marker, 1)[1])
            if method == "PUT":
                self.manifests[tag] = body
                digest = "sha256:" + hashlib.sha256(body).hexdigest()
                return HttpResponseV1(
                    201,
                    self._headers(**{"Docker-Content-Digest": digest}),
                    b"",
                    url,
                )
            if method == "GET":
                payload = self.manifests.get(tag)
                if payload is None:
                    return HttpResponseV1(404, (), b"", url)
                digest = "sha256:" + hashlib.sha256(payload).hexdigest()
                return HttpResponseV1(
                    200,
                    self._headers(
                        **{
                            "Content-Type": "application/vnd.oci.image.manifest.v1+json",
                            "Docker-Content-Digest": digest,
                        }
                    ),
                    payload,
                    url,
                )

        blob_marker = "/v2/demo/blobs/"
        upload_marker = "/v2/demo/blobs/uploads/"
        if blob_marker in path and upload_marker not in path:
            digest = path.split(blob_marker, 1)[1]
            payload = self.blobs.get(digest)
            if payload is None:
                return HttpResponseV1(404, (), b"", url)
            if method == "HEAD":
                return HttpResponseV1(
                    200,
                    self._headers(
                        **{
                            "Content-Length": str(len(payload)),
                            "Docker-Content-Digest": digest,
                        }
                    ),
                    b"",
                    url,
                )
            if method == "GET":
                range_header = headers.get("Range")
                if range_header:
                    start_text, end_text = range_header.removeprefix("bytes=").split("-", 1)
                    start = int(start_text)
                    end = min(int(end_text), len(payload) - 1)
                    part = payload[start : end + 1]
                    return HttpResponseV1(
                        206,
                        self._headers(
                            **{
                                "Content-Range": f"bytes {start}-{end}/{len(payload)}",
                                "Content-Length": str(len(part)),
                                "Docker-Content-Digest": digest,
                            }
                        ),
                        part,
                        url,
                    )
                return HttpResponseV1(
                    200,
                    self._headers(
                        **{
                            "Content-Length": str(len(payload)),
                            "Docker-Content-Digest": digest,
                        }
                    ),
                    payload,
                    url,
                )

        if path.endswith("/v2/demo/blobs/uploads/") and method == "POST":
            digest = query.get("digest")
            if digest is not None and body:
                if digest != "sha256:" + hashlib.sha256(body).hexdigest():
                    return HttpResponseV1(400, (), b"", url)
                self.blobs[digest] = body
                return HttpResponseV1(201, (), b"", url)
            token = f"u{self.next_upload}"
            self.next_upload += 1
            self.uploads[token] = bytearray()
            location = f"/v2/demo/blobs/uploads/{token}"
            return HttpResponseV1(
                202,
                self._headers(Location=location),
                b"",
                url,
            )

        if upload_marker in path:
            token = path.split(upload_marker, 1)[1]
            current = self.uploads.get(token)
            if current is None:
                return HttpResponseV1(404, (), b"", url)
            location = f"/v2/demo/blobs/uploads/{token}"
            if method == "GET":
                response_headers = {"Location": location}
                if current:
                    response_headers["Range"] = f"0-{len(current) - 1}"
                return HttpResponseV1(
                    204,
                    self._headers(**response_headers),
                    b"",
                    url,
                )
            if method == "PATCH":
                start_text, end_text = headers["Content-Range"].split("-", 1)
                start, end = int(start_text), int(end_text)
                if start != len(current) or end != start + len(body) - 1:
                    return HttpResponseV1(416, (), b"", url)
                current.extend(body)
                return HttpResponseV1(
                    202,
                    self._headers(
                        Location=location,
                        Range=f"0-{len(current) - 1}",
                    ),
                    b"",
                    url,
                )
            if method == "PUT":
                if body:
                    current.extend(body)
                digest = query.get("digest")
                if digest != "sha256:" + hashlib.sha256(bytes(current)).hexdigest():
                    return HttpResponseV1(400, (), b"", url)
                self.blobs[digest] = bytes(current)
                del self.uploads[token]
                return HttpResponseV1(201, (), b"", url)
            if method == "DELETE":
                del self.uploads[token]
                return HttpResponseV1(202, (), b"", url)

        return HttpResponseV1(404, (), b"", url)


def test_px3_generic_remote_roundtrip_retry_and_duplicate_put(tmp_path: Path):
    local = LocalArtifactStoreV1(tmp_path / "local")
    artifact = _artifact(b"px3-roundtrip")
    local.put_artifact(artifact)
    backend = MemoryRemoteBackend()
    repository = RemoteArtifactRepositoryV1(
        local,
        backend,
        policy=RemoteTransferPolicyV1(chunk_size=64, retry_backoff_seconds=0),
    )

    backend.fail_upload_retryable_after_accept_at = 0
    first = repository.push_artifact(artifact.artifact_id)
    assert first.retry_count == 1
    assert not first.remote_reused
    assert backend.objects[artifact_remote_key_v1(artifact.artifact_id)] == artifact.to_bytes()

    second = repository.push_artifact(artifact.artifact_id)
    assert second.remote_reused
    assert second.artifact_id == artifact.artifact_id

    destination = LocalArtifactStoreV1(tmp_path / "destination")
    pulled = RemoteArtifactRepositoryV1(
        destination,
        backend,
        policy=RemoteTransferPolicyV1(chunk_size=31),
    ).pull_artifact(artifact.artifact_id)
    assert pulled.source is RemoteTransferSourceV1.REMOTE
    assert destination.get_artifact_bytes(artifact.artifact_id) == artifact.to_bytes()


def test_px3_upload_checkpoint_recovers_server_ahead_of_local_checkpoint(tmp_path: Path):
    local = LocalArtifactStoreV1(tmp_path / "local")
    artifact = _artifact(b"resume-upload" * 200)
    local.put_artifact(artifact)
    backend = MemoryRemoteBackend()
    repository = RemoteArtifactRepositoryV1(
        local,
        backend,
        policy=RemoteTransferPolicyV1(chunk_size=64),
    )
    checkpoint = tmp_path / "upload.json"
    backend.fail_upload_fatal_after_accept_at = 64

    with pytest.raises(RemoteStoreError, match="interrupted"):
        repository.push_artifact(
            artifact.artifact_id,
            checkpoint_path=checkpoint,
        )
    record = RemoteUploadCheckpointV1.from_bytes(checkpoint.read_bytes())
    assert record.session.accepted_offset == 64

    result = repository.push_artifact(
        artifact.artifact_id,
        checkpoint_path=checkpoint,
    )
    assert result.resumed_from == 128
    assert not checkpoint.exists()
    assert backend.objects[artifact_remote_key_v1(artifact.artifact_id)] == artifact.to_bytes()


def test_px3_expired_upload_session_restarts_cleanly(tmp_path: Path):
    local = LocalArtifactStoreV1(tmp_path / "local")
    artifact = _artifact(b"expired-session" * 150)
    local.put_artifact(artifact)
    backend = MemoryRemoteBackend()
    repository = RemoteArtifactRepositoryV1(
        local,
        backend,
        policy=RemoteTransferPolicyV1(chunk_size=64),
    )
    checkpoint = tmp_path / "expired.json"
    backend.fail_upload_fatal_after_accept_at = 64

    with pytest.raises(RemoteStoreError):
        repository.push_artifact(
            artifact.artifact_id,
            checkpoint_path=checkpoint,
        )
    record = RemoteUploadCheckpointV1.from_bytes(checkpoint.read_bytes())
    backend.sessions.pop(record.session.token)

    result = repository.push_artifact(
        artifact.artifact_id,
        checkpoint_path=checkpoint,
    )
    assert result.resumed_from == 0
    assert not checkpoint.exists()


def test_px3_download_resume_validates_before_local_publication(tmp_path: Path):
    source = LocalArtifactStoreV1(tmp_path / "source")
    artifact = _artifact(b"resume-download" * 200)
    source.put_artifact(artifact)
    backend = MemoryRemoteBackend()
    backend.seed(artifact_remote_key_v1(artifact.artifact_id), artifact.to_bytes())

    destination = LocalArtifactStoreV1(tmp_path / "destination")
    repository = RemoteArtifactRepositoryV1(
        destination,
        backend,
        policy=RemoteTransferPolicyV1(chunk_size=64),
    )
    checkpoint = tmp_path / "download.json"
    partial = tmp_path / "download.part"
    backend.fail_download_once_at = 64

    with pytest.raises(RemoteStoreError):
        repository.pull_artifact(
            artifact.artifact_id,
            checkpoint_path=checkpoint,
            partial_path=partial,
        )
    assert not destination.has_artifact(artifact.artifact_id)
    record = RemoteDownloadCheckpointV1.from_bytes(checkpoint.read_bytes())
    assert record.accepted_offset == 64
    assert partial.stat().st_size == 64

    result = repository.pull_artifact(
        artifact.artifact_id,
        checkpoint_path=checkpoint,
        partial_path=partial,
    )
    assert result.resumed_from == 64
    assert destination.get_artifact_bytes(artifact.artifact_id) == artifact.to_bytes()
    assert not checkpoint.exists()
    assert not partial.exists()


def test_px3_corrupt_remote_never_publishes_into_px1(tmp_path: Path):
    artifact = _artifact(b"remote-corruption")
    backend = MemoryRemoteBackend()
    raw = bytearray(artifact.to_bytes())
    raw[-1] ^= 1
    backend.seed(artifact_remote_key_v1(artifact.artifact_id), bytes(raw))
    local = LocalArtifactStoreV1(tmp_path / "local")

    with pytest.raises(RemoteIntegrityError):
        RemoteArtifactRepositoryV1(local, backend).pull_artifact(
            artifact.artifact_id
        )
    assert not local.has_artifact(artifact.artifact_id)


def test_px3_verified_cache_is_disposable_and_corruption_is_a_miss(tmp_path: Path):
    artifact = _artifact(b"cache-semantics")
    backend = MemoryRemoteBackend()
    backend.seed(artifact_remote_key_v1(artifact.artifact_id), artifact.to_bytes())
    cache = VerifiedRemoteArtifactCacheV1(tmp_path / "cache")
    local = LocalArtifactStoreV1(tmp_path / "local")
    repository = RemoteArtifactRepositoryV1(local, backend, cache=cache)

    first = repository.pull_artifact(artifact.artifact_id)
    assert first.source is RemoteTransferSourceV1.REMOTE
    assert local.delete_artifact(artifact.artifact_id)

    cached = repository.pull_artifact(artifact.artifact_id)
    assert cached.source is RemoteTransferSourceV1.VERIFIED_CACHE
    assert local.delete_artifact(artifact.artifact_id)

    path = cache._path(artifact.artifact_id)
    corrupt = bytearray(path.read_bytes())
    corrupt[-1] ^= 1
    path.write_bytes(bytes(corrupt))
    remote_again = repository.pull_artifact(artifact.artifact_id)
    assert remote_again.source is RemoteTransferSourceV1.REMOTE
    assert local.get_artifact_bytes(artifact.artifact_id) == artifact.to_bytes()

    assert cache.evict(artifact.artifact_id)
    assert local.delete_artifact(artifact.artifact_id)
    after_evict = repository.pull_artifact(artifact.artifact_id)
    assert after_evict.source is RemoteTransferSourceV1.REMOTE



def test_px3_rejects_oversize_remote_from_head_before_read(tmp_path: Path):
    artifact = _artifact(b"oversize-preflight")
    key = artifact_remote_key_v1(artifact.artifact_id)
    backend = MemoryRemoteBackend()

    def oversized_head(observed_key: str):
        assert observed_key == key
        return RemoteObjectInfoV1(
            key=key,
            size=4097,
            revision="oversize",
            wire_sha256=None,
        )

    def forbidden_read(*args, **kwargs):
        raise AssertionError("PX3 attempted body read after oversize HEAD")

    backend.head = oversized_head
    backend.read_range = forbidden_read
    local = LocalArtifactStoreV1(tmp_path / "local")
    with pytest.raises(RemoteIntegrityError, match="max_object_bytes"):
        RemoteArtifactRepositoryV1(
            local,
            backend,
            policy=RemoteTransferPolicyV1(max_object_bytes=4096),
        ).pull_artifact(artifact.artifact_id)
    assert not local.has_artifact(artifact.artifact_id)


def test_px3_checkpoint_codec_rejects_semantic_noncanonical_variants(tmp_path: Path):
    local = LocalArtifactStoreV1(tmp_path / "local")
    artifact = _artifact(b"checkpoint-canonicality" * 100)
    local.put_artifact(artifact)
    backend = MemoryRemoteBackend()
    repo = RemoteArtifactRepositoryV1(
        local,
        backend,
        policy=RemoteTransferPolicyV1(chunk_size=64),
    )
    checkpoint = tmp_path / "upload.json"
    backend.fail_upload_fatal_after_accept_at = 64
    with pytest.raises(RemoteStoreError):
        repo.push_artifact(artifact.artifact_id, checkpoint_path=checkpoint)

    payload = checkpoint.read_bytes()
    record = RemoteUploadCheckpointV1.from_bytes(payload)
    assert record.to_bytes() == payload
    mutated = payload.replace(b'"version":1', b'"version":1 ')
    assert mutated != payload
    with pytest.raises(RemoteCheckpointError, match="canonical"):
        RemoteUploadCheckpointV1.from_bytes(mutated)

def test_px3_http_mirror_range_and_full_fallback(tmp_path: Path):
    artifact = _artifact(b"http-mirror" * 80)
    key = artifact_remote_key_v1(artifact.artifact_id)
    objects = {key: artifact.to_bytes()}
    base = "https://mirror.example/"

    ranged_backend = HttpReadOnlyMirrorBackendV1(
        base,
        transport=StaticMirrorTransport(base, objects),
        headers={"Authorization": "Bearer secret-a"},
    )
    other_credentials = HttpReadOnlyMirrorBackendV1(
        base,
        transport=StaticMirrorTransport(base, objects),
        headers={"Authorization": "Bearer secret-b"},
    )
    assert ranged_backend.fingerprint == other_credentials.fingerprint

    local = LocalArtifactStoreV1(tmp_path / "ranged")
    result = RemoteArtifactRepositoryV1(
        local,
        ranged_backend,
        policy=RemoteTransferPolicyV1(chunk_size=53),
    ).pull_artifact(artifact.artifact_id)
    assert result.source is RemoteTransferSourceV1.REMOTE
    assert local.get_artifact_bytes(artifact.artifact_id) == artifact.to_bytes()
    with pytest.raises(RemoteReadOnlyError):
        RemoteArtifactRepositoryV1(local, ranged_backend).push_artifact(
            artifact.artifact_id
        )

    full_backend = HttpReadOnlyMirrorBackendV1(
        base,
        transport=StaticMirrorTransport(base, objects, ignore_range=True),
    )
    full_local = LocalArtifactStoreV1(tmp_path / "full")
    RemoteArtifactRepositoryV1(
        full_local,
        full_backend,
        policy=RemoteTransferPolicyV1(chunk_size=17),
    ).pull_artifact(artifact.artifact_id)
    assert full_local.get_artifact_bytes(artifact.artifact_id) == artifact.to_bytes()


def test_px3_s3_backend_roundtrip_and_multipart_resume(tmp_path: Path):
    client = FakeS3Client()
    backend = S3CompatibleBackendV1(
        client,
        "bucket",
        prefix="sigma-test",
        endpoint_identity="minio.example",
        minimum_part_size=16,
    )

    # Direct backend multipart exercises more than one part independently of the
    # small canonical Artifact V1 envelope.
    data = bytes(range(40))
    digest = hashlib.sha256(data).digest()
    session = backend.begin_upload(
        "raw/test.bin",
        total_size=len(data),
        wire_sha256=digest,
        preferred_chunk_size=8,
    )
    session = backend.upload_chunk(session, data[:16])
    resumed = backend.resume_upload(session)
    assert resumed.accepted_offset == 16
    resumed = backend.upload_chunk(resumed, data[16:32])
    resumed = backend.upload_chunk(resumed, data[32:])
    info = backend.complete_upload(resumed)
    assert info.size == len(data)
    assert backend.read_range("raw/test.bin", start=5, max_bytes=9).data == data[5:14]

    local = LocalArtifactStoreV1(tmp_path / "local")
    artifact = _artifact(b"s3-artifact")
    local.put_artifact(artifact)
    repository = RemoteArtifactRepositoryV1(
        local,
        backend,
        policy=RemoteTransferPolicyV1(chunk_size=8),
    )
    repository.push_artifact(artifact.artifact_id)

    destination = LocalArtifactStoreV1(tmp_path / "destination")
    RemoteArtifactRepositoryV1(
        destination,
        backend,
        policy=RemoteTransferPolicyV1(chunk_size=7),
    ).pull_artifact(artifact.artifact_id)
    assert destination.get_artifact_bytes(artifact.artifact_id) == artifact.to_bytes()


def test_px3_oci_distribution_storage_roundtrip(tmp_path: Path):
    transport = FakeOciTransport()
    backend = OciRegistryBackendV1(
        "https://registry.example/",
        "demo",
        transport=transport,
        headers={"Authorization": "Bearer secret-a"},
    )
    same_public_backend = OciRegistryBackendV1(
        "https://registry.example/",
        "demo",
        transport=transport,
        headers={"Authorization": "Bearer secret-b"},
    )
    assert backend.fingerprint == same_public_backend.fingerprint

    local = LocalArtifactStoreV1(tmp_path / "local")
    artifact = _artifact(b"oci-artifact" * 80)
    local.put_artifact(artifact)
    push = RemoteArtifactRepositoryV1(
        local,
        backend,
        policy=RemoteTransferPolicyV1(chunk_size=97),
    ).push_artifact(artifact.artifact_id)
    assert not push.remote_reused

    info = backend.head(artifact_remote_key_v1(artifact.artifact_id))
    assert info is not None
    assert info.wire_sha256 == hashlib.sha256(artifact.to_bytes()).digest()

    destination = LocalArtifactStoreV1(tmp_path / "destination")
    pull = RemoteArtifactRepositoryV1(
        destination,
        backend,
        policy=RemoteTransferPolicyV1(chunk_size=73),
    ).pull_artifact(artifact.artifact_id)
    assert pull.source is RemoteTransferSourceV1.REMOTE
    assert destination.get_artifact_bytes(artifact.artifact_id) == artifact.to_bytes()



def test_px3_oci_locator_manifest_has_hard_metadata_bound():
    transport = FakeOciTransport()
    backend = OciRegistryBackendV1(
        "https://registry.example/",
        "demo",
        transport=transport,
    )
    key = "artifacts/v1/" + "11" * 32 + ".sigart"
    tag = backend._tag_for_key(key)
    transport.manifests[tag] = b"{" + (b" " * (1024 * 1024 + 1)) + b"}"
    with pytest.raises(RemoteIntegrityError, match="metadata size limit"):
        backend.head(key)


def test_px3_boto_adapter_bounds_listparts_to_protocol_maximum():
    class TooManyPartsClient:
        def list_parts(self, **kwargs):
            return {
                "IsTruncated": False,
                "Parts": [
                    {
                        "PartNumber": index,
                        "Size": 5 * 1024 * 1024,
                        "ETag": f'"p{index}"',
                        "ChecksumSHA256": "AA==",
                    }
                    for index in range(1, 10_002)
                ],
            }

    adapter = Boto3S3ClientAdapterV1(TooManyPartsClient())
    with pytest.raises(RemoteIntegrityError, match="10,000-part"):
        adapter.list_parts("bucket", "key", "upload")

def test_px3_remote_object_metadata_never_changes_artifact_identity(tmp_path: Path):
    artifact = _artifact(b"metadata-independence")
    local = LocalArtifactStoreV1(tmp_path / "local")
    local.put_artifact(artifact)

    backend_a = MemoryRemoteBackend(identity="same-public-backend")
    backend_b = MemoryRemoteBackend(identity="same-public-backend")
    key = artifact_remote_key_v1(artifact.artifact_id)
    backend_a.seed(key, artifact.to_bytes())
    backend_b.seed(key, artifact.to_bytes())

    info_a = backend_a.head(key)
    info_b = backend_b.head(key)
    assert info_a is not None and info_b is not None
    assert artifact.artifact_id == _artifact(b"metadata-independence").artifact_id
    assert local.get_artifact(artifact.artifact_id).artifact_id == artifact.artifact_id
