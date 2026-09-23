"""Deterministic provider/fault models used only by the PX3 local closure gate."""

from __future__ import annotations

import base64
import hashlib
import urllib.parse

from sigma.artifact.remote import (
    RemoteConflictError,
    RemoteNotFoundError,
    RemoteObjectInfoV1,
    RemoteReadChunkV1,
    RemoteRetryableError,
    RemoteSessionExpiredError,
    RemoteStoreError,
    RemoteUploadSessionV1,
)
from sigma.artifact.remote_http import HttpResponseV1
from sigma.artifact.remote_s3 import (
    S3ObjectHeadV1,
    S3RangeResultV1,
    S3UploadedPartV1,
)


class GateMemoryRemoteBackend:
    def __init__(self, identity: str = "px3-gate-memory-v1") -> None:
        self._fingerprint = identity
        self.objects: dict[str, bytes] = {}
        self.sessions: dict[str, bytearray] = {}
        self.session_meta: dict[str, tuple[str, int, bytes, int]] = {}
        self.next_token = 1
        self.retryable_accept_offset: int | None = None
        self.fatal_accept_offset: int | None = None
        self.download_fail_offset: int | None = None

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
            key,
            len(payload),
            revision="m-" + digest.hex(),
            wire_sha256=digest,
            provider_locator="memory://" + key,
        )

    def seed(self, key: str, payload: bytes) -> None:
        self.objects[key] = payload

    def head(self, key: str) -> RemoteObjectInfoV1 | None:
        payload = self.objects.get(key)
        return None if payload is None else self._info(key, payload)

    def read_range(self, key: str, *, start: int, max_bytes: int) -> RemoteReadChunkV1:
        if self.download_fail_offset == start:
            self.download_fail_offset = None
            raise RemoteStoreError("PX3 injected download interruption")
        payload = self.objects.get(key)
        if payload is None:
            raise RemoteNotFoundError(key)
        end = min(len(payload), start + max_bytes)
        info = self._info(key, payload)
        return RemoteReadChunkV1(
            key,
            start,
            payload[start:end],
            len(payload),
            info.revision,
            info.wire_sha256,
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
        self.sessions[token] = bytearray()
        self.session_meta[token] = (
            key,
            total_size,
            wire_sha256,
            preferred_chunk_size,
        )
        return RemoteUploadSessionV1(
            self.fingerprint,
            key,
            total_size,
            wire_sha256,
            token,
            0,
            preferred_chunk_size,
        )

    def _state(self, session: RemoteUploadSessionV1) -> bytearray:
        value = self.sessions.get(session.token)
        if value is None:
            raise RemoteSessionExpiredError("PX3 gate session expired")
        return value

    def resume_upload(self, session: RemoteUploadSessionV1) -> RemoteUploadSessionV1:
        value = self._state(session)
        return RemoteUploadSessionV1(
            self.fingerprint,
            session.key,
            session.total_size,
            session.wire_sha256,
            session.token,
            len(value),
            session.chunk_size,
            session.opaque,
        )

    def upload_chunk(
        self,
        session: RemoteUploadSessionV1,
        data: bytes,
    ) -> RemoteUploadSessionV1:
        value = self._state(session)
        start = session.accepted_offset
        if len(value) > start:
            end = start + len(data)
            if len(value) == end and bytes(value[start:end]) == data:
                return self.resume_upload(session)
            raise RemoteConflictError("PX3 gate stale upload conflict")
        if len(value) != start:
            raise RemoteConflictError("PX3 gate non-contiguous upload")
        value.extend(data)
        if self.retryable_accept_offset == start:
            self.retryable_accept_offset = None
            raise RemoteRetryableError("PX3 response lost after accepted bytes")
        if self.fatal_accept_offset == start:
            self.fatal_accept_offset = None
            raise RemoteStoreError("PX3 process interruption after accepted bytes")
        return self.resume_upload(session)

    def complete_upload(self, session: RemoteUploadSessionV1) -> RemoteObjectInfoV1:
        value = self._state(session)
        payload = bytes(value)
        if (
            len(payload) != session.total_size
            or hashlib.sha256(payload).digest() != session.wire_sha256
        ):
            raise RemoteConflictError("PX3 gate incomplete/corrupt upload")
        self.objects[session.key] = payload
        del self.sessions[session.token]
        self.session_meta.pop(session.token, None)
        return self._info(session.key, payload)

    def abort_upload(self, session: RemoteUploadSessionV1) -> None:
        self.sessions.pop(session.token, None)
        self.session_meta.pop(session.token, None)


class GateStaticMirrorTransport:
    def __init__(
        self,
        base_url: str,
        objects: dict[str, bytes],
        *,
        ignore_range: bool = False,
    ) -> None:
        self.base_url = base_url.rstrip("/") + "/"
        self.objects = objects
        self.ignore_range = ignore_range

    def request(self, method, url, *, headers=None, body=None, timeout=30.0):
        path = urllib.parse.unquote(urllib.parse.urlsplit(url).path.lstrip("/"))
        base_path = urllib.parse.urlsplit(self.base_url).path.lstrip("/")
        if base_path and path.startswith(base_path):
            path = path[len(base_path) :].lstrip("/")
        payload = self.objects.get(path)
        if payload is None:
            return HttpResponseV1(404, (), b"", url)
        digest = hashlib.sha256(payload).hexdigest()
        common = (
            ("Content-Length", str(len(payload))),
            ("ETag", '"gate-mirror"'),
            ("X-Sigma-Wire-SHA256", digest),
        )
        if method == "HEAD":
            return HttpResponseV1(200, common, b"", url)
        if method != "GET":
            return HttpResponseV1(405, (), b"", url)
        range_header = (headers or {}).get("Range")
        if self.ignore_range or range_header is None:
            return HttpResponseV1(200, common, payload, url)
        start_text, end_text = range_header.removeprefix("bytes=").split("-", 1)
        start = int(start_text)
        end = min(int(end_text), len(payload) - 1)
        part = payload[start : end + 1]
        return HttpResponseV1(
            206,
            (
                ("Content-Range", f"bytes {start}-{end}/{len(payload)}"),
                ("Content-Length", str(len(part))),
                ("ETag", '"gate-mirror"'),
                ("X-Sigma-Wire-SHA256", digest),
            ),
            part,
            url,
        )


class GateS3Client:
    def __init__(self) -> None:
        self.objects: dict[tuple[str, str], tuple[bytes, dict[str, str], str]] = {}
        self.uploads: dict[str, dict[str, object]] = {}
        self.next_upload = 1

    def head_object(self, bucket: str, key: str):
        value = self.objects.get((bucket, key))
        if value is None:
            return None
        payload, metadata, etag = value
        return S3ObjectHeadV1(
            len(payload),
            etag,
            tuple(sorted(metadata.items())),
        )

    def get_object_range(
        self,
        bucket: str,
        key: str,
        *,
        start: int,
        end_exclusive: int,
    ):
        value = self.objects.get((bucket, key))
        if value is None:
            raise RemoteNotFoundError(key)
        payload, metadata, etag = value
        return S3RangeResultV1(
            payload[start:end_exclusive],
            len(payload),
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
            "payloads": {},
        }
        return upload_id

    def list_parts(self, bucket, key, upload_id):
        state = self.uploads.get(upload_id)
        if state is None:
            raise RemoteSessionExpiredError("PX3 gate S3 upload expired")
        parts = state["parts"]
        return tuple(parts[index] for index in sorted(parts))

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
        if expected != checksum_sha256_b64:
            raise RemoteConflictError("PX3 gate S3 checksum mismatch")
        part = S3UploadedPartV1(
            part_number,
            len(data),
            f'"p{part_number}-{hashlib.sha256(data).hexdigest()[:8]}"',
            expected,
        )
        state["parts"][part_number] = part
        state["payloads"][part_number] = data
        return part

    def complete_multipart_upload(
        self,
        bucket,
        key,
        upload_id,
        *,
        parts,
    ):
        state = self.uploads[upload_id]
        payload = b"".join(
            state["payloads"][part.part_number]
            for part in parts
        )
        metadata = dict(state["metadata"])
        etag = '"complete-' + hashlib.sha256(payload).hexdigest()[:12] + '"'
        self.objects[(bucket, key)] = (payload, metadata, etag)
        del self.uploads[upload_id]
        return self.head_object(bucket, key)

    def abort_multipart_upload(self, bucket, key, upload_id):
        self.uploads.pop(upload_id, None)


class GateOciTransport:
    def __init__(self) -> None:
        self.blobs: dict[str, bytes] = {}
        self.manifests: dict[str, bytes] = {}
        self.uploads: dict[str, bytearray] = {}
        self.next_upload = 1

    @staticmethod
    def _headers(**values: str):
        return tuple((key, value) for key, value in values.items())

    def request(self, method, url, *, headers=None, body=None, timeout=30.0):
        headers = dict(headers or {})
        body = b"" if body is None else body
        parsed = urllib.parse.urlsplit(url)
        path = parsed.path
        query = dict(urllib.parse.parse_qsl(parsed.query))

        manifest_marker = "/v2/demo/manifests/"
        if manifest_marker in path:
            tag = urllib.parse.unquote(path.split(manifest_marker, 1)[1])
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
                            "Docker-Content-Digest": digest,
                            "Content-Type": "application/vnd.oci.image.manifest.v1+json",
                        }
                    ),
                    payload,
                    url,
                )

        upload_marker = "/v2/demo/blobs/uploads/"
        blob_marker = "/v2/demo/blobs/"
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
            return HttpResponseV1(
                202,
                self._headers(Location=f"/v2/demo/blobs/uploads/{token}"),
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
                values = {"Location": location}
                if current:
                    values["Range"] = f"0-{len(current) - 1}"
                return HttpResponseV1(
                    204,
                    self._headers(**values),
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


__all__ = [
    "GateMemoryRemoteBackend",
    "GateOciTransport",
    "GateS3Client",
    "GateStaticMirrorTransport",
]
