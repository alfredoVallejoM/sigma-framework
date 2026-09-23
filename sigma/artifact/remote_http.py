"""PX3 HTTP mirror and OCI Distribution remote backends."""

from __future__ import annotations

import hashlib
import json
import re
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass
from typing import Mapping, Protocol, runtime_checkable

from .remote import (
    RemoteBlobBackendV1,
    RemoteConflictError,
    RemoteIntegrityError,
    RemoteNotFoundError,
    RemoteObjectInfoV1,
    RemoteRangeUnsupportedError,
    RemoteReadChunkV1,
    RemoteReadOnlyError,
    RemoteRetryableError,
    RemoteSessionExpiredError,
    RemoteStoreError,
    RemoteUploadSessionV1,
)

_OCI_MANIFEST_MEDIA_TYPE = "application/vnd.oci.image.manifest.v1+json"
_OCI_EMPTY_MEDIA_TYPE = "application/vnd.oci.empty.v1+json"
_OCI_EMPTY_BYTES = b"{}"
_OCI_EMPTY_DIGEST = (
    "sha256:44136fa355b3678a1146ad16f7e8649e94fb4fc21fe77e8310c060f61caaff8a"
)
_SIGMA_PX3_ARTIFACT_TYPE = "application/vnd.sigma.px3.remote-object.v1"
_SIGMA_PX3_PAYLOAD_MEDIA_TYPE = "application/vnd.sigma.px3.remote-payload.v1"
_RANGE_RE = re.compile(r"^bytes ([0-9]+)-([0-9]+)/([0-9]+)$")
_OCI_UPLOAD_RANGE_RE = re.compile(r"^(?:bytes=)?([0-9]+)-([0-9]+)$")


@dataclass(frozen=True)
class HttpResponseV1:
    status: int
    headers: tuple[tuple[str, str], ...]
    body: bytes
    final_url: str

    def __post_init__(self) -> None:
        if isinstance(self.status, bool) or not isinstance(self.status, int):
            raise TypeError("HTTP status must be int")
        if not isinstance(self.body, bytes):
            raise TypeError("HTTP body must be bytes")
        if not isinstance(self.final_url, str):
            raise TypeError("final_url must be str")

    def header(self, name: str) -> str | None:
        target = name.lower()
        for key, value in self.headers:
            if key.lower() == target:
                return value
        return None


@runtime_checkable
class HttpTransportV1(Protocol):
    def request(
        self,
        method: str,
        url: str,
        *,
        headers: Mapping[str, str] | None = None,
        body: bytes | None = None,
        timeout: float = 30.0,
    ) -> HttpResponseV1:
        ...


class _SafeRedirectHandler(urllib.request.HTTPRedirectHandler):
    """Strip credentials on cross-origin redirects."""

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        redirected = super().redirect_request(req, fp, code, msg, headers, newurl)
        if redirected is None:
            return None
        old = urllib.parse.urlsplit(req.full_url)
        new = urllib.parse.urlsplit(newurl)
        if (old.scheme.lower(), old.hostname, old.port) != (
            new.scheme.lower(),
            new.hostname,
            new.port,
        ):
            redirected.remove_header("Authorization")
            redirected.remove_header("Proxy-Authorization")
        return redirected


class UrllibHttpTransportV1:
    """Dependency-free HTTP transport with safe redirect credential handling."""

    def __init__(self) -> None:
        self._opener = urllib.request.build_opener(_SafeRedirectHandler())

    def request(
        self,
        method: str,
        url: str,
        *,
        headers: Mapping[str, str] | None = None,
        body: bytes | None = None,
        timeout: float = 30.0,
    ) -> HttpResponseV1:
        request = urllib.request.Request(
            url,
            data=body,
            headers=dict(headers or {}),
            method=method.upper(),
        )
        try:
            response = self._opener.open(request, timeout=timeout)
            try:
                payload = response.read()
                return HttpResponseV1(
                    int(response.status),
                    tuple((str(k), str(v)) for k, v in response.headers.items()),
                    payload,
                    str(response.geturl()),
                )
            finally:
                response.close()
        except urllib.error.HTTPError as exc:
            try:
                body_bytes = exc.read()
            finally:
                exc.close()
            return HttpResponseV1(
                int(exc.code),
                tuple((str(k), str(v)) for k, v in exc.headers.items()),
                body_bytes,
                str(exc.geturl()),
            )
        except (urllib.error.URLError, TimeoutError, OSError) as exc:
            raise RemoteRetryableError(f"HTTP transport failure: {exc}") from exc


def _validate_base_url(value: str) -> str:
    if not isinstance(value, str):
        raise TypeError("base_url must be str")
    parsed = urllib.parse.urlsplit(value)
    if parsed.scheme not in ("http", "https") or not parsed.netloc:
        raise ValueError("base_url must be absolute http/https URL")
    if parsed.query or parsed.fragment:
        raise ValueError("base_url must not contain query or fragment")
    return value.rstrip("/") + "/"


def _validate_headers(values: Mapping[str, str] | None) -> dict[str, str]:
    result: dict[str, str] = {}
    for key, value in (values or {}).items():
        if not isinstance(key, str) or not isinstance(value, str):
            raise TypeError("HTTP headers must be str -> str")
        if "\r" in key or "\n" in key or "\r" in value or "\n" in value:
            raise ValueError("HTTP header contains newline")
        result[key] = value
    return result


def _remote_failure(response: HttpResponseV1, *, operation: str) -> None:
    if response.status in (408, 425, 429) or 500 <= response.status <= 599:
        raise RemoteRetryableError(
            f"{operation} returned retryable HTTP {response.status}"
        )
    if response.status == 404:
        raise RemoteNotFoundError(f"{operation} returned HTTP 404")
    raise RemoteStoreError(f"{operation} returned HTTP {response.status}")


def _sha256_header(value: str | None) -> bytes | None:
    if value is None:
        return None
    candidate = value.strip()
    if candidate.startswith("sha256:"):
        candidate = candidate[len("sha256:") :]
    try:
        raw = bytes.fromhex(candidate)
    except ValueError:
        return None
    return raw if len(raw) == 32 else None


def _parse_content_range(value: str | None) -> tuple[int, int, int] | None:
    if value is None:
        return None
    match = _RANGE_RE.fullmatch(value.strip())
    if match is None:
        return None
    start, end, total = (int(match.group(i)) for i in range(1, 4))
    if start > end or end >= total:
        return None
    return start, end, total


class HttpReadOnlyMirrorBackendV1(RemoteBlobBackendV1):
    """Read-only ArtifactId path mirror over ordinary HTTP Range GETs."""

    def __init__(
        self,
        base_url: str,
        *,
        transport: HttpTransportV1 | None = None,
        headers: Mapping[str, str] | None = None,
        timeout: float = 30.0,
    ) -> None:
        self.base_url = _validate_base_url(base_url)
        self.transport = UrllibHttpTransportV1() if transport is None else transport
        if not isinstance(self.transport, HttpTransportV1):
            raise TypeError("transport must implement HttpTransportV1")
        self.headers = _validate_headers(headers)
        if (
            isinstance(timeout, bool)
            or not isinstance(timeout, (int, float))
            or timeout <= 0
        ):
            raise ValueError("timeout must be positive")
        self.timeout = float(timeout)
        public = hashlib.sha256(self.base_url.encode("utf-8")).hexdigest()
        self._fingerprint = f"http-mirror-v1:{public}"

    @property
    def fingerprint(self) -> str:
        return self._fingerprint

    @property
    def read_only(self) -> bool:
        return True

    def _url(self, key: str) -> str:
        segments = [
            urllib.parse.quote(segment, safe="-._~")
            for segment in key.split("/")
        ]
        return urllib.parse.urljoin(self.base_url, "/".join(segments))

    def head(self, key: str) -> RemoteObjectInfoV1 | None:
        response = self.transport.request(
            "HEAD",
            self._url(key),
            headers=self.headers,
            timeout=self.timeout,
        )
        if response.status == 404:
            return None
        if response.status in (405, 501):
            # Some static mirrors omit HEAD. A zero-range GET is an equivalent
            # metadata probe without treating provider metadata as identity.
            response = self.transport.request(
                "GET",
                self._url(key),
                headers={**self.headers, "Range": "bytes=0-0"},
                timeout=self.timeout,
            )
        if response.status not in (200, 206):
            _remote_failure(response, operation="HTTP mirror head")
        size_header = response.header("Content-Length")
        parsed_range = _parse_content_range(response.header("Content-Range"))
        if parsed_range is not None:
            size = parsed_range[2]
        elif size_header is not None:
            try:
                size = int(size_header)
            except ValueError as exc:
                raise RemoteIntegrityError("HTTP mirror Content-Length is invalid") from exc
        else:
            size = len(response.body)
        if size < 0:
            raise RemoteIntegrityError("HTTP mirror reported negative size")
        return RemoteObjectInfoV1(
            key=key,
            size=size,
            revision=response.header("ETag"),
            wire_sha256=_sha256_header(
                response.header("X-Sigma-Wire-SHA256")
            ),
            provider_locator=response.final_url,
        )

    def read_range(
        self,
        key: str,
        *,
        start: int,
        max_bytes: int,
    ) -> RemoteReadChunkV1:
        if (
            isinstance(start, bool)
            or not isinstance(start, int)
            or start < 0
            or isinstance(max_bytes, bool)
            or not isinstance(max_bytes, int)
            or max_bytes < 1
        ):
            raise ValueError("invalid HTTP mirror range")
        end = start + max_bytes - 1
        response = self.transport.request(
            "GET",
            self._url(key),
            headers={**self.headers, "Range": f"bytes={start}-{end}"},
            timeout=self.timeout,
        )
        if response.status == 404:
            raise RemoteNotFoundError(f"HTTP mirror key not found: {key}")
        if response.status == 206:
            parsed = _parse_content_range(response.header("Content-Range"))
            if parsed is None:
                raise RemoteIntegrityError("HTTP mirror 206 lacks valid Content-Range")
            actual_start, actual_end, total = parsed
            if (
                actual_start != start
                or actual_end > end
                or len(response.body) != actual_end - actual_start + 1
            ):
                raise RemoteIntegrityError("HTTP mirror ranged body geometry mismatch")
        elif response.status == 200:
            if start != 0:
                raise RemoteRangeUnsupportedError(
                    "HTTP mirror ignored byte range"
                )
            total = len(response.body)
        else:
            _remote_failure(response, operation="HTTP mirror ranged GET")
            raise AssertionError("unreachable")
        return RemoteReadChunkV1(
            key=key,
            start=start,
            data=response.body,
            total_size=total,
            revision=response.header("ETag"),
            wire_sha256=_sha256_header(
                response.header("X-Sigma-Wire-SHA256")
            ),
        )

    def begin_upload(
        self,
        key: str,
        *,
        total_size: int,
        wire_sha256: bytes,
        preferred_chunk_size: int,
    ) -> RemoteUploadSessionV1:
        raise RemoteReadOnlyError("HTTP mirror is read-only")

    def resume_upload(self, session: RemoteUploadSessionV1) -> RemoteUploadSessionV1:
        raise RemoteReadOnlyError("HTTP mirror is read-only")

    def upload_chunk(
        self,
        session: RemoteUploadSessionV1,
        data: bytes,
    ) -> RemoteUploadSessionV1:
        raise RemoteReadOnlyError("HTTP mirror is read-only")

    def complete_upload(
        self,
        session: RemoteUploadSessionV1,
    ) -> RemoteObjectInfoV1:
        raise RemoteReadOnlyError("HTTP mirror is read-only")

    def abort_upload(self, session: RemoteUploadSessionV1) -> None:
        raise RemoteReadOnlyError("HTTP mirror is read-only")


class OciRegistryBackendV1(RemoteBlobBackendV1):
    """OCI Distribution storage backend using an image manifest as a locator.

    This is storage plumbing only. It is intentionally not the richer IX0 OCI
    artifact/referrer integration.
    """

    def __init__(
        self,
        base_url: str,
        repository: str,
        *,
        transport: HttpTransportV1 | None = None,
        headers: Mapping[str, str] | None = None,
        timeout: float = 30.0,
    ) -> None:
        self.base_url = _validate_base_url(base_url)
        if (
            not isinstance(repository, str)
            or not repository
            or repository.startswith("/")
            or ".." in repository.split("/")
        ):
            raise ValueError("OCI repository is invalid")
        self.repository = repository.strip("/")
        self.transport = UrllibHttpTransportV1() if transport is None else transport
        if not isinstance(self.transport, HttpTransportV1):
            raise TypeError("transport must implement HttpTransportV1")
        self.headers = _validate_headers(headers)
        if (
            isinstance(timeout, bool)
            or not isinstance(timeout, (int, float))
            or timeout <= 0
        ):
            raise ValueError("timeout must be positive")
        self.timeout = float(timeout)
        public = f"{self.base_url}|{self.repository}".encode("utf-8")
        self._fingerprint = f"oci-distribution-v1:{hashlib.sha256(public).hexdigest()}"

    @property
    def fingerprint(self) -> str:
        return self._fingerprint

    @property
    def read_only(self) -> bool:
        return False

    def _repo_path(self) -> str:
        return "/".join(
            urllib.parse.quote(part, safe="-._~")
            for part in self.repository.split("/")
        )

    def _api_url(self, suffix: str) -> str:
        path = f"v2/{self._repo_path()}/{suffix.lstrip('/')}"
        return urllib.parse.urljoin(self.base_url, path)

    @staticmethod
    def _tag_for_key(key: str) -> str:
        return "sigma-px3-" + hashlib.sha256(key.encode("ascii")).hexdigest()

    def _manifest_url(self, key: str) -> str:
        return self._api_url(
            "manifests/" + urllib.parse.quote(self._tag_for_key(key), safe="-._~")
        )

    def _request(
        self,
        method: str,
        url: str,
        *,
        headers: Mapping[str, str] | None = None,
        body: bytes | None = None,
    ) -> HttpResponseV1:
        return self.transport.request(
            method,
            url,
            headers={**self.headers, **dict(headers or {})},
            body=body,
            timeout=self.timeout,
        )

    def _resolve_location(self, base: str, location: str | None) -> str:
        if location is None or not location:
            raise RemoteIntegrityError("OCI response omitted upload Location")
        resolved = urllib.parse.urljoin(base, location)
        parsed = urllib.parse.urlsplit(resolved)
        if parsed.scheme not in ("http", "https") or not parsed.netloc:
            raise RemoteIntegrityError("OCI upload Location is not absolute/resolvable")
        return resolved

    def _manifest_info(self, key: str) -> RemoteObjectInfoV1 | None:
        response = self._request(
            "GET",
            self._manifest_url(key),
            headers={"Accept": _OCI_MANIFEST_MEDIA_TYPE},
        )
        if response.status == 404:
            return None
        if response.status != 200:
            _remote_failure(response, operation="OCI manifest GET")
        try:
            manifest = json.loads(response.body.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise RemoteIntegrityError("OCI locator manifest is invalid JSON") from exc
        if not isinstance(manifest, dict):
            raise RemoteIntegrityError("OCI locator manifest must be an object")
        if (
            manifest.get("schemaVersion") != 2
            or manifest.get("mediaType") != _OCI_MANIFEST_MEDIA_TYPE
            or manifest.get("artifactType") != _SIGMA_PX3_ARTIFACT_TYPE
        ):
            raise RemoteIntegrityError("OCI locator manifest profile mismatch")
        annotations = manifest.get("annotations")
        if not isinstance(annotations, dict):
            raise RemoteIntegrityError("OCI locator manifest annotations missing")
        expected_key_hash = hashlib.sha256(key.encode("ascii")).hexdigest()
        if annotations.get("dev.sigma.px3.key-sha256") != expected_key_hash:
            raise RemoteIntegrityError("OCI locator manifest key binding mismatch")
        config = manifest.get("config")
        if (
            not isinstance(config, dict)
            or config.get("mediaType") != _OCI_EMPTY_MEDIA_TYPE
            or config.get("digest") != _OCI_EMPTY_DIGEST
            or config.get("size") != len(_OCI_EMPTY_BYTES)
        ):
            raise RemoteIntegrityError("OCI locator manifest empty config mismatch")
        layers = manifest.get("layers")
        if not isinstance(layers, list) or len(layers) != 1:
            raise RemoteIntegrityError("OCI locator manifest must contain one payload layer")
        layer = layers[0]
        if (
            not isinstance(layer, dict)
            or layer.get("mediaType") != _SIGMA_PX3_PAYLOAD_MEDIA_TYPE
            or not isinstance(layer.get("digest"), str)
            or not str(layer["digest"]).startswith("sha256:")
            or not isinstance(layer.get("size"), int)
            or int(layer["size"]) < 0
        ):
            raise RemoteIntegrityError("OCI locator payload descriptor is invalid")
        digest = str(layer["digest"])
        wire_sha = _sha256_header(digest)
        if wire_sha is None:
            raise RemoteIntegrityError("OCI payload digest is not sha256")
        revision = response.header("Docker-Content-Digest") or response.header("ETag")
        return RemoteObjectInfoV1(
            key=key,
            size=int(layer["size"]),
            revision=revision,
            wire_sha256=wire_sha,
            provider_locator=response.final_url,
        )

    def head(self, key: str) -> RemoteObjectInfoV1 | None:
        return self._manifest_info(key)

    def read_range(
        self,
        key: str,
        *,
        start: int,
        max_bytes: int,
    ) -> RemoteReadChunkV1:
        if start < 0 or max_bytes < 1:
            raise ValueError("invalid OCI range")
        info = self._manifest_info(key)
        if info is None or info.wire_sha256 is None:
            raise RemoteNotFoundError(f"OCI key not found: {key}")
        digest = "sha256:" + info.wire_sha256.hex()
        url = self._api_url("blobs/" + digest)
        end = start + max_bytes - 1
        response = self._request(
            "GET",
            url,
            headers={"Range": f"bytes={start}-{end}"},
        )
        if response.status == 404:
            raise RemoteIntegrityError("OCI locator references missing payload blob")
        if response.status == 206:
            parsed = _parse_content_range(response.header("Content-Range"))
            if parsed is None:
                raise RemoteIntegrityError("OCI 206 lacks valid Content-Range")
            actual_start, actual_end, total = parsed
            if (
                actual_start != start
                or actual_end > end
                or len(response.body) != actual_end - actual_start + 1
            ):
                raise RemoteIntegrityError("OCI ranged blob geometry mismatch")
        elif response.status == 200:
            if start != 0:
                raise RemoteRangeUnsupportedError("OCI registry ignored byte Range")
            total = len(response.body)
        else:
            _remote_failure(response, operation="OCI blob GET")
            raise AssertionError("unreachable")
        if total != info.size:
            raise RemoteIntegrityError("OCI manifest/blob size mismatch")
        docker_digest = response.header("Docker-Content-Digest")
        if docker_digest is not None and docker_digest != digest:
            raise RemoteIntegrityError("OCI blob response digest header mismatch")
        return RemoteReadChunkV1(
            key=key,
            start=start,
            data=response.body,
            total_size=info.size,
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
        if total_size < 0 or len(wire_sha256) != 32 or preferred_chunk_size < 1:
            raise ValueError("invalid OCI upload parameters")
        url = self._api_url("blobs/uploads/")
        response = self._request(
            "POST",
            url,
            headers={"Content-Length": "0"},
            body=b"",
        )
        if response.status != 202:
            _remote_failure(response, operation="OCI begin blob upload")
        location = self._resolve_location(
            response.final_url,
            response.header("Location"),
        )
        minimum = response.header("OCI-Chunk-Min-Length")
        min_chunk = 0
        if minimum is not None:
            try:
                min_chunk = int(minimum)
            except ValueError as exc:
                raise RemoteIntegrityError(
                    "OCI-Chunk-Min-Length is invalid"
                ) from exc
            if min_chunk < 0:
                raise RemoteIntegrityError("OCI minimum chunk is negative")
        return RemoteUploadSessionV1(
            backend_fingerprint=self.fingerprint,
            key=key,
            total_size=total_size,
            wire_sha256=wire_sha256,
            token=location,
            accepted_offset=0,
            chunk_size=max(preferred_chunk_size, min_chunk or 1),
            opaque=(
                ("min_chunk_size", str(min_chunk)),
            ),
        )

    @staticmethod
    def _upload_offset(value: str | None, fallback: int) -> int:
        if value is None:
            return fallback
        match = _OCI_UPLOAD_RANGE_RE.fullmatch(value.strip())
        if match is None:
            raise RemoteIntegrityError("OCI upload Range header is invalid")
        start, end = int(match.group(1)), int(match.group(2))
        if start != 0 or end < start:
            raise RemoteIntegrityError("OCI upload Range is non-canonical")
        return end + 1

    def resume_upload(
        self,
        session: RemoteUploadSessionV1,
    ) -> RemoteUploadSessionV1:
        self._validate_session(session)
        response = self._request("GET", session.token)
        if response.status in (404, 410):
            raise RemoteSessionExpiredError("OCI upload session expired")
        if response.status not in (204, 202):
            _remote_failure(response, operation="OCI upload status")
        location = self._resolve_location(
            response.final_url,
            response.header("Location") or session.token,
        )
        offset = self._upload_offset(
            response.header("Range"),
            session.accepted_offset,
        )
        if offset > session.total_size:
            raise RemoteIntegrityError("OCI upload offset exceeds object size")
        return RemoteUploadSessionV1(
            backend_fingerprint=session.backend_fingerprint,
            key=session.key,
            total_size=session.total_size,
            wire_sha256=session.wire_sha256,
            token=location,
            accepted_offset=offset,
            chunk_size=session.chunk_size,
            opaque=session.opaque,
        )

    def _validate_session(self, session: RemoteUploadSessionV1) -> None:
        if session.backend_fingerprint != self.fingerprint:
            raise RemoteConflictError("upload session belongs to another OCI backend")

    def upload_chunk(
        self,
        session: RemoteUploadSessionV1,
        data: bytes,
    ) -> RemoteUploadSessionV1:
        self._validate_session(session)
        if not isinstance(data, bytes) or not data:
            raise ValueError("OCI upload chunk must be non-empty bytes")
        start = session.accepted_offset
        end_exclusive = start + len(data)
        if end_exclusive > session.total_size:
            raise ValueError("OCI upload chunk exceeds object size")
        response = self._request(
            "PATCH",
            session.token,
            headers={
                "Content-Length": str(len(data)),
                "Content-Range": f"{start}-{end_exclusive - 1}",
                "Content-Type": "application/octet-stream",
            },
            body=data,
        )
        if response.status == 416:
            reconciled = self.resume_upload(session)
            if reconciled.accepted_offset == end_exclusive:
                return reconciled
            raise RemoteConflictError(
                "OCI upload server offset does not match retried chunk"
            )
        if response.status != 202:
            _remote_failure(response, operation="OCI upload chunk")
        location = self._resolve_location(
            response.final_url,
            response.header("Location") or session.token,
        )
        accepted = self._upload_offset(response.header("Range"), end_exclusive)
        if accepted != end_exclusive:
            raise RemoteIntegrityError("OCI upload accepted unexpected byte range")
        return RemoteUploadSessionV1(
            backend_fingerprint=session.backend_fingerprint,
            key=session.key,
            total_size=session.total_size,
            wire_sha256=session.wire_sha256,
            token=location,
            accepted_offset=accepted,
            chunk_size=session.chunk_size,
            opaque=session.opaque,
        )

    @staticmethod
    def _with_query(url: str, **params: str) -> str:
        parsed = urllib.parse.urlsplit(url)
        query = urllib.parse.parse_qsl(parsed.query, keep_blank_values=True)
        query.extend(params.items())
        return urllib.parse.urlunsplit(
            (
                parsed.scheme,
                parsed.netloc,
                parsed.path,
                urllib.parse.urlencode(query),
                parsed.fragment,
            )
        )

    def _ensure_empty_blob(self) -> None:
        head = self._request(
            "HEAD",
            self._api_url("blobs/" + _OCI_EMPTY_DIGEST),
        )
        if head.status == 200:
            return
        if head.status != 404:
            _remote_failure(head, operation="OCI empty blob HEAD")
        upload_url = self._api_url("blobs/uploads/")
        single = self._request(
            "POST",
            self._with_query(upload_url, digest=_OCI_EMPTY_DIGEST),
            headers={
                "Content-Length": str(len(_OCI_EMPTY_BYTES)),
                "Content-Type": "application/octet-stream",
            },
            body=_OCI_EMPTY_BYTES,
        )
        if single.status == 201:
            return
        if single.status != 202:
            _remote_failure(single, operation="OCI empty blob upload")
        location = self._resolve_location(
            single.final_url,
            single.header("Location"),
        )
        complete = self._request(
            "PUT",
            self._with_query(location, digest=_OCI_EMPTY_DIGEST),
            headers={
                "Content-Length": str(len(_OCI_EMPTY_BYTES)),
                "Content-Type": "application/octet-stream",
            },
            body=_OCI_EMPTY_BYTES,
        )
        if complete.status != 201:
            _remote_failure(complete, operation="OCI empty blob completion")

    @staticmethod
    def _manifest_bytes(key: str, size: int, wire_sha256: bytes) -> bytes:
        manifest = {
            "annotations": {
                "dev.sigma.px3.key-sha256": hashlib.sha256(
                    key.encode("ascii")
                ).hexdigest()
            },
            "artifactType": _SIGMA_PX3_ARTIFACT_TYPE,
            "config": {
                "digest": _OCI_EMPTY_DIGEST,
                "mediaType": _OCI_EMPTY_MEDIA_TYPE,
                "size": len(_OCI_EMPTY_BYTES),
            },
            "layers": [
                {
                    "digest": "sha256:" + wire_sha256.hex(),
                    "mediaType": _SIGMA_PX3_PAYLOAD_MEDIA_TYPE,
                    "size": size,
                }
            ],
            "mediaType": _OCI_MANIFEST_MEDIA_TYPE,
            "schemaVersion": 2,
        }
        return json.dumps(
            manifest,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")

    def complete_upload(
        self,
        session: RemoteUploadSessionV1,
    ) -> RemoteObjectInfoV1:
        self._validate_session(session)
        if session.accepted_offset != session.total_size:
            raise RemoteConflictError("OCI upload session is incomplete")
        digest = "sha256:" + session.wire_sha256.hex()
        response = self._request(
            "PUT",
            self._with_query(session.token, digest=digest),
            headers={"Content-Length": "0"},
            body=b"",
        )
        if response.status not in (201, 204):
            if response.status == 400:
                raise RemoteIntegrityError("OCI registry rejected final blob digest")
            _remote_failure(response, operation="OCI complete blob upload")

        self._ensure_empty_blob()
        manifest_bytes = self._manifest_bytes(
            session.key,
            session.total_size,
            session.wire_sha256,
        )
        manifest_response = self._request(
            "PUT",
            self._manifest_url(session.key),
            headers={
                "Content-Length": str(len(manifest_bytes)),
                "Content-Type": _OCI_MANIFEST_MEDIA_TYPE,
            },
            body=manifest_bytes,
        )
        if manifest_response.status != 201:
            _remote_failure(manifest_response, operation="OCI publish locator manifest")
        info = self._manifest_info(session.key)
        if info is None:
            raise RemoteIntegrityError("OCI locator manifest disappeared after publish")
        if info.size != session.total_size or info.wire_sha256 != session.wire_sha256:
            raise RemoteIntegrityError("OCI published locator differs from upload")
        return info

    def abort_upload(self, session: RemoteUploadSessionV1) -> None:
        self._validate_session(session)
        response = self._request("DELETE", session.token)
        if response.status not in (202, 204, 404):
            _remote_failure(response, operation="OCI abort blob upload")


__all__ = [
    "HttpReadOnlyMirrorBackendV1",
    "HttpResponseV1",
    "HttpTransportV1",
    "OciRegistryBackendV1",
    "UrllibHttpTransportV1",
]
