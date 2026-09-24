"""IX0 OCI Distribution registry client for Sigma Artifact V1 referrers.

The registry is treated as an untrusted distribution/discovery service.  Sigma
ArtifactId is always recomputed from canonical Sigma bytes after pull.
"""

from __future__ import annotations

import json
import re
import time
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass
from enum import Enum
from typing import Mapping, Protocol, runtime_checkable

from sigma.artifact.remote import RemoteRetryableError
from sigma.artifact.remote_http import HttpResponseV1, HttpTransportV1
from sigma.artifact.record import SigmaArtifactV1

from .oci import (
    MAX_OCI_MANIFEST_BYTES,
    OCI_EMPTY_CONFIG_BYTES,
    OCI_EMPTY_CONFIG_DIGEST,
    OCI_IMAGE_INDEX_MEDIA_TYPE,
    OCI_IMAGE_MANIFEST_MEDIA_TYPE,
    SIGMA_ARTIFACT_ID_ANNOTATION,
    SIGMA_ARTIFACT_REFERRER_TYPE,
    OciDescriptorV1,
    OciSigmaArtifactBindingV1,
    build_sigma_artifact_referrer_v1,
    oci_sha256_digest_v1,
    parse_sigma_referrers_index_v1,
    verify_sigma_artifact_referrer_v1,
)

_RETRYABLE_STATUS = frozenset({408, 425, 429})
_DIGEST_RE = re.compile(r"^([A-Za-z0-9+._-]+):([A-Za-z0-9=_-]+)$")
_TAG_CHAR_RE = re.compile(r"[^A-Za-z0-9_.-]")
_LINK_NEXT_RE = re.compile(r'<([^>]+)>\s*;\s*rel="?next"?', re.IGNORECASE)

DEFAULT_OCI_MAX_BLOB_BYTES = 64 * 1024 * 1024
DEFAULT_OCI_MAX_REFERRERS_BYTES = 4 * 1024 * 1024
DEFAULT_OCI_MAX_REFERRERS = 10_000
DEFAULT_OCI_MAX_PAGES = 32
DEFAULT_OCI_MAX_RETRIES = 4


class OciRegistryError(RuntimeError):
    """Base IX0 registry failure."""


class OciRegistryProtocolError(OciRegistryError):
    """Registry response violates the IX0/OCI contract."""


class OciRegistryNotFoundError(OciRegistryError):
    """Requested OCI content does not exist."""


class OciRegistryConflictError(OciRegistryError):
    """Concurrent or contradictory registry state was observed."""


class OciRegistryResourceLimitError(OciRegistryError):
    """Configured IX0 resource ceiling was exceeded."""


class OciReferrersSourceV1(str, Enum):
    API = "api"
    TAG_FALLBACK = "tag-fallback"


@dataclass(frozen=True)
class OciRegistryLimitsV1:
    max_blob_bytes: int = DEFAULT_OCI_MAX_BLOB_BYTES
    max_manifest_bytes: int = MAX_OCI_MANIFEST_BYTES
    max_referrers_bytes: int = DEFAULT_OCI_MAX_REFERRERS_BYTES
    max_referrers: int = DEFAULT_OCI_MAX_REFERRERS
    max_pages: int = DEFAULT_OCI_MAX_PAGES
    max_retries: int = DEFAULT_OCI_MAX_RETRIES
    retry_backoff_seconds: float = 0.05

    def __post_init__(self) -> None:
        integer_fields = (
            self.max_blob_bytes,
            self.max_manifest_bytes,
            self.max_referrers_bytes,
            self.max_referrers,
            self.max_pages,
            self.max_retries,
        )
        if any(
            isinstance(value, bool) or not isinstance(value, int) or value < 0
            for value in integer_fields
        ):
            raise ValueError("OCI registry integer limits must be non-negative ints")
        if self.max_blob_bytes < 1:
            raise ValueError("max_blob_bytes must be positive")
        if self.max_manifest_bytes < 1:
            raise ValueError("max_manifest_bytes must be positive")
        if self.max_referrers_bytes < 1:
            raise ValueError("max_referrers_bytes must be positive")
        if self.max_referrers < 1 or self.max_pages < 1:
            raise ValueError("referrer/page limits must be positive")
        if (
            isinstance(self.retry_backoff_seconds, bool)
            or not isinstance(self.retry_backoff_seconds, (int, float))
            or self.retry_backoff_seconds < 0
        ):
            raise ValueError("retry_backoff_seconds must be non-negative")


@dataclass(frozen=True)
class OciBlobPutResultV1:
    digest: str
    size: int
    reused: bool


@dataclass(frozen=True)
class OciManifestPutResultV1:
    digest: str
    size: int
    reference: str
    subject_acknowledged: bool


@dataclass(frozen=True)
class OciReferrersResultV1:
    subject_digest: str
    descriptors: tuple[OciDescriptorV1, ...]
    source: OciReferrersSourceV1
    pages: int


@dataclass(frozen=True)
class OciAttachResultV1:
    binding: OciSigmaArtifactBindingV1
    config_reused: bool
    payload_reused: bool
    subject_acknowledged: bool
    fallback_tag_updated: bool
    discovered_after_push: bool


@runtime_checkable
class OciRegistryTransportV1(Protocol):
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
    """Remove caller credentials when urllib follows a cross-origin redirect."""

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


class BoundedUrllibOciTransportV1:
    """Dependency-free HTTP transport with a hard response-body ceiling."""

    def __init__(self, *, hard_max_response_bytes: int) -> None:
        if (
            isinstance(hard_max_response_bytes, bool)
            or not isinstance(hard_max_response_bytes, int)
            or hard_max_response_bytes < 1
        ):
            raise ValueError("hard_max_response_bytes must be positive")
        self.hard_max_response_bytes = hard_max_response_bytes
        self._opener = urllib.request.build_opener(_SafeRedirectHandler())

    def _read_bounded(self, response) -> bytes:
        payload = response.read(self.hard_max_response_bytes + 1)
        if len(payload) > self.hard_max_response_bytes:
            raise OciRegistryResourceLimitError(
                "registry response exceeded hard transport body limit"
            )
        return payload

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
                payload = self._read_bounded(response)
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
                payload = self._read_bounded(exc)
                return HttpResponseV1(
                    int(exc.code),
                    tuple((str(k), str(v)) for k, v in exc.headers.items()),
                    payload,
                    str(exc.geturl()),
                )
            finally:
                exc.close()
        except OciRegistryResourceLimitError:
            raise
        except (urllib.error.URLError, TimeoutError, OSError) as exc:
            raise RemoteRetryableError(f"OCI HTTP transport failure: {exc}") from exc


def _origin(url: str) -> tuple[str, str | None, int | None]:
    parsed = urllib.parse.urlsplit(url)
    return parsed.scheme.lower(), parsed.hostname, parsed.port


def _validate_base_url(value: str) -> str:
    if not isinstance(value, str):
        raise TypeError("base_url must be str")
    parsed = urllib.parse.urlsplit(value)
    if parsed.scheme not in ("http", "https") or not parsed.netloc:
        raise ValueError("base_url must be absolute http/https URL")
    if parsed.query or parsed.fragment:
        raise ValueError("base_url must not contain query or fragment")
    return value.rstrip("/") + "/"


def _validate_repository(value: str) -> str:
    if (
        not isinstance(value, str)
        or not value
        or value.startswith("/")
        or value.endswith("/")
        or any(part in ("", ".", "..") for part in value.split("/"))
    ):
        raise ValueError("OCI repository is invalid")
    return value


def _validate_headers(values: Mapping[str, str] | None) -> dict[str, str]:
    result: dict[str, str] = {}
    for key, value in (values or {}).items():
        if not isinstance(key, str) or not isinstance(value, str):
            raise TypeError("OCI headers must be str -> str")
        if "\r" in key or "\n" in key or "\r" in value or "\n" in value:
            raise ValueError("OCI header contains newline")
        result[key] = value
    return result


def _validate_digest(value: str) -> str:
    if not isinstance(value, str) or _DIGEST_RE.fullmatch(value) is None:
        raise ValueError("invalid OCI digest")
    return value


def _strict_json_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
    out: dict[str, object] = {}
    for key, value in pairs:
        if key in out:
            raise OciRegistryProtocolError("duplicate JSON object key")
        out[key] = value
    return out


def _json_object(data: bytes, *, what: str) -> dict[str, object]:
    try:
        value = json.loads(
            data.decode("utf-8"),
            object_pairs_hook=_strict_json_object,
        )
    except OciRegistryProtocolError:
        raise
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise OciRegistryProtocolError(f"{what} is invalid JSON") from exc
    if not isinstance(value, dict):
        raise OciRegistryProtocolError(f"{what} must be a JSON object")
    return value


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


def oci_referrers_tag_v1(subject_digest: str) -> str:
    """Return the OCI Distribution 1.1 referrers-tag fallback for a digest."""

    match = _DIGEST_RE.fullmatch(_validate_digest(subject_digest))
    if match is None:
        raise ValueError("invalid OCI digest")
    algorithm = _TAG_CHAR_RE.sub("-", match.group(1)[:32])
    encoded = _TAG_CHAR_RE.sub("-", match.group(2)[:64])
    return f"{algorithm}-{encoded}"


class OciRegistryClientV1:
    """Bounded OCI Distribution client for Sigma IX0 attach/discover/pull."""

    def __init__(
        self,
        base_url: str,
        repository: str,
        *,
        transport: OciRegistryTransportV1 | HttpTransportV1 | None = None,
        headers: Mapping[str, str] | None = None,
        timeout: float = 30.0,
        limits: OciRegistryLimitsV1 | None = None,
    ) -> None:
        self.base_url = _validate_base_url(base_url)
        self.repository = _validate_repository(repository)
        self.headers = _validate_headers(headers)
        if (
            isinstance(timeout, bool)
            or not isinstance(timeout, (int, float))
            or timeout <= 0
        ):
            raise ValueError("timeout must be positive")
        self.timeout = float(timeout)
        self.limits = OciRegistryLimitsV1() if limits is None else limits
        if not isinstance(self.limits, OciRegistryLimitsV1):
            raise TypeError("limits must be OciRegistryLimitsV1")
        hard_limit = max(
            self.limits.max_blob_bytes,
            self.limits.max_manifest_bytes,
            self.limits.max_referrers_bytes,
        )
        self.transport = (
            BoundedUrllibOciTransportV1(
                hard_max_response_bytes=hard_limit,
            )
            if transport is None
            else transport
        )
        if not isinstance(self.transport, OciRegistryTransportV1):
            raise TypeError("transport must implement OciRegistryTransportV1")

    def _repo_path(self) -> str:
        return "/".join(
            urllib.parse.quote(part, safe="-._~")
            for part in self.repository.split("/")
        )

    def _api_url(self, suffix: str) -> str:
        return urllib.parse.urljoin(
            self.base_url,
            f"v2/{self._repo_path()}/{suffix.lstrip('/')}",
        )

    def _headers_for_url(
        self,
        url: str,
        extra: Mapping[str, str] | None = None,
    ) -> dict[str, str]:
        result = dict(self.headers)
        if _origin(url) != _origin(self.base_url):
            result = {
                key: value
                for key, value in result.items()
                if key.lower()
                not in {"authorization", "proxy-authorization"}
            }
        result.update(dict(extra or {}))
        return result

    def _request(
        self,
        method: str,
        url: str,
        *,
        headers: Mapping[str, str] | None = None,
        body: bytes | None = None,
    ) -> HttpResponseV1:
        attempt = 0
        while True:
            try:
                response = self.transport.request(
                    method,
                    url,
                    headers=self._headers_for_url(url, headers),
                    body=body,
                    timeout=self.timeout,
                )
            except RemoteRetryableError as exc:
                if attempt >= self.limits.max_retries:
                    raise OciRegistryError(
                        "OCI transport exhausted retry budget"
                    ) from exc
                attempt += 1
                if self.limits.retry_backoff_seconds:
                    time.sleep(self.limits.retry_backoff_seconds * attempt)
                continue
            if response.status in _RETRYABLE_STATUS or 500 <= response.status <= 599:
                if attempt >= self.limits.max_retries:
                    raise OciRegistryError(
                        f"{method} {url} exhausted retries at HTTP {response.status}"
                    )
                attempt += 1
                if self.limits.retry_backoff_seconds:
                    time.sleep(self.limits.retry_backoff_seconds * attempt)
                continue
            return response

    @staticmethod
    def _require_digest_header(
        response: HttpResponseV1,
        expected_digest: str,
        *,
        what: str,
    ) -> None:
        header = response.header("Docker-Content-Digest")
        if header is not None and header.strip() != expected_digest:
            raise OciRegistryProtocolError(
                f"{what} Docker-Content-Digest mismatch"
            )

    def _resolve_upload_location(
        self,
        response: HttpResponseV1,
    ) -> str:
        location = response.header("Location")
        if not location:
            raise OciRegistryProtocolError(
                "OCI upload response omitted Location"
            )
        resolved = urllib.parse.urljoin(response.final_url, location)
        parsed = urllib.parse.urlsplit(resolved)
        if parsed.scheme not in ("http", "https") or not parsed.netloc:
            raise OciRegistryProtocolError(
                "OCI upload Location is not resolvable"
            )
        return resolved

    def ping(self) -> bool:
        response = self._request(
            "GET",
            urllib.parse.urljoin(self.base_url, "v2/"),
        )
        return response.status == 200

    def _blob_url(self, digest: str) -> str:
        return self._api_url(
            "blobs/" + urllib.parse.quote(
                _validate_digest(digest),
                safe="-._~:+=",
            )
        )

    def _manifest_url(self, reference: str) -> str:
        if not isinstance(reference, str) or not reference:
            raise ValueError("manifest reference must be non-empty")
        return self._api_url(
            "manifests/" + urllib.parse.quote(
                reference,
                safe="-._~:+=",
            )
        )

    def _blob_exists(
        self,
        digest: str,
        *,
        expected_size: int,
    ) -> bool:
        response = self._request(
            "HEAD",
            self._blob_url(digest),
        )
        if response.status == 404:
            return False
        if response.status != 200:
            raise OciRegistryProtocolError(
                f"OCI blob HEAD returned HTTP {response.status}"
            )
        self._require_digest_header(
            response,
            digest,
            what="OCI blob HEAD",
        )
        length = response.header("Content-Length")
        if length is not None:
            try:
                remote_size = int(length)
            except ValueError as exc:
                raise OciRegistryProtocolError(
                    "OCI blob Content-Length is invalid"
                ) from exc
            if remote_size != expected_size:
                raise OciRegistryConflictError(
                    "existing OCI blob size differs from requested bytes"
                )
        return True

    def put_blob(self, data: bytes) -> OciBlobPutResultV1:
        if not isinstance(data, bytes):
            raise TypeError("OCI blob must be bytes")
        if len(data) > self.limits.max_blob_bytes:
            raise OciRegistryResourceLimitError(
                "OCI blob exceeds configured IX0 size limit"
            )
        digest = oci_sha256_digest_v1(data)
        if self._blob_exists(digest, expected_size=len(data)):
            return OciBlobPutResultV1(digest, len(data), True)

        start = self._request(
            "POST",
            self._api_url("blobs/uploads/"),
            headers={"Content-Length": "0"},
            body=b"",
        )
        if start.status != 202:
            raise OciRegistryProtocolError(
                f"OCI begin blob upload returned HTTP {start.status}"
            )
        location = self._resolve_upload_location(start)
        complete = self._request(
            "PUT",
            _with_query(location, digest=digest),
            headers={
                "Content-Length": str(len(data)),
                "Content-Type": "application/octet-stream",
            },
            body=data,
        )
        if complete.status not in (201, 204):
            raise OciRegistryProtocolError(
                f"OCI complete blob upload returned HTTP {complete.status}"
            )
        self._require_digest_header(
            complete,
            digest,
            what="OCI blob completion",
        )
        if not self._blob_exists(digest, expected_size=len(data)):
            raise OciRegistryProtocolError(
                "OCI blob disappeared after successful upload"
            )
        return OciBlobPutResultV1(digest, len(data), False)

    def put_manifest(
        self,
        manifest_wire: bytes,
        *,
        media_type: str,
        reference: str | None = None,
        expected_subject_digest: str | None = None,
        conditional_etag: str | None = None,
    ) -> OciManifestPutResultV1:
        if not isinstance(manifest_wire, bytes):
            raise TypeError("manifest_wire must be bytes")
        if len(manifest_wire) > self.limits.max_manifest_bytes:
            raise OciRegistryResourceLimitError(
                "OCI manifest exceeds configured IX0 size limit"
            )
        digest = oci_sha256_digest_v1(manifest_wire)
        selected_reference = digest if reference is None else reference
        headers = {
            "Content-Length": str(len(manifest_wire)),
            "Content-Type": media_type,
        }
        if conditional_etag is not None:
            headers["If-Match"] = conditional_etag
        response = self._request(
            "PUT",
            self._manifest_url(selected_reference),
            headers=headers,
            body=manifest_wire,
        )
        if response.status == 412:
            raise OciRegistryConflictError(
                "OCI referrers tag changed during conditional update"
            )
        if response.status != 201:
            raise OciRegistryProtocolError(
                f"OCI manifest PUT returned HTTP {response.status}"
            )
        self._require_digest_header(
            response,
            digest,
            what="OCI manifest PUT",
        )
        acknowledged = False
        if expected_subject_digest is not None:
            _validate_digest(expected_subject_digest)
            subject_header = response.header("OCI-Subject")
            if subject_header is not None:
                if subject_header.strip() != expected_subject_digest:
                    raise OciRegistryProtocolError(
                        "OCI-Subject acknowledgement mismatch"
                    )
                acknowledged = True
        return OciManifestPutResultV1(
            digest=digest,
            size=len(manifest_wire),
            reference=selected_reference,
            subject_acknowledged=acknowledged,
        )

    def _get_manifest(
        self,
        reference: str,
        *,
        accept: str,
        max_bytes: int,
    ) -> tuple[bytes, str | None]:
        response = self._request(
            "GET",
            self._manifest_url(reference),
            headers={"Accept": accept},
        )
        if response.status == 404:
            raise OciRegistryNotFoundError(
                f"OCI manifest not found: {reference}"
            )
        if response.status != 200:
            raise OciRegistryProtocolError(
                f"OCI manifest GET returned HTTP {response.status}"
            )
        if len(response.body) > max_bytes:
            raise OciRegistryResourceLimitError(
                "OCI manifest response exceeds configured limit"
            )
        digest = oci_sha256_digest_v1(response.body)
        if _DIGEST_RE.fullmatch(reference):
            if digest != reference:
                raise OciRegistryProtocolError(
                    "OCI manifest bytes do not match requested digest"
                )
        self._require_digest_header(
            response,
            digest,
            what="OCI manifest GET",
        )
        return response.body, response.header("ETag")

    def _get_blob(
        self,
        descriptor: OciDescriptorV1,
    ) -> bytes:
        if descriptor.size > self.limits.max_blob_bytes:
            raise OciRegistryResourceLimitError(
                "OCI descriptor exceeds configured IX0 blob limit"
            )
        response = self._request(
            "GET",
            self._blob_url(descriptor.digest),
        )
        if response.status == 404:
            raise OciRegistryNotFoundError(
                f"OCI blob not found: {descriptor.digest}"
            )
        if response.status != 200:
            raise OciRegistryProtocolError(
                f"OCI blob GET returned HTTP {response.status}"
            )
        if len(response.body) > self.limits.max_blob_bytes:
            raise OciRegistryResourceLimitError(
                "OCI blob response exceeds configured IX0 limit"
            )
        if len(response.body) != descriptor.size:
            raise OciRegistryProtocolError(
                "OCI blob size differs from descriptor"
            )
        digest = oci_sha256_digest_v1(response.body)
        if digest != descriptor.digest:
            raise OciRegistryProtocolError(
                "OCI blob bytes do not match descriptor digest"
            )
        self._require_digest_header(
            response,
            descriptor.digest,
            what="OCI blob GET",
        )
        return response.body

    @staticmethod
    def _parse_all_referrers_index(
        wire: bytes,
        *,
        max_referrers: int,
    ) -> tuple[OciDescriptorV1, ...]:
        value = _json_object(
            wire,
            what="OCI referrers index",
        )
        allowed = {
            "schemaVersion",
            "mediaType",
            "manifests",
            "annotations",
        }
        if set(value) - allowed:
            raise OciRegistryProtocolError(
                "unsupported OCI referrers index field"
            )
        if (
            value.get("schemaVersion") != 2
            or value.get("mediaType") != OCI_IMAGE_INDEX_MEDIA_TYPE
        ):
            raise OciRegistryProtocolError(
                "OCI referrers fallback is not an image index"
            )
        manifests = value.get("manifests")
        if not isinstance(manifests, list):
            raise OciRegistryProtocolError(
                "OCI referrers manifests must be a list"
            )
        if len(manifests) > max_referrers:
            raise OciRegistryResourceLimitError(
                "OCI referrers descriptor count exceeds configured limit"
            )
        return tuple(
            OciDescriptorV1.from_dict(item)
            for item in manifests
        )

    @staticmethod
    def _referrers_index_annotations(
        wire: bytes,
    ) -> dict[str, str]:
        value = _json_object(
            wire,
            what="OCI referrers index",
        )
        annotations = value.get("annotations")
        if annotations is None:
            return {}
        if not isinstance(annotations, dict) or any(
            not isinstance(key, str) or not isinstance(item, str)
            for key, item in annotations.items()
        ):
            raise OciRegistryProtocolError(
                "OCI referrers index annotations must be a string map"
            )
        return dict(annotations)

    @staticmethod
    def _build_referrers_index(
        descriptors: tuple[OciDescriptorV1, ...],
        *,
        annotations: Mapping[str, str] | None = None,
    ) -> bytes:
        ordered = tuple(
            sorted(
                descriptors,
                key=lambda item: (
                    item.digest,
                    item.media_type,
                    item.artifact_type or "",
                ),
            )
        )
        payload: dict[str, object] = {
            "schemaVersion": 2,
            "mediaType": OCI_IMAGE_INDEX_MEDIA_TYPE,
            "manifests": [item.to_dict() for item in ordered],
        }
        if annotations:
            payload["annotations"] = dict(sorted(annotations.items()))
        return json.dumps(
            payload,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")

    def _fallback_referrers(
        self,
        subject_digest: str,
    ) -> OciReferrersResultV1:
        tag = oci_referrers_tag_v1(subject_digest)
        try:
            wire, _ = self._get_manifest(
                tag,
                accept=OCI_IMAGE_INDEX_MEDIA_TYPE,
                max_bytes=self.limits.max_referrers_bytes,
            )
        except OciRegistryNotFoundError:
            return OciReferrersResultV1(
                subject_digest,
                (),
                OciReferrersSourceV1.TAG_FALLBACK,
                1,
            )
        descriptors = self._parse_all_referrers_index(
            wire,
            max_referrers=self.limits.max_referrers,
        )
        sigma = tuple(
            item
            for item in descriptors
            if item.artifact_type == SIGMA_ARTIFACT_REFERRER_TYPE
        )
        return OciReferrersResultV1(
            subject_digest,
            tuple(sorted(sigma, key=lambda item: item.digest)),
            OciReferrersSourceV1.TAG_FALLBACK,
            1,
        )

    def _next_referrers_link(
        self,
        response: HttpResponseV1,
    ) -> str | None:
        link = response.header("Link")
        if link is None:
            return None
        match = _LINK_NEXT_RE.search(link)
        if match is None:
            raise OciRegistryProtocolError(
                "OCI referrers Link header is not understood"
            )
        next_url = urllib.parse.urljoin(response.final_url, match.group(1))
        if _origin(next_url) != _origin(self.base_url):
            raise OciRegistryProtocolError(
                "OCI referrers pagination attempted cross-origin navigation"
            )
        return next_url

    def list_referrers(
        self,
        subject_digest: str,
    ) -> OciReferrersResultV1:
        _validate_digest(subject_digest)
        initial = self._api_url(
            "referrers/"
            + urllib.parse.quote(subject_digest, safe="-._~:+=")
        )
        url = _with_query(
            initial,
            artifactType=SIGMA_ARTIFACT_REFERRER_TYPE,
        )
        descriptors: dict[str, OciDescriptorV1] = {}
        pages = 0
        while True:
            pages += 1
            if pages > self.limits.max_pages:
                raise OciRegistryResourceLimitError(
                    "OCI referrers pagination exceeds configured page limit"
                )
            response = self._request(
                "GET",
                url,
                headers={"Accept": OCI_IMAGE_INDEX_MEDIA_TYPE},
            )
            if response.status == 404:
                if pages != 1:
                    raise OciRegistryProtocolError(
                        "OCI referrers pagination disappeared"
                    )
                return self._fallback_referrers(subject_digest)
            if response.status != 200:
                raise OciRegistryProtocolError(
                    f"OCI referrers GET returned HTTP {response.status}"
                )
            if len(response.body) > self.limits.max_referrers_bytes:
                raise OciRegistryResourceLimitError(
                    "OCI referrers response exceeds configured byte limit"
                )
            for item in parse_sigma_referrers_index_v1(response.body):
                previous = descriptors.get(item.digest)
                if previous is not None and previous != item:
                    raise OciRegistryConflictError(
                        "same OCI referrer digest has contradictory descriptors"
                    )
                descriptors[item.digest] = item
                if len(descriptors) > self.limits.max_referrers:
                    raise OciRegistryResourceLimitError(
                        "OCI referrer count exceeds configured limit"
                    )
            next_url = self._next_referrers_link(response)
            if next_url is None:
                break
            url = next_url
        return OciReferrersResultV1(
            subject_digest,
            tuple(sorted(descriptors.values(), key=lambda item: item.digest)),
            OciReferrersSourceV1.API,
            pages,
        )

    def _update_referrers_tag(
        self,
        subject_digest: str,
        descriptor: OciDescriptorV1,
    ) -> bool:
        tag = oci_referrers_tag_v1(subject_digest)
        try:
            wire, etag = self._get_manifest(
                tag,
                accept=OCI_IMAGE_INDEX_MEDIA_TYPE,
                max_bytes=self.limits.max_referrers_bytes,
            )
            existing = self._parse_all_referrers_index(
                wire,
                max_referrers=self.limits.max_referrers,
            )
            index_annotations = self._referrers_index_annotations(wire)
        except OciRegistryNotFoundError:
            existing = ()
            etag = None
            index_annotations = {}

        by_digest = {item.digest: item for item in existing}
        previous = by_digest.get(descriptor.digest)
        if previous is not None:
            if previous != descriptor:
                raise OciRegistryConflictError(
                    "referrers tag contains contradictory descriptor"
                )
            return False
        if len(existing) >= self.limits.max_referrers:
            raise OciRegistryResourceLimitError(
                "referrers fallback tag is full"
            )
        updated = (*existing, descriptor)
        updated_wire = self._build_referrers_index(
            updated,
            annotations=index_annotations,
        )
        if len(updated_wire) > self.limits.max_referrers_bytes:
            raise OciRegistryResourceLimitError(
                "updated referrers fallback exceeds byte limit"
            )
        self.put_manifest(
            updated_wire,
            media_type=OCI_IMAGE_INDEX_MEDIA_TYPE,
            reference=tag,
            conditional_etag=etag,
        )
        return True

    def attach_artifact(
        self,
        artifact: SigmaArtifactV1,
        *,
        subject: OciDescriptorV1,
        annotations: (
            Mapping[str, str] | tuple[tuple[str, str], ...] | None
        ) = None,
    ) -> OciAttachResultV1:
        binding = build_sigma_artifact_referrer_v1(
            artifact,
            subject=subject,
            annotations=annotations,
        )
        config_result = self.put_blob(OCI_EMPTY_CONFIG_BYTES)
        if config_result.digest != OCI_EMPTY_CONFIG_DIGEST:
            raise AssertionError("canonical OCI empty config digest drifted")
        payload_result = self.put_blob(binding.artifact_wire)
        if payload_result.digest != binding.payload_descriptor.digest:
            raise AssertionError("IX0 payload descriptor digest drifted")

        manifest_result = self.put_manifest(
            binding.manifest_wire,
            media_type=OCI_IMAGE_MANIFEST_MEDIA_TYPE,
            reference=binding.manifest_descriptor.digest,
            expected_subject_digest=subject.digest,
        )
        fallback_updated = False
        if not manifest_result.subject_acknowledged:
            fallback_updated = self._update_referrers_tag(
                subject.digest,
                binding.manifest_descriptor,
            )

        discovered = self.list_referrers(subject.digest)
        discovered_after_push = any(
            item.digest == binding.manifest_descriptor.digest
            for item in discovered.descriptors
        )
        if not discovered_after_push:
            raise OciRegistryProtocolError(
                "pushed Sigma referrer is not discoverable"
            )
        return OciAttachResultV1(
            binding=binding,
            config_reused=config_result.reused,
            payload_reused=payload_result.reused,
            subject_acknowledged=manifest_result.subject_acknowledged,
            fallback_tag_updated=fallback_updated,
            discovered_after_push=discovered_after_push,
        )

    @staticmethod
    def _payload_descriptor_from_referrer_manifest(
        manifest_wire: bytes,
    ) -> OciDescriptorV1:
        value = _json_object(
            manifest_wire,
            what="Sigma OCI referrer manifest",
        )
        layers = value.get("layers")
        if not isinstance(layers, list) or len(layers) != 1:
            raise OciRegistryProtocolError(
                "Sigma OCI referrer must contain one payload layer"
            )
        return OciDescriptorV1.from_dict(layers[0])

    def pull_referrer_by_digest(
        self,
        referrer_digest: str,
        *,
        expected_subject: OciDescriptorV1 | None = None,
        expected_artifact_id: bytes | None = None,
    ) -> OciSigmaArtifactBindingV1:
        _validate_digest(referrer_digest)
        manifest_wire, _ = self._get_manifest(
            referrer_digest,
            accept=OCI_IMAGE_MANIFEST_MEDIA_TYPE,
            max_bytes=self.limits.max_manifest_bytes,
        )
        if oci_sha256_digest_v1(manifest_wire) != referrer_digest:
            raise OciRegistryProtocolError(
                "referrer manifest digest mismatch"
            )
        payload_descriptor = self._payload_descriptor_from_referrer_manifest(
            manifest_wire
        )
        artifact_wire = self._get_blob(payload_descriptor)
        return verify_sigma_artifact_referrer_v1(
            manifest_wire,
            artifact_wire,
            expected_subject=expected_subject,
            expected_artifact_id=expected_artifact_id,
        )

    def pull_artifact(
        self,
        subject_digest: str,
        artifact_id: bytes,
    ) -> OciSigmaArtifactBindingV1:
        if not isinstance(artifact_id, bytes) or len(artifact_id) != 32:
            raise ValueError("artifact_id must contain exactly 32 bytes")
        refs = self.list_referrers(subject_digest)
        expected_hex = artifact_id.hex()
        matches = tuple(
            item
            for item in refs.descriptors
            if dict(item.annotations).get(SIGMA_ARTIFACT_ID_ANNOTATION)
            == expected_hex
        )
        if not matches:
            raise OciRegistryNotFoundError(
                "no Sigma referrer matches requested ArtifactId"
            )
        unique_digests = {item.digest for item in matches}
        if len(unique_digests) != 1:
            raise OciRegistryConflictError(
                "multiple Sigma referrers claim the same ArtifactId"
            )
        return self.pull_referrer_by_digest(
            matches[0].digest,
            expected_artifact_id=artifact_id,
        )


__all__ = [
    "DEFAULT_OCI_MAX_BLOB_BYTES",
    "DEFAULT_OCI_MAX_PAGES",
    "DEFAULT_OCI_MAX_REFERRERS",
    "DEFAULT_OCI_MAX_REFERRERS_BYTES",
    "DEFAULT_OCI_MAX_RETRIES",
    "BoundedUrllibOciTransportV1",
    "OciAttachResultV1",
    "OciBlobPutResultV1",
    "OciManifestPutResultV1",
    "OciReferrersResultV1",
    "OciReferrersSourceV1",
    "OciRegistryClientV1",
    "OciRegistryConflictError",
    "OciRegistryError",
    "OciRegistryLimitsV1",
    "OciRegistryNotFoundError",
    "OciRegistryProtocolError",
    "OciRegistryResourceLimitError",
    "OciRegistryTransportV1",
    "oci_referrers_tag_v1",
]
