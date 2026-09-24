"""Deterministic in-memory OCI Distribution fixtures for the IX0 gate."""

from __future__ import annotations

import hashlib
import json
import urllib.parse
from dataclasses import dataclass, field
from typing import Mapping

from sigma.artifact.remote_http import HttpResponseV1
from sigma.interop.oci import OCI_IMAGE_INDEX_MEDIA_TYPE, oci_sha256_digest_v1


def _headers(**values: str) -> tuple[tuple[str, str], ...]:
    return tuple((key.replace("_", "-"), value) for key, value in values.items())


def _strict_manifest_descriptor(wire: bytes, digest: str) -> dict[str, object]:
    value = json.loads(wire.decode("utf-8"))
    if not isinstance(value, dict):
        raise AssertionError("fixture manifest must be object")
    descriptor: dict[str, object] = {
        "mediaType": value.get(
            "mediaType",
            "application/vnd.oci.image.manifest.v1+json",
        ),
        "digest": digest,
        "size": len(wire),
    }
    artifact_type = value.get("artifactType")
    if isinstance(artifact_type, str):
        descriptor["artifactType"] = artifact_type
    annotations = value.get("annotations")
    if isinstance(annotations, dict):
        descriptor["annotations"] = dict(annotations)
    return descriptor


@dataclass
class GateOciRegistryTransport:
    """Small OCI registry model supporting both native and fallback referrers."""

    native_referrers: bool = True
    page_size: int | None = None
    cross_origin_upload: bool = False
    manifest_content_type_override: str | None = None
    referrers_content_type_override: str | None = None
    pagination_loop: bool = False
    lose_blob_completion_once: bool = False
    lose_conditional_manifest_once: bool = False
    retry_once: dict[tuple[str, str], int] = field(default_factory=dict)
    blobs: dict[str, bytes] = field(default_factory=dict)
    manifests: dict[str, bytes] = field(default_factory=dict)
    tags: dict[str, str] = field(default_factory=dict)
    referrers: dict[str, dict[str, dict[str, object]]] = field(default_factory=dict)
    requests: list[tuple[str, str, dict[str, str], bytes | None]] = field(
        default_factory=list
    )
    _upload_counter: int = 0
    _completed_uploads: set[str] = field(default_factory=set)
    _lost_blob_completion_emitted: bool = False
    _lost_conditional_manifest_emitted: bool = False

    def _response(
        self,
        status: int,
        url: str,
        *,
        headers: tuple[tuple[str, str], ...] = (),
        body: bytes = b"",
    ) -> HttpResponseV1:
        return HttpResponseV1(status, headers, body, url)

    def _maybe_retry(self, method: str, path: str, url: str) -> HttpResponseV1 | None:
        for (candidate_method, fragment), remaining in tuple(self.retry_once.items()):
            if candidate_method == method and fragment in path and remaining > 0:
                self.retry_once[(candidate_method, fragment)] = remaining - 1
                return self._response(503, url)
        return None

    @staticmethod
    def _manifest_reference(path: str) -> str | None:
        marker = "/manifests/"
        if marker not in path:
            return None
        return urllib.parse.unquote(path.split(marker, 1)[1])

    @staticmethod
    def _blob_digest(path: str) -> str | None:
        marker = "/blobs/"
        if marker not in path or "/uploads/" in path:
            return None
        return urllib.parse.unquote(path.split(marker, 1)[1])

    def _manifest_digest_for_reference(self, reference: str) -> str | None:
        if reference in self.manifests:
            return reference
        return self.tags.get(reference)

    def _get_manifest(
        self,
        reference: str,
        url: str,
    ) -> HttpResponseV1:
        digest = self._manifest_digest_for_reference(reference)
        if digest is None:
            return self._response(404, url)
        wire = self.manifests[digest]
        content_type = self.manifest_content_type_override
        if content_type is None:
            try:
                decoded = json.loads(wire.decode("utf-8"))
            except (UnicodeDecodeError, json.JSONDecodeError):
                decoded = None
            if isinstance(decoded, dict) and isinstance(
                decoded.get("mediaType"),
                str,
            ):
                content_type = str(decoded["mediaType"])
        response_headers = [
            ("Docker-Content-Digest", digest),
            ("Content-Length", str(len(wire))),
            ("ETag", f'"{digest}"'),
        ]
        if content_type is not None:
            response_headers.append(("Content-Type", content_type))
        return self._response(
            200,
            url,
            headers=tuple(response_headers),
            body=wire,
        )

    def _put_manifest(
        self,
        reference: str,
        url: str,
        headers: dict[str, str],
        body: bytes,
    ) -> HttpResponseV1:
        current_digest = self._manifest_digest_for_reference(reference)
        if_match = headers.get("If-Match")
        if if_match is not None:
            expected = None if current_digest is None else f'"{current_digest}"'
            if if_match != expected:
                return self._response(412, url)

        digest = oci_sha256_digest_v1(body)
        if ":" in reference and reference.startswith("sha256:") and reference != digest:
            return self._response(400, url)
        self.manifests[digest] = body
        if reference != digest:
            self.tags[reference] = digest

        subject_digest: str | None = None
        try:
            value = json.loads(body.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError):
            value = None
        if isinstance(value, dict):
            subject = value.get("subject")
            if isinstance(subject, dict) and isinstance(subject.get("digest"), str):
                subject_digest = str(subject["digest"])
                if self.native_referrers:
                    descriptor = _strict_manifest_descriptor(body, digest)
                    self.referrers.setdefault(subject_digest, {})[digest] = descriptor

        response_headers = [
            ("Docker-Content-Digest", digest),
            ("Location", url),
        ]
        if subject_digest is not None and self.native_referrers:
            response_headers.append(("OCI-Subject", subject_digest))
        if (
            self.lose_conditional_manifest_once
            and if_match is not None
            and not self._lost_conditional_manifest_emitted
        ):
            self._lost_conditional_manifest_emitted = True
            return self._response(503, url)
        return self._response(
            201,
            url,
            headers=tuple(response_headers),
        )

    def _get_referrers(
        self,
        path: str,
        query: dict[str, list[str]],
        url: str,
    ) -> HttpResponseV1:
        if not self.native_referrers:
            return self._response(404, url)
        marker = "/referrers/"
        subject_digest = urllib.parse.unquote(path.split(marker, 1)[1])
        values = list(self.referrers.get(subject_digest, {}).values())
        requested_type = query.get("artifactType", [None])[0]
        if requested_type is not None:
            values = [
                item
                for item in values
                if item.get("artifactType") == requested_type
            ]
        values.sort(key=lambda item: str(item["digest"]))

        page = int(query.get("page", ["1"])[0])
        if self.page_size is None:
            selected = values
            has_next = False
        else:
            start = (page - 1) * self.page_size
            end = start + self.page_size
            selected = values[start:end]
            has_next = end < len(values)

        wire = json.dumps(
            {
                "schemaVersion": 2,
                "mediaType": OCI_IMAGE_INDEX_MEDIA_TYPE,
                "manifests": selected,
            },
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
        response_headers: list[tuple[str, str]] = [
            (
                "Content-Type",
                (
                    OCI_IMAGE_INDEX_MEDIA_TYPE
                    if self.referrers_content_type_override is None
                    else self.referrers_content_type_override
                ),
            )
        ]
        if requested_type is not None:
            response_headers.append(("OCI-Filters-Applied", "artifactType"))
        if has_next:
            next_query = dict(query)
            next_query["page"] = [str(page + 1)]
            flat = []
            for key, entries in next_query.items():
                for entry in entries:
                    flat.append((key, entry))
            parsed = urllib.parse.urlsplit(url)
            next_url = urllib.parse.urlunsplit(
                (
                    parsed.scheme,
                    parsed.netloc,
                    parsed.path,
                    urllib.parse.urlencode(flat),
                    "",
                )
            )
            if self.pagination_loop:
                next_url = url
            response_headers.append(("Link", f'<{next_url}>; rel="next"'))
        return self._response(
            200,
            url,
            headers=tuple(response_headers),
            body=wire,
        )

    def request(
        self,
        method: str,
        url: str,
        *,
        headers: Mapping[str, str] | None = None,
        body: bytes | None = None,
        timeout: float = 30.0,
    ) -> HttpResponseV1:
        del timeout
        method = method.upper()
        normalized_headers = dict(headers or {})
        self.requests.append((method, url, normalized_headers, body))
        parsed = urllib.parse.urlsplit(url)
        path = parsed.path
        query = urllib.parse.parse_qs(parsed.query)

        retry = self._maybe_retry(method, path, url)
        if retry is not None:
            return retry

        if path == "/v2/" and method == "GET":
            return self._response(200, url)

        if "/referrers/" in path and method == "GET":
            return self._get_referrers(path, query, url)

        reference = self._manifest_reference(path)
        if reference is not None:
            if method == "GET":
                return self._get_manifest(reference, url)
            if method == "PUT":
                return self._put_manifest(
                    reference,
                    url,
                    normalized_headers,
                    b"" if body is None else body,
                )
            if method == "HEAD":
                response = self._get_manifest(reference, url)
                return self._response(
                    response.status,
                    url,
                    headers=response.headers,
                )

        digest = self._blob_digest(path)
        if digest is not None:
            if method == "HEAD":
                payload = self.blobs.get(digest)
                if payload is None:
                    return self._response(404, url)
                return self._response(
                    200,
                    url,
                    headers=_headers(
                        Docker_Content_Digest=digest,
                        Content_Length=str(len(payload)),
                    ),
                )
            if method == "GET":
                payload = self.blobs.get(digest)
                if payload is None:
                    return self._response(404, url)
                return self._response(
                    200,
                    url,
                    headers=_headers(
                        Docker_Content_Digest=digest,
                        Content_Length=str(len(payload)),
                    ),
                    body=payload,
                )

        if path.endswith("/blobs/uploads/") and method == "POST":
            self._upload_counter += 1
            origin = (
                "https://uploads.example"
                if self.cross_origin_upload
                else f"{parsed.scheme}://{parsed.netloc}"
            )
            location = f"{origin}/uploads/{self._upload_counter}"
            return self._response(
                202,
                url,
                headers=_headers(Location=location),
            )

        if path.startswith("/uploads/") and method == "PUT":
            if path in self._completed_uploads:
                return self._response(404, url)
            digest_values = query.get("digest")
            if not digest_values:
                return self._response(400, url)
            digest = digest_values[0]
            payload = b"" if body is None else body
            if oci_sha256_digest_v1(payload) != digest:
                return self._response(400, url)
            self.blobs[digest] = payload
            self._completed_uploads.add(path)
            if (
                self.lose_blob_completion_once
                and not self._lost_blob_completion_emitted
            ):
                self._lost_blob_completion_emitted = True
                return self._response(503, url)
            return self._response(
                201,
                url,
                headers=_headers(
                    Docker_Content_Digest=digest,
                    Location=self._blob_location(digest, parsed),
                ),
            )

        return self._response(404, url)

    @staticmethod
    def _blob_location(
        digest: str,
        parsed: urllib.parse.SplitResult,
    ) -> str:
        return f"{parsed.scheme}://{parsed.netloc}/v2/test/blobs/{digest}"


def make_subject_descriptor(
    payload: bytes,
    *,
    media_type: str = "application/vnd.oci.image.manifest.v1+json",
):
    from sigma.interop import OciDescriptorV1

    return OciDescriptorV1(
        media_type=media_type,
        digest="sha256:" + hashlib.sha256(payload).hexdigest(),
        size=len(payload),
    )


__all__ = [
    "GateOciRegistryTransport",
    "make_subject_descriptor",
]
