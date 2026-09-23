"""PX3 S3-compatible multipart remote backend.

The core has no boto3 dependency. S3CompatibleBackendV1 consumes S3ClientV1;
Boto3S3ClientAdapterV1 adapts an already-created boto3-compatible client.
"""

from __future__ import annotations

import base64
import hashlib
from dataclasses import dataclass
from typing import Any, Mapping, Protocol, runtime_checkable

from .remote import (
    RemoteBlobBackendV1,
    RemoteConflictError,
    RemoteIntegrityError,
    RemoteNotFoundError,
    RemoteObjectInfoV1,
    RemoteReadChunkV1,
    RemoteRetryableError,
    RemoteSessionExpiredError,
    RemoteStoreError,
    RemoteUploadSessionV1,
)

S3_MIN_MULTIPART_PART_SIZE = 5 * 1024 * 1024
S3_MAX_PARTS = 10_000


@dataclass(frozen=True)
class S3ObjectHeadV1:
    size: int
    etag: str | None
    metadata: tuple[tuple[str, str], ...] = ()

    def __post_init__(self) -> None:
        if isinstance(self.size, bool) or not isinstance(self.size, int) or self.size < 0:
            raise ValueError("S3 object size must be non-negative")
        if self.etag is not None and not isinstance(self.etag, str):
            raise TypeError("etag must be str or None")
        if (
            not isinstance(self.metadata, tuple)
            or tuple(sorted(set(self.metadata))) != self.metadata
            or any(
                not isinstance(key, str) or not isinstance(value, str)
                for key, value in self.metadata
            )
            or len({key for key, _ in self.metadata}) != len(self.metadata)
        ):
            raise ValueError("S3 metadata must be sorted unique-key str pairs")

    def metadata_dict(self) -> dict[str, str]:
        return dict(self.metadata)


@dataclass(frozen=True)
class S3RangeResultV1:
    data: bytes
    total_size: int
    etag: str | None
    metadata: tuple[tuple[str, str], ...] = ()

    def __post_init__(self) -> None:
        if not isinstance(self.data, bytes):
            raise TypeError("S3 range data must be bytes")
        if (
            isinstance(self.total_size, bool)
            or not isinstance(self.total_size, int)
            or self.total_size < len(self.data)
        ):
            raise ValueError("S3 total size is invalid")
        if (
            not isinstance(self.metadata, tuple)
            or tuple(sorted(set(self.metadata))) != self.metadata
            or any(
                not isinstance(key, str) or not isinstance(value, str)
                for key, value in self.metadata
            )
            or len({key for key, _ in self.metadata}) != len(self.metadata)
        ):
            raise ValueError("S3 range metadata must be sorted unique-key str pairs")

    def metadata_dict(self) -> dict[str, str]:
        return dict(self.metadata)


@dataclass(frozen=True)
class S3UploadedPartV1:
    part_number: int
    size: int
    etag: str
    checksum_sha256_b64: str | None = None

    def __post_init__(self) -> None:
        if (
            isinstance(self.part_number, bool)
            or not isinstance(self.part_number, int)
            or not 1 <= self.part_number <= S3_MAX_PARTS
        ):
            raise ValueError("S3 part_number is outside supported range")
        if isinstance(self.size, bool) or not isinstance(self.size, int) or self.size < 0:
            raise ValueError("S3 part size must be non-negative")
        if not isinstance(self.etag, str) or not self.etag:
            raise ValueError("S3 part ETag must be non-empty str")
        if self.checksum_sha256_b64 is not None and not isinstance(
            self.checksum_sha256_b64, str
        ):
            raise TypeError("S3 part checksum must be str or None")


@runtime_checkable
class S3ClientV1(Protocol):
    def head_object(self, bucket: str, key: str) -> S3ObjectHeadV1 | None:
        ...

    def get_object_range(
        self,
        bucket: str,
        key: str,
        *,
        start: int,
        end_exclusive: int,
    ) -> S3RangeResultV1:
        ...

    def create_multipart_upload(
        self,
        bucket: str,
        key: str,
        *,
        metadata: Mapping[str, str],
    ) -> str:
        ...

    def list_parts(
        self,
        bucket: str,
        key: str,
        upload_id: str,
    ) -> tuple[S3UploadedPartV1, ...]:
        ...

    def upload_part(
        self,
        bucket: str,
        key: str,
        upload_id: str,
        *,
        part_number: int,
        data: bytes,
        checksum_sha256_b64: str,
    ) -> S3UploadedPartV1:
        ...

    def complete_multipart_upload(
        self,
        bucket: str,
        key: str,
        upload_id: str,
        *,
        parts: tuple[S3UploadedPartV1, ...],
    ) -> S3ObjectHeadV1:
        ...

    def abort_multipart_upload(
        self,
        bucket: str,
        key: str,
        upload_id: str,
    ) -> None:
        ...


def _http_status_from_exception(exc: BaseException) -> int | None:
    response = getattr(exc, "response", None)
    if not isinstance(response, dict):
        return None
    metadata = response.get("ResponseMetadata")
    if isinstance(metadata, dict):
        status = metadata.get("HTTPStatusCode")
        if isinstance(status, int):
            return status
    return None


def _raise_boto_error(exc: BaseException, operation: str) -> None:
    status = _http_status_from_exception(exc)
    if status == 404:
        raise RemoteNotFoundError(f"{operation}: S3 object/session not found") from exc
    if status in (408, 425, 429) or (status is not None and 500 <= status <= 599):
        raise RemoteRetryableError(f"{operation}: retryable S3 HTTP {status}") from exc
    raise RemoteStoreError(f"{operation}: S3 client failure") from exc


class Boto3S3ClientAdapterV1(S3ClientV1):
    """Adapter over a boto3-compatible S3 client object."""

    def __init__(self, client: Any) -> None:
        self.client = client

    @staticmethod
    def _metadata(value: Any) -> tuple[tuple[str, str], ...]:
        if not isinstance(value, dict):
            return ()
        return tuple(sorted((str(k).lower(), str(v)) for k, v in value.items()))

    def head_object(self, bucket: str, key: str) -> S3ObjectHeadV1 | None:
        try:
            response = self.client.head_object(Bucket=bucket, Key=key)
        except Exception as exc:
            if _http_status_from_exception(exc) == 404:
                return None
            _raise_boto_error(exc, "HeadObject")
            raise AssertionError("unreachable")
        return S3ObjectHeadV1(
            size=int(response["ContentLength"]),
            etag=(None if response.get("ETag") is None else str(response["ETag"])),
            metadata=self._metadata(response.get("Metadata")),
        )

    def get_object_range(
        self,
        bucket: str,
        key: str,
        *,
        start: int,
        end_exclusive: int,
    ) -> S3RangeResultV1:
        try:
            response = self.client.get_object(
                Bucket=bucket,
                Key=key,
                Range=f"bytes={start}-{end_exclusive - 1}",
            )
            body = response["Body"]
            try:
                payload = body.read()
            finally:
                close = getattr(body, "close", None)
                if callable(close):
                    close()
        except Exception as exc:
            _raise_boto_error(exc, "GetObject")
            raise AssertionError("unreachable")
        content_range = response.get("ContentRange")
        if not isinstance(content_range, str) or "/" not in content_range:
            raise RemoteIntegrityError(
                "S3 ranged GetObject omitted ContentRange"
            )
        try:
            total_size = int(content_range.rsplit("/", 1)[-1])
        except ValueError as exc:
            raise RemoteIntegrityError(
                "S3 ranged GetObject ContentRange is invalid"
            ) from exc
        return S3RangeResultV1(
            data=bytes(payload),
            total_size=total_size,
            etag=(None if response.get("ETag") is None else str(response["ETag"])),
            metadata=self._metadata(response.get("Metadata")),
        )

    def create_multipart_upload(
        self,
        bucket: str,
        key: str,
        *,
        metadata: Mapping[str, str],
    ) -> str:
        try:
            response = self.client.create_multipart_upload(
                Bucket=bucket,
                Key=key,
                Metadata=dict(metadata),
                ChecksumAlgorithm="SHA256",
            )
        except Exception as exc:
            _raise_boto_error(exc, "CreateMultipartUpload")
            raise AssertionError("unreachable")
        upload_id = response.get("UploadId")
        if not isinstance(upload_id, str) or not upload_id:
            raise RemoteIntegrityError("S3 CreateMultipartUpload omitted UploadId")
        return upload_id

    def list_parts(
        self,
        bucket: str,
        key: str,
        upload_id: str,
    ) -> tuple[S3UploadedPartV1, ...]:
        marker = 0
        result: list[S3UploadedPartV1] = []
        while True:
            kwargs: dict[str, Any] = {
                "Bucket": bucket,
                "Key": key,
                "UploadId": upload_id,
            }
            if marker:
                kwargs["PartNumberMarker"] = marker
            try:
                response = self.client.list_parts(**kwargs)
            except Exception as exc:
                status = _http_status_from_exception(exc)
                if status in (404, 410):
                    raise RemoteSessionExpiredError(
                        "S3 multipart upload session expired"
                    ) from exc
                _raise_boto_error(exc, "ListParts")
                raise AssertionError("unreachable")
            parts = response.get("Parts", [])
            if not isinstance(parts, list):
                raise RemoteIntegrityError("S3 ListParts returned invalid Parts")
            for raw in parts:
                if not isinstance(raw, dict):
                    raise RemoteIntegrityError("S3 ListParts part is invalid")
                if len(result) >= S3_MAX_PARTS:
                    raise RemoteIntegrityError(
                        "S3 ListParts exceeds the 10,000-part protocol bound"
                    )
                result.append(
                    S3UploadedPartV1(
                        part_number=int(raw["PartNumber"]),
                        size=int(raw["Size"]),
                        etag=str(raw["ETag"]),
                        checksum_sha256_b64=(
                            None
                            if raw.get("ChecksumSHA256") is None
                            else str(raw["ChecksumSHA256"])
                        ),
                    )
                )
            if not response.get("IsTruncated"):
                break
            next_marker = response.get("NextPartNumberMarker")
            if not isinstance(next_marker, int) or next_marker <= marker:
                raise RemoteIntegrityError("S3 ListParts pagination did not progress")
            marker = next_marker
        return tuple(sorted(result, key=lambda part: part.part_number))

    def upload_part(
        self,
        bucket: str,
        key: str,
        upload_id: str,
        *,
        part_number: int,
        data: bytes,
        checksum_sha256_b64: str,
    ) -> S3UploadedPartV1:
        try:
            response = self.client.upload_part(
                Bucket=bucket,
                Key=key,
                UploadId=upload_id,
                PartNumber=part_number,
                Body=data,
                ChecksumSHA256=checksum_sha256_b64,
            )
        except Exception as exc:
            _raise_boto_error(exc, "UploadPart")
            raise AssertionError("unreachable")
        etag = response.get("ETag")
        if not isinstance(etag, str) or not etag:
            raise RemoteIntegrityError("S3 UploadPart omitted ETag")
        returned_checksum = response.get("ChecksumSHA256")
        if returned_checksum is not None and str(returned_checksum) != checksum_sha256_b64:
            raise RemoteIntegrityError("S3 UploadPart checksum response mismatch")
        return S3UploadedPartV1(
            part_number=part_number,
            size=len(data),
            etag=etag,
            checksum_sha256_b64=checksum_sha256_b64,
        )

    def complete_multipart_upload(
        self,
        bucket: str,
        key: str,
        upload_id: str,
        *,
        parts: tuple[S3UploadedPartV1, ...],
    ) -> S3ObjectHeadV1:
        request_parts: list[dict[str, Any]] = []
        for part in parts:
            item: dict[str, Any] = {
                "ETag": part.etag,
                "PartNumber": part.part_number,
            }
            if part.checksum_sha256_b64 is not None:
                item["ChecksumSHA256"] = part.checksum_sha256_b64
            request_parts.append(item)
        try:
            self.client.complete_multipart_upload(
                Bucket=bucket,
                Key=key,
                UploadId=upload_id,
                MultipartUpload={"Parts": request_parts},
            )
        except Exception as exc:
            _raise_boto_error(exc, "CompleteMultipartUpload")
            raise AssertionError("unreachable")
        head = self.head_object(bucket, key)
        if head is None:
            raise RemoteIntegrityError("S3 object missing after multipart completion")
        return head

    def abort_multipart_upload(
        self,
        bucket: str,
        key: str,
        upload_id: str,
    ) -> None:
        try:
            self.client.abort_multipart_upload(
                Bucket=bucket,
                Key=key,
                UploadId=upload_id,
            )
        except Exception as exc:
            if _http_status_from_exception(exc) == 404:
                return
            _raise_boto_error(exc, "AbortMultipartUpload")


def _wire_sha_from_metadata(metadata: Mapping[str, str]) -> bytes | None:
    value = metadata.get("sigma-wire-sha256")
    if value is None:
        return None
    try:
        raw = bytes.fromhex(value)
    except ValueError:
        return None
    return raw if len(raw) == 32 else None


class S3CompatibleBackendV1(RemoteBlobBackendV1):
    """S3 multipart backend with deterministic Sigma key prefix."""

    def __init__(
        self,
        client: S3ClientV1,
        bucket: str,
        *,
        prefix: str = "sigma",
        endpoint_identity: str = "s3-compatible",
        minimum_part_size: int = S3_MIN_MULTIPART_PART_SIZE,
    ) -> None:
        if not isinstance(client, S3ClientV1):
            raise TypeError("client must implement S3ClientV1")
        if not isinstance(bucket, str) or not bucket:
            raise ValueError("bucket must be non-empty str")
        if (
            not isinstance(prefix, str)
            or prefix.startswith("/")
            or prefix.endswith("/")
            or ".." in prefix.split("/")
        ):
            raise ValueError("S3 prefix is non-canonical")
        if not isinstance(endpoint_identity, str) or not endpoint_identity:
            raise ValueError("endpoint_identity must be non-empty public identifier")
        if (
            isinstance(minimum_part_size, bool)
            or not isinstance(minimum_part_size, int)
            or minimum_part_size < 1
        ):
            raise ValueError("minimum_part_size must be positive")
        self.client = client
        self.bucket = bucket
        self.prefix = prefix
        self.minimum_part_size = minimum_part_size
        public = f"{endpoint_identity}|{bucket}|{prefix}".encode("utf-8")
        self._fingerprint = f"s3-compatible-v1:{hashlib.sha256(public).hexdigest()}"

    @property
    def fingerprint(self) -> str:
        return self._fingerprint

    @property
    def read_only(self) -> bool:
        return False

    def _key(self, key: str) -> str:
        return f"{self.prefix}/{key}" if self.prefix else key

    def head(self, key: str) -> RemoteObjectInfoV1 | None:
        head = self.client.head_object(self.bucket, self._key(key))
        if head is None:
            return None
        metadata = head.metadata_dict()
        return RemoteObjectInfoV1(
            key=key,
            size=head.size,
            revision=head.etag,
            wire_sha256=_wire_sha_from_metadata(metadata),
            provider_locator=f"s3://{self.bucket}/{self._key(key)}",
        )

    def read_range(
        self,
        key: str,
        *,
        start: int,
        max_bytes: int,
    ) -> RemoteReadChunkV1:
        if start < 0 or max_bytes < 1:
            raise ValueError("invalid S3 range")
        head = self.head(key)
        if head is None:
            raise RemoteNotFoundError(f"S3 remote key not found: {key}")
        if start >= head.size:
            raise RemoteIntegrityError("S3 range starts beyond object size")
        end = min(head.size, start + max_bytes)
        response = self.client.get_object_range(
            self.bucket,
            self._key(key),
            start=start,
            end_exclusive=end,
        )
        if response.total_size != head.size or len(response.data) != end - start:
            raise RemoteIntegrityError("S3 ranged response geometry mismatch")
        if head.revision is not None and response.etag is not None and head.revision != response.etag:
            raise RemoteIntegrityError("S3 ETag changed during ranged read")
        range_wire_sha = _wire_sha_from_metadata(response.metadata_dict())
        if (
            head.wire_sha256 is not None
            and range_wire_sha is not None
            and head.wire_sha256 != range_wire_sha
        ):
            raise RemoteIntegrityError("S3 object metadata changed during ranged read")
        return RemoteReadChunkV1(
            key=key,
            start=start,
            data=response.data,
            total_size=head.size,
            revision=head.revision,
            wire_sha256=head.wire_sha256,
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
            raise ValueError("invalid S3 upload parameters")
        chunk_size = max(preferred_chunk_size, self.minimum_part_size)
        required_parts = max(1, (total_size + chunk_size - 1) // chunk_size)
        if required_parts > S3_MAX_PARTS:
            raise RemoteConflictError("S3 upload would exceed 10,000 parts")
        upload_id = self.client.create_multipart_upload(
            self.bucket,
            self._key(key),
            metadata={
                "sigma-wire-sha256": wire_sha256.hex(),
                "sigma-px3-key-sha256": hashlib.sha256(
                    key.encode("ascii")
                ).hexdigest(),
            },
        )
        return RemoteUploadSessionV1(
            backend_fingerprint=self.fingerprint,
            key=key,
            total_size=total_size,
            wire_sha256=wire_sha256,
            token=upload_id,
            accepted_offset=0,
            chunk_size=chunk_size,
            opaque=(("next_part", "1"),),
        )

    def _validate_session(self, session: RemoteUploadSessionV1) -> None:
        if session.backend_fingerprint != self.fingerprint:
            raise RemoteConflictError("upload session belongs to another S3 backend")

    def resume_upload(
        self,
        session: RemoteUploadSessionV1,
    ) -> RemoteUploadSessionV1:
        self._validate_session(session)
        parts = self.client.list_parts(
            self.bucket,
            self._key(session.key),
            session.token,
        )
        expected_number = 1
        offset = 0
        for part in parts:
            if part.part_number != expected_number:
                raise RemoteIntegrityError("S3 multipart parts are not contiguous")
            if part.size <= 0 or part.size > session.chunk_size:
                raise RemoteIntegrityError("S3 resumed part size is invalid")
            next_offset = offset + part.size
            if next_offset < session.total_size and part.size != session.chunk_size:
                raise RemoteIntegrityError(
                    "S3 resumed non-final part size differs from session chunk size"
                )
            offset = next_offset
            expected_number += 1
        if offset > session.total_size:
            raise RemoteIntegrityError("S3 resumed parts exceed object size")
        if len(parts) >= S3_MAX_PARTS and offset < session.total_size:
            raise RemoteConflictError("S3 multipart session exhausted part numbers")
        return RemoteUploadSessionV1(
            backend_fingerprint=session.backend_fingerprint,
            key=session.key,
            total_size=session.total_size,
            wire_sha256=session.wire_sha256,
            token=session.token,
            accepted_offset=offset,
            chunk_size=session.chunk_size,
            opaque=(("next_part", str(expected_number)),),
        )

    def upload_chunk(
        self,
        session: RemoteUploadSessionV1,
        data: bytes,
    ) -> RemoteUploadSessionV1:
        self._validate_session(session)
        if not isinstance(data, bytes) or not data:
            raise ValueError("S3 upload chunk must be non-empty bytes")
        if session.accepted_offset + len(data) > session.total_size:
            raise ValueError("S3 upload chunk exceeds object size")
        if (
            session.accepted_offset + len(data) < session.total_size
            and len(data) != session.chunk_size
        ):
            raise ValueError("non-final S3 part must equal session chunk size")
        opaque = session.opaque_dict()
        try:
            part_number = int(opaque["next_part"])
        except (KeyError, ValueError) as exc:
            raise RemoteIntegrityError("S3 upload session lacks next_part") from exc
        if not 1 <= part_number <= S3_MAX_PARTS:
            raise RemoteConflictError("S3 multipart part number exhausted")
        checksum = base64.b64encode(hashlib.sha256(data).digest()).decode("ascii")
        returned = self.client.upload_part(
            self.bucket,
            self._key(session.key),
            session.token,
            part_number=part_number,
            data=data,
            checksum_sha256_b64=checksum,
        )
        if (
            returned.part_number != part_number
            or returned.size != len(data)
            or (
                returned.checksum_sha256_b64 is not None
                and returned.checksum_sha256_b64 != checksum
            )
        ):
            raise RemoteIntegrityError("S3 uploaded part acknowledgement mismatch")
        return RemoteUploadSessionV1(
            backend_fingerprint=session.backend_fingerprint,
            key=session.key,
            total_size=session.total_size,
            wire_sha256=session.wire_sha256,
            token=session.token,
            accepted_offset=session.accepted_offset + len(data),
            chunk_size=session.chunk_size,
            opaque=(("next_part", str(part_number + 1)),),
        )

    def complete_upload(
        self,
        session: RemoteUploadSessionV1,
    ) -> RemoteObjectInfoV1:
        self._validate_session(session)
        if session.accepted_offset != session.total_size:
            raise RemoteConflictError("S3 multipart upload is incomplete")
        parts = self.client.list_parts(
            self.bucket,
            self._key(session.key),
            session.token,
        )
        if not parts and session.total_size:
            raise RemoteIntegrityError("S3 multipart upload has no parts")
        if sum(part.size for part in parts) != session.total_size:
            raise RemoteIntegrityError("S3 multipart part sizes do not match object")
        for expected_number, part in enumerate(parts, start=1):
            if part.part_number != expected_number:
                raise RemoteIntegrityError("S3 completion parts are not contiguous")
        head = self.client.complete_multipart_upload(
            self.bucket,
            self._key(session.key),
            session.token,
            parts=parts,
        )
        metadata = head.metadata_dict()
        if head.size != session.total_size:
            raise RemoteIntegrityError("S3 completed object size mismatch")
        metadata_wire = _wire_sha_from_metadata(metadata)
        if metadata_wire is not None and metadata_wire != session.wire_sha256:
            raise RemoteIntegrityError("S3 completed object metadata digest mismatch")
        info = self.head(session.key)
        if info is None:
            raise RemoteIntegrityError("S3 object disappeared after completion")
        return info

    def abort_upload(self, session: RemoteUploadSessionV1) -> None:
        self._validate_session(session)
        self.client.abort_multipart_upload(
            self.bucket,
            self._key(session.key),
            session.token,
        )


__all__ = [
    "Boto3S3ClientAdapterV1",
    "S3ClientV1",
    "S3CompatibleBackendV1",
    "S3ObjectHeadV1",
    "S3RangeResultV1",
    "S3UploadedPartV1",
    "S3_MAX_PARTS",
    "S3_MIN_MULTIPART_PART_SIZE",
]
