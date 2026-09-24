"""PX4 gateway runtime primitives: limits, cancellation, audit and responses."""

from __future__ import annotations

import json
import threading
import time
from dataclasses import dataclass
from enum import Enum
from pathlib import Path
from typing import Callable, Iterator, Protocol, runtime_checkable

from sigma.sources import CanonicalSource
from sigma.version import PACKAGE_VERSION

GATEWAY_PROTOCOL_VERSION = 1
GATEWAY_ERROR_SCHEMA = "sigma-gateway-error-v1"
GATEWAY_AUDIT_SCHEMA = "sigma-gateway-audit-v1"
GATEWAY_VERSION_SCHEMA = "sigma-gateway-version-v1"
GATEWAY_HEALTH_SCHEMA = "sigma-gateway-health-v1"

DEFAULT_GATEWAY_MAX_REQUEST_BYTES = (1 << 30) + (16 << 20)
DEFAULT_GATEWAY_MAX_METADATA_BYTES = 4 << 20
DEFAULT_GATEWAY_MAX_SOURCE_BYTES = 1 << 30
DEFAULT_GATEWAY_MAX_MEMORY_SPOOL_BYTES = 1 << 20
DEFAULT_GATEWAY_MAX_TOTAL_SPOOL_BYTES = 4 << 30
DEFAULT_GATEWAY_MAX_PROOF_VALUE_BYTES = 64 << 20
DEFAULT_GATEWAY_MAX_BATCH_ITEMS = 256
DEFAULT_GATEWAY_MAX_BATCH_TOTAL_SOURCE_BYTES = 1 << 30
DEFAULT_GATEWAY_MAX_CONCURRENT_REQUESTS = 16
DEFAULT_GATEWAY_MAX_HTTP_CONNECTIONS = 32
DEFAULT_GATEWAY_TIMEOUT_SECONDS = 120.0
DEFAULT_GATEWAY_READ_CHUNK_BYTES = 1 << 20
DEFAULT_GATEWAY_MAX_RESPONSE_BYTES = 32 << 20
DEFAULT_GATEWAY_MAX_HEADER_BYTES = 64 << 10
DEFAULT_GATEWAY_MAX_TRAJECTORY_ROUNDS = 1_000_064


class GatewayErrorCodeV1(str, Enum):
    BAD_REQUEST = "bad-request"
    METHOD_NOT_ALLOWED = "method-not-allowed"
    LENGTH_REQUIRED = "length-required"
    HEADER_TOO_LARGE = "header-too-large"
    UNSUPPORTED_MEDIA_TYPE = "unsupported-media-type"
    NOT_FOUND = "not-found"
    REQUEST_TOO_LARGE = "request-too-large"
    METADATA_TOO_LARGE = "metadata-too-large"
    SOURCE_TOO_LARGE = "source-too-large"
    POLICY_LIMIT = "policy-limit"
    MALFORMED_ARTIFACT = "malformed-artifact"
    MALFORMED_POLICY = "malformed-policy"
    MALFORMED_EVIDENCE = "malformed-evidence"
    MALFORMED_PROOF = "malformed-proof"
    ARTIFACT_ID_MISMATCH = "artifact-id-mismatch"
    TIMEOUT = "timeout"
    CANCELLED = "cancelled"
    BUSY = "busy"
    INTERNAL = "internal"


class GatewayError(RuntimeError):
    """Base error with stable HTTP/code projection."""

    status: int = 400
    code: GatewayErrorCodeV1 = GatewayErrorCodeV1.BAD_REQUEST
    safe_message: str = "request rejected"
    retryable: bool = False

    def __init__(
        self,
        message: str | None = None,
        *,
        status: int | None = None,
        code: GatewayErrorCodeV1 | None = None,
        safe_message: str | None = None,
        retryable: bool | None = None,
    ) -> None:
        super().__init__(message or safe_message or self.safe_message)
        if status is not None:
            self.status = status
        if code is not None:
            self.code = code
        if safe_message is not None:
            self.safe_message = safe_message
        if retryable is not None:
            self.retryable = retryable


class GatewayCancelledError(GatewayError):
    status = 409
    code = GatewayErrorCodeV1.CANCELLED
    safe_message = "request cancelled"


class GatewayTimeoutError(GatewayError):
    status = 408
    code = GatewayErrorCodeV1.TIMEOUT
    safe_message = "request deadline exceeded"
    retryable = True


class GatewayBusyError(GatewayError):
    status = 503
    code = GatewayErrorCodeV1.BUSY
    safe_message = "gateway concurrency limit reached"
    retryable = True


class GatewayRequestTooLargeError(GatewayError):
    status = 413
    code = GatewayErrorCodeV1.REQUEST_TOO_LARGE
    safe_message = "request body exceeds gateway limit"


class GatewaySourceTooLargeError(GatewayError):
    status = 413
    code = GatewayErrorCodeV1.SOURCE_TOO_LARGE
    safe_message = "source exceeds gateway limit"


class GatewayMetadataTooLargeError(GatewayError):
    status = 413
    code = GatewayErrorCodeV1.METADATA_TOO_LARGE
    safe_message = "request metadata exceeds gateway limit"


class GatewayNotFoundError(GatewayError):
    status = 404
    code = GatewayErrorCodeV1.NOT_FOUND
    safe_message = "resource not found"


def canonical_json_bytes(value: object) -> bytes:
    return (
        json.dumps(
            value,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
            allow_nan=False,
        )
        + "\n"
    ).encode("ascii")


@dataclass(frozen=True)
class GatewayLimitsV1:
    max_request_bytes: int = DEFAULT_GATEWAY_MAX_REQUEST_BYTES
    max_metadata_bytes: int = DEFAULT_GATEWAY_MAX_METADATA_BYTES
    max_source_bytes: int = DEFAULT_GATEWAY_MAX_SOURCE_BYTES
    max_memory_spool_bytes: int = DEFAULT_GATEWAY_MAX_MEMORY_SPOOL_BYTES
    max_total_spool_bytes: int = DEFAULT_GATEWAY_MAX_TOTAL_SPOOL_BYTES
    max_proof_value_bytes: int = DEFAULT_GATEWAY_MAX_PROOF_VALUE_BYTES
    max_batch_items: int = DEFAULT_GATEWAY_MAX_BATCH_ITEMS
    max_batch_total_source_bytes: int = DEFAULT_GATEWAY_MAX_BATCH_TOTAL_SOURCE_BYTES
    max_concurrent_requests: int = DEFAULT_GATEWAY_MAX_CONCURRENT_REQUESTS
    max_http_connections: int = DEFAULT_GATEWAY_MAX_HTTP_CONNECTIONS
    request_timeout_seconds: float = DEFAULT_GATEWAY_TIMEOUT_SECONDS
    read_chunk_bytes: int = DEFAULT_GATEWAY_READ_CHUNK_BYTES
    max_response_bytes: int = DEFAULT_GATEWAY_MAX_RESPONSE_BYTES
    max_header_bytes: int = DEFAULT_GATEWAY_MAX_HEADER_BYTES
    max_trajectory_rounds: int = DEFAULT_GATEWAY_MAX_TRAJECTORY_ROUNDS

    def __post_init__(self) -> None:
        integer_fields = (
            "max_request_bytes",
            "max_metadata_bytes",
            "max_source_bytes",
            "max_memory_spool_bytes",
            "max_total_spool_bytes",
            "max_proof_value_bytes",
            "max_batch_items",
            "max_batch_total_source_bytes",
            "max_concurrent_requests",
            "max_http_connections",
            "read_chunk_bytes",
            "max_response_bytes",
            "max_header_bytes",
            "max_trajectory_rounds",
        )
        for name in integer_fields:
            value = getattr(self, name)
            if isinstance(value, bool) or not isinstance(value, int) or value < 1:
                raise ValueError(f"{name} must be a positive integer")
        if self.max_memory_spool_bytes > self.max_source_bytes:
            raise ValueError("max_memory_spool_bytes exceeds max_source_bytes")
        if (
            isinstance(self.request_timeout_seconds, bool)
            or not isinstance(self.request_timeout_seconds, (int, float))
            or self.request_timeout_seconds <= 0
        ):
            raise ValueError("request_timeout_seconds must be positive")


class GatewayCancellationTokenV1:
    """Cooperative cancellation/deadline state local to one request."""

    def __init__(
        self,
        *,
        timeout_seconds: float | None = None,
        monotonic: Callable[[], float] = time.monotonic,
    ) -> None:
        self._event = threading.Event()
        self._monotonic = monotonic
        self._created = monotonic()
        self._deadline = (
            None
            if timeout_seconds is None
            else self._created + float(timeout_seconds)
        )

    @property
    def cancelled(self) -> bool:
        return self._event.is_set()

    @property
    def deadline(self) -> float | None:
        return self._deadline

    def cancel(self) -> None:
        self._event.set()

    def check(self) -> None:
        if self._event.is_set():
            raise GatewayCancelledError()
        if self._deadline is not None and self._monotonic() >= self._deadline:
            raise GatewayTimeoutError()


class CancellableSourceV1(CanonicalSource):
    """CanonicalSource decorator that checks request cancellation per replay chunk."""

    def __init__(
        self,
        source: CanonicalSource,
        token: GatewayCancellationTokenV1,
    ) -> None:
        if not isinstance(source, CanonicalSource):
            raise TypeError("source must be CanonicalSource")
        if not isinstance(token, GatewayCancellationTokenV1):
            raise TypeError("token must be GatewayCancellationTokenV1")
        self._source = source
        self._token = token

    @property
    def byte_length(self) -> int:
        self._token.check()
        return self._source.byte_length

    def iter_chunks(self, chunk_size: int) -> Iterator[bytes]:
        self._token.check()
        for chunk in self._source.iter_chunks(chunk_size):
            self._token.check()
            yield chunk
        self._token.check()

    def close(self) -> None:
        self._source.close()


@dataclass(frozen=True)
class GatewayResponseV1:
    status: int
    content_type: str
    body: bytes
    headers: tuple[tuple[str, str], ...] = ()

    def __post_init__(self) -> None:
        if (
            isinstance(self.status, bool)
            or not isinstance(self.status, int)
            or not 100 <= self.status <= 599
        ):
            raise ValueError("gateway HTTP status is invalid")
        if not isinstance(self.content_type, str) or not self.content_type:
            raise ValueError("gateway content_type must be non-empty str")
        if not isinstance(self.body, bytes):
            raise TypeError("gateway body must be bytes")
        if (
            not isinstance(self.headers, tuple)
            or tuple(sorted(set(self.headers))) != self.headers
            or any(
                not isinstance(key, str) or not isinstance(value, str)
                for key, value in self.headers
            )
            or len({key.lower() for key, _ in self.headers}) != len(self.headers)
        ):
            raise ValueError("gateway headers must be sorted unique-name str pairs")


def error_response_v1(error: GatewayError) -> GatewayResponseV1:
    if not isinstance(error, GatewayError):
        raise TypeError("error must be GatewayError")
    return GatewayResponseV1(
        error.status,
        "application/json",
        canonical_json_bytes(
            {
                "code": error.code.value,
                "message": error.safe_message,
                "retryable": error.retryable,
                "schema": GATEWAY_ERROR_SCHEMA,
            }
        ),
    )


@dataclass(frozen=True)
class GatewayAuditRecordV1:
    sequence: int
    method: str
    endpoint: str
    status: int
    error_code: str
    artifact_id_hex: str
    policy_id_hex: str
    decision: str
    bytes_in: int
    bytes_out: int
    elapsed_milliseconds: int
    timed_out: bool
    cancelled: bool

    def __post_init__(self) -> None:
        for name in ("sequence", "status", "bytes_in", "bytes_out", "elapsed_milliseconds"):
            value = getattr(self, name)
            if isinstance(value, bool) or not isinstance(value, int) or value < 0:
                raise ValueError(f"{name} must be a non-negative integer")
        for name in (
            "method",
            "endpoint",
            "error_code",
            "artifact_id_hex",
            "policy_id_hex",
            "decision",
        ):
            value = getattr(self, name)
            if not isinstance(value, str):
                raise TypeError(f"{name} must be str")
        if not isinstance(self.timed_out, bool) or not isinstance(self.cancelled, bool):
            raise TypeError("audit timeout/cancelled flags must be bool")

    def to_json_bytes(self) -> bytes:
        return canonical_json_bytes(
            {
                "artifact_id": self.artifact_id_hex,
                "bytes_in": self.bytes_in,
                "bytes_out": self.bytes_out,
                "cancelled": self.cancelled,
                "decision": self.decision,
                "elapsed_milliseconds": self.elapsed_milliseconds,
                "endpoint": self.endpoint,
                "error_code": self.error_code,
                "method": self.method,
                "policy_id": self.policy_id_hex,
                "schema": GATEWAY_AUDIT_SCHEMA,
                "sequence": self.sequence,
                "status": self.status,
                "timed_out": self.timed_out,
            }
        )


@runtime_checkable
class GatewayAuditSinkV1(Protocol):
    def emit(self, record: GatewayAuditRecordV1) -> None:
        ...


class NullGatewayAuditSinkV1:
    def emit(self, record: GatewayAuditRecordV1) -> None:
        if not isinstance(record, GatewayAuditRecordV1):
            raise TypeError("record must be GatewayAuditRecordV1")


class MemoryGatewayAuditSinkV1:
    def __init__(self) -> None:
        self.records: list[GatewayAuditRecordV1] = []
        self._lock = threading.Lock()

    def emit(self, record: GatewayAuditRecordV1) -> None:
        if not isinstance(record, GatewayAuditRecordV1):
            raise TypeError("record must be GatewayAuditRecordV1")
        with self._lock:
            self.records.append(record)


class JsonLinesGatewayAuditSinkV1:
    """Append-only JSONL audit sink containing only the fixed safe schema."""

    def __init__(self, path: str | Path) -> None:
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.Lock()

    def emit(self, record: GatewayAuditRecordV1) -> None:
        if not isinstance(record, GatewayAuditRecordV1):
            raise TypeError("record must be GatewayAuditRecordV1")
        payload = record.to_json_bytes()
        with self._lock:
            with self.path.open("ab") as handle:
                handle.write(payload)
                handle.flush()


def health_response_v1() -> GatewayResponseV1:
    return GatewayResponseV1(
        200,
        "application/json",
        canonical_json_bytes(
            {
                "schema": GATEWAY_HEALTH_SCHEMA,
                "status": "ok",
            }
        ),
    )


def version_response_v1() -> GatewayResponseV1:
    return GatewayResponseV1(
        200,
        "application/json",
        canonical_json_bytes(
            {
                "gateway_protocol_version": GATEWAY_PROTOCOL_VERSION,
                "package_version": PACKAGE_VERSION,
                "schema": GATEWAY_VERSION_SCHEMA,
            }
        ),
    )


__all__ = [
    "CancellableSourceV1",
    "GATEWAY_AUDIT_SCHEMA",
    "GATEWAY_ERROR_SCHEMA",
    "GATEWAY_HEALTH_SCHEMA",
    "GATEWAY_PROTOCOL_VERSION",
    "GATEWAY_VERSION_SCHEMA",
    "GatewayAuditRecordV1",
    "GatewayAuditSinkV1",
    "GatewayBusyError",
    "GatewayCancellationTokenV1",
    "GatewayCancelledError",
    "GatewayError",
    "GatewayErrorCodeV1",
    "GatewayLimitsV1",
    "GatewayMetadataTooLargeError",
    "GatewayNotFoundError",
    "GatewayRequestTooLargeError",
    "GatewayResponseV1",
    "GatewaySourceTooLargeError",
    "GatewayTimeoutError",
    "JsonLinesGatewayAuditSinkV1",
    "MemoryGatewayAuditSinkV1",
    "NullGatewayAuditSinkV1",
    "canonical_json_bytes",
    "error_response_v1",
    "health_response_v1",
    "version_response_v1",
]
