"""PX3 remote artifact transport, retry, resume and verified-cache core.

PX3 treats every remote system as an untrusted byte transport. ArtifactId and
canonical Sigma wires remain authoritative; remote URLs, ETags, credentials,
provider digests and cache state are operational metadata only.
"""

from __future__ import annotations

import contextlib
import hashlib
import json
import os
import tempfile
import time
from dataclasses import dataclass
from enum import IntEnum
from pathlib import Path
from typing import Callable, Protocol, TypeVar, runtime_checkable

from .record import SigmaArtifactV1
from .store import (
    ArtifactStoreIdentityError,
    LocalArtifactStoreV1,
    StorePutResultV1,
)

REMOTE_CHECKPOINT_VERSION = 1
DEFAULT_REMOTE_CHUNK_SIZE = 8 * 1024 * 1024
DEFAULT_REMOTE_MAX_OBJECT_BYTES = 64 * 1024 * 1024
DEFAULT_REMOTE_MAX_RETRIES = 4
REMOTE_ARTIFACT_PREFIX = "artifacts/v1"


class RemoteStoreError(RuntimeError):
    """Base PX3 remote-store failure."""


class RemoteRetryableError(RemoteStoreError):
    """Transient transport/provider failure eligible for bounded retry."""


class RemoteNotFoundError(RemoteStoreError):
    """Requested remote object does not exist."""


class RemoteConflictError(RemoteStoreError):
    """Remote key exists with bytes inconsistent with the requested object."""


class RemoteIntegrityError(RemoteStoreError):
    """Transferred bytes fail canonical/integrity validation."""


class RemoteReadOnlyError(RemoteStoreError):
    """A write operation was attempted against a read-only backend."""


class RemoteRangeUnsupportedError(RemoteStoreError):
    """Backend cannot honor a requested non-zero byte range."""


class RemoteCheckpointError(RemoteStoreError):
    """Resume checkpoint is malformed or does not match the requested transfer."""


class RemoteSessionExpiredError(RemoteStoreError):
    """Provider no longer recognizes a resumable upload session."""


class RemoteTransferDirectionV1(IntEnum):
    UPLOAD = 0x0001
    DOWNLOAD = 0x0002


class RemoteTransferSourceV1(IntEnum):
    LOCAL = 0x0001
    VERIFIED_CACHE = 0x0002
    REMOTE = 0x0003


@dataclass(frozen=True)
class RemoteTransferPolicyV1:
    chunk_size: int = DEFAULT_REMOTE_CHUNK_SIZE
    max_object_bytes: int = DEFAULT_REMOTE_MAX_OBJECT_BYTES
    max_retries: int = DEFAULT_REMOTE_MAX_RETRIES
    retry_backoff_seconds: float = 0.0
    fsync_each_chunk: bool = True
    verify_after_upload: bool = True

    def __post_init__(self) -> None:
        if (
            isinstance(self.chunk_size, bool)
            or not isinstance(self.chunk_size, int)
            or self.chunk_size < 1
        ):
            raise ValueError("chunk_size must be a positive integer")
        if (
            isinstance(self.max_object_bytes, bool)
            or not isinstance(self.max_object_bytes, int)
            or self.max_object_bytes < 1
        ):
            raise ValueError("max_object_bytes must be a positive integer")
        if (
            isinstance(self.max_retries, bool)
            or not isinstance(self.max_retries, int)
            or self.max_retries < 0
        ):
            raise ValueError("max_retries must be a non-negative integer")
        if (
            isinstance(self.retry_backoff_seconds, bool)
            or not isinstance(self.retry_backoff_seconds, (int, float))
            or self.retry_backoff_seconds < 0
        ):
            raise ValueError("retry_backoff_seconds must be non-negative")
        if not isinstance(self.fsync_each_chunk, bool):
            raise TypeError("fsync_each_chunk must be bool")
        if not isinstance(self.verify_after_upload, bool):
            raise TypeError("verify_after_upload must be bool")


@dataclass(frozen=True)
class RemoteObjectInfoV1:
    key: str
    size: int
    revision: str | None = None
    wire_sha256: bytes | None = None
    provider_locator: str | None = None

    def __post_init__(self) -> None:
        _validate_key(self.key)
        if isinstance(self.size, bool) or not isinstance(self.size, int) or self.size < 0:
            raise ValueError("remote object size must be a non-negative integer")
        if self.revision is not None and not isinstance(self.revision, str):
            raise TypeError("revision must be str or None")
        if self.wire_sha256 is not None and (
            not isinstance(self.wire_sha256, bytes) or len(self.wire_sha256) != 32
        ):
            raise ValueError("wire_sha256 must contain exactly 32 bytes")
        if self.provider_locator is not None and not isinstance(
            self.provider_locator, str
        ):
            raise TypeError("provider_locator must be str or None")


@dataclass(frozen=True)
class RemoteReadChunkV1:
    key: str
    start: int
    data: bytes
    total_size: int
    revision: str | None = None
    wire_sha256: bytes | None = None

    def __post_init__(self) -> None:
        _validate_key(self.key)
        if isinstance(self.start, bool) or not isinstance(self.start, int) or self.start < 0:
            raise ValueError("remote chunk start must be non-negative")
        if not isinstance(self.data, bytes):
            raise TypeError("remote chunk data must be bytes")
        if (
            isinstance(self.total_size, bool)
            or not isinstance(self.total_size, int)
            or self.total_size < 0
        ):
            raise ValueError("remote total_size must be non-negative")
        if self.start + len(self.data) > self.total_size:
            raise ValueError("remote chunk exceeds declared total size")
        if self.revision is not None and not isinstance(self.revision, str):
            raise TypeError("revision must be str or None")
        if self.wire_sha256 is not None and (
            not isinstance(self.wire_sha256, bytes) or len(self.wire_sha256) != 32
        ):
            raise ValueError("wire_sha256 must contain exactly 32 bytes")


@dataclass(frozen=True)
class RemoteUploadSessionV1:
    backend_fingerprint: str
    key: str
    total_size: int
    wire_sha256: bytes
    token: str
    accepted_offset: int = 0
    chunk_size: int = DEFAULT_REMOTE_CHUNK_SIZE
    opaque: tuple[tuple[str, str], ...] = ()

    def __post_init__(self) -> None:
        if not isinstance(self.backend_fingerprint, str) or not self.backend_fingerprint:
            raise ValueError("backend_fingerprint must be non-empty str")
        _validate_key(self.key)
        if (
            isinstance(self.total_size, bool)
            or not isinstance(self.total_size, int)
            or self.total_size < 0
        ):
            raise ValueError("total_size must be non-negative")
        if not isinstance(self.wire_sha256, bytes) or len(self.wire_sha256) != 32:
            raise ValueError("wire_sha256 must contain exactly 32 bytes")
        if not isinstance(self.token, str) or not self.token:
            raise ValueError("upload token must be non-empty str")
        if (
            isinstance(self.accepted_offset, bool)
            or not isinstance(self.accepted_offset, int)
            or not 0 <= self.accepted_offset <= self.total_size
        ):
            raise ValueError("accepted_offset is outside upload size")
        if (
            isinstance(self.chunk_size, bool)
            or not isinstance(self.chunk_size, int)
            or self.chunk_size < 1
        ):
            raise ValueError("chunk_size must be positive")
        if (
            not isinstance(self.opaque, tuple)
            or tuple(sorted(set(self.opaque))) != self.opaque
            or any(
                not isinstance(key, str) or not isinstance(value, str)
                for key, value in self.opaque
            )
            or len({key for key, _ in self.opaque}) != len(self.opaque)
        ):
            raise ValueError(
                "opaque upload state must be sorted unique-key str pairs"
            )

    def opaque_dict(self) -> dict[str, str]:
        return dict(self.opaque)


@dataclass(frozen=True)
class RemoteTransferResultV1:
    direction: RemoteTransferDirectionV1
    artifact_id: bytes
    key: str
    bytes_transferred: int
    resumed_from: int
    retry_count: int
    source: RemoteTransferSourceV1
    remote_revision: str | None = None
    remote_locator: str | None = None
    remote_reused: bool = False
    local_created: bool | None = None

    def __post_init__(self) -> None:
        if not isinstance(self.direction, RemoteTransferDirectionV1):
            raise TypeError("direction must be RemoteTransferDirectionV1")
        _validate_artifact_id(self.artifact_id)
        _validate_key(self.key)
        for name in ("bytes_transferred", "resumed_from", "retry_count"):
            value = getattr(self, name)
            if isinstance(value, bool) or not isinstance(value, int) or value < 0:
                raise ValueError(f"{name} must be a non-negative integer")
        if not isinstance(self.source, RemoteTransferSourceV1):
            raise TypeError("source must be RemoteTransferSourceV1")
        if not isinstance(self.remote_reused, bool):
            raise TypeError("remote_reused must be bool")
        if self.local_created is not None and not isinstance(self.local_created, bool):
            raise TypeError("local_created must be bool or None")


@runtime_checkable
class RemoteBlobBackendV1(Protocol):
    """Provider-neutral append/resume byte transport required by PX3."""

    @property
    def fingerprint(self) -> str:
        ...

    @property
    def read_only(self) -> bool:
        ...

    def head(self, key: str) -> RemoteObjectInfoV1 | None:
        ...

    def read_range(
        self,
        key: str,
        *,
        start: int,
        max_bytes: int,
    ) -> RemoteReadChunkV1:
        ...

    def begin_upload(
        self,
        key: str,
        *,
        total_size: int,
        wire_sha256: bytes,
        preferred_chunk_size: int,
    ) -> RemoteUploadSessionV1:
        ...

    def resume_upload(
        self,
        session: RemoteUploadSessionV1,
    ) -> RemoteUploadSessionV1:
        ...

    def upload_chunk(
        self,
        session: RemoteUploadSessionV1,
        data: bytes,
    ) -> RemoteUploadSessionV1:
        ...

    def complete_upload(
        self,
        session: RemoteUploadSessionV1,
    ) -> RemoteObjectInfoV1:
        ...

    def abort_upload(self, session: RemoteUploadSessionV1) -> None:
        ...


def _validate_artifact_id(value: bytes) -> bytes:
    if not isinstance(value, bytes) or len(value) != 32:
        raise ValueError("ArtifactId must contain exactly 32 bytes")
    return value


def _validate_key(value: str) -> str:
    if not isinstance(value, str) or not value:
        raise ValueError("remote object key must be non-empty str")
    if "\x00" in value or value.startswith("/") or ".." in value.split("/"):
        raise ValueError("remote object key is not canonical")
    try:
        value.encode("ascii", "strict")
    except UnicodeEncodeError as exc:
        raise ValueError("remote object key must be ASCII") from exc
    return value


def artifact_remote_key_v1(artifact_id: bytes) -> str:
    _validate_artifact_id(artifact_id)
    return f"{REMOTE_ARTIFACT_PREFIX}/{artifact_id.hex()}.sigart"


def artifact_from_remote_bytes_v1(
    payload: bytes,
    *,
    expected_artifact_id: bytes,
) -> SigmaArtifactV1:
    _validate_artifact_id(expected_artifact_id)
    if not isinstance(payload, bytes):
        raise TypeError("remote artifact payload must be bytes")
    try:
        artifact = SigmaArtifactV1.from_bytes(payload)
    except (TypeError, ValueError) as exc:
        raise RemoteIntegrityError("remote artifact wire is invalid") from exc
    if artifact.trajectory_audit is not None:
        raise RemoteIntegrityError(
            "remote ArtifactId object must be the canonical no-audit base envelope"
        )
    if artifact.artifact_id != expected_artifact_id:
        raise RemoteIntegrityError(
            "remote artifact canonical ArtifactId differs from requested key"
        )
    if artifact.to_bytes() != payload:
        raise RemoteIntegrityError("remote artifact wire is not canonical")
    return artifact


T = TypeVar("T")


class _RetryController:
    def __init__(
        self,
        policy: RemoteTransferPolicyV1,
        sleeper: Callable[[float], None],
    ) -> None:
        self.policy = policy
        self.sleeper = sleeper
        self.retry_count = 0

    def call(self, operation: Callable[[], T]) -> T:
        attempt = 0
        while True:
            try:
                return operation()
            except RemoteRetryableError:
                if attempt >= self.policy.max_retries:
                    raise
                attempt += 1
                self.retry_count += 1
                delay = float(self.policy.retry_backoff_seconds) * (2 ** (attempt - 1))
                if delay:
                    self.sleeper(delay)


def _atomic_write(path: Path, payload: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, temporary_name = tempfile.mkstemp(
        prefix=f".{path.name}.",
        suffix=".tmp",
        dir=path.parent,
    )
    temporary = Path(temporary_name)
    try:
        with os.fdopen(fd, "wb") as handle:
            handle.write(payload)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
        try:
            directory_fd = os.open(path.parent, os.O_RDONLY)
        except OSError:
            return
        try:
            with contextlib.suppress(OSError):
                os.fsync(directory_fd)
        finally:
            os.close(directory_fd)
    finally:
        with contextlib.suppress(FileNotFoundError):
            temporary.unlink()


def _checkpoint_json(data: dict[str, object]) -> bytes:
    return (
        json.dumps(
            data,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
        )
        + "\n"
    ).encode("ascii")


def _load_checkpoint(path: Path) -> dict[str, object]:
    try:
        payload = path.read_bytes()
    except FileNotFoundError as exc:
        raise RemoteCheckpointError(f"checkpoint does not exist: {path}") from exc
    try:
        value = json.loads(payload.decode("ascii"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise RemoteCheckpointError("remote checkpoint is not canonical JSON") from exc
    if not isinstance(value, dict):
        raise RemoteCheckpointError("remote checkpoint must be a JSON object")
    if _checkpoint_json(value) != payload:
        raise RemoteCheckpointError("remote checkpoint JSON is non-canonical")
    return value


@dataclass(frozen=True)
class RemoteUploadCheckpointV1:
    backend_fingerprint: str
    key: str
    artifact_id: bytes
    total_size: int
    wire_sha256: bytes
    session: RemoteUploadSessionV1

    def __post_init__(self) -> None:
        _validate_artifact_id(self.artifact_id)
        _validate_key(self.key)
        if self.session.backend_fingerprint != self.backend_fingerprint:
            raise ValueError("checkpoint/session backend mismatch")
        if self.session.key != self.key:
            raise ValueError("checkpoint/session key mismatch")
        if self.session.total_size != self.total_size:
            raise ValueError("checkpoint/session size mismatch")
        if self.session.wire_sha256 != self.wire_sha256:
            raise ValueError("checkpoint/session digest mismatch")

    def to_bytes(self) -> bytes:
        return _checkpoint_json(
            {
                "artifact_id": self.artifact_id.hex(),
                "backend_fingerprint": self.backend_fingerprint,
                "key": self.key,
                "schema": "sigma-px3-upload-checkpoint-v1",
                "session": {
                    "accepted_offset": self.session.accepted_offset,
                    "backend_fingerprint": self.session.backend_fingerprint,
                    "chunk_size": self.session.chunk_size,
                    "key": self.session.key,
                    "opaque": [list(item) for item in self.session.opaque],
                    "token": self.session.token,
                    "total_size": self.session.total_size,
                    "wire_sha256": self.session.wire_sha256.hex(),
                },
                "total_size": self.total_size,
                "version": REMOTE_CHECKPOINT_VERSION,
                "wire_sha256": self.wire_sha256.hex(),
            }
        )

    @classmethod
    def from_bytes(cls, payload: bytes) -> "RemoteUploadCheckpointV1":
        if not isinstance(payload, bytes):
            raise TypeError("upload checkpoint payload must be bytes")
        try:
            data = json.loads(payload.decode("ascii"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise RemoteCheckpointError("invalid upload checkpoint JSON") from exc
        if not isinstance(data, dict) or _checkpoint_json(data) != payload:
            raise RemoteCheckpointError("upload checkpoint must be canonical JSON")
        if (
            data.get("schema") != "sigma-px3-upload-checkpoint-v1"
            or data.get("version") != REMOTE_CHECKPOINT_VERSION
            or not isinstance(data.get("session"), dict)
        ):
            raise RemoteCheckpointError("unsupported upload checkpoint")
        session_data = data["session"]
        try:
            opaque_raw = session_data["opaque"]
            if not isinstance(opaque_raw, list):
                raise TypeError
            opaque = tuple(
                sorted(
                    (str(item[0]), str(item[1]))
                    for item in opaque_raw
                    if isinstance(item, list) and len(item) == 2
                )
            )
            if len(opaque) != len(opaque_raw):
                raise TypeError
            session = RemoteUploadSessionV1(
                backend_fingerprint=str(session_data["backend_fingerprint"]),
                key=str(session_data["key"]),
                total_size=int(session_data["total_size"]),
                wire_sha256=bytes.fromhex(str(session_data["wire_sha256"])),
                token=str(session_data["token"]),
                accepted_offset=int(session_data["accepted_offset"]),
                chunk_size=int(session_data["chunk_size"]),
                opaque=opaque,
            )
            return cls(
                backend_fingerprint=str(data["backend_fingerprint"]),
                key=str(data["key"]),
                artifact_id=bytes.fromhex(str(data["artifact_id"])),
                total_size=int(data["total_size"]),
                wire_sha256=bytes.fromhex(str(data["wire_sha256"])),
                session=session,
            )
        except (KeyError, TypeError, ValueError) as exc:
            raise RemoteCheckpointError("invalid upload checkpoint fields") from exc


@dataclass(frozen=True)
class RemoteDownloadCheckpointV1:
    backend_fingerprint: str
    key: str
    artifact_id: bytes
    total_size: int
    accepted_offset: int
    remote_revision: str | None
    remote_wire_sha256: bytes | None

    def __post_init__(self) -> None:
        _validate_artifact_id(self.artifact_id)
        _validate_key(self.key)
        if (
            isinstance(self.total_size, bool)
            or not isinstance(self.total_size, int)
            or self.total_size < 0
        ):
            raise ValueError("download total_size must be non-negative")
        if (
            isinstance(self.accepted_offset, bool)
            or not isinstance(self.accepted_offset, int)
            or not 0 <= self.accepted_offset <= self.total_size
        ):
            raise ValueError("download accepted_offset is outside size")
        if self.remote_wire_sha256 is not None and len(self.remote_wire_sha256) != 32:
            raise ValueError("remote_wire_sha256 must contain 32 bytes")

    def to_bytes(self) -> bytes:
        return _checkpoint_json(
            {
                "accepted_offset": self.accepted_offset,
                "artifact_id": self.artifact_id.hex(),
                "backend_fingerprint": self.backend_fingerprint,
                "key": self.key,
                "remote_revision": self.remote_revision,
                "remote_wire_sha256": (
                    None
                    if self.remote_wire_sha256 is None
                    else self.remote_wire_sha256.hex()
                ),
                "schema": "sigma-px3-download-checkpoint-v1",
                "total_size": self.total_size,
                "version": REMOTE_CHECKPOINT_VERSION,
            }
        )

    @classmethod
    def from_bytes(cls, payload: bytes) -> "RemoteDownloadCheckpointV1":
        if not isinstance(payload, bytes):
            raise TypeError("download checkpoint payload must be bytes")
        try:
            data = json.loads(payload.decode("ascii"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise RemoteCheckpointError("invalid download checkpoint JSON") from exc
        if (
            not isinstance(data, dict)
            or _checkpoint_json(data) != payload
            or data.get("schema") != "sigma-px3-download-checkpoint-v1"
            or data.get("version") != REMOTE_CHECKPOINT_VERSION
        ):
            raise RemoteCheckpointError("unsupported/non-canonical download checkpoint")
        try:
            remote_wire = data["remote_wire_sha256"]
            return cls(
                backend_fingerprint=str(data["backend_fingerprint"]),
                key=str(data["key"]),
                artifact_id=bytes.fromhex(str(data["artifact_id"])),
                total_size=int(data["total_size"]),
                accepted_offset=int(data["accepted_offset"]),
                remote_revision=(
                    None
                    if data["remote_revision"] is None
                    else str(data["remote_revision"])
                ),
                remote_wire_sha256=(
                    None if remote_wire is None else bytes.fromhex(str(remote_wire))
                ),
            )
        except (KeyError, TypeError, ValueError) as exc:
            raise RemoteCheckpointError("invalid download checkpoint fields") from exc


class VerifiedRemoteArtifactCacheV1:
    """Disposable verified-wire cache. Cache presence never establishes identity."""

    def __init__(self, root: str | os.PathLike[str]) -> None:
        self.root = Path(root)
        self.root.mkdir(parents=True, exist_ok=True)

    def _path(self, artifact_id: bytes) -> Path:
        _validate_artifact_id(artifact_id)
        value = artifact_id.hex()
        return self.root / value[:2] / f"{value[2:]}.sigart"

    def get(self, artifact_id: bytes) -> bytes | None:
        path = self._path(artifact_id)
        try:
            payload = path.read_bytes()
        except FileNotFoundError:
            return None
        try:
            artifact_from_remote_bytes_v1(
                payload,
                expected_artifact_id=artifact_id,
            )
        except RemoteIntegrityError:
            with contextlib.suppress(OSError):
                path.unlink(missing_ok=True)
            return None
        return payload

    def put(self, artifact_id: bytes, payload: bytes) -> None:
        artifact_from_remote_bytes_v1(
            payload,
            expected_artifact_id=artifact_id,
        )
        _atomic_write(self._path(artifact_id), payload)

    def evict(self, artifact_id: bytes) -> bool:
        path = self._path(artifact_id)
        existed = path.exists()
        with contextlib.suppress(OSError):
            path.unlink(missing_ok=True)
        return existed


class RemoteArtifactRepositoryV1:
    """Verified ArtifactId transport between a PX1 store and one remote backend."""

    def __init__(
        self,
        local_store: LocalArtifactStoreV1,
        backend: RemoteBlobBackendV1,
        *,
        policy: RemoteTransferPolicyV1 | None = None,
        cache: VerifiedRemoteArtifactCacheV1 | None = None,
        sleeper: Callable[[float], None] = time.sleep,
    ) -> None:
        if not isinstance(local_store, LocalArtifactStoreV1):
            raise TypeError("local_store must be LocalArtifactStoreV1")
        if not isinstance(backend, RemoteBlobBackendV1):
            raise TypeError("backend must implement RemoteBlobBackendV1")
        if cache is not None and not isinstance(cache, VerifiedRemoteArtifactCacheV1):
            raise TypeError("cache must be VerifiedRemoteArtifactCacheV1 or None")
        self.local_store = local_store
        self.backend = backend
        self.policy = RemoteTransferPolicyV1() if policy is None else policy
        if not isinstance(self.policy, RemoteTransferPolicyV1):
            raise TypeError("policy must be RemoteTransferPolicyV1")
        self.cache = cache
        self._sleeper = sleeper

    def _head(
        self,
        key: str,
        retry: _RetryController,
    ) -> RemoteObjectInfoV1 | None:
        return retry.call(lambda: self.backend.head(key))

    def _validate_info_size(self, info: RemoteObjectInfoV1) -> None:
        if info.size > self.policy.max_object_bytes:
            raise RemoteIntegrityError(
                "remote object exceeds configured max_object_bytes before download"
            )

    def _download_complete(
        self,
        artifact_id: bytes,
        key: str,
        retry: _RetryController,
    ) -> tuple[bytes, RemoteObjectInfoV1, int]:
        info = self._head(key, retry)
        if info is None:
            raise RemoteNotFoundError(f"remote artifact not found: {artifact_id.hex()}")
        self._validate_info_size(info)
        offset = 0
        output = bytearray()
        observed_revision = info.revision
        observed_wire_sha = info.wire_sha256
        while offset < info.size:
            chunk = retry.call(
                lambda offset=offset: self.backend.read_range(
                    key,
                    start=offset,
                    max_bytes=min(self.policy.chunk_size, info.size - offset),
                )
            )
            if chunk.key != key or chunk.start != offset or chunk.total_size != info.size:
                raise RemoteIntegrityError("remote range response geometry mismatch")
            if not chunk.data and offset != info.size:
                raise RemoteIntegrityError("remote range response made no progress")
            if (
                observed_revision is not None
                and chunk.revision is not None
                and chunk.revision != observed_revision
            ):
                raise RemoteIntegrityError("remote object revision changed during download")
            if (
                observed_wire_sha is not None
                and chunk.wire_sha256 is not None
                and chunk.wire_sha256 != observed_wire_sha
            ):
                raise RemoteIntegrityError("remote provider digest changed during download")
            output.extend(chunk.data)
            offset += len(chunk.data)
        payload = bytes(output)
        actual_sha = hashlib.sha256(payload).digest()
        if observed_wire_sha is not None and actual_sha != observed_wire_sha:
            raise RemoteIntegrityError("remote provider digest differs from downloaded bytes")
        artifact_from_remote_bytes_v1(
            payload,
            expected_artifact_id=artifact_id,
        )
        return payload, info, len(payload)

    def push_artifact(
        self,
        artifact_id: bytes,
        *,
        checkpoint_path: str | os.PathLike[str] | None = None,
    ) -> RemoteTransferResultV1:
        _validate_artifact_id(artifact_id)
        if self.backend.read_only:
            raise RemoteReadOnlyError("remote backend is read-only")
        payload = self.local_store.get_artifact_bytes(artifact_id)
        artifact_from_remote_bytes_v1(
            payload,
            expected_artifact_id=artifact_id,
        )
        if len(payload) > self.policy.max_object_bytes:
            raise RemoteIntegrityError(
                "local artifact exceeds configured remote max_object_bytes"
            )
        key = artifact_remote_key_v1(artifact_id)
        wire_sha256 = hashlib.sha256(payload).digest()
        retry = _RetryController(self.policy, self._sleeper)

        existing = self._head(key, retry)
        if existing is not None:
            self._validate_info_size(existing)
            remote_payload, verified_info, transferred = self._download_complete(
                artifact_id,
                key,
                retry,
            )
            if remote_payload != payload:
                raise RemoteConflictError(
                    "remote ArtifactId key contains different canonical bytes"
                )
            return RemoteTransferResultV1(
                direction=RemoteTransferDirectionV1.UPLOAD,
                artifact_id=artifact_id,
                key=key,
                bytes_transferred=transferred,
                resumed_from=0,
                retry_count=retry.retry_count,
                source=RemoteTransferSourceV1.LOCAL,
                remote_revision=verified_info.revision,
                remote_locator=verified_info.provider_locator,
                remote_reused=True,
                local_created=None,
            )

        checkpoint = Path(checkpoint_path) if checkpoint_path is not None else None
        session: RemoteUploadSessionV1
        resumed_from = 0

        if checkpoint is not None and checkpoint.exists():
            record = RemoteUploadCheckpointV1.from_bytes(checkpoint.read_bytes())
            if (
                record.backend_fingerprint != self.backend.fingerprint
                or record.key != key
                or record.artifact_id != artifact_id
                or record.total_size != len(payload)
                or record.wire_sha256 != wire_sha256
            ):
                raise RemoteCheckpointError(
                    "upload checkpoint does not match requested artifact/backend"
                )
            try:
                session = retry.call(
                    lambda: self.backend.resume_upload(record.session)
                )
            except RemoteSessionExpiredError:
                checkpoint.unlink(missing_ok=True)
                session = retry.call(
                    lambda: self.backend.begin_upload(
                        key,
                        total_size=len(payload),
                        wire_sha256=wire_sha256,
                        preferred_chunk_size=self.policy.chunk_size,
                    )
                )
                resumed_from = 0
            else:
                if (
                    session.backend_fingerprint != self.backend.fingerprint
                    or session.key != key
                    or session.total_size != len(payload)
                    or session.wire_sha256 != wire_sha256
                ):
                    raise RemoteCheckpointError(
                        "provider resumed a session with incompatible identity"
                    )
                resumed_from = session.accepted_offset
        else:
            session = retry.call(
                lambda: self.backend.begin_upload(
                    key,
                    total_size=len(payload),
                    wire_sha256=wire_sha256,
                    preferred_chunk_size=self.policy.chunk_size,
                )
            )
            if session.accepted_offset != 0:
                raise RemoteCheckpointError("new remote upload session did not start at zero")

        def save_session(current: RemoteUploadSessionV1) -> None:
            if checkpoint is None:
                return
            _atomic_write(
                checkpoint,
                RemoteUploadCheckpointV1(
                    backend_fingerprint=self.backend.fingerprint,
                    key=key,
                    artifact_id=artifact_id,
                    total_size=len(payload),
                    wire_sha256=wire_sha256,
                    session=current,
                ).to_bytes(),
            )

        save_session(session)
        while session.accepted_offset < len(payload):
            start = session.accepted_offset
            effective_chunk = min(
                max(self.policy.chunk_size, session.chunk_size),
                len(payload) - start,
            )
            data = payload[start : start + effective_chunk]
            previous_offset = start
            session = retry.call(
                lambda session=session, data=data: self.backend.upload_chunk(
                    session,
                    data,
                )
            )
            if not previous_offset < session.accepted_offset <= len(payload):
                raise RemoteIntegrityError(
                    "remote upload session returned invalid progress"
                )
            save_session(session)

        info = retry.call(lambda: self.backend.complete_upload(session))
        if info.key != key or info.size != len(payload):
            raise RemoteIntegrityError("completed remote object metadata mismatch")
        if info.wire_sha256 is not None and info.wire_sha256 != wire_sha256:
            raise RemoteIntegrityError("completed remote provider digest mismatch")

        transferred = len(payload) - resumed_from
        verified_info = info
        if self.policy.verify_after_upload:
            remote_payload, verified_info, post_verify_bytes = self._download_complete(
                artifact_id,
                key,
                retry,
            )
            transferred += post_verify_bytes
            if remote_payload != payload:
                raise RemoteIntegrityError(
                    "post-upload remote bytes differ from local canonical artifact"
                )

        if checkpoint is not None:
            with contextlib.suppress(FileNotFoundError):
                checkpoint.unlink()
        return RemoteTransferResultV1(
            direction=RemoteTransferDirectionV1.UPLOAD,
            artifact_id=artifact_id,
            key=key,
            bytes_transferred=transferred,
            resumed_from=resumed_from,
            retry_count=retry.retry_count,
            source=RemoteTransferSourceV1.LOCAL,
            remote_revision=verified_info.revision,
            remote_locator=verified_info.provider_locator,
            remote_reused=False,
            local_created=None,
        )

    def pull_artifact(
        self,
        artifact_id: bytes,
        *,
        checkpoint_path: str | os.PathLike[str] | None = None,
        partial_path: str | os.PathLike[str] | None = None,
        use_cache: bool = True,
    ) -> RemoteTransferResultV1:
        _validate_artifact_id(artifact_id)
        key = artifact_remote_key_v1(artifact_id)

        if self.local_store.has_artifact(artifact_id):
            self.local_store.get_artifact_bytes(artifact_id)
            return RemoteTransferResultV1(
                direction=RemoteTransferDirectionV1.DOWNLOAD,
                artifact_id=artifact_id,
                key=key,
                bytes_transferred=0,
                resumed_from=0,
                retry_count=0,
                source=RemoteTransferSourceV1.LOCAL,
                local_created=False,
            )

        if use_cache and self.cache is not None:
            cached = self.cache.get(artifact_id)
            if cached is not None:
                result = self.local_store.put_artifact_bytes(
                    cached,
                    expected_artifact_id=artifact_id,
                )
                return RemoteTransferResultV1(
                    direction=RemoteTransferDirectionV1.DOWNLOAD,
                    artifact_id=artifact_id,
                    key=key,
                    bytes_transferred=0,
                    resumed_from=0,
                    retry_count=0,
                    source=RemoteTransferSourceV1.VERIFIED_CACHE,
                    local_created=result.created,
                )

        retry = _RetryController(self.policy, self._sleeper)
        info = self._head(key, retry)
        if info is None:
            raise RemoteNotFoundError(f"remote artifact not found: {artifact_id.hex()}")
        self._validate_info_size(info)

        checkpoint = Path(checkpoint_path) if checkpoint_path is not None else None
        if partial_path is None:
            if checkpoint is None:
                fd, generated = tempfile.mkstemp(prefix="sigma-px3-", suffix=".part")
                os.close(fd)
                partial = Path(generated)
                ephemeral_partial = True
            else:
                partial = checkpoint.with_suffix(checkpoint.suffix + ".part")
                ephemeral_partial = False
        else:
            partial = Path(partial_path)
            ephemeral_partial = False

        resumed_from = 0
        try:
            offset = 0
            if checkpoint is not None and checkpoint.exists():
                record = RemoteDownloadCheckpointV1.from_bytes(
                    checkpoint.read_bytes()
                )
                matches = (
                    record.backend_fingerprint == self.backend.fingerprint
                    and record.key == key
                    and record.artifact_id == artifact_id
                    and record.total_size == info.size
                    and (
                        record.remote_revision is None
                        or info.revision is None
                        or record.remote_revision == info.revision
                    )
                    and (
                        record.remote_wire_sha256 is None
                        or info.wire_sha256 is None
                        or record.remote_wire_sha256 == info.wire_sha256
                    )
                )
                if matches and partial.exists():
                    actual_size = partial.stat().st_size
                    if actual_size == record.accepted_offset:
                        offset = actual_size
                        resumed_from = offset
                    else:
                        partial.unlink(missing_ok=True)
                        checkpoint.unlink(missing_ok=True)
                else:
                    partial.unlink(missing_ok=True)
                    checkpoint.unlink(missing_ok=True)

            partial.parent.mkdir(parents=True, exist_ok=True)
            mode = "ab" if offset else "wb"
            with partial.open(mode) as handle:
                while offset < info.size:
                    request_size = min(self.policy.chunk_size, info.size - offset)
                    try:
                        chunk = retry.call(
                            lambda offset=offset, request_size=request_size: (
                                self.backend.read_range(
                                    key,
                                    start=offset,
                                    max_bytes=request_size,
                                )
                            )
                        )
                    except RemoteRangeUnsupportedError:
                        if offset == 0:
                            raise
                        handle.close()
                        partial.unlink(missing_ok=True)
                        if checkpoint is not None:
                            checkpoint.unlink(missing_ok=True)
                        return self.pull_artifact(
                            artifact_id,
                            checkpoint_path=checkpoint_path,
                            partial_path=partial_path,
                            use_cache=False,
                        )

                    if (
                        chunk.key != key
                        or chunk.start != offset
                        or chunk.total_size != info.size
                    ):
                        raise RemoteIntegrityError(
                            "remote ranged-download geometry mismatch"
                        )
                    if not chunk.data:
                        raise RemoteIntegrityError(
                            "remote ranged download made no progress"
                        )
                    if (
                        info.revision is not None
                        and chunk.revision is not None
                        and info.revision != chunk.revision
                    ):
                        raise RemoteIntegrityError(
                            "remote object revision changed during resumed download"
                        )
                    if (
                        info.wire_sha256 is not None
                        and chunk.wire_sha256 is not None
                        and info.wire_sha256 != chunk.wire_sha256
                    ):
                        raise RemoteIntegrityError(
                            "remote provider digest changed during resumed download"
                        )
                    handle.write(chunk.data)
                    handle.flush()
                    if self.policy.fsync_each_chunk:
                        os.fsync(handle.fileno())
                    offset += len(chunk.data)
                    if checkpoint is not None:
                        _atomic_write(
                            checkpoint,
                            RemoteDownloadCheckpointV1(
                                backend_fingerprint=self.backend.fingerprint,
                                key=key,
                                artifact_id=artifact_id,
                                total_size=info.size,
                                accepted_offset=offset,
                                remote_revision=info.revision,
                                remote_wire_sha256=info.wire_sha256,
                            ).to_bytes(),
                        )

            payload = partial.read_bytes()
            if len(payload) != info.size:
                raise RemoteIntegrityError(
                    "resumed download size differs from remote object metadata"
                )
            actual_sha = hashlib.sha256(payload).digest()
            if info.wire_sha256 is not None and actual_sha != info.wire_sha256:
                raise RemoteIntegrityError(
                    "resumed download provider digest mismatch"
                )
            artifact_from_remote_bytes_v1(
                payload,
                expected_artifact_id=artifact_id,
            )

            # Publication into PX1 happens only after complete canonical validation.
            local_result: StorePutResultV1 = self.local_store.put_artifact_bytes(
                payload,
                expected_artifact_id=artifact_id,
            )
            if self.cache is not None:
                self.cache.put(artifact_id, payload)
            if checkpoint is not None:
                checkpoint.unlink(missing_ok=True)
            partial.unlink(missing_ok=True)
            return RemoteTransferResultV1(
                direction=RemoteTransferDirectionV1.DOWNLOAD,
                artifact_id=artifact_id,
                key=key,
                bytes_transferred=info.size - resumed_from,
                resumed_from=resumed_from,
                retry_count=retry.retry_count,
                source=RemoteTransferSourceV1.REMOTE,
                remote_revision=info.revision,
                remote_locator=info.provider_locator,
                local_created=local_result.created,
            )
        finally:
            if ephemeral_partial:
                with contextlib.suppress(OSError):
                    partial.unlink(missing_ok=True)


__all__ = [
    "DEFAULT_REMOTE_CHUNK_SIZE",
    "DEFAULT_REMOTE_MAX_OBJECT_BYTES",
    "DEFAULT_REMOTE_MAX_RETRIES",
    "REMOTE_ARTIFACT_PREFIX",
    "REMOTE_CHECKPOINT_VERSION",
    "RemoteArtifactRepositoryV1",
    "RemoteBlobBackendV1",
    "RemoteCheckpointError",
    "RemoteConflictError",
    "RemoteDownloadCheckpointV1",
    "RemoteIntegrityError",
    "RemoteNotFoundError",
    "RemoteObjectInfoV1",
    "RemoteRangeUnsupportedError",
    "RemoteReadChunkV1",
    "RemoteReadOnlyError",
    "RemoteRetryableError",
    "RemoteSessionExpiredError",
    "RemoteStoreError",
    "RemoteTransferDirectionV1",
    "RemoteTransferPolicyV1",
    "RemoteTransferResultV1",
    "RemoteTransferSourceV1",
    "RemoteUploadCheckpointV1",
    "RemoteUploadSessionV1",
    "VerifiedRemoteArtifactCacheV1",
    "artifact_from_remote_bytes_v1",
    "artifact_remote_key_v1",
]
