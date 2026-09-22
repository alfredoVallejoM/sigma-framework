"""Pointwise batch verification and receipt generation for SV3."""

from __future__ import annotations

import hashlib
import unicodedata
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from enum import IntEnum

from sigma.outputs.digest import SigmaDigestV2
from sigma.outputs.digest_v3 import SigmaDigestV3
from sigma.sources import CanonicalSource
from sigma.spec.codec_v3 import decode_record, encode_record
from sigma.spec.encoding import DecodeError, decode_uint, encode_uint
from sigma.trajectory.audit_v3 import TrajectoryAuditV3
from sigma.trajectory.policy_v1 import (
    ParsedVerificationEvidenceV1,
    VerificationCapabilitiesV1,
    VerificationDecisionV1,
    VerificationPolicyV1,
    verify_with_policy_v1,
)
from sigma.trajectory.receipt_v1 import (
    VerificationReceiptV1,
    receipt_from_decision_v1,
    sign_receipt_ed25519_v1,
)
from sigma.version import PACKAGE_VERSION

_BATCH_MAGIC = b"SIGBCHT1"
_BATCH_ITEM_MAGIC = b"SIGBCRI1"
_MAX_BATCH_ITEMS = 4096
_MAX_ITEM_WIRE = 1 << 20


class _BatchField(IntEnum):
    ITEMS = 1


class _BatchItemField(IntEnum):
    INDEX = 1
    ARTIFACT_IDENTITY = 2
    RECEIPT = 3
    ERROR_TYPE = 4
    ERROR_MESSAGE = 5


def _safe_error_text(value: object) -> str:
    text = unicodedata.normalize("NFC", str(value)).replace("\x00", "\\0")
    encoded = text.encode("utf-8", "replace")
    if len(encoded) <= 4096:
        return text
    shortened = encoded[:4096]
    while True:
        try:
            return shortened.decode("utf-8")
        except UnicodeDecodeError:
            shortened = shortened[:-1]


def _canonical_error_text(name: str, value: str) -> str:
    if not isinstance(value, str):
        raise TypeError(f"{name} must be str")
    if "\x00" in value:
        raise ValueError(f"{name} must not contain NUL")
    normalized = unicodedata.normalize("NFC", value)
    if normalized != value:
        raise ValueError(f"{name} must be NFC-normalized")
    encoded = value.encode("utf-8", "strict")
    if len(encoded) > 4096:
        raise ValueError(f"{name} is too large")
    return value


def _validate_artifact_identity(value: bytes) -> bytes:
    if not isinstance(value, bytes):
        raise TypeError("artifact_identity must be bytes")
    if not 1 <= len(value) <= 255:
        raise ValueError("artifact_identity length must be 1..255 bytes")
    return value


def _encode_item_sequence(values: tuple[bytes, ...]) -> bytes:
    if not 1 <= len(values) <= _MAX_BATCH_ITEMS:
        raise ValueError("batch item count is out of range")
    out = bytearray(encode_uint(len(values), 2))
    for value in values:
        if not isinstance(value, bytes) or not value or len(value) > _MAX_ITEM_WIRE:
            raise ValueError("batch item wire length is out of range")
        out.extend(encode_uint(len(value), 4))
        out.extend(value)
    return bytes(out)


def _decode_item_sequence(data: bytes) -> tuple[bytes, ...]:
    if not isinstance(data, bytes) or len(data) < 2:
        raise DecodeError("truncated batch item sequence")
    count = decode_uint(data[:2], 2)
    if not 1 <= count <= _MAX_BATCH_ITEMS:
        raise DecodeError("batch item count is out of range")
    offset = 2
    output: list[bytes] = []
    for _ in range(count):
        if offset + 4 > len(data):
            raise DecodeError("truncated batch item length")
        length = decode_uint(data[offset : offset + 4], 4)
        offset += 4
        if not 0 < length <= _MAX_ITEM_WIRE or offset + length > len(data):
            raise DecodeError("invalid batch item wire length")
        output.append(data[offset : offset + length])
        offset += length
    if offset != len(data):
        raise DecodeError("trailing batch item sequence data")
    return tuple(output)


@dataclass(frozen=True)
class BatchVerificationItemV1:
    artifact_identity: bytes
    evidence: (
        bytes
        | ParsedVerificationEvidenceV1
        | SigmaDigestV3
        | TrajectoryAuditV3
        | SigmaDigestV2
    )
    policy: VerificationPolicyV1
    source: CanonicalSource | bytes | None = None
    capabilities: VerificationCapabilitiesV1 = field(default_factory=VerificationCapabilitiesV1)
    evidence_hashes: tuple[bytes, ...] | None = None
    claimed_unix_time: int | None = None

    def __post_init__(self) -> None:
        _validate_artifact_identity(self.artifact_identity)
        if not isinstance(self.policy, VerificationPolicyV1):
            raise TypeError("policy must be VerificationPolicyV1")
        if not isinstance(self.capabilities, VerificationCapabilitiesV1):
            raise TypeError("capabilities must be VerificationCapabilitiesV1")
        if self.evidence_hashes is not None:
            if not isinstance(self.evidence_hashes, tuple):
                raise TypeError("evidence_hashes must be tuple or None")
            if any(
                not isinstance(value, bytes) or len(value) != 32
                for value in self.evidence_hashes
            ):
                raise ValueError("batch evidence hashes must be 32-byte values")
        if self.claimed_unix_time is not None and (
            isinstance(self.claimed_unix_time, bool)
            or not isinstance(self.claimed_unix_time, int)
            or not 0 <= self.claimed_unix_time < (1 << 64)
        ):
            raise ValueError("claimed_unix_time must be u64 or None")


@dataclass(frozen=True)
class BatchItemResultV1:
    index: int
    artifact_identity: bytes
    receipt: VerificationReceiptV1 | None
    error_type: str = ""
    error_message: str = ""

    def __post_init__(self) -> None:
        if isinstance(self.index, bool) or not isinstance(self.index, int) or self.index < 0:
            raise ValueError("batch result index must be a non-negative int")
        _validate_artifact_identity(self.artifact_identity)
        if self.receipt is not None and not isinstance(
            self.receipt, VerificationReceiptV1
        ):
            raise TypeError("receipt must be VerificationReceiptV1 or None")
        _canonical_error_text("error_type", self.error_type)
        _canonical_error_text("error_message", self.error_message)
        if self.receipt is None:
            if not self.error_type:
                raise ValueError("failed batch result requires error_type")
        elif self.error_type or self.error_message:
            raise ValueError("successful batch result must not carry error fields")

    @property
    def succeeded(self) -> bool:
        return self.receipt is not None

    @property
    def decision(self) -> VerificationDecisionV1 | None:
        return None if self.receipt is None else self.receipt.decision_projection()

    def to_bytes(self) -> bytes:
        return encode_record(
            _BATCH_ITEM_MAGIC,
            (
                (_BatchItemField.INDEX, encode_uint(self.index, 8)),
                (_BatchItemField.ARTIFACT_IDENTITY, self.artifact_identity),
                (
                    _BatchItemField.RECEIPT,
                    b"" if self.receipt is None else self.receipt.to_bytes(),
                ),
                (_BatchItemField.ERROR_TYPE, self.error_type.encode("utf-8")),
                (_BatchItemField.ERROR_MESSAGE, self.error_message.encode("utf-8")),
            ),
        )

    @classmethod
    def from_bytes(cls, data: bytes) -> "BatchItemResultV1":
        fields = decode_record(
            data,
            magic=_BATCH_ITEM_MAGIC,
            allowed_tags=frozenset(int(field) for field in _BatchItemField),
        )
        try:
            receipt = (
                None
                if not fields[_BatchItemField.RECEIPT]
                else VerificationReceiptV1.from_bytes(fields[_BatchItemField.RECEIPT])
            )
            return cls(
                index=decode_uint(fields[_BatchItemField.INDEX], 8),
                artifact_identity=fields[_BatchItemField.ARTIFACT_IDENTITY],
                receipt=receipt,
                error_type=fields[_BatchItemField.ERROR_TYPE].decode("utf-8"),
                error_message=fields[_BatchItemField.ERROR_MESSAGE].decode("utf-8"),
            )
        except DecodeError:
            raise
        except (KeyError, UnicodeDecodeError, TypeError, ValueError) as exc:
            raise DecodeError("invalid BatchItemResultV1") from exc


@dataclass(frozen=True)
class BatchVerificationResultV1:
    items: tuple[BatchItemResultV1, ...]

    def __post_init__(self) -> None:
        if not isinstance(self.items, tuple) or not self.items:
            raise ValueError("batch result must contain at least one item")
        if len(self.items) > _MAX_BATCH_ITEMS:
            raise ValueError("batch result contains too many items")
        if any(not isinstance(item, BatchItemResultV1) for item in self.items):
            raise TypeError("batch result items must be BatchItemResultV1")
        if tuple(item.index for item in self.items) != tuple(range(len(self.items))):
            raise ValueError("batch result indices must preserve input order")

    @property
    def batch_id(self) -> bytes:
        return hashlib.sha256(self.to_bytes()).digest()

    @property
    def accepted_count(self) -> int:
        return sum(
            1
            for item in self.items
            if item.decision is not None and item.decision.accepted
        )

    @property
    def error_count(self) -> int:
        return sum(1 for item in self.items if not item.succeeded)

    def to_bytes(self) -> bytes:
        return encode_record(
            _BATCH_MAGIC,
            (
                (
                    _BatchField.ITEMS,
                    _encode_item_sequence(tuple(item.to_bytes() for item in self.items)),
                ),
            ),
        )

    @classmethod
    def from_bytes(cls, data: bytes) -> "BatchVerificationResultV1":
        fields = decode_record(
            data,
            magic=_BATCH_MAGIC,
            allowed_tags=frozenset(int(field) for field in _BatchField),
        )
        try:
            return cls(
                tuple(
                    BatchItemResultV1.from_bytes(raw)
                    for raw in _decode_item_sequence(fields[_BatchField.ITEMS])
                )
            )
        except DecodeError:
            raise
        except (KeyError, TypeError, ValueError) as exc:
            raise DecodeError("invalid BatchVerificationResultV1") from exc


def verify_batch_item_v1(
    item: BatchVerificationItemV1,
    *,
    index: int = 0,
    verifier_package: str = "sigma-framework",
    verifier_version: str = PACKAGE_VERSION,
    verifier_build: bytes = b"",
    signing_private_key: bytes | None = None,
    public_key_id: bytes | None = None,
) -> BatchItemResultV1:
    if not isinstance(item, BatchVerificationItemV1):
        raise TypeError("item must be BatchVerificationItemV1")
    if isinstance(index, bool) or not isinstance(index, int) or index < 0:
        raise ValueError("index must be a non-negative int")
    try:
        decision = verify_with_policy_v1(
            item.evidence,
            policy=item.policy,
            source=item.source,
            capabilities=item.capabilities,
        )
        receipt = receipt_from_decision_v1(
            item.artifact_identity,
            item.policy,
            decision,
            verifier_package=verifier_package,
            verifier_version=verifier_version,
            verifier_build=verifier_build,
            evidence_hashes=item.evidence_hashes,
            claimed_unix_time=item.claimed_unix_time,
        )
        if signing_private_key is not None:
            if public_key_id is None:
                raise ValueError("public_key_id is required when signing receipts")
            receipt = sign_receipt_ed25519_v1(
                receipt,
                signing_private_key,
                public_key_id,
            )
        elif public_key_id is not None:
            raise ValueError("signing_private_key is required with public_key_id")
        return BatchItemResultV1(index, item.artifact_identity, receipt)
    except Exception as exc:
        return BatchItemResultV1(
            index=index,
            artifact_identity=item.artifact_identity,
            receipt=None,
            error_type=_safe_error_text(type(exc).__name__),
            error_message=_safe_error_text(exc),
        )


def verify_batch_v1(
    items: tuple[BatchVerificationItemV1, ...],
    *,
    verifier_package: str = "sigma-framework",
    verifier_version: str = PACKAGE_VERSION,
    verifier_build: bytes = b"",
    signing_private_key: bytes | None = None,
    public_key_id: bytes | None = None,
    max_workers: int = 1,
) -> BatchVerificationResultV1:
    if not isinstance(items, tuple) or not items:
        raise ValueError("items must be a non-empty tuple")
    if len(items) > _MAX_BATCH_ITEMS:
        raise ValueError("batch contains too many items")
    if any(not isinstance(item, BatchVerificationItemV1) for item in items):
        raise TypeError("all batch items must be BatchVerificationItemV1")
    if isinstance(max_workers, bool) or not isinstance(max_workers, int) or max_workers < 1:
        raise ValueError("max_workers must be a positive int")
    if signing_private_key is not None:
        if not isinstance(signing_private_key, bytes) or len(signing_private_key) != 32:
            raise ValueError("signing_private_key must contain exactly 32 bytes")
        if public_key_id is None:
            raise ValueError("public_key_id is required when signing receipts")
    elif public_key_id is not None:
        raise ValueError("signing_private_key is required with public_key_id")

    def run(index_item: tuple[int, BatchVerificationItemV1]) -> BatchItemResultV1:
        index, item = index_item
        return verify_batch_item_v1(
            item,
            index=index,
            verifier_package=verifier_package,
            verifier_version=verifier_version,
            verifier_build=verifier_build,
            signing_private_key=signing_private_key,
            public_key_id=public_key_id,
        )

    indexed = tuple(enumerate(items))
    if max_workers == 1:
        results = tuple(run(value) for value in indexed)
    else:
        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            results = tuple(executor.map(run, indexed))
    return BatchVerificationResultV1(results)


__all__ = [
    "BatchItemResultV1",
    "BatchVerificationItemV1",
    "BatchVerificationResultV1",
    "verify_batch_item_v1",
    "verify_batch_v1",
]
