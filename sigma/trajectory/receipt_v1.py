"""Canonical verification receipts for SV3.

A receipt records what verifier evaluated what policy over what artifact identity.
It authenticates the canonical record when signed, but does not turn opaque
artifact/provenance claims into semantic truth.
"""

from __future__ import annotations

import hashlib
import hmac
import unicodedata
from dataclasses import dataclass, replace
from enum import IntEnum

from sigma.spec.codec_v3 import decode_record, encode_record
from sigma.spec.encoding import DecodeError, decode_uint, encode_uint
from sigma.spec.ids import SignatureAlgorithmId
from sigma.trajectory.policy_v1 import (
    VerificationDecisionCodeV1,
    VerificationDecisionKindV1,
    VerificationDecisionV1,
    VerificationEvidenceKindV1,
    VerificationPolicyV1,
)
from sigma.version import PACKAGE_VERSION

_RECEIPT_MAGIC = b"SIGRCPT1"
_SIGNING_DOMAIN = b"SIGMA-VERIFICATION-RECEIPT-V1\x00"
_MAX_IDENTITY_BYTES = 255
_MAX_TEXT_BYTES = 1024
_MAX_EVIDENCE_HASHES = 64


class ReceiptSignatureStatusV1(IntEnum):
    UNSIGNED = 1
    SIGNED = 2


class _ReceiptField(IntEnum):
    ARTIFACT_IDENTITY = 1
    POLICY_ID = 2
    VERIFIER_PACKAGE = 3
    VERIFIER_VERSION = 4
    VERIFIER_BUILD = 5
    EVIDENCE_KIND = 6
    EVIDENCE_ID = 7
    DECISION_KIND = 8
    DECISION_CODE = 9
    DECISION_REASON = 10
    STRUCTURE_VALID = 11
    MESSAGE_BINDING_VERIFIED = 12
    EVIDENCE_HASHES = 13
    CLAIMED_UNIX_TIME = 14
    SIGNATURE_STATUS = 15
    SIGNATURE_ALGORITHM = 16
    PUBLIC_KEY_ID = 17
    SIGNATURE = 18


def _canonical_text(name: str, value: str, *, max_bytes: int = _MAX_TEXT_BYTES) -> str:
    if not isinstance(value, str):
        raise TypeError(f"{name} must be str")
    if "\x00" in value:
        raise ValueError(f"{name} must not contain NUL")
    normalized = unicodedata.normalize("NFC", value)
    if normalized != value:
        raise ValueError(f"{name} must already be NFC-normalized")
    encoded = value.encode("utf-8", "strict")
    if not 1 <= len(encoded) <= max_bytes:
        raise ValueError(f"{name} UTF-8 length is out of range")
    return value


def _validate_identity(name: str, value: bytes, *, allow_empty: bool = False) -> bytes:
    if not isinstance(value, bytes):
        raise TypeError(f"{name} must be bytes")
    minimum = 0 if allow_empty else 1
    if not minimum <= len(value) <= _MAX_IDENTITY_BYTES:
        raise ValueError(f"{name} length is out of range")
    return value


def _encode_optional_enum(value: VerificationEvidenceKindV1 | None) -> bytes:
    return b"" if value is None else value.value.encode("ascii")


def _decode_optional_evidence_kind(data: bytes) -> VerificationEvidenceKindV1 | None:
    if not data:
        return None
    try:
        return VerificationEvidenceKindV1(data.decode("ascii"))
    except (UnicodeDecodeError, ValueError) as exc:
        raise DecodeError("invalid receipt evidence kind") from exc


def _encode_optional_hash(value: bytes | None) -> bytes:
    if value is None:
        return b""
    if not isinstance(value, bytes) or len(value) != 32:
        raise ValueError("receipt evidence_id must contain exactly 32 bytes")
    return value


def _decode_optional_hash(data: bytes) -> bytes | None:
    if not data:
        return None
    if len(data) != 32:
        raise DecodeError("receipt evidence_id must contain exactly 32 bytes")
    return data


def _encode_tristate(value: bool | None) -> bytes:
    if value is None:
        return encode_uint(0, 1)
    if not isinstance(value, bool):
        raise TypeError("receipt tristate must be bool or None")
    return encode_uint(2 if value else 1, 1)


def _decode_tristate(data: bytes) -> bool | None:
    value = decode_uint(data, 1)
    if value == 0:
        return None
    if value == 1:
        return False
    if value == 2:
        return True
    raise DecodeError("invalid receipt tristate")


def _encode_hash_sequence(values: tuple[bytes, ...]) -> bytes:
    if not isinstance(values, tuple):
        raise TypeError("evidence_hashes must be tuple")
    if len(values) > _MAX_EVIDENCE_HASHES:
        raise ValueError("too many receipt evidence hashes")
    if tuple(sorted(set(values))) != values:
        raise ValueError("evidence_hashes must be sorted and unique")
    out = bytearray(encode_uint(len(values), 2))
    for value in values:
        if not isinstance(value, bytes) or len(value) != 32:
            raise ValueError("each evidence hash must contain exactly 32 bytes")
        out.extend(value)
    return bytes(out)


def _decode_hash_sequence(data: bytes) -> tuple[bytes, ...]:
    if not isinstance(data, bytes) or len(data) < 2:
        raise DecodeError("truncated receipt evidence-hash sequence")
    count = decode_uint(data[:2], 2)
    if count > _MAX_EVIDENCE_HASHES or len(data) != 2 + count * 32:
        raise DecodeError("invalid receipt evidence-hash sequence")
    values = tuple(data[i : i + 32] for i in range(2, len(data), 32))
    if tuple(sorted(set(values))) != values:
        raise DecodeError("receipt evidence hashes are not canonical")
    return values


@dataclass(frozen=True)
class VerificationReceiptV1:
    artifact_identity: bytes
    policy_id: bytes
    verifier_package: str
    verifier_version: str
    verifier_build: bytes
    evidence_kind: VerificationEvidenceKindV1 | None
    evidence_id: bytes | None
    decision_kind: VerificationDecisionKindV1
    decision_code: VerificationDecisionCodeV1
    decision_reason: str
    structure_valid: bool | None
    message_binding_verified: bool | None
    evidence_hashes: tuple[bytes, ...] = ()
    claimed_unix_time: int | None = None
    signature_status: ReceiptSignatureStatusV1 = ReceiptSignatureStatusV1.UNSIGNED
    signature_algorithm: SignatureAlgorithmId | None = None
    public_key_id: bytes = b""
    signature: bytes = b""

    def __post_init__(self) -> None:
        _validate_identity("artifact_identity", self.artifact_identity)
        if not isinstance(self.policy_id, bytes) or len(self.policy_id) != 32:
            raise ValueError("policy_id must contain exactly 32 bytes")
        _canonical_text("verifier_package", self.verifier_package, max_bytes=255)
        _canonical_text("verifier_version", self.verifier_version, max_bytes=255)
        _validate_identity("verifier_build", self.verifier_build, allow_empty=True)
        if self.evidence_kind is not None and not isinstance(
            self.evidence_kind, VerificationEvidenceKindV1
        ):
            raise TypeError("evidence_kind must be VerificationEvidenceKindV1 or None")
        _encode_optional_hash(self.evidence_id)
        if not isinstance(self.decision_kind, VerificationDecisionKindV1):
            raise TypeError("decision_kind must be VerificationDecisionKindV1")
        if not isinstance(self.decision_code, VerificationDecisionCodeV1):
            raise TypeError("decision_code must be VerificationDecisionCodeV1")
        _canonical_text("decision_reason", self.decision_reason)
        _encode_tristate(self.structure_valid)
        _encode_tristate(self.message_binding_verified)
        _encode_hash_sequence(self.evidence_hashes)
        if self.evidence_id is not None and self.evidence_id not in self.evidence_hashes:
            raise ValueError("evidence_hashes must include evidence_id when present")
        if self.claimed_unix_time is not None:
            if (
                isinstance(self.claimed_unix_time, bool)
                or not isinstance(self.claimed_unix_time, int)
                or not 0 <= self.claimed_unix_time < (1 << 64)
            ):
                raise ValueError("claimed_unix_time must be u64 or None")
        if not isinstance(self.signature_status, ReceiptSignatureStatusV1):
            raise TypeError("signature_status must be ReceiptSignatureStatusV1")
        if self.signature_status is ReceiptSignatureStatusV1.UNSIGNED:
            if (
                self.signature_algorithm is not None
                or self.public_key_id
                or self.signature
            ):
                raise ValueError("unsigned receipt must carry no signature material")
        else:
            if self.signature_algorithm is not SignatureAlgorithmId.ED25519:
                raise ValueError("signed receipt must use Ed25519")
            _validate_identity("public_key_id", self.public_key_id)
            if not isinstance(self.signature, bytes) or len(self.signature) != 64:
                raise ValueError("signed receipt signature must contain 64 bytes")

    @property
    def is_signed(self) -> bool:
        return self.signature_status is ReceiptSignatureStatusV1.SIGNED

    @property
    def receipt_id(self) -> bytes:
        return hashlib.sha256(self.to_bytes()).digest()

    def _common_fields(self) -> tuple[tuple[int, bytes], ...]:
        claimed_time = (
            b""
            if self.claimed_unix_time is None
            else encode_uint(self.claimed_unix_time, 8)
        )
        return (
            (_ReceiptField.ARTIFACT_IDENTITY, self.artifact_identity),
            (_ReceiptField.POLICY_ID, self.policy_id),
            (_ReceiptField.VERIFIER_PACKAGE, self.verifier_package.encode("utf-8")),
            (_ReceiptField.VERIFIER_VERSION, self.verifier_version.encode("utf-8")),
            (_ReceiptField.VERIFIER_BUILD, self.verifier_build),
            (_ReceiptField.EVIDENCE_KIND, _encode_optional_enum(self.evidence_kind)),
            (_ReceiptField.EVIDENCE_ID, _encode_optional_hash(self.evidence_id)),
            (_ReceiptField.DECISION_KIND, self.decision_kind.value.encode("ascii")),
            (_ReceiptField.DECISION_CODE, self.decision_code.value.encode("ascii")),
            (_ReceiptField.DECISION_REASON, self.decision_reason.encode("utf-8")),
            (_ReceiptField.STRUCTURE_VALID, _encode_tristate(self.structure_valid)),
            (
                _ReceiptField.MESSAGE_BINDING_VERIFIED,
                _encode_tristate(self.message_binding_verified),
            ),
            (_ReceiptField.EVIDENCE_HASHES, _encode_hash_sequence(self.evidence_hashes)),
            (_ReceiptField.CLAIMED_UNIX_TIME, claimed_time),
        )

    def _signature_fields(self, *, empty_signature: bool = False) -> tuple[tuple[int, bytes], ...]:
        algorithm = (
            b""
            if self.signature_algorithm is None
            else encode_uint(self.signature_algorithm, 2)
        )
        return (
            (_ReceiptField.SIGNATURE_STATUS, encode_uint(self.signature_status, 1)),
            (_ReceiptField.SIGNATURE_ALGORITHM, algorithm),
            (_ReceiptField.PUBLIC_KEY_ID, self.public_key_id),
            (
                _ReceiptField.SIGNATURE,
                b"" if empty_signature else self.signature,
            ),
        )

    def signing_input(self) -> bytes:
        if not self.is_signed:
            raise ValueError("unsigned receipt has no signing input")
        canonical_without_signature = encode_record(
            _RECEIPT_MAGIC,
            (*self._common_fields(), *self._signature_fields(empty_signature=True)),
        )
        return _SIGNING_DOMAIN + canonical_without_signature

    def to_bytes(self) -> bytes:
        return encode_record(
            _RECEIPT_MAGIC,
            (*self._common_fields(), *self._signature_fields()),
        )

    @classmethod
    def from_bytes(cls, data: bytes) -> "VerificationReceiptV1":
        fields = decode_record(
            data,
            magic=_RECEIPT_MAGIC,
            allowed_tags=frozenset(int(field) for field in _ReceiptField),
        )
        try:
            artifact_identity = fields[_ReceiptField.ARTIFACT_IDENTITY]
            policy_id = fields[_ReceiptField.POLICY_ID]
            verifier_package = fields[_ReceiptField.VERIFIER_PACKAGE].decode("utf-8")
            verifier_version = fields[_ReceiptField.VERIFIER_VERSION].decode("utf-8")
            verifier_build = fields[_ReceiptField.VERIFIER_BUILD]
            evidence_kind = _decode_optional_evidence_kind(
                fields[_ReceiptField.EVIDENCE_KIND]
            )
            evidence_id = _decode_optional_hash(fields[_ReceiptField.EVIDENCE_ID])
            decision_kind = VerificationDecisionKindV1(
                fields[_ReceiptField.DECISION_KIND].decode("ascii")
            )
            decision_code = VerificationDecisionCodeV1(
                fields[_ReceiptField.DECISION_CODE].decode("ascii")
            )
            decision_reason = fields[_ReceiptField.DECISION_REASON].decode("utf-8")
            structure_valid = _decode_tristate(fields[_ReceiptField.STRUCTURE_VALID])
            message_binding_verified = _decode_tristate(
                fields[_ReceiptField.MESSAGE_BINDING_VERIFIED]
            )
            evidence_hashes = _decode_hash_sequence(
                fields[_ReceiptField.EVIDENCE_HASHES]
            )
            raw_time = fields[_ReceiptField.CLAIMED_UNIX_TIME]
            claimed_unix_time = None if not raw_time else decode_uint(raw_time, 8)
            signature_status = ReceiptSignatureStatusV1(
                decode_uint(fields[_ReceiptField.SIGNATURE_STATUS], 1)
            )
            raw_algorithm = fields[_ReceiptField.SIGNATURE_ALGORITHM]
            signature_algorithm = (
                None
                if not raw_algorithm
                else SignatureAlgorithmId(decode_uint(raw_algorithm, 2))
            )
            public_key_id = fields[_ReceiptField.PUBLIC_KEY_ID]
            signature = fields[_ReceiptField.SIGNATURE]
            return cls(
                artifact_identity=artifact_identity,
                policy_id=policy_id,
                verifier_package=verifier_package,
                verifier_version=verifier_version,
                verifier_build=verifier_build,
                evidence_kind=evidence_kind,
                evidence_id=evidence_id,
                decision_kind=decision_kind,
                decision_code=decision_code,
                decision_reason=decision_reason,
                structure_valid=structure_valid,
                message_binding_verified=message_binding_verified,
                evidence_hashes=evidence_hashes,
                claimed_unix_time=claimed_unix_time,
                signature_status=signature_status,
                signature_algorithm=signature_algorithm,
                public_key_id=public_key_id,
                signature=signature,
            )
        except DecodeError:
            raise
        except (KeyError, UnicodeDecodeError, TypeError, ValueError) as exc:
            raise DecodeError("invalid VerificationReceiptV1") from exc

    def decision_projection(self) -> VerificationDecisionV1:
        return VerificationDecisionV1(
            kind=self.decision_kind,
            code=self.decision_code,
            reason=self.decision_reason,
            policy_id=self.policy_id,
            evidence_id=self.evidence_id,
            evidence_kind=self.evidence_kind,
            structure_valid=self.structure_valid,
            message_binding_verified=self.message_binding_verified,
        )


def receipt_from_decision_v1(
    artifact_identity: bytes,
    policy: VerificationPolicyV1,
    decision: VerificationDecisionV1,
    *,
    verifier_package: str = "sigma-framework",
    verifier_version: str = PACKAGE_VERSION,
    verifier_build: bytes = b"",
    evidence_hashes: tuple[bytes, ...] | None = None,
    claimed_unix_time: int | None = None,
) -> VerificationReceiptV1:
    if not isinstance(policy, VerificationPolicyV1):
        raise TypeError("policy must be VerificationPolicyV1")
    if not isinstance(decision, VerificationDecisionV1):
        raise TypeError("decision must be VerificationDecisionV1")
    if not hmac.compare_digest(policy.policy_id, decision.policy_id):
        raise ValueError("decision policy_id does not match supplied policy")
    hashes = (
        (() if decision.evidence_id is None else (decision.evidence_id,))
        if evidence_hashes is None
        else evidence_hashes
    )
    hashes = tuple(sorted(set(hashes)))
    return VerificationReceiptV1(
        artifact_identity=artifact_identity,
        policy_id=decision.policy_id,
        verifier_package=verifier_package,
        verifier_version=verifier_version,
        verifier_build=verifier_build,
        evidence_kind=decision.evidence_kind,
        evidence_id=decision.evidence_id,
        decision_kind=decision.kind,
        decision_code=decision.code,
        decision_reason=decision.reason,
        structure_valid=decision.structure_valid,
        message_binding_verified=decision.message_binding_verified,
        evidence_hashes=hashes,
        claimed_unix_time=claimed_unix_time,
    )


def sign_receipt_ed25519_v1(
    receipt: VerificationReceiptV1,
    private_key: bytes,
    public_key_id: bytes,
) -> VerificationReceiptV1:
    if not isinstance(receipt, VerificationReceiptV1):
        raise TypeError("receipt must be VerificationReceiptV1")
    if receipt.is_signed:
        raise ValueError("receipt is already signed")
    if not isinstance(private_key, bytes) or len(private_key) != 32:
        raise ValueError("private key must contain exactly 32 bytes")
    _validate_identity("public_key_id", public_key_id)
    try:
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    except ImportError as exc:  # pragma: no cover
        raise RuntimeError("Ed25519 support requires the signatures extra") from exc

    placeholder = replace(
        receipt,
        signature_status=ReceiptSignatureStatusV1.SIGNED,
        signature_algorithm=SignatureAlgorithmId.ED25519,
        public_key_id=public_key_id,
        signature=bytes(64),
    )
    signature = Ed25519PrivateKey.from_private_bytes(private_key).sign(
        placeholder.signing_input()
    )
    return replace(placeholder, signature=signature)


def verify_receipt_signature_v1(
    receipt: VerificationReceiptV1,
    public_key: bytes,
    *,
    expected_public_key_id: bytes | None = None,
) -> bool:
    if not isinstance(receipt, VerificationReceiptV1):
        raise TypeError("receipt must be VerificationReceiptV1")
    if not receipt.is_signed:
        return False
    if not isinstance(public_key, bytes) or len(public_key) != 32:
        raise ValueError("public key must contain exactly 32 bytes")
    if expected_public_key_id is not None:
        _validate_identity("expected_public_key_id", expected_public_key_id)
        if not hmac.compare_digest(receipt.public_key_id, expected_public_key_id):
            return False
    try:
        from cryptography.exceptions import InvalidSignature
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
    except ImportError as exc:  # pragma: no cover
        raise RuntimeError("Ed25519 support requires the signatures extra") from exc
    try:
        Ed25519PublicKey.from_public_bytes(public_key).verify(
            receipt.signature,
            receipt.signing_input(),
        )
    except InvalidSignature:
        return False
    return True


__all__ = [
    "ReceiptSignatureStatusV1",
    "VerificationReceiptV1",
    "receipt_from_decision_v1",
    "sign_receipt_ed25519_v1",
    "verify_receipt_signature_v1",
]
