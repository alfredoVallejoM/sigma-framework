"""Independent stdlib-only encoder for SV3 receipts and batch results."""

from __future__ import annotations

import struct

VERSION = 3
RECEIPT_MAGIC = b"SIGRCPT1"
BATCH_ITEM_MAGIC = b"SIGBCRI1"
BATCH_MAGIC = b"SIGBCHT1"
SIGNING_DOMAIN = b"SIGMA-VERIFICATION-RECEIPT-V1\x00"
MAX_FIELD_LENGTH = 1 << 20
MAX_RECORD_BODY_LENGTH = 1 << 20


def _u(value: int, width: int) -> bytes:
    return value.to_bytes(width, "big")


def _field(tag: int, value: bytes) -> bytes:
    if not 0 < tag <= 0xFFFF:
        raise ValueError("invalid TLV tag")
    if len(value) > MAX_FIELD_LENGTH:
        raise ValueError("field too large")
    return struct.pack(">HI", tag, len(value)) + value


def _record(magic: bytes, fields) -> bytes:
    body = bytearray()
    previous = 0
    for tag, value in fields:
        if tag <= previous:
            raise ValueError("non-canonical TLV order")
        body.extend(_field(tag, value))
        previous = tag
    if len(body) > MAX_RECORD_BODY_LENGTH:
        raise ValueError("record too large")
    return magic + _u(VERSION, 2) + _u(len(body), 4) + bytes(body)


def _tristate(value) -> bytes:
    if value is None:
        return b"\x00"
    return b"\x02" if value else b"\x01"


def _hash_sequence(values) -> bytes:
    values = tuple(values)
    return _u(len(values), 2) + b"".join(values)


def receipt_wire(
    *,
    artifact_identity: bytes,
    policy_id: bytes,
    verifier_package: str,
    verifier_version: str,
    verifier_build: bytes,
    evidence_kind: str | None,
    evidence_id: bytes | None,
    decision_kind: str,
    decision_code: str,
    decision_reason: str,
    structure_valid,
    message_binding_verified,
    evidence_hashes,
    claimed_unix_time: int | None,
    signature_status: int,
    signature_algorithm: int | None,
    public_key_id: bytes,
    signature: bytes,
) -> bytes:
    return _record(
        RECEIPT_MAGIC,
        (
            (1, artifact_identity),
            (2, policy_id),
            (3, verifier_package.encode("utf-8")),
            (4, verifier_version.encode("utf-8")),
            (5, verifier_build),
            (6, b"" if evidence_kind is None else evidence_kind.encode("ascii")),
            (7, b"" if evidence_id is None else evidence_id),
            (8, decision_kind.encode("ascii")),
            (9, decision_code.encode("ascii")),
            (10, decision_reason.encode("utf-8")),
            (11, _tristate(structure_valid)),
            (12, _tristate(message_binding_verified)),
            (13, _hash_sequence(evidence_hashes)),
            (14, b"" if claimed_unix_time is None else _u(claimed_unix_time, 8)),
            (15, _u(signature_status, 1)),
            (16, b"" if signature_algorithm is None else _u(signature_algorithm, 2)),
            (17, public_key_id),
            (18, signature),
        ),
    )


def receipt_signing_input(**kwargs) -> bytes:
    signed = dict(kwargs)
    signed["signature"] = b""
    return SIGNING_DOMAIN + receipt_wire(**signed)


def batch_item_wire(
    *,
    index: int,
    artifact_identity: bytes,
    receipt: bytes,
    error_type: str,
    error_message: str,
) -> bytes:
    return _record(
        BATCH_ITEM_MAGIC,
        (
            (1, _u(index, 8)),
            (2, artifact_identity),
            (3, receipt),
            (4, error_type.encode("utf-8")),
            (5, error_message.encode("utf-8")),
        ),
    )


def batch_wire(item_wires) -> bytes:
    item_wires = tuple(item_wires)
    seq = bytearray(_u(len(item_wires), 2))
    for wire in item_wires:
        seq.extend(_u(len(wire), 4))
        seq.extend(wire)
    return _record(BATCH_MAGIC, ((1, bytes(seq)),))


__all__ = [
    "batch_item_wire",
    "batch_wire",
    "receipt_signing_input",
    "receipt_wire",
]
