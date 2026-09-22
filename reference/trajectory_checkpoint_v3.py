"""Independent stdlib-only encoder for SV1 trajectory checkpoints."""

from __future__ import annotations

import struct
from typing import Any

VERSION = 3
MAGIC = b"SIG3TCK0"
MAX_SEQUENCE_ITEMS = 64
MAX_SEQUENCE_ITEM_LENGTH = 1 << 16
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


def _tlv(fields) -> bytes:
    out = bytearray()
    previous = 0
    for tag, value in fields:
        if tag <= previous:
            raise ValueError("non-canonical TLV")
        out += _field(tag, value)
        previous = tag
    return bytes(out)


def _record(magic: bytes, fields) -> bytes:
    body = _tlv(fields)
    if len(body) > MAX_RECORD_BODY_LENGTH:
        raise ValueError("record body too large")
    return magic + _u(VERSION, 2) + _u(len(body), 4) + body


def _sequence(values) -> bytes:
    values = tuple(values)
    if len(values) > MAX_SEQUENCE_ITEMS:
        raise ValueError("sequence too large")
    out = bytearray(_u(len(values), 2))
    for value in values:
        if not isinstance(value, bytes):
            raise TypeError("sequence item must be bytes")
        if len(value) > MAX_SEQUENCE_ITEM_LENGTH:
            raise ValueError("sequence item too large")
        out += _u(len(value), 4) + value
    return bytes(out)


def checkpoint_from_reference_evaluation(
    evaluation: dict[str, Any],
    round_index: int,
) -> bytes:
    states = tuple(evaluation["states"])
    histories = tuple(evaluation["histories"])
    target = int(evaluation["target_round"])
    count = int(evaluation["state_count"])
    final_index = target + count - 1
    if not 0 <= round_index <= final_index:
        raise ValueError("round_index outside reference trajectory")
    if len(states) != final_index + 1:
        raise ValueError("reference trajectory state cardinality mismatch")

    window_prefix = states[target:round_index] if round_index > target else ()
    history = histories[round_index] if histories else b""

    return _record(
        MAGIC,
        (
            (1, evaluation["context"]),
            (2, evaluation["binding"]),
            (3, evaluation["parameters"]),
            (4, _u(round_index, 8)),
            (5, states[round_index]),
            (6, history),
            (7, _sequence(window_prefix)),
        ),
    )


__all__ = ["checkpoint_from_reference_evaluation"]
