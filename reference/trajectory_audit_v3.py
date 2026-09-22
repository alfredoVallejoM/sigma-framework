"""Independent stdlib-only encoder for Sigma v3 trajectory audits.

This module imports no code from sigma. It consumes dictionaries returned by
reference.independent_v3.evaluate_suite().
"""

from __future__ import annotations

import struct

VERSION = 3
AUDIT_MAGIC = b"SIG3AUD0"
ROUND_MAGIC = b"SIG3AUR0"
MAX_SEQUENCE_ITEMS = 64
MAX_SEQUENCE_ITEM_LENGTH = 1 << 16
MAX_FIELD_LENGTH = 1 << 20
MAX_RECORD_BODY_LENGTH = 1 << 20

MODE_COMPACT = 1
MODE_FULL = 2


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
            raise ValueError("non-canonical TLV order")
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


def _round_wire(
    *,
    index: int,
    layout: bytes,
    round_binding: bytes,
    state_frame: bytes,
    branch_frames,
    branch_outputs,
    fold_frame: bytes,
) -> bytes:
    return _record(
        ROUND_MAGIC,
        (
            (1, _u(index, 8)),
            (2, layout),
            (3, round_binding),
            (4, state_frame),
            (5, _sequence(branch_frames)),
            (6, _sequence(branch_outputs)),
            (7, fold_frame),
        ),
    )


def audit_from_reference_evaluation(
    evaluation: dict[str, object],
    *,
    mode: int,
) -> bytes:
    if mode not in (MODE_COMPACT, MODE_FULL):
        raise ValueError("unknown reference audit mode")

    states = tuple(evaluation["states"])
    round_layouts = tuple(evaluation["round_layouts"])
    histories = tuple(evaluation["histories"])
    round_bindings = tuple(evaluation["round_bindings"])
    round_frames = tuple(evaluation["round_frames"])
    branch_frames = tuple(evaluation["branch_frames"])
    branch_outputs = tuple(evaluation["branch_outputs"])
    fold_frames = tuple(evaluation["fold_frames"])

    if len(round_layouts) != len(states) - 1:
        raise ValueError("reference evaluation round cardinality mismatch")
    if len(round_frames) != len(round_layouts):
        raise ValueError("reference evaluation frame cardinality mismatch")
    if len(branch_frames) != len(round_layouts):
        raise ValueError("reference branch-frame cardinality mismatch")
    if len(branch_outputs) != len(round_layouts):
        raise ValueError("reference branch-output cardinality mismatch")

    rounds = []
    for index, layout in enumerate(round_layouts):
        if mode == MODE_FULL:
            round_binding = (
                round_bindings[index]
                if len(round_bindings) == len(round_layouts)
                else b""
            )
            state_frame = round_frames[index]
            current_branch_frames = branch_frames[index]
            current_branch_outputs = branch_outputs[index]
            fold_frame = (
                fold_frames[index]
                if len(fold_frames) == len(round_layouts)
                else b""
            )
        else:
            round_binding = b""
            state_frame = b""
            current_branch_frames = ()
            current_branch_outputs = ()
            fold_frame = b""

        rounds.append(
            _round_wire(
                index=index,
                layout=layout,
                round_binding=round_binding,
                state_frame=state_frame,
                branch_frames=current_branch_frames,
                branch_outputs=current_branch_outputs,
                fold_frame=fold_frame,
            )
        )

    return _record(
        AUDIT_MAGIC,
        (
            (1, _u(mode, 2)),
            (2, evaluation["digest"]),
            (3, evaluation["binding"]),
            (4, evaluation["init_layout"]),
            (5, _sequence(states)),
            (6, _sequence(histories)),
            (7, _sequence(rounds)),
        ),
    )


__all__ = [
    "MODE_COMPACT",
    "MODE_FULL",
    "audit_from_reference_evaluation",
]
