"""Canonical streaming transcript framing for Sigma v3."""

from __future__ import annotations

import io
import struct
from collections.abc import Iterable
from typing import Protocol

from sigma.spec.ids_v3 import DomainIdV3

TRANSCRIPT_MAGIC = b"SIGMA3TR"
TRANSCRIPT_VERSION = 3
MAX_TRANSCRIPT_FIELD_LENGTH = (1 << 64) - 1
_FIELD_HEADER = struct.Struct(">HQ")


class TranscriptSink(Protocol):
    def update(self, data: bytes) -> None: ...


class TranscriptWriter:
    """Write ordered typed fields without materializing their payloads."""

    def __init__(self, sink: TranscriptSink, domain: DomainIdV3) -> None:
        if not isinstance(domain, DomainIdV3):
            raise TypeError("domain must be DomainIdV3")
        if not callable(getattr(sink, "update", None)):
            raise TypeError("sink must provide update(bytes)")
        self._sink = sink
        self._last_tag = 0
        self._finished = False
        self._failed = False
        sink.update(TRANSCRIPT_MAGIC + TRANSCRIPT_VERSION.to_bytes(2, "big"))
        sink.update(int(domain).to_bytes(2, "big"))

    def write_field(self, tag: int, length: int, chunks: Iterable[bytes]) -> None:
        if self._failed:
            raise RuntimeError("transcript writer is invalid")
        if self._finished:
            raise RuntimeError("transcript is finalized")
        if isinstance(tag, bool) or not isinstance(tag, int) or not self._last_tag < tag <= 0xFFFF:
            raise ValueError("transcript tags must be unique and strictly increasing")
        if isinstance(length, bool) or not isinstance(length, int):
            raise TypeError("field length must be int")
        if not 0 <= length <= MAX_TRANSCRIPT_FIELD_LENGTH:
            raise ValueError("field length is out of range")
        try:
            self._sink.update(_FIELD_HEADER.pack(tag, length))
            written = 0
            for chunk in chunks:
                if not isinstance(chunk, bytes):
                    raise TypeError("transcript chunks must be bytes")
                written += len(chunk)
                if written > length:
                    raise ValueError("field payload exceeds declared length")
                self._sink.update(chunk)
            if written != length:
                raise ValueError("field payload is shorter than declared length")
        except BaseException:
            # Streaming sinks cannot be rolled back. A partial transcript and
            # its digest must never be finalized or reused.
            self._failed = True
            raise
        self._last_tag = tag

    def write_bytes(self, tag: int, value: bytes) -> None:
        if not isinstance(value, bytes):
            raise TypeError("field value must be bytes")
        self.write_field(tag, len(value), (value,))

    def finish(self) -> None:
        if self._failed:
            raise RuntimeError("transcript writer is invalid")
        if self._finished:
            raise RuntimeError("transcript is already finalized")
        self._finished = True


class _BufferSink:
    def __init__(self) -> None:
        self.buffer = io.BytesIO()

    def update(self, data: bytes) -> None:
        self.buffer.write(data)


def encode_transcript(
    domain: DomainIdV3,
    fields: Iterable[tuple[int, bytes]],
) -> bytes:
    sink = _BufferSink()
    writer = TranscriptWriter(sink, domain)
    for tag, value in fields:
        writer.write_bytes(tag, value)
    writer.finish()
    return sink.buffer.getvalue()
