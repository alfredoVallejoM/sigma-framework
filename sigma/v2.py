"""Safe, explicit facade for the Sigma v2 reference construction."""

import hmac
import os
from typing import BinaryIO, Iterable, Optional, Union

from sigma.anchors import (
    AnchorEvidence,
    CrossWide,
    CrossWideEvidence,
    StreamWide,
    TreeWide,
)
from sigma.backends import SERIAL_BACKEND, ExecutionBackend, FileExecutionBackend
from sigma.outputs import SigmaDigestV2
from sigma.rounds import Deep, RoundTranscript, WideOnce
from sigma.spec import SigmaContextV2
from sigma.spec.ids import AnchorProfileId, RoundProfileId

DEFAULT_READ_SIZE = 64 * 1024


def _anchor_engine(context: SigmaContextV2):
    if context.anchor_profile is AnchorProfileId.STREAM_WIDE:
        return StreamWide(context)
    if context.anchor_profile is AnchorProfileId.CROSS_WIDE:
        return CrossWide(context)
    if context.anchor_profile is AnchorProfileId.TREE_WIDE:
        return TreeWide(context)
    raise ValueError(f"unsupported anchor profile: {context.anchor_profile.name}")


def _round_engine(context: SigmaContextV2):
    if context.round_profile is RoundProfileId.WIDE_ONCE:
        return WideOnce(context)
    if context.round_profile is RoundProfileId.DEEP:
        return Deep(context)
    raise ValueError(f"unsupported round profile: {context.round_profile.name}")


def hash_chunks(chunks: Iterable[bytes], context: Optional[SigmaContextV2] = None) -> SigmaDigestV2:
    selected_context = context if context is not None else SigmaContextV2()
    engine = _anchor_engine(selected_context)
    for chunk in chunks:
        engine.update(chunk)
    anchor = engine.finalize()
    digest, _ = _round_engine(selected_context).evaluate(anchor)
    return digest


def hash_bytes(
    data: bytes,
    context: Optional[SigmaContextV2] = None,
    backend: Optional[ExecutionBackend] = None,
) -> SigmaDigestV2:
    if not isinstance(data, bytes):
        raise TypeError("data must be bytes")
    selected_context = context if context is not None else SigmaContextV2()
    selected_backend = backend if backend is not None else SERIAL_BACKEND
    if not isinstance(selected_backend, ExecutionBackend):
        raise TypeError("backend must implement ExecutionBackend")
    anchor = selected_backend.compute_anchor(data, selected_context)
    digest, _ = _round_engine(selected_context).evaluate(anchor)
    return digest


def hash_text(text: str, context: Optional[SigmaContextV2] = None) -> SigmaDigestV2:
    """Hash Unicode text using the single normative UTF-8 encoding."""

    if not isinstance(text, str):
        raise TypeError("text must be str")
    return hash_bytes(text.encode("utf-8"), context)


def hash_reader(
    reader: BinaryIO,
    context: Optional[SigmaContextV2] = None,
    read_size: int = DEFAULT_READ_SIZE,
) -> SigmaDigestV2:
    if isinstance(read_size, bool) or not isinstance(read_size, int) or read_size <= 0:
        raise ValueError("read_size must be a positive integer")
    selected_context = context if context is not None else SigmaContextV2()
    anchor_engine = _anchor_engine(selected_context)
    while True:
        chunk = reader.read(read_size)
        if not isinstance(chunk, bytes):
            raise TypeError("binary reader must return bytes")
        if not chunk:
            break
        anchor_engine.update(chunk)
    digest, _ = _round_engine(selected_context).evaluate(anchor_engine.finalize())
    return digest


def hash_file(
    path,
    context: Optional[SigmaContextV2] = None,
    backend: Optional[FileExecutionBackend] = None,
) -> SigmaDigestV2:
    selected_context = context if context is not None else SigmaContextV2()
    if backend is None:
        with open(os.fspath(path), "rb") as reader:
            return hash_reader(reader, selected_context)
    if not isinstance(backend, FileExecutionBackend):
        raise TypeError("file backend must implement FileExecutionBackend")
    anchor = backend.compute_anchor_file(path, selected_context)
    digest, _ = _round_engine(selected_context).evaluate(anchor)
    return digest


def trace_bytes(data: bytes, context: Optional[SigmaContextV2] = None) -> RoundTranscript:
    """Return a diagnostic transcript; do not persist secret-bearing traces."""

    if not isinstance(data, bytes):
        raise TypeError("data must be bytes")
    selected_context = context if context is not None else SigmaContextV2()
    engine = _anchor_engine(selected_context)
    engine.update(data)
    anchor = engine.finalize()
    _, transcript = _round_engine(selected_context).evaluate(anchor)
    return transcript


def verify_full(data: bytes, digest: SigmaDigestV2) -> bool:
    """Recompute the complete anchor and trajectory for the supplied message."""

    if not isinstance(digest, SigmaDigestV2):
        raise TypeError("digest must be SigmaDigestV2")
    expected = hash_bytes(data, digest.context)
    return hmac.compare_digest(expected.to_bytes(), digest.to_bytes())


def verify_full_file(path, digest: SigmaDigestV2) -> bool:
    if not isinstance(digest, SigmaDigestV2):
        raise TypeError("digest must be SigmaDigestV2")
    expected = hash_file(path, digest.context)
    return hmac.compare_digest(expected.to_bytes(), digest.to_bytes())


def verify_adjacent_only(
    context: SigmaContextV2,
    anchor: Union[AnchorEvidence, CrossWideEvidence],
    index: int,
    state: bytes,
    successor: bytes,
) -> bool:
    """Verify one transition only; this does not prove the preceding history."""

    expected = _round_engine(context).next_state(anchor, index, state)
    return hmac.compare_digest(expected, successor)
