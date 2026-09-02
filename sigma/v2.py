"""Safe, explicit facade for the Sigma v2 reference construction."""

import hmac
from dataclasses import dataclass
from typing import BinaryIO, Iterable, Optional, Union

from sigma.anchors import (
    AnchorEvidence,
    CrossWide,
    CrossWideEvidence,
    StreamWide,
    TreeWide,
)
from sigma.backends import SERIAL_BACKEND, ExecutionBackend, FileExecutionBackend
from sigma.file_snapshot import FileIdentity, immutable_snapshot, stable_open
from sigma.outputs import SigmaDigestV2
from sigma.policy import DEFAULT_RESOURCE_POLICY, PolicyViolation, ResourcePolicy
from sigma.rounds import Deep, RoundTranscript, TraceConfig, WideOnce
from sigma.spec import SigmaContextV2
from sigma.spec.ids import AnchorProfileId, RoundProfileId
from sigma.validation import ValidationError, require_int

DEFAULT_READ_SIZE = 64 * 1024


@dataclass(frozen=True)
class FileHashResult:
    digest: SigmaDigestV2
    source: FileIdentity


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


def hash_chunks(
    chunks: Iterable[bytes],
    context: Optional[SigmaContextV2] = None,
    *,
    policy: ResourcePolicy = DEFAULT_RESOURCE_POLICY,
) -> SigmaDigestV2:
    selected_context = context if context is not None else SigmaContextV2()
    policy.validate_context(selected_context)
    engine = _anchor_engine(selected_context)
    total = 0
    for chunk in chunks:
        if not isinstance(chunk, bytes):
            raise TypeError("message chunks must be bytes")
        total += len(chunk)
        policy.validate_message_size(total)
        engine.update(chunk)
    anchor = engine.finalize()
    return _round_engine(selected_context).evaluate_digest(anchor)


def hash_bytes(
    data: bytes,
    context: Optional[SigmaContextV2] = None,
    backend: Optional[ExecutionBackend] = None,
    *,
    policy: ResourcePolicy = DEFAULT_RESOURCE_POLICY,
) -> SigmaDigestV2:
    if not isinstance(data, bytes):
        raise TypeError("data must be bytes")
    selected_context = context if context is not None else SigmaContextV2()
    policy.validate_context(selected_context)
    policy.validate_message_size(len(data))
    selected_backend = backend if backend is not None else SERIAL_BACKEND
    if not isinstance(selected_backend, ExecutionBackend):
        raise TypeError("backend must implement ExecutionBackend")
    anchor = selected_backend.compute_anchor(data, selected_context)
    return _round_engine(selected_context).evaluate_digest(anchor)


def hash_text(
    text: str,
    context: Optional[SigmaContextV2] = None,
    *,
    policy: ResourcePolicy = DEFAULT_RESOURCE_POLICY,
) -> SigmaDigestV2:
    """Hash Unicode text using the single normative UTF-8 encoding."""

    if not isinstance(text, str):
        raise TypeError("text must be str")
    return hash_bytes(text.encode("utf-8"), context, policy=policy)


def hash_reader(
    reader: BinaryIO,
    context: Optional[SigmaContextV2] = None,
    read_size: int = DEFAULT_READ_SIZE,
    *,
    policy: ResourcePolicy = DEFAULT_RESOURCE_POLICY,
) -> SigmaDigestV2:
    try:
        require_int("read_size", read_size, minimum=1, maximum=(1 << 63) - 1)
    except ValidationError:
        raise ValidationError("read_size must be a positive integer") from None
    selected_context = context if context is not None else SigmaContextV2()
    policy.validate_context(selected_context)
    anchor_engine = _anchor_engine(selected_context)
    total = 0
    while True:
        chunk = reader.read(read_size)
        if not isinstance(chunk, bytes):
            raise TypeError("binary reader must return bytes")
        if not chunk:
            break
        total += len(chunk)
        policy.validate_message_size(total)
        anchor_engine.update(chunk)
    return _round_engine(selected_context).evaluate_digest(anchor_engine.finalize())


def hash_file(
    path,
    context: Optional[SigmaContextV2] = None,
    backend: Optional[FileExecutionBackend] = None,
    *,
    policy: ResourcePolicy = DEFAULT_RESOURCE_POLICY,
) -> SigmaDigestV2:
    return hash_file_with_snapshot(path, context, backend, policy=policy).digest


def hash_file_with_snapshot(
    path,
    context: Optional[SigmaContextV2] = None,
    backend: Optional[FileExecutionBackend] = None,
    *,
    policy: ResourcePolicy = DEFAULT_RESOURCE_POLICY,
) -> FileHashResult:
    selected_context = context if context is not None else SigmaContextV2()
    policy.validate_context(selected_context)
    if backend is None:
        with stable_open(path) as (reader, identity):
            policy.validate_message_size(identity.size)
            digest = hash_reader(reader, selected_context, policy=policy)
        return FileHashResult(digest, identity)
    if not isinstance(backend, FileExecutionBackend):
        raise TypeError("file backend must implement FileExecutionBackend")
    with immutable_snapshot(path) as (snapshot, identity):
        policy.validate_message_size(identity.size)
        anchor = backend.compute_anchor_file(snapshot, selected_context)
        digest = _round_engine(selected_context).evaluate_digest(anchor)
    return FileHashResult(digest, identity)


def trace_bytes(
    data: bytes,
    context: Optional[SigmaContextV2] = None,
    trace: Optional[TraceConfig] = None,
) -> RoundTranscript:
    """Return a diagnostic transcript; do not persist secret-bearing traces."""

    if not isinstance(data, bytes):
        raise TypeError("data must be bytes")
    selected_context = context if context is not None else SigmaContextV2()
    engine = _anchor_engine(selected_context)
    engine.update(data)
    anchor = engine.finalize()
    _, transcript = _round_engine(selected_context).evaluate_trace(anchor, trace)
    return transcript


def verify_full(
    data: bytes,
    digest: SigmaDigestV2,
    *,
    policy: ResourcePolicy = DEFAULT_RESOURCE_POLICY,
) -> bool:
    """Recompute the complete anchor and trajectory for the supplied message."""

    if not isinstance(digest, SigmaDigestV2):
        raise TypeError("digest must be SigmaDigestV2")
    try:
        expected = hash_bytes(data, digest.context, policy=policy)
    except PolicyViolation:
        return False
    return hmac.compare_digest(expected.to_bytes(), digest.to_bytes())


def verify_full_file(
    path,
    digest: SigmaDigestV2,
    *,
    policy: ResourcePolicy = DEFAULT_RESOURCE_POLICY,
) -> bool:
    if not isinstance(digest, SigmaDigestV2):
        raise TypeError("digest must be SigmaDigestV2")
    try:
        expected = hash_file(path, digest.context, policy=policy)
    except PolicyViolation:
        return False
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
