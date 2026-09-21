"""Normative deterministic byte-stream generator for R15 STAT-01.

The generator defines the exact logical bytes consumed by external batteries.
It never serializes Sigma framing bytes as pseudo-random output: only standard
hash digests or raw Sigma trajectory state bytes are emitted.
"""

from __future__ import annotations

import hashlib
from collections.abc import Iterator

from sigma.rounds.evaluate_v3 import evaluate_v3
from sigma.sources import BytesSource
from sigma.spec.context_v3 import SigmaContextV3
from sigma.spec.ids_v3 import SuiteIdV3

from .r15_stat_adapters import StreamHasherV3, StreamIdentityV3, derive_stream_seed_v3

STAT_CONSTRUCTIONS = (
    "SHA512",
    "SHA3-512",
    "BLAKE2b-512",
    "SHAKE256-512",
    "R12.5-wide",
    "R12.5-deep",
    "R12.5-vector",
    "broken-control",
)
STAT_CORPORA = ("counter", "ff-tail", "alternating")
MESSAGE_BYTES = 128


def validate_stream_identity_v3(identity: StreamIdentityV3) -> None:
    if identity.construction not in STAT_CONSTRUCTIONS:
        raise ValueError("unknown STAT construction")
    if identity.corpus not in STAT_CORPORA:
        raise ValueError("unknown STAT corpus")
    expected = derive_stream_seed_v3(
        identity.freeze_id,
        identity.construction,
        identity.corpus,
        identity.stream_id,
    ).hex()
    if identity.seed_hex != expected:
        raise ValueError("stream identity seed does not match its labels")


def stat_message_v3(seed: bytes, corpus: str, counter: int) -> bytes:
    if len(seed) != 32:
        raise ValueError("STAT seed must contain exactly 32 bytes")
    if corpus not in STAT_CORPORA:
        raise ValueError("unknown STAT corpus")
    if counter < 0 or counter >= 1 << 64:
        raise ValueError("STAT message counter must fit uint64")

    prefix = seed + counter.to_bytes(8, "big")
    if corpus == "counter":
        suffix = bytes(MESSAGE_BYTES - len(prefix))
    elif corpus == "ff-tail":
        suffix = bytes(24) + bytes([0xFF]) * 64
    else:
        suffix = (b"\xaa\x55" * 44)
    message = prefix + suffix
    if len(message) != MESSAGE_BYTES:
        raise RuntimeError("STAT corpus message width drifted")
    return message


def _sigma_context(seed: bytes, construction: str, corpus: str) -> SigmaContextV3:
    suite = {
        "R12.5-wide": SuiteIdV3.REFERENCE_IAP_HISTORY_V3,
        "R12.5-deep": SuiteIdV3.DEEP_HISTORY_V3,
        "R12.5-vector": SuiteIdV3.DEEP_VECTOR_HISTORY_V3,
    }[construction]
    salt = hashlib.sha256(b"sigma-r15-stat-salt\0" + seed).digest()
    challenge = hashlib.sha256(b"sigma-r15-stat-challenge\0" + seed).digest()
    application_context = (
        b"sigma-v3-r15-stat-stream-v1\0"
        + construction.encode("ascii")
        + b"\0"
        + corpus.encode("ascii")
    )
    return SigmaContextV3.for_suite(
        suite,
        salt=salt,
        challenge=challenge,
        application_context=application_context,
    )


def _standard_output(construction: str, message: bytes) -> bytes:
    if construction == "SHA512":
        return hashlib.sha512(message).digest()
    if construction == "SHA3-512":
        return hashlib.sha3_512(message).digest()
    if construction == "BLAKE2b-512":
        return hashlib.blake2b(message, digest_size=64).digest()
    if construction == "SHAKE256-512":
        return hashlib.shake_256(message).digest(64)
    if construction == "broken-control":
        digest = hashlib.sha512(message).digest()
        return digest[:32] + digest[:32]
    raise ValueError("construction is not a standard/broken output")


class StatStreamGeneratorV3:
    def __init__(self, identity: StreamIdentityV3) -> None:
        validate_stream_identity_v3(identity)
        self.identity = identity
        self._seed = bytes.fromhex(identity.seed_hex)
        self._context = (
            _sigma_context(self._seed, identity.construction, identity.corpus)
            if identity.construction.startswith("R12.5-")
            else None
        )

    def output_block(self, counter: int) -> bytes:
        message = stat_message_v3(self._seed, self.identity.corpus, counter)
        if self._context is None:
            return _standard_output(self.identity.construction, message)
        evaluation = evaluate_v3(self._context, BytesSource(message))
        states = evaluation.window.states
        if not states:
            raise RuntimeError("Sigma STAT evaluation returned an empty window")
        return b"".join(states)

    def iter_chunks(self, *, emit_chunk_bytes: int = 1 << 20) -> Iterator[bytes]:
        if emit_chunk_bytes <= 0:
            raise ValueError("emit_chunk_bytes must be positive")
        remaining = self.identity.total_bytes
        buffer = bytearray()
        counter = 0
        while remaining > 0:
            block = self.output_block(counter)
            counter += 1
            if not block:
                raise RuntimeError("STAT construction emitted an empty block")
            take = min(len(block), remaining)
            buffer.extend(block[:take])
            remaining -= take
            while len(buffer) >= emit_chunk_bytes:
                yield bytes(buffer[:emit_chunk_bytes])
                del buffer[:emit_chunk_bytes]
        if buffer:
            yield bytes(buffer)


def hash_stat_stream_v3(
    identity: StreamIdentityV3,
    *,
    emit_chunk_bytes: int = 1 << 20,
) -> dict[str, object]:
    generator = StatStreamGeneratorV3(identity)
    hasher = StreamHasherV3(chunk_bytes=identity.chunk_bytes)
    for chunk in generator.iter_chunks(emit_chunk_bytes=emit_chunk_bytes):
        hasher.update(chunk)
    result = hasher.finish()
    if result["total_bytes"] != identity.total_bytes:
        raise RuntimeError("STAT stream length mismatch")
    return result


__all__ = [
    "MESSAGE_BYTES",
    "STAT_CONSTRUCTIONS",
    "STAT_CORPORA",
    "StatStreamGeneratorV3",
    "hash_stat_stream_v3",
    "stat_message_v3",
    "validate_stream_identity_v3",
]
