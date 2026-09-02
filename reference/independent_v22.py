"""Literal DeepVector v2-2 implementation that never imports :mod:`sigma`."""

import hashlib
import struct
from collections.abc import Callable
from typing import Any

ALGORITHMS: tuple[tuple[int, Callable[..., Any]], ...] = (
    (1, hashlib.sha512),
    (2, hashlib.sha3_512),
    (3, lambda data=b"": hashlib.blake2b(data, digest_size=64)),
    (4, hashlib.shake_256),
)
CONTEXT_MAGIC = b"SIGMACTX"
EVIDENCE_MAGIC = b"SIGMAAE"
DIGEST_MAGIC = b"SIGMADG2\x00"
SUITE_ID = 0x0106


def u16(value: int) -> bytes:
    return struct.pack(">H", value)


def u32(value: int) -> bytes:
    return struct.pack(">I", value)


def u64(value: int) -> bytes:
    return struct.pack(">Q", value)


def tlv(*fields: tuple[int, bytes]) -> bytes:
    return b"".join(struct.pack(">HI", tag, len(value)) + value for tag, value in fields)


def domain(identifier: int) -> bytes:
    return b"SIGMADST" + u16(identifier)


def hash_branch(algorithm: int, data: bytes) -> bytes:
    constructor = dict(ALGORITHMS)[algorithm]
    hasher = constructor(data)
    return hasher.digest(64) if algorithm == 4 else hasher.digest()


def context_bytes(
    target_round: int,
    state_count: int,
    *,
    salt: bytes = b"",
    challenge: bytes = b"",
    application_context: bytes = b"",
) -> bytes:
    branches = u16(len(ALGORITHMS)) + b"".join(u16(identifier) for identifier, _ in ALGORITHMS)
    body = tlv(
        (1, u16(SUITE_ID)),
        (2, u16(3)),
        (3, u16(3)),
        (4, u16(1)),
        (5, u32(target_round)),
        (6, u16(state_count)),
        (7, branches),
        (8, u32(0)),
        (9, salt),
        (10, challenge),
        (11, application_context),
    )
    return CONTEXT_MAGIC + u16(2) + u32(len(body)) + body


def encode_components(values: list[bytes]) -> bytes:
    return u16(len(values)) + b"".join(
        u16(algorithm) + u16(len(value)) + value
        for (algorithm, _), value in zip(ALGORITHMS, values, strict=True)
    )


def evidence_envelope(evidence_type: int, body: bytes) -> bytes:
    return EVIDENCE_MAGIC + u16(2) + u16(evidence_type) + u16(SUITE_ID) + u32(len(body)) + body


def cross_evidence(message: bytes, context: bytes) -> tuple[bytes, list[bytes], list[bytes]]:
    roots = []
    for position, (algorithm, _) in enumerate(ALGORITHMS):
        descriptor = tlv((1, u16(position)), (2, u16(algorithm)), (3, context))
        roots.append(
            hash_branch(algorithm, domain(1) + descriptor + message + domain(2) + u64(len(message)))
        )
    wide_body = tlv((1, u64(len(message))), (2, encode_components(roots)))
    wide_evidence = evidence_envelope(1, wide_body)
    cross_roots = [
        hash_branch(
            algorithm, domain(6) + tlv((1, u16(position)), (2, context), (3, wide_evidence))
        )
        for position, (algorithm, _) in enumerate(ALGORITHMS)
    ]
    body = tlv(
        (1, u64(len(message))),
        (2, encode_components(roots)),
        (3, encode_components(cross_roots)),
    )
    return evidence_envelope(2, body), roots, cross_roots


def deep_vector(
    message: bytes,
    target_round: int = 1,
    state_count: int = 2,
    *,
    salt: bytes = b"",
    challenge: bytes = b"",
    application_context: bytes = b"",
) -> dict[str, Any]:
    context = context_bytes(
        target_round,
        state_count,
        salt=salt,
        challenge=challenge,
        application_context=application_context,
    )
    evidence, roots, cross_roots = cross_evidence(message, context)
    initial_common = tlv((1, context), (2, evidence))
    components = [
        hash_branch(algorithm, domain(14) + initial_common + tlv((3, u16(position))))
        for position, (algorithm, _) in enumerate(ALGORITHMS)
    ]
    vector = b"".join(components)
    vectors = [vector]
    component_rows = [components]
    for index in range(target_round + state_count - 1):
        common = tlv((1, context), (2, u64(index)), (3, evidence), (4, vector))
        components = [
            hash_branch(algorithm, domain(15) + common + tlv((5, u16(position))))
            for position, (algorithm, _) in enumerate(ALGORITHMS)
        ]
        vector = b"".join(components)
        vectors.append(vector)
        component_rows.append(components)
    published = vectors[-state_count:]
    encoded_states = b"".join(u16(len(state)) + state for state in published)
    digest = DIGEST_MAGIC + u32(len(context)) + context + u16(len(published)) + encoded_states
    return {
        "context": context,
        "roots": roots,
        "cross_roots": cross_roots,
        "evidence": evidence,
        "vectors": vectors,
        "components": component_rows,
        "digest": digest,
    }
