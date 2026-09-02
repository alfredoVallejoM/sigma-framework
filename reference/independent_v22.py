"""Literal Sigma v2.2 consumer that never imports :mod:`sigma`.

This intentionally duplicates the wire format and construction.  Its purpose is
to detect specification/implementation drift, not to provide another public API.
"""

import hashlib
import struct
from collections.abc import Callable
from dataclasses import dataclass
from typing import Any

ALGORITHMS: tuple[tuple[int, Callable[..., Any]], ...] = (
    (1, hashlib.sha512),
    (2, hashlib.sha3_512),
    (3, lambda data=b"": hashlib.blake2b(data, digest_size=64)),
    (4, hashlib.shake_256),
)
LIGHT_ALGORITHMS = ALGORITHMS[:2]
CONTEXT_MAGIC = b"SIGMACTX"
EVIDENCE_MAGIC = b"SIGMAAE"
DIGEST_MAGIC = b"SIGMADG2\x00"


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
    suite_id: int,
    anchor_profile: int,
    round_profile: int,
    algorithms: tuple[tuple[int, Callable[..., Any]], ...],
    target_round: int,
    state_count: int,
    *,
    chunk_size: int = 0,
    salt: bytes = b"",
    challenge: bytes = b"",
    application_context: bytes = b"",
) -> bytes:
    branches = u16(len(algorithms)) + b"".join(u16(identifier) for identifier, _ in algorithms)
    body = tlv(
        (1, u16(suite_id)),
        (2, u16(anchor_profile)),
        (3, u16(round_profile)),
        (4, u16(1)),
        (5, u32(target_round)),
        (6, u16(state_count)),
        (7, branches),
        (8, u32(chunk_size)),
        (9, salt),
        (10, challenge),
        (11, application_context),
    )
    return CONTEXT_MAGIC + u16(2) + u32(len(body)) + body


def encode_components(
    algorithms: tuple[tuple[int, Callable[..., Any]], ...], values: list[bytes]
) -> bytes:
    return u16(len(values)) + b"".join(
        u16(algorithm) + u16(len(value)) + value
        for (algorithm, _), value in zip(algorithms, values, strict=True)
    )


def evidence_envelope(suite_id: int, evidence_type: int, body: bytes) -> bytes:
    return EVIDENCE_MAGIC + u16(2) + u16(evidence_type) + u16(suite_id) + u32(len(body)) + body


def wide_evidence(
    message: bytes,
    context: bytes,
    suite_id: int,
    algorithms: tuple[tuple[int, Callable[..., Any]], ...],
    *,
    evidence_version: int = 2,
) -> tuple[bytes, list[bytes]]:
    roots = []
    for position, (algorithm, _) in enumerate(algorithms):
        descriptor = tlv((1, u16(position)), (2, u16(algorithm)), (3, context))
        roots.append(
            hash_branch(algorithm, domain(1) + descriptor + message + domain(2) + u64(len(message)))
        )
    if evidence_version == 1:
        evidence = (
            domain(3)
            + u16(len(roots))
            + b"".join(
                u16(algorithm) + u16(len(root)) + root
                for (algorithm, _), root in zip(algorithms, roots, strict=True)
            )
        )
        return evidence + u64(len(message)), roots
    body = tlv((1, u64(len(message))), (2, encode_components(algorithms, roots)))
    return evidence_envelope(suite_id, 1, body), roots


def cross_evidence(
    message: bytes,
    context: bytes,
    suite_id: int,
    algorithms: tuple[tuple[int, Callable[..., Any]], ...],
    *,
    evidence_version: int = 2,
) -> tuple[bytes, list[bytes], list[bytes]]:
    wide, roots = wide_evidence(
        message, context, suite_id, algorithms, evidence_version=evidence_version
    )
    cross_roots = [
        hash_branch(algorithm, domain(6) + tlv((1, u16(position)), (2, context), (3, wide)))
        for position, (algorithm, _) in enumerate(algorithms)
    ]
    if evidence_version == 1:
        evidence = domain(3) + u16(3) + encode_components(algorithms, roots)
        evidence += encode_components(algorithms, cross_roots) + u64(len(message))
        return evidence, roots, cross_roots
    body = tlv(
        (1, u64(len(message))),
        (2, encode_components(algorithms, roots)),
        (3, encode_components(algorithms, cross_roots)),
    )
    return evidence_envelope(suite_id, 2, body), roots, cross_roots


def encode_digest(context: bytes, states: list[bytes]) -> bytes:
    encoded_states = b"".join(u16(len(state)) + state for state in states)
    return DIGEST_MAGIC + u32(len(context)) + context + u16(len(states)) + encoded_states


def sequential_suite(
    message: bytes,
    suite_id: int,
    anchor_profile: int,
    round_profile: int,
    target_round: int = 1,
    state_count: int = 2,
    *,
    algorithms: tuple[tuple[int, Callable[..., Any]], ...] = ALGORITHMS,
    chunk_size: int = 0,
    salt: bytes = b"",
    challenge: bytes = b"",
    application_context: bytes = b"",
    evidence_version: int = 2,
) -> dict[str, Any]:
    """Evaluate Stream/Cross v2.2 with WideOnce or Deep rounds."""

    context = context_bytes(
        suite_id,
        anchor_profile,
        round_profile,
        algorithms,
        target_round,
        state_count,
        chunk_size=chunk_size,
        salt=salt,
        challenge=challenge,
        application_context=application_context,
    )
    if anchor_profile == 3:
        evidence, roots, cross_roots = cross_evidence(
            message,
            context,
            suite_id,
            algorithms,
            evidence_version=evidence_version,
        )
    else:
        evidence, roots = wide_evidence(
            message,
            context,
            suite_id,
            algorithms,
            evidence_version=evidence_version,
        )
        cross_roots = []
    state = hashlib.sha3_512(domain(4) + tlv((1, context), (2, evidence))).digest()
    states = [state]
    output_rows: list[list[bytes]] = []
    for index in range(target_round + state_count - 1):
        if round_profile == 1:
            state = hashlib.sha3_512(
                domain(5) + tlv((1, context), (2, u64(index)), (3, evidence), (4, state))
            ).digest()
        elif round_profile == 2:
            outputs = [
                hash_branch(
                    algorithm,
                    domain(7)
                    + tlv(
                        (1, context),
                        (2, u64(index)),
                        (3, u16(algorithm)),
                        (4, evidence),
                        (5, state),
                    ),
                )
                for algorithm, _ in algorithms
            ]
            output_rows.append(outputs)
            fold_input = tlv(
                (1, context),
                (2, u64(index)),
                (3, evidence),
                (4, encode_components(algorithms, outputs)),
            )
            state = hashlib.sha3_512(domain(8) + fold_input).digest()
        else:
            raise ValueError("sequential_suite supports only WideOnce and Deep")
        states.append(state)
    published = states[-state_count:]
    return {
        "context": context,
        "roots": roots,
        "cross_roots": cross_roots,
        "evidence": evidence,
        "states": states,
        "branch_outputs": output_rows,
        "digest": encode_digest(context, published),
    }


@dataclass(frozen=True)
class _Node:
    digest: bytes
    start: int
    leaf_count: int
    byte_length: int
    height: int


def tree_suite(
    message: bytes,
    target_round: int = 1,
    state_count: int = 2,
    *,
    chunk_size: int = 65536,
    salt: bytes = b"",
    challenge: bytes = b"",
    application_context: bytes = b"",
) -> dict[str, Any]:
    """Independently construct the simultaneous TreeWide v2.2 suite."""

    suite_id = 0x0103
    context = context_bytes(
        suite_id,
        2,
        1,
        ALGORITHMS,
        target_round,
        state_count,
        chunk_size=chunk_size,
        salt=salt,
        challenge=challenge,
        application_context=application_context,
    )
    roots = []
    for algorithm, _ in ALGORITHMS:
        frontier: list[_Node] = []
        for leaf_index, offset in enumerate(range(0, len(message), chunk_size)):
            leaf = message[offset : offset + chunk_size]
            framed = tlv(
                (1, context),
                (2, u16(algorithm)),
                (3, u64(leaf_index)),
                (4, u32(len(leaf))),
                (5, leaf),
            )
            node = _Node(hash_branch(algorithm, domain(10) + framed), leaf_index, 1, len(leaf), 0)
            while frontier and frontier[-1].leaf_count == node.leaf_count:
                node = _tree_parent(algorithm, context, frontier.pop(), node)
            frontier.append(node)
        if not frontier:
            framed = tlv((1, context), (2, u16(algorithm)), (3, u64(0)))
            roots.append(hash_branch(algorithm, domain(12) + framed))
        else:
            node = frontier[-1]
            for left in reversed(frontier[:-1]):
                node = _tree_parent(algorithm, context, left, node)
            roots.append(node.digest)
    body = tlv((1, u64(len(message))), (2, encode_components(ALGORITHMS, roots)))
    evidence = evidence_envelope(suite_id, 1, body)
    state = hashlib.sha3_512(domain(4) + tlv((1, context), (2, evidence))).digest()
    states = [state]
    for index in range(target_round + state_count - 1):
        state = hashlib.sha3_512(
            domain(5) + tlv((1, context), (2, u64(index)), (3, evidence), (4, state))
        ).digest()
        states.append(state)
    return {
        "context": context,
        "roots": roots,
        "evidence": evidence,
        "states": states,
        "digest": encode_digest(context, states[-state_count:]),
    }


def _tree_parent(algorithm: int, context: bytes, left: _Node, right: _Node) -> _Node:
    height = max(left.height, right.height) + 1
    leaf_count = left.leaf_count + right.leaf_count
    byte_length = left.byte_length + right.byte_length
    framed = tlv(
        (1, context),
        (2, u16(algorithm)),
        (3, u32(height)),
        (4, u64(left.start)),
        (5, u64(leaf_count)),
        (6, u64(byte_length)),
        (7, left.digest),
        (8, right.digest),
    )
    return _Node(
        hash_branch(algorithm, domain(11) + framed),
        left.start,
        leaf_count,
        byte_length,
        height,
    )


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
        0x0106,
        3,
        3,
        ALGORITHMS,
        target_round,
        state_count,
        salt=salt,
        challenge=challenge,
        application_context=application_context,
    )
    evidence, roots, cross_roots = cross_evidence(message, context, 0x0106, ALGORITHMS)
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
    return {
        "context": context,
        "roots": roots,
        "cross_roots": cross_roots,
        "evidence": evidence,
        "vectors": vectors,
        "components": component_rows,
        "digest": encode_digest(context, published),
    }
