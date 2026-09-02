import hashlib
import json
import struct
from pathlib import Path
from typing import Any, Callable

from sigma.anchors import StreamWide
from sigma.rounds import WideOnce
from sigma.spec import SigmaContextV2, SuiteId
from sigma.vectors import REFERENCE_STREAM_WIDE_ABC

VECTOR_PATH = (
    Path(__file__).parents[2]
    / "specification"
    / "test-vectors"
    / "reference-stream-wide-v2-draft1.json"
)
VECTOR_V22_PATH = (
    Path(__file__).parents[2]
    / "specification"
    / "test-vectors"
    / "reference-stream-wide-v2-2.json"
)


def _tlv(*fields):
    return b"".join(struct.pack(">HI", tag, len(value)) + value for tag, value in fields)


def _domain(identifier: int) -> bytes:
    return b"SIGMADST" + struct.pack(">H", identifier)


def test_vector_matches_independent_literal_reference() -> None:
    vector = json.loads(VECTOR_PATH.read_text(encoding="utf-8"))
    message = bytes.fromhex(vector["message_hex"])
    context_bytes = bytes.fromhex(vector["context_hex"])
    algorithms: tuple[tuple[int, Callable[..., Any]], ...] = (
        (1, hashlib.sha512),
        (2, hashlib.sha3_512),
        (3, lambda data: hashlib.blake2b(data, digest_size=64)),
        (4, hashlib.shake_256),
    )
    roots = []
    for index, (algorithm_id, constructor) in enumerate(algorithms):
        descriptor = _tlv(
            (1, struct.pack(">H", index)),
            (2, struct.pack(">H", algorithm_id)),
            (3, context_bytes),
        )
        hasher = constructor(
            _domain(1) + descriptor + message + _domain(2) + struct.pack(">Q", len(message))
        )
        roots.append(hasher.digest(64) if algorithm_id == 4 else hasher.digest())
    assert [root.hex() for root in roots] == vector["roots_hex"]

    anchor = _domain(3) + struct.pack(">H", 4)
    for algorithm_id, root in zip(range(1, 5), roots, strict=False):
        anchor += struct.pack(">HH", algorithm_id, len(root)) + root
    anchor += struct.pack(">Q", len(message))

    state = hashlib.sha3_512(_domain(4) + _tlv((1, context_bytes), (2, anchor))).digest()
    states = [state]
    for index in range(2):
        state = hashlib.sha3_512(
            _domain(5)
            + _tlv(
                (1, context_bytes),
                (2, struct.pack(">Q", index)),
                (3, anchor),
                (4, state),
            )
        ).digest()
        states.append(state)
    assert [state.hex() for state in states] == vector["transcript_states_hex"]


def test_vector_matches_public_implementation() -> None:
    vector = json.loads(VECTOR_PATH.read_text(encoding="utf-8"))
    context = SigmaContextV2(target_round=vector["target_round"], state_count=vector["state_count"])
    assert context.to_bytes().hex() == vector["context_hex"]
    anchor = StreamWide.compute(context, (bytes.fromhex(vector["message_hex"]),))
    digest, transcript = WideOnce(context).evaluate(anchor)
    assert [root.hex() for root in anchor.roots] == vector["roots_hex"]
    assert [state.hex() for state in transcript.states] == vector["transcript_states_hex"]
    assert digest.to_bytes().hex() == vector["digest_hex"]


def test_runtime_vector_matches_frozen_specification() -> None:
    vector = json.loads(VECTOR_PATH.read_text(encoding="utf-8"))
    assert {
        "digest_hex": vector["digest_hex"],
        "message_hex": vector["message_hex"],
        "name": f"{vector['suite']}/abc/t1/k2",
        "state_count": vector["state_count"],
        "target_round": vector["target_round"],
    } == REFERENCE_STREAM_WIDE_ABC


def test_v22_vector_matches_independent_literal_reference() -> None:
    vector = json.loads(VECTOR_V22_PATH.read_text(encoding="utf-8"))
    message = bytes.fromhex(vector["message_hex"])
    context_bytes = bytes.fromhex(vector["context_hex"])
    algorithms: tuple[tuple[int, Callable[..., Any]], ...] = (
        (1, hashlib.sha512),
        (2, hashlib.sha3_512),
        (3, lambda data: hashlib.blake2b(data, digest_size=64)),
        (4, hashlib.shake_256),
    )
    roots = []
    for index, (algorithm_id, constructor) in enumerate(algorithms):
        descriptor = _tlv(
            (1, struct.pack(">H", index)),
            (2, struct.pack(">H", algorithm_id)),
            (3, context_bytes),
        )
        hasher = constructor(
            _domain(1) + descriptor + message + _domain(2) + struct.pack(">Q", len(message))
        )
        roots.append(hasher.digest(64) if algorithm_id == 4 else hasher.digest())
    assert [root.hex() for root in roots] == vector["roots_hex"]

    components = struct.pack(">H", len(roots)) + b"".join(
        struct.pack(">HH", algorithm_id, len(root)) + root
        for (algorithm_id, _), root in zip(algorithms, roots, strict=True)
    )
    body = _tlv((1, struct.pack(">Q", len(message))), (2, components))
    evidence = b"SIGMAAE" + struct.pack(">HHHI", 2, 1, 0x0101, len(body)) + body
    assert evidence.hex() == vector["evidence_hex"]

    state = hashlib.sha3_512(_domain(4) + _tlv((1, context_bytes), (2, evidence))).digest()
    states = [state]
    for index in range(2):
        state = hashlib.sha3_512(
            _domain(5)
            + _tlv(
                (1, context_bytes),
                (2, struct.pack(">Q", index)),
                (3, evidence),
                (4, state),
            )
        ).digest()
        states.append(state)
    assert [state.hex() for state in states] == vector["transcript_states_hex"]
    selected = states[1:3]
    digest = (
        b"SIGMADG2\x00"
        + struct.pack(">I", len(context_bytes))
        + context_bytes
        + struct.pack(">H", len(selected))
        + b"".join(struct.pack(">H", len(state)) + state for state in selected)
    )
    assert digest.hex() == vector["digest_hex"]


def test_v22_vector_matches_public_implementation() -> None:
    vector = json.loads(VECTOR_V22_PATH.read_text(encoding="utf-8"))
    context = SigmaContextV2(suite_id=SuiteId.REFERENCE_STREAM_WIDE_V2_2)
    anchor = StreamWide.compute(context, (bytes.fromhex(vector["message_hex"]),))
    digest, transcript = WideOnce(context).evaluate(anchor)
    assert context.to_bytes().hex() == vector["context_hex"]
    assert anchor.to_bytes().hex() == vector["evidence_hex"]
    assert [state.hex() for state in transcript.states] == vector["transcript_states_hex"]
    assert digest.to_bytes().hex() == vector["digest_hex"]
