import hashlib
import json
import struct
from pathlib import Path
from typing import Any, Callable

from sigma.anchors import StreamWide
from sigma.presets import reference_v2_2
from sigma.rounds import WideOnce

VECTOR_PATH = Path(__file__).parents[2] / "specification" / "test-vectors" / "conformance-v2-2.json"


def _vector() -> dict[str, Any]:
    corpus = json.loads(VECTOR_PATH.read_text(encoding="utf-8"))
    return next(
        vector for vector in corpus["suites"] if vector["name"] == "reference-stream-wide-v2-2"
    )


def _tlv(*fields):
    return b"".join(struct.pack(">HI", tag, len(value)) + value for tag, value in fields)


def _domain(identifier: int) -> bytes:
    return b"SIGMADST" + struct.pack(">H", identifier)


def test_v22_vector_matches_independent_literal_reference() -> None:
    vector = _vector()
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
    assert evidence.hex() == vector["anchor_evidence_hex"]

    state = hashlib.sha3_512(_domain(4) + _tlv((1, context_bytes), (2, evidence))).digest()
    states = [state]
    for index in range(4):
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
    assert [state.hex() for state in states] == vector["states_hex"]
    selected = states[2:5]
    digest = (
        b"SIGMADG2\x00"
        + struct.pack(">I", len(context_bytes))
        + context_bytes
        + struct.pack(">H", len(selected))
        + b"".join(struct.pack(">H", len(state)) + state for state in selected)
    )
    assert digest.hex() == vector["digest_hex"]


def test_v22_vector_matches_public_implementation() -> None:
    vector = _vector()
    context = reference_v2_2(target_round=2, state_count=3)
    anchor = StreamWide.compute(context, (bytes.fromhex(vector["message_hex"]),))
    digest, transcript = WideOnce(context).evaluate(anchor)
    assert context.to_bytes().hex() == vector["context_hex"]
    assert anchor.to_bytes().hex() == vector["anchor_evidence_hex"]
    assert [state.hex() for state in transcript.states] == vector["states_hex"]
    assert digest.to_bytes().hex() == vector["digest_hex"]
