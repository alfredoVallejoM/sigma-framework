from typing import Any

from sigma.anchors import AnchorEvidence, StreamWide
from sigma.outputs import SigmaDigestV2
from sigma.rounds import WideOnce
from sigma.spec import SigmaContextV2
from sigma.v2 import hash_bytes, verify_full

from .common import derived_random


def _flip(value: bytes, bit: int) -> bytes:
    changed = bytearray(value)
    changed[bit // 8] ^= 1 << (bit % 8)
    return bytes(changed)


def _distance(left: tuple[bytes, ...], right: tuple[bytes, ...]) -> int:
    return sum(
        (a ^ b).bit_count()
        for x, y in zip(left, right, strict=True)
        for a, b in zip(x, y, strict=True)
    )


def run(config: dict[str, Any]) -> list[dict[str, Any]]:
    rng = derived_random(str(config["master_seed"]), "EXP-14/faults")
    records: list[dict[str, Any]] = []
    context = SigmaContextV2(
        target_round=int(config.get("target_round", 2)),
        state_count=int(config.get("state_count", 2)),
    )
    for trial in range(int(config.get("trials", 128))):
        message = rng.randbytes(int(config.get("message_bytes", 64)))
        expected = hash_bytes(message, context)
        bit = rng.randrange(len(message) * 8)
        changed = hash_bytes(_flip(message, bit), context)
        records.append(
            {
                "detected": changed.to_bytes() != expected.to_bytes(),
                "fault_site": "message",
                "model": "bit-flip",
                "output_hamming": _distance(expected.states, changed.states),
                "trial": trial,
            }
        )

        anchor = StreamWide.compute(context, (message,))
        root_index = rng.randrange(len(anchor.roots))
        roots = list(anchor.roots)
        roots[root_index] = _flip(roots[root_index], rng.randrange(len(roots[root_index]) * 8))
        faulty_anchor = AnchorEvidence(anchor.algorithms, tuple(roots), anchor.message_length)
        changed = WideOnce(context).evaluate_digest(faulty_anchor)
        records.append(
            {
                "detected": changed.to_bytes() != expected.to_bytes(),
                "fault_site": "anchor-root",
                "model": "bit-flip",
                "output_hamming": _distance(expected.states, changed.states),
                "trial": trial,
            }
        )

        states = list(expected.states)
        state_index = rng.randrange(len(states))
        states[state_index] = _flip(
            states[state_index], rng.randrange(len(states[state_index]) * 8)
        )
        faulty_digest = SigmaDigestV2(context, tuple(states))
        records.append(
            {
                "detected": not verify_full(message, faulty_digest),
                "fault_site": "published-state",
                "model": "bit-flip",
                "output_hamming": _distance(expected.states, faulty_digest.states),
                "trial": trial,
            }
        )
    return records


def summarize(records: list[dict[str, Any]]) -> list[dict[str, Any]]:
    groups: dict[str, list[dict[str, Any]]] = {}
    for record in records:
        groups.setdefault(str(record["fault_site"]), []).append(record)
    return [
        {
            "detection_rate": sum(bool(row["detected"]) for row in group) / len(group),
            "fault_site": site,
            "mean_output_hamming": sum(int(row["output_hamming"]) for row in group) / len(group),
            "trials": len(group),
        }
        for site, group in sorted(groups.items())
    ]
