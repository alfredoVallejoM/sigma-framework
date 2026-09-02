"""Deterministic reduced-width PRF model used only by simulation experiments."""

import hashlib
from dataclasses import dataclass


def encode_integer(value: int, bits: int) -> bytes:
    width = (bits + 7) // 8
    return value.to_bytes(width, "big")


@dataclass(frozen=True)
class ReducedOracle:
    seed: bytes

    def query(self, domain: str, bits: int, *parts: bytes) -> int:
        if not 1 <= bits <= 256:
            raise ValueError("reduced oracle width must be in [1, 256]")
        framed = [b"SIGMA-REDUCED-ORACLE-v1", len(self.seed).to_bytes(2, "big"), self.seed]
        domain_bytes = domain.encode("ascii")
        framed.extend((len(domain_bytes).to_bytes(2, "big"), domain_bytes))
        for part in parts:
            framed.extend((len(part).to_bytes(4, "big"), part))
        value = int.from_bytes(hashlib.sha256(b"".join(framed)).digest(), "big")
        return value & ((1 << bits) - 1)


def trajectory(
    oracle: ReducedOracle,
    candidate: int,
    n: int,
    anchor_bits: int,
    target_round: int,
    state_count: int,
    reinjected: bool,
) -> tuple[int, tuple[int, ...]]:
    candidate_bytes = candidate.to_bytes(16, "big")
    anchor = oracle.query("anchor", anchor_bits, candidate_bytes)
    anchor_bytes = encode_integer(anchor, anchor_bits)
    state = oracle.query("init", n, anchor_bytes)
    states = [state]
    last = target_round + state_count - 1
    for index in range(last):
        parts = [index.to_bytes(8, "big"), encode_integer(state, n)]
        if reinjected:
            parts.insert(0, anchor_bytes)
        state = oracle.query("round-reinjected" if reinjected else "round-simple", n, *parts)
        states.append(state)
    return anchor, tuple(states[target_round : last + 1])
