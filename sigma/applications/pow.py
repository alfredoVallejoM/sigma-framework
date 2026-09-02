"""A minimal, canonically domain-separated Sigma v2 proof-of-work profile.

Verification recomputes the complete trajectory.  Consequently this module
does not claim asymmetric or "cheap" verification, memory hardness, or ASIC
resistance.
"""

import hmac
from dataclasses import dataclass
from enum import IntEnum

from sigma.outputs import SigmaDigestV2
from sigma.spec import SigmaContextV2
from sigma.spec.encoding import DecodeError, decode_tlv, decode_uint, encode_tlv, encode_uint
from sigma.suites.registry import get_suite
from sigma.v2 import hash_bytes
from sigma.validation import require_int

POW_MAGIC = b"SIGMAPOW2"
MAX_NONCE = (1 << 64) - 1


class PowPredicate(IntEnum):
    SINGLE_STATE = 1
    DUAL_STATE = 2
    CONCATENATED = 3


@dataclass(frozen=True)
class PowParameters:
    challenge: bytes
    target_round: int
    state_count: int
    predicate: PowPredicate
    difficulty_bits: int

    def __post_init__(self) -> None:
        if not isinstance(self.challenge, bytes) or not self.challenge:
            raise ValueError("challenge must be non-empty bytes")
        if not isinstance(self.predicate, PowPredicate):
            raise TypeError("predicate must be PowPredicate")
        require_int("target_round", self.target_round, minimum=0, maximum=1_000_000)
        require_int("state_count", self.state_count, minimum=1, maximum=16)
        require_int("difficulty_bits", self.difficulty_bits, minimum=0, maximum=0xFFFF)
        if self.predicate is PowPredicate.DUAL_STATE and self.state_count < 2:
            raise ValueError("dual-state predicate requires at least two states")
        available = 512 * self.state_count if self.predicate is PowPredicate.CONCATENATED else 512
        if self.difficulty_bits > available:
            raise ValueError(f"difficulty_bits must be at most {available}")
        # Reuse the normative context validation for round/count resource bounds.
        self.context()

    def to_bytes(self) -> bytes:
        return POW_MAGIC + encode_tlv(
            (
                (1, self.challenge),
                (2, encode_uint(self.target_round, 4)),
                (3, encode_uint(self.state_count, 2)),
                (4, encode_uint(self.predicate, 1)),
                (5, encode_uint(self.difficulty_bits, 2)),
            )
        )

    @classmethod
    def from_bytes(cls, data: bytes) -> "PowParameters":
        if not isinstance(data, bytes) or not data.startswith(POW_MAGIC):
            raise DecodeError("invalid PoW parameter magic")
        fields = decode_tlv(data[len(POW_MAGIC) :], allowed_tags=frozenset(range(1, 6)))
        if set(fields) != set(range(1, 6)):
            raise DecodeError("missing PoW parameter fields")
        try:
            return cls(
                challenge=fields[1],
                target_round=decode_uint(fields[2], 4),
                state_count=decode_uint(fields[3], 2),
                predicate=PowPredicate(decode_uint(fields[4], 1)),
                difficulty_bits=decode_uint(fields[5], 2),
            )
        except (TypeError, ValueError) as exc:
            raise DecodeError(f"invalid PoW parameters: {exc}") from exc

    def context(self) -> SigmaContextV2:
        application = encode_tlv(
            (
                (1, POW_MAGIC),
                (2, encode_uint(self.predicate, 1)),
                (3, encode_uint(self.difficulty_bits, 2)),
            )
        )
        return SigmaContextV2(
            target_round=self.target_round,
            state_count=self.state_count,
            challenge=self.challenge,
            application_context=application,
        )


@dataclass(frozen=True)
class PowProof:
    nonce: int
    digest: SigmaDigestV2

    def __post_init__(self) -> None:
        require_int("nonce", self.nonce, minimum=0, maximum=MAX_NONCE)
        if not isinstance(self.digest, SigmaDigestV2):
            raise TypeError("digest must be SigmaDigestV2")


def _message(payload: bytes, nonce: int) -> bytes:
    if not isinstance(payload, bytes):
        raise TypeError("payload must be bytes")
    require_int("nonce", nonce, minimum=0, maximum=MAX_NONCE)
    return POW_MAGIC + encode_tlv(((1, payload), (2, encode_uint(nonce, 8))))


def _has_leading_zero_bits(value: bytes, bits: int) -> bool:
    whole, partial = divmod(bits, 8)
    if any(value[:whole]):
        return False
    return partial == 0 or value[whole] >> (8 - partial) == 0


def accepts(digest: SigmaDigestV2, parameters: PowParameters) -> bool:
    if not isinstance(digest, SigmaDigestV2) or not isinstance(parameters, PowParameters):
        return False
    try:
        expected_context = parameters.context()
        expected_size = get_suite(digest.context.suite_id).state_size
    except (AttributeError, TypeError, ValueError):
        return False
    if (
        len(digest.states) != digest.context.state_count
        or not digest.states
        or any(not isinstance(state, bytes) or len(state) != expected_size for state in digest.states)
    ):
        return False
    if not hmac.compare_digest(digest.context.to_bytes(), expected_context.to_bytes()):
        return False
    bits = parameters.difficulty_bits
    if parameters.predicate is PowPredicate.SINGLE_STATE:
        return _has_leading_zero_bits(digest.states[0], bits)
    if parameters.predicate is PowPredicate.DUAL_STATE:
        return _has_leading_zero_bits(digest.states[0], bits) and _has_leading_zero_bits(
            digest.states[1], bits
        )
    return _has_leading_zero_bits(b"".join(digest.states), bits)


def evaluate_nonce(payload: bytes, nonce: int, parameters: PowParameters) -> PowProof:
    return PowProof(nonce, hash_bytes(_message(payload, nonce), parameters.context()))


def verify(payload: bytes, proof: PowProof, parameters: PowParameters) -> bool:
    expected = evaluate_nonce(payload, proof.nonce, parameters)
    return accepts(proof.digest, parameters) and hmac.compare_digest(
        expected.digest.to_bytes(), proof.digest.to_bytes()
    )


def solve(
    payload: bytes,
    parameters: PowParameters,
    *,
    start_nonce: int = 0,
    max_attempts: int = 1_000_000,
) -> tuple[PowProof, int]:
    require_int("start_nonce", start_nonce, minimum=0, maximum=MAX_NONCE)
    require_int("max_attempts", max_attempts, minimum=1, maximum=MAX_NONCE)
    for attempts in range(1, max_attempts + 1):
        nonce = start_nonce + attempts - 1
        if nonce > MAX_NONCE:
            break
        proof = evaluate_nonce(payload, nonce, parameters)
        if accepts(proof.digest, parameters):
            return proof, attempts
    raise RuntimeError("no valid nonce found within max_attempts")
