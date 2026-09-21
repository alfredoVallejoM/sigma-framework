"""Nonce-complete proof-of-work profile for Sigma v3.

The nonce is encoded into the canonical input before anchor, binding and work
parameters are derived. Verification recomputes the complete trajectory. This
module claims neither VDF behaviour, constant-time execution, memory hardness
nor ASIC resistance.
"""

from __future__ import annotations

import hashlib
import hmac
from dataclasses import dataclass
from enum import IntEnum

from sigma.crypto.primitives import domain_tag_v3
from sigma.outputs.digest_v3 import SigmaDigestV3, digest_from_evaluation_v3
from sigma.policy import DEFAULT_RESOURCE_POLICY, PolicyViolation, ResourcePolicy
from sigma.rounds.evaluate_v3 import evaluate_v3
from sigma.sources import BytesSource
from sigma.spec.codec_v3 import decode_record, encode_record, validate_record_prefix
from sigma.spec.context_v3 import SigmaContextV3
from sigma.spec.encoding import DecodeError, decode_uint, encode_uint
from sigma.spec.ids_v3 import DomainIdV3, SuiteIdV3
from sigma.suites.registry_v3 import get_suite_v3
from sigma.validation import require_int


class PowPredicateV3(IntEnum):
    DIGEST_SHA512 = 1


class _ParameterField(IntEnum):
    DOMAIN = 1
    SUITE = 2
    CHALLENGE = 3
    PREDICATE = 4
    DIFFICULTY_BITS = 5


class _InputField(IntEnum):
    DOMAIN = 1
    PAYLOAD = 2
    NONCE = 3


class _ProofField(IntEnum):
    DOMAIN = 1
    NONCE = 2
    DIGEST = 3


@dataclass(frozen=True)
class PowParametersV3:
    challenge: bytes
    difficulty_bits: int
    suite_id: SuiteIdV3 = SuiteIdV3.REFERENCE_IAP_V3
    predicate: PowPredicateV3 = PowPredicateV3.DIGEST_SHA512

    def __post_init__(self) -> None:
        if not isinstance(self.challenge, bytes) or not 1 <= len(self.challenge) <= 4096:
            raise ValueError("challenge must contain 1..4096 bytes")
        require_int("difficulty_bits", self.difficulty_bits, minimum=0, maximum=512)
        if not isinstance(self.suite_id, SuiteIdV3):
            raise TypeError("suite_id must be SuiteIdV3")
        get_suite_v3(self.suite_id)
        if self.predicate is not PowPredicateV3.DIGEST_SHA512:
            raise ValueError("unsupported PoW predicate")

    def to_bytes(self) -> bytes:
        return encode_record(
            POW_PARAMETERS_V3_MAGIC,
            (
                (_ParameterField.DOMAIN, domain_tag_v3(DomainIdV3.POW_CHALLENGE)),
                (_ParameterField.SUITE, encode_uint(self.suite_id, 2)),
                (_ParameterField.CHALLENGE, self.challenge),
                (_ParameterField.PREDICATE, encode_uint(self.predicate, 1)),
                (_ParameterField.DIFFICULTY_BITS, encode_uint(self.difficulty_bits, 2)),
            ),
        )

    @classmethod
    def from_bytes(cls, data: bytes) -> PowParametersV3:
        validate_record_prefix(
            data,
            magic=POW_PARAMETERS_V3_MAGIC,
            expected_fields=(
                (int(_ParameterField.DOMAIN), domain_tag_v3(DomainIdV3.POW_CHALLENGE)),
            ),
        )
        fields = decode_record(
            data,
            magic=POW_PARAMETERS_V3_MAGIC,
            allowed_tags=_PARAMETER_FIELDS,
            required_tags=_PARAMETER_FIELDS,
        )
        try:
            return cls(
                challenge=fields[_ParameterField.CHALLENGE],
                difficulty_bits=decode_uint(fields[_ParameterField.DIFFICULTY_BITS], 2),
                suite_id=SuiteIdV3(decode_uint(fields[_ParameterField.SUITE], 2)),
                predicate=PowPredicateV3(decode_uint(fields[_ParameterField.PREDICATE], 1)),
            )
        except DecodeError:
            raise
        except (TypeError, ValueError) as exc:
            raise DecodeError("invalid Sigma v3 PoW parameters") from exc

    def context(self) -> SigmaContextV3:
        encoded = self.to_bytes()
        salt = hashlib.sha256(domain_tag_v3(DomainIdV3.POW_CHALLENGE) + encoded).digest()
        return SigmaContextV3.for_suite(
            self.suite_id,
            salt=salt,
            challenge=self.challenge,
            application_context=encoded,
        )


@dataclass(frozen=True)
class PowProofV3:
    nonce: int
    digest: SigmaDigestV3

    def __post_init__(self) -> None:
        require_int("nonce", self.nonce, minimum=0, maximum=MAX_NONCE)
        if not isinstance(self.digest, SigmaDigestV3):
            raise TypeError("digest must be SigmaDigestV3")

    def to_bytes(self) -> bytes:
        return encode_record(
            POW_PROOF_V3_MAGIC,
            (
                (_ProofField.DOMAIN, domain_tag_v3(DomainIdV3.POW_PREDICATE)),
                (_ProofField.NONCE, encode_uint(self.nonce, 8)),
                (_ProofField.DIGEST, self.digest.to_bytes()),
            ),
        )

    @classmethod
    def from_bytes(cls, data: bytes) -> PowProofV3:
        validate_record_prefix(
            data,
            magic=POW_PROOF_V3_MAGIC,
            expected_fields=((int(_ProofField.DOMAIN), domain_tag_v3(DomainIdV3.POW_PREDICATE)),),
        )
        fields = decode_record(
            data,
            magic=POW_PROOF_V3_MAGIC,
            allowed_tags=_PROOF_FIELDS,
            required_tags=_PROOF_FIELDS,
        )
        try:
            return cls(
                decode_uint(fields[_ProofField.NONCE], 8),
                SigmaDigestV3.from_bytes(fields[_ProofField.DIGEST]),
            )
        except DecodeError:
            raise
        except (TypeError, ValueError) as exc:
            raise DecodeError("invalid Sigma v3 PoW proof") from exc


def pow_input_v3(payload: bytes, nonce: int) -> bytes:
    """Return the exact nonce-bearing input used by every Sigma derivation."""
    if not isinstance(payload, bytes):
        raise TypeError("payload must be bytes")
    if len(payload) > MAX_POW_PAYLOAD_BYTES:
        raise ValueError("payload exceeds the PoW application bound")
    checked_nonce = require_int("nonce", nonce, minimum=0, maximum=MAX_NONCE)
    return encode_record(
        POW_INPUT_V3_MAGIC,
        (
            (_InputField.DOMAIN, domain_tag_v3(DomainIdV3.POW_NONCE)),
            (_InputField.PAYLOAD, payload),
            (_InputField.NONCE, encode_uint(checked_nonce, 8)),
        ),
    )


def accepts_v3(digest: SigmaDigestV3, parameters: PowParametersV3) -> bool:
    if not isinstance(digest, SigmaDigestV3) or not isinstance(parameters, PowParametersV3):
        return False
    if not hmac.compare_digest(digest.context.to_bytes(), parameters.context().to_bytes()):
        return False
    predicate_value = hashlib.sha512(
        domain_tag_v3(DomainIdV3.POW_PREDICATE) + parameters.to_bytes() + digest.to_bytes()
    ).digest()
    return _has_leading_zero_bits(predicate_value, parameters.difficulty_bits)


def evaluate_nonce_v3(
    payload: bytes,
    nonce: int,
    parameters: PowParametersV3,
    *,
    policy: ResourcePolicy = DEFAULT_RESOURCE_POLICY,
) -> PowProofV3:
    if not isinstance(parameters, PowParametersV3):
        raise TypeError("parameters must be PowParametersV3")
    if not isinstance(policy, ResourcePolicy):
        raise TypeError("policy must be ResourcePolicy")
    policy.validate_pow(parameters.difficulty_bits)
    if not isinstance(payload, bytes):
        raise TypeError("payload must be bytes")
    policy.validate_message_size(len(payload))
    canonical_input = pow_input_v3(payload, nonce)
    evaluation = evaluate_v3(parameters.context(), BytesSource(canonical_input))
    return PowProofV3(nonce, digest_from_evaluation_v3(evaluation))


def verify_pow_v3(
    payload: bytes,
    proof: PowProofV3,
    parameters: PowParametersV3,
    *,
    policy: ResourcePolicy = DEFAULT_RESOURCE_POLICY,
) -> bool:
    if not isinstance(proof, PowProofV3) or not isinstance(parameters, PowParametersV3):
        return False
    try:
        expected = evaluate_nonce_v3(payload, proof.nonce, parameters, policy=policy)
    except (PolicyViolation, TypeError, ValueError):
        return False
    return hmac.compare_digest(expected.digest.to_bytes(), proof.digest.to_bytes()) and accepts_v3(
        proof.digest,
        parameters,
    )


def solve_pow_v3(
    payload: bytes,
    parameters: PowParametersV3,
    *,
    start_nonce: int = 0,
    max_attempts: int = 1_000_000,
    policy: ResourcePolicy = DEFAULT_RESOURCE_POLICY,
) -> tuple[PowProofV3, int]:
    start = require_int("start_nonce", start_nonce, minimum=0, maximum=MAX_NONCE)
    attempts_limit = require_int("max_attempts", max_attempts, minimum=1, maximum=MAX_NONCE)
    if not isinstance(parameters, PowParametersV3):
        raise TypeError("parameters must be PowParametersV3")
    policy.validate_pow(parameters.difficulty_bits, attempts_limit)
    if attempts_limit > MAX_NONCE - start + 1:
        raise ValueError("nonce search exceeds uint64 range")
    for attempts in range(1, attempts_limit + 1):
        proof = evaluate_nonce_v3(
            payload,
            start + attempts - 1,
            parameters,
            policy=policy,
        )
        if accepts_v3(proof.digest, parameters):
            return proof, attempts
    raise LookupError("no PoW solution found within max_attempts")


def _has_leading_zero_bits(value: bytes, bits: int) -> bool:
    whole, partial = divmod(bits, 8)
    if any(value[:whole]):
        return False
    return partial == 0 or value[whole] >> (8 - partial) == 0


POW_PARAMETERS_V3_MAGIC = b"SIG3POWP"
POW_INPUT_V3_MAGIC = b"SIG3POWI"
POW_PROOF_V3_MAGIC = b"SIG3POWR"
MAX_NONCE = (1 << 64) - 1
MAX_POW_PAYLOAD_BYTES = (1 << 20) - 128
_PARAMETER_FIELDS = frozenset(int(field) for field in _ParameterField)
_PROOF_FIELDS = frozenset(int(field) for field in _ProofField)

__all__ = [
    "PowParametersV3",
    "PowPredicateV3",
    "PowProofV3",
    "accepts_v3",
    "evaluate_nonce_v3",
    "pow_input_v3",
    "solve_pow_v3",
    "verify_pow_v3",
]
