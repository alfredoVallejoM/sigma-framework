"""Independent byte constructions for Sigma's optional application profiles."""

import hashlib
from typing import Any

from reference.independent_v22 import (
    ALGORITHMS,
    LIGHT_ALGORITHMS,
    domain,
    encode_digest,
    sequential_suite,
    tlv,
    u16,
    u32,
    u64,
)

POW_MAGIC = b"SIGMAPOW2"
KDF_MAGIC = b"SIGMAKDF2"
KDF_RESULT_MAGIC = b"SIGMAKDR2"
KDF_FINAL_DOMAIN = b"SIGMA-KDF-FINAL-V1"
SIGNED_MAGIC = b"SIGMASIG"


def pow_parameters(
    challenge: bytes,
    target_round: int,
    state_count: int,
    predicate: int,
    difficulty_bits: int,
) -> bytes:
    return POW_MAGIC + tlv(
        (1, challenge),
        (2, u32(target_round)),
        (3, u16(state_count)),
        (4, bytes((predicate,))),
        (5, u16(difficulty_bits)),
    )


def pow_candidate(
    payload: bytes,
    nonce: int,
    challenge: bytes,
    target_round: int,
    state_count: int,
    predicate: int,
    difficulty_bits: int,
) -> dict[str, Any]:
    parameters = pow_parameters(challenge, target_round, state_count, predicate, difficulty_bits)
    application_context = tlv(
        (1, POW_MAGIC),
        (2, bytes((predicate,))),
        (3, u16(difficulty_bits)),
    )
    message = POW_MAGIC + tlv((1, payload), (2, u64(nonce)))
    evaluated = sequential_suite(
        message,
        0x0001,
        1,
        1,
        target_round,
        state_count,
        algorithms=ALGORITHMS,
        challenge=challenge,
        application_context=application_context,
        evidence_version=1,
    )
    return {"parameters": parameters, "message": message, **evaluated}


def argon2_parameters(
    memory_kib: int,
    time_cost: int,
    parallelism: int,
    output_length: int,
    version: int = 0x13,
) -> bytes:
    return KDF_MAGIC + tlv(
        (1, u32(memory_kib)),
        (2, u32(time_cost)),
        (3, u16(parallelism)),
        (4, u16(output_length)),
        (5, bytes((version,))),
    )


def kdf_from_base_key(
    base_key: bytes, parameters: bytes, salt: bytes, output_length: int
) -> dict[str, Any]:
    evaluated = sequential_suite(
        base_key,
        0x0102,
        1,
        1,
        algorithms=LIGHT_ALGORITHMS,
        salt=salt,
        application_context=KDF_FINAL_DOMAIN + parameters,
    )
    digest = evaluated["digest"]
    final_input = tlv((1, parameters), (2, salt), (3, digest))
    final_key = hashlib.shake_256(KDF_FINAL_DOMAIN + final_input).digest(output_length)
    result = KDF_RESULT_MAGIC + tlv((1, parameters), (2, salt), (3, digest), (4, final_key))
    return {**evaluated, "final_key": final_key, "result": result}


def signed_lightweight(
    message: bytes,
    private_key_seed: bytes,
    public_key_id: bytes,
    *,
    target_round: int = 1,
    state_count: int = 2,
) -> dict[str, Any]:
    evaluated = sequential_suite(
        message,
        0x0102,
        1,
        1,
        target_round,
        state_count,
        algorithms=LIGHT_ALGORITHMS,
    )
    published = evaluated["states"][-state_count:]
    encoded_states = u16(len(published)) + b"".join(u16(len(state)) + state for state in published)
    unsigned = (
        SIGNED_MAGIC
        + u16(2)
        + tlv(
            (1, evaluated["context"]),
            (2, evaluated["evidence"]),
            (3, encoded_states),
            (4, u16(1)),
            (5, public_key_id),
        )
    )
    signing_input = domain(13) + unsigned
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    signature = Ed25519PrivateKey.from_private_bytes(private_key_seed).sign(signing_input)
    commitment = unsigned + tlv((6, signature))
    assert encode_digest(evaluated["context"], published) == evaluated["digest"]
    return {
        **evaluated,
        "unsigned": unsigned,
        "signing_input": signing_input,
        "signature": signature,
        "commitment": commitment,
    }
