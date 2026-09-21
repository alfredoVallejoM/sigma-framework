"""Independent byte constructions for Sigma's optional application profiles."""

import hashlib
from typing import Any

from reference.independent_v22 import (
    ALGORITHMS,
    LIGHT_ALGORITHMS,
    deep_vector,
    domain,
    encode_digest,
    sequential_suite,
    tlv,
    tree_suite,
    u16,
    u32,
    u64,
)

POW_MAGIC = b"SIGMAPOW3"
KDF_MAGIC = b"SIGMAKDF2"
KDF_RECORD_MAGIC = b"SIGMAKVR2"
KDF_FINAL_DOMAIN = b"SIGMA-KDF-BIND-V2"
KDF_KEY_DOMAIN = b"SIGMA-KDF-KEY-V2"
SIGNED_MAGIC = b"SIGMASIG"

SUITE_PARAMETERS = {
    0x0101: (1, 1, ALGORITHMS),
    0x0102: (1, 1, LIGHT_ALGORITHMS),
    0x0104: (3, 1, ALGORITHMS),
    0x0105: (3, 2, ALGORITHMS),
}


def active_suite(
    message: bytes,
    suite_id: int,
    target_round: int,
    state_count: int,
    *,
    salt: bytes = b"",
    challenge: bytes = b"",
    application_context: bytes = b"",
) -> dict[str, Any]:
    """Evaluate any registered v2.2 suite without importing :mod:`sigma`."""

    if suite_id == 0x0103:
        return tree_suite(
            message,
            target_round,
            state_count,
            salt=salt,
            challenge=challenge,
            application_context=application_context,
        )
    if suite_id == 0x0106:
        return deep_vector(
            message,
            target_round,
            state_count,
            salt=salt,
            challenge=challenge,
            application_context=application_context,
        )
    try:
        anchor_profile, round_profile, algorithms = SUITE_PARAMETERS[suite_id]
    except KeyError as exc:
        raise ValueError(f"unsupported independent v2.2 suite: {suite_id:#06x}") from exc
    return sequential_suite(
        message,
        suite_id,
        anchor_profile,
        round_profile,
        target_round,
        state_count,
        algorithms=algorithms,
        salt=salt,
        challenge=challenge,
        application_context=application_context,
    )


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
        0x0101,
        1,
        1,
        target_round,
        state_count,
        algorithms=ALGORITHMS,
        challenge=challenge,
        application_context=application_context,
        evidence_version=2,
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
    base_key: bytes,
    parameters: bytes,
    salt: bytes,
    output_length: int,
    *,
    suite_id: int = 0x0102,
) -> dict[str, Any]:
    if suite_id not in {0x0102, 0x0104, 0x0105, 0x0106}:
        raise ValueError("suite is not registered for independent KDF composition")
    evaluated = active_suite(
        base_key,
        suite_id,
        1,
        2,
        salt=salt,
        application_context=KDF_FINAL_DOMAIN + parameters,
    )
    digest = evaluated["digest"]
    final_input = tlv((1, base_key), (2, parameters), (3, salt), (4, digest))
    final_key = hashlib.shake_256(KDF_KEY_DOMAIN + final_input).digest(output_length)
    record = KDF_RECORD_MAGIC + tlv((1, parameters), (2, salt), (3, digest))
    return {**evaluated, "final_key": final_key, "record": record}


def signed_commitment(
    message: bytes,
    private_key_seed: bytes,
    public_key_id: bytes,
    *,
    suite_id: int = 0x0102,
    target_round: int = 1,
    state_count: int = 2,
) -> dict[str, Any]:
    evaluated = active_suite(
        message,
        suite_id,
        target_round,
        state_count,
    )
    trajectory = evaluated.get("states", evaluated.get("vectors"))
    assert trajectory is not None
    published = trajectory[-state_count:]
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
        "states": trajectory,
        "unsigned": unsigned,
        "signing_input": signing_input,
        "signature": signature,
        "commitment": commitment,
    }


def signed_lightweight(
    message: bytes,
    private_key_seed: bytes,
    public_key_id: bytes,
    *,
    target_round: int = 1,
    state_count: int = 2,
) -> dict[str, Any]:
    """Compatibility wrapper for the original independent application vector."""

    return signed_commitment(
        message,
        private_key_seed,
        public_key_id,
        suite_id=0x0102,
        target_round=target_round,
        state_count=state_count,
    )
