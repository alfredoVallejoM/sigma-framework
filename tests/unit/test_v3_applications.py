from __future__ import annotations

import pickle
from dataclasses import replace

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from sigma.applications.kdf_argon2id_v3 import (
    Argon2idParametersV3,
    SigmaDerivedKeyV3,
    SigmaPasswordRecordV3,
    compose_argon2id_output_v3,
    derive_argon2id_sigma_v3,
    verify_password_v3,
)
from sigma.applications.pow_v3 import (
    MAX_NONCE,
    PowParametersV3,
    PowProofV3,
    accepts_v3,
    evaluate_nonce_v3,
    pow_input_v3,
    solve_pow_v3,
    verify_pow_v3,
)
from sigma.applications.signed_v3 import (
    SigmaSignedCommitmentV3,
    sign_digest_ed25519_v3,
    verify_full_signed_v3,
    verify_signed_digest_v3,
)
from sigma.crypto.primitives import domain_tag_v3
from sigma.outputs.digest_v3 import digest_from_evaluation_v3
from sigma.policy import DEFAULT_RESOURCE_POLICY, PolicyViolation
from sigma.sources import BytesSource
from sigma.spec.context_v3 import SigmaContextV3
from sigma.spec.encoding import DecodeError
from sigma.spec.ids_v3 import DomainIdV3, SuiteIdV3
from sigma.v3 import evaluate_v3

PRIVATE_KEY = bytes(range(32))
PUBLIC_KEY = Ed25519PrivateKey.from_private_bytes(PRIVATE_KEY).public_key().public_bytes_raw()
KEY_ID = b"r11-test-key"
KDF_SALT = b"r11-kdf-salt-16"


def _digest(message: bytes = b"v3 application message"):
    context = SigmaContextV3.reference(
        salt=b"v3-app-salt",
        challenge=b"v3-app-challenge",
        application_context=b"tests/v3/applications",
    )
    return digest_from_evaluation_v3(evaluate_v3(context, BytesSource(message)))


def _relaxed_policy():
    return replace(
        DEFAULT_RESOURCE_POLICY,
        min_argon2_memory_kib=8,
        min_argon2_time_cost=1,
        max_pow_attempts=1000,
    )


def test_signed_v3_round_trip_attestation_and_full_verification() -> None:
    digest = _digest()
    commitment = sign_digest_ed25519_v3(digest, PRIVATE_KEY, KEY_ID)

    assert SigmaSignedCommitmentV3.from_bytes(commitment.to_bytes()) == commitment
    assert verify_signed_digest_v3(commitment, PUBLIC_KEY, expected_public_key_id=KEY_ID)
    assert verify_full_signed_v3(BytesSource(b"v3 application message"), commitment, PUBLIC_KEY)
    assert not verify_full_signed_v3(BytesSource(b"wrong message"), commitment, PUBLIC_KEY)
    assert not verify_signed_digest_v3(
        commitment,
        PUBLIC_KEY,
        expected_public_key_id=b"another-key",
    )


def test_signed_v3_authenticates_digest_key_id_and_wire_domain() -> None:
    commitment = sign_digest_ed25519_v3(_digest(b"signed"), PRIVATE_KEY, KEY_ID)
    changed_digest = replace(commitment, digest=_digest(b"changed"))
    changed_key_id = replace(commitment, public_key_id=b"changed-key")
    changed_signature = replace(
        commitment,
        signature=bytes((commitment.signature[0] ^ 1,)) + commitment.signature[1:],
    )

    assert not verify_signed_digest_v3(changed_digest, PUBLIC_KEY)
    assert not verify_signed_digest_v3(changed_key_id, PUBLIC_KEY)
    assert not verify_signed_digest_v3(changed_signature, PUBLIC_KEY)

    encoded = commitment.to_bytes()
    downgraded = encoded.replace(
        domain_tag_v3(DomainIdV3.SIGNED_COMMITMENT),
        domain_tag_v3(DomainIdV3.KDF_BINDING),
        1,
    )
    with pytest.raises(DecodeError):
        SigmaSignedCommitmentV3.from_bytes(downgraded)
    with pytest.raises(DecodeError):
        SigmaSignedCommitmentV3.from_bytes(encoded[:-1])
    with pytest.raises(TypeError):
        verify_signed_digest_v3(object(), PUBLIC_KEY)  # type: ignore[arg-type]
    with pytest.raises(ValueError, match="public key"):
        verify_signed_digest_v3(commitment, b"short")


@pytest.mark.parametrize(
    "private_key,key_id",
    [(b"short", KEY_ID), (PRIVATE_KEY, b""), (PRIVATE_KEY, b"x" * 256)],
)
def test_signed_v3_rejects_key_boundaries(private_key: bytes, key_id: bytes) -> None:
    with pytest.raises(ValueError):
        sign_digest_ed25519_v3(_digest(), private_key, key_id)


def test_kdf_v3_parameters_composition_record_and_secret_boundaries() -> None:
    parameters = Argon2idParametersV3(8, 1, 1)
    policy = _relaxed_policy()
    base_key = bytes(range(parameters.output_length))
    derived = compose_argon2id_output_v3(
        base_key,
        KDF_SALT,
        parameters,
        policy=policy,
    )

    assert Argon2idParametersV3.from_bytes(parameters.to_bytes()) == parameters
    record = derived.password_record()
    assert SigmaPasswordRecordV3.from_bytes(record.to_bytes()) == record
    assert len(derived.final_key) == parameters.output_length
    assert "final_key" not in repr(derived)
    assert not hasattr(derived, "to_bytes")
    with pytest.raises(TypeError, match="must not be pickled"):
        pickle.dumps(derived)

    repeated = compose_argon2id_output_v3(base_key, KDF_SALT, parameters, policy=policy)
    assert repeated.final_key == derived.final_key
    with pytest.raises(ValueError, match="base_key length"):
        compose_argon2id_output_v3(b"short", KDF_SALT, parameters, policy=policy)


def test_kdf_v3_derives_and_verifies_argon2id_without_claiming_sigma_memory_hardness() -> None:
    parameters = Argon2idParametersV3(8, 1, 1, output_length=16)
    policy = _relaxed_policy()
    derived = derive_argon2id_sigma_v3(b"correct password", KDF_SALT, parameters, policy=policy)
    record = derived.password_record()

    assert verify_password_v3(b"correct password", record, policy=policy)
    assert not verify_password_v3(b"wrong password", record, policy=policy)
    assert derived.sigma_digest.context.application_context == parameters.to_bytes()
    assert derived.sigma_digest.context.challenge == domain_tag_v3(DomainIdV3.KDF_BINDING)


def test_kdf_v3_rejects_policy_downgrade_context_mismatch_and_cross_wire() -> None:
    parameters = Argon2idParametersV3(8, 1, 1)
    with pytest.raises(PolicyViolation):
        compose_argon2id_output_v3(bytes(32), KDF_SALT, parameters)

    derived = compose_argon2id_output_v3(
        bytes(32),
        KDF_SALT,
        parameters,
        policy=_relaxed_policy(),
    )
    with pytest.raises(ValueError, match="does not bind"):
        SigmaPasswordRecordV3(parameters, b"different-salt", derived.sigma_digest)

    crossed = parameters.to_bytes().replace(
        domain_tag_v3(DomainIdV3.KDF_BINDING),
        domain_tag_v3(DomainIdV3.POW_CHALLENGE),
        1,
    )
    with pytest.raises(DecodeError):
        Argon2idParametersV3.from_bytes(crossed)
    with pytest.raises((TypeError, ValueError)):
        SigmaDerivedKeyV3(parameters, KDF_SALT, derived.sigma_digest, b"short")
    with pytest.raises(TypeError):
        verify_password_v3(b"password", object())  # type: ignore[arg-type]


@pytest.mark.parametrize(
    "changes",
    [
        {"version": 0x10},
        {"suite_id": 0x0301},
        {"parallelism": 2, "memory_kib": 8},
    ],
)
def test_kdf_v3_rejects_parameter_downgrades(changes: dict[str, object]) -> None:
    values: dict[str, object] = {
        "memory_kib": 16,
        "time_cost": 1,
        "parallelism": 1,
        "version": 0x13,
        "suite_id": SuiteIdV3.REFERENCE_IAP_V3,
    }
    values.update(changes)
    with pytest.raises((TypeError, ValueError)):
        Argon2idParametersV3(**values)  # type: ignore[arg-type]


def test_pow_v3_nonce_is_in_complete_canonical_input_and_proof_round_trips() -> None:
    parameters = PowParametersV3(b"pow challenge", 0)
    first_input = pow_input_v3(b"payload", 0)
    second_input = pow_input_v3(b"payload", 1)
    assert first_input != second_input
    assert domain_tag_v3(DomainIdV3.POW_NONCE) in first_input

    first = evaluate_nonce_v3(b"payload", 0, parameters)
    second = evaluate_nonce_v3(b"payload", 1, parameters)
    assert first.digest.header.cardinality == second.digest.header.cardinality
    assert first.digest.header.length_signature == second.digest.header.length_signature
    assert first.digest.header.anchor != second.digest.header.anchor
    assert first.digest.to_bytes() != second.digest.to_bytes()
    assert first.digest.header.parameters != second.digest.header.parameters
    assert PowProofV3.from_bytes(first.to_bytes()) == first
    assert accepts_v3(first.digest, parameters)
    assert verify_pow_v3(b"payload", first, parameters)
    assert not verify_pow_v3(b"different", first, parameters)


def test_pow_v3_solver_limits_policy_and_downgrade_regressions() -> None:
    parameters = PowParametersV3(b"solve challenge", 0)
    proof, attempts = solve_pow_v3(b"payload", parameters, start_nonce=9, max_attempts=1)
    assert proof.nonce == 9
    assert attempts == 1
    assert verify_pow_v3(b"payload", proof, parameters)

    strict = replace(DEFAULT_RESOURCE_POLICY, max_pow_difficulty_bits=0)
    with pytest.raises(PolicyViolation):
        evaluate_nonce_v3(b"payload", 0, replace(parameters, difficulty_bits=1), policy=strict)
    with pytest.raises(ValueError, match="uint64"):
        solve_pow_v3(b"payload", parameters, start_nonce=MAX_NONCE, max_attempts=2)

    encoded = parameters.to_bytes()
    assert PowParametersV3.from_bytes(encoded) == parameters
    downgraded = encoded.replace(
        domain_tag_v3(DomainIdV3.POW_CHALLENGE),
        domain_tag_v3(DomainIdV3.KDF_BINDING),
        1,
    )
    with pytest.raises(DecodeError):
        PowParametersV3.from_bytes(downgraded)
    impossible = replace(parameters, difficulty_bits=512)
    with pytest.raises(LookupError):
        solve_pow_v3(b"payload", impossible, max_attempts=1)

    wrong_context = _digest(b"not-pow")
    assert not accepts_v3(wrong_context, parameters)
    assert not accepts_v3(object(), parameters)  # type: ignore[arg-type]
    assert not verify_pow_v3(b"payload", object(), parameters)  # type: ignore[arg-type]


@pytest.mark.parametrize("nonce", [True, -1, 2**64])
def test_pow_v3_rejects_invalid_nonce(nonce: object) -> None:
    with pytest.raises((TypeError, ValueError), match="nonce"):
        pow_input_v3(b"payload", nonce)  # type: ignore[arg-type]


def test_pow_v3_rejects_invalid_boundaries_and_proof_domain() -> None:
    with pytest.raises(ValueError, match="challenge"):
        PowParametersV3(b"", 0)
    with pytest.raises(TypeError):
        PowParametersV3(b"challenge", 0, suite_id=0x0301)  # type: ignore[arg-type]
    with pytest.raises(TypeError, match="payload"):
        pow_input_v3("payload", 0)  # type: ignore[arg-type]

    proof = evaluate_nonce_v3(b"payload", 0, PowParametersV3(b"challenge", 0))
    crossed = proof.to_bytes().replace(
        domain_tag_v3(DomainIdV3.POW_PREDICATE),
        domain_tag_v3(DomainIdV3.POW_NONCE),
        1,
    )
    with pytest.raises(DecodeError):
        PowProofV3.from_bytes(crossed)


def test_application_wires_are_mutually_incompatible() -> None:
    signed = sign_digest_ed25519_v3(_digest(), PRIVATE_KEY, KEY_ID).to_bytes()
    parameters = Argon2idParametersV3(8, 1, 1).to_bytes()
    pow_parameters = PowParametersV3(b"challenge", 0).to_bytes()

    with pytest.raises(DecodeError):
        SigmaSignedCommitmentV3.from_bytes(parameters)
    with pytest.raises(DecodeError):
        Argon2idParametersV3.from_bytes(pow_parameters)
    with pytest.raises(DecodeError):
        PowParametersV3.from_bytes(signed)
