import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from reference.independent_applications import (
    argon2_parameters,
    kdf_from_base_key,
    pow_candidate,
    signed_commitment,
    signed_lightweight,
)
from sigma.applications.kdf_argon2id import (
    Argon2idParameters,
    compose_argon2id_output,
)
from sigma.applications.pow import PowParameters, PowPredicate, evaluate_nonce
from sigma.applications.signed import sign_ed25519
from sigma.presets import (
    lightweight_v2_2,
    paranoid_deep_v2_2,
    paranoid_deep_vector_v2_2,
    paranoid_wide_v2_2,
    reference_v2_2,
    simultaneous_v2_2,
)


@pytest.mark.parametrize("predicate", list(PowPredicate))
def test_independent_pow_all_predicates(predicate: PowPredicate) -> None:
    state_count = 2 if predicate is PowPredicate.DUAL_STATE else 3
    parameters = PowParameters(b"predicate-matrix", 2, state_count, predicate, 0)
    proof = evaluate_nonce(b"payload", 17, parameters)
    independent = pow_candidate(
        b"payload", 17, b"predicate-matrix", 2, state_count, int(predicate), 0
    )
    assert independent["parameters"] == parameters.to_bytes()
    assert independent["context"] == proof.digest.context.to_bytes()
    assert independent["digest"] == proof.digest.to_bytes()


def test_independent_pow_framing_and_evaluation() -> None:
    parameters = PowParameters(b"independent-challenge", 2, 3, PowPredicate.DUAL_STATE, 0)
    proof = evaluate_nonce(b"payload", 0x0102030405060708, parameters)
    independent = pow_candidate(
        b"payload",
        proof.nonce,
        parameters.challenge,
        parameters.target_round,
        parameters.state_count,
        int(parameters.predicate),
        parameters.difficulty_bits,
    )
    assert independent["parameters"] == parameters.to_bytes()
    assert independent["context"] == proof.digest.context.to_bytes()
    assert independent["digest"] == proof.digest.to_bytes()


def test_independent_kdf_binding_after_argon2_stage() -> None:
    parameters = Argon2idParameters(19_456, 2, 1, 32)
    salt = b"independent-salt"
    base_key = bytes(range(32))
    encoded_parameters = argon2_parameters(19_456, 2, 1, 32)
    public = compose_argon2id_output(base_key, salt, parameters)
    independent = kdf_from_base_key(base_key, encoded_parameters, salt, 32)
    assert encoded_parameters == parameters.to_bytes()
    assert independent["context"] == public.sigma_digest.context.to_bytes()
    assert independent["digest"] == public.sigma_digest.to_bytes()
    assert independent["final_key"] == public.final_key
    assert independent["record"] == public.password_record().to_bytes()


@pytest.mark.parametrize(
    "preset,suite_id",
    [
        ("lightweight-v2-2", 0x0102),
        ("paranoid-wide-v2-2", 0x0104),
        ("paranoid-deep-v2-2", 0x0105),
        ("paranoid-deep-vector-v2-2", 0x0106),
    ],
)
def test_independent_kdf_covers_every_registered_composition(preset: str, suite_id: int) -> None:
    parameters = Argon2idParameters(19_456, 2, 1, 32)
    salt = b"independent-matrix-salt"
    base_key = bytes(range(32))
    encoded_parameters = argon2_parameters(19_456, 2, 1, 32)
    public = compose_argon2id_output(base_key, salt, parameters, preset=preset)
    independent = kdf_from_base_key(base_key, encoded_parameters, salt, 32, suite_id=suite_id)
    assert independent["context"] == public.sigma_digest.context.to_bytes()
    assert independent["digest"] == public.sigma_digest.to_bytes()
    assert independent["final_key"] == public.final_key
    assert independent["record"] == public.password_record().to_bytes()


def test_independent_signed_commitment_and_signature() -> None:
    private_key = bytes(range(32))
    key_id = b"independent-key"
    public = sign_ed25519(
        b"signed independently",
        lightweight_v2_2(target_round=2, state_count=3),
        private_key,
        key_id,
    )
    independent = signed_lightweight(
        b"signed independently",
        private_key,
        key_id,
        target_round=2,
        state_count=3,
    )
    assert independent["context"] == public.context.to_bytes()
    assert independent["evidence"] == public.anchor_evidence.to_bytes()
    assert tuple(independent["states"][-3:]) == public.states
    assert independent["signing_input"] == public.signing_input()
    assert independent["signature"] == public.signature
    assert independent["commitment"] == public.to_bytes()
    public_key = Ed25519PrivateKey.from_private_bytes(private_key).public_key()
    public_key.verify(independent["signature"], independent["signing_input"])


@pytest.mark.parametrize(
    "context_factory,suite_id",
    [
        (reference_v2_2, 0x0101),
        (lightweight_v2_2, 0x0102),
        (simultaneous_v2_2, 0x0103),
        (paranoid_wide_v2_2, 0x0104),
        (paranoid_deep_v2_2, 0x0105),
        (paranoid_deep_vector_v2_2, 0x0106),
    ],
)
def test_independent_signed_commitment_covers_every_v22_suite(
    context_factory, suite_id: int
) -> None:
    private_key = bytes(range(32))
    key_id = b"independent-suite-matrix"
    public = sign_ed25519(
        b"signed suite matrix",
        context_factory(target_round=2, state_count=2),
        private_key,
        key_id,
    )
    independent = signed_commitment(
        b"signed suite matrix",
        private_key,
        key_id,
        suite_id=suite_id,
        target_round=2,
        state_count=2,
    )
    assert independent["context"] == public.context.to_bytes()
    assert independent["evidence"] == public.anchor_evidence.to_bytes()
    assert tuple(independent["states"][-2:]) == public.states
    assert independent["commitment"] == public.to_bytes()
