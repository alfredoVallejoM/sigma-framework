from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from reference.independent_applications import (
    argon2_parameters,
    kdf_from_base_key,
    pow_candidate,
    signed_lightweight,
)
from sigma.applications.kdf_argon2id import (
    KDF_FINAL_DOMAIN,
    Argon2idParameters,
    SigmaKdfResult,
)
from sigma.applications.pow import PowParameters, PowPredicate, evaluate_nonce
from sigma.applications.signed import sign_ed25519
from sigma.presets import lightweight_v2_2
from sigma.v2 import hash_bytes


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
    context = lightweight_v2_2(
        salt=salt,
        application_context=KDF_FINAL_DOMAIN + parameters.to_bytes(),
    )
    public = SigmaKdfResult.bind(parameters, salt, hash_bytes(base_key, context))
    independent = kdf_from_base_key(base_key, encoded_parameters, salt, 32)
    assert encoded_parameters == parameters.to_bytes()
    assert independent["context"] == public.sigma_digest.context.to_bytes()
    assert independent["digest"] == public.sigma_digest.to_bytes()
    assert independent["final_key"] == public.final_key
    assert independent["result"] == public.to_bytes()


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
