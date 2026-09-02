import importlib.util

import pytest

from sigma.applications.kdf_argon2id import (
    Argon2idParameters,
    SigmaKdfResult,
    derive_argon2id,
    derive_argon2id_sigma,
    verify_password,
)
from sigma.policy import ResourcePolicy
from sigma.presets import lightweight_v2_2
from sigma.v2 import hash_bytes


def test_kdf_parameters_are_canonical_and_validated() -> None:
    parameters = Argon2idParameters(1024, 2, 1)
    assert parameters.to_bytes().startswith(b"SIGMAKDF2")
    assert Argon2idParameters.from_bytes(parameters.to_bytes()) == parameters
    with pytest.raises(ValueError, match=r"8 \* parallelism"):
        Argon2idParameters(7, 1, 1)


@pytest.mark.skipif(
    importlib.util.find_spec("argon2") is None, reason="optional argon2-cffi absent"
)
def test_argon2_composition_hides_base_and_binds_parameters() -> None:
    parameters = Argon2idParameters(19_456, 2, 1)
    salt = b"0123456789abcdef"
    base = derive_argon2id(b"password", salt, parameters)
    result = derive_argon2id_sigma(b"password", salt, parameters)
    assert not hasattr(result, "base_key")
    assert result.final_key != base
    assert result.sigma_digest.context.salt == salt
    assert SigmaKdfResult.from_bytes(result.to_bytes()) == result
    assert verify_password(b"password", result)
    assert not verify_password(b"wrong", result)


def test_kdf_result_codec_rejects_inconsistent_final_key() -> None:
    parameters = Argon2idParameters(19_456, 2, 1)
    salt = b"0123456789abcdef"
    context = lightweight_v2_2(
        salt=salt,
        application_context=b"SIGMA-KDF-FINAL-V1" + parameters.to_bytes(),
    )
    digest = hash_bytes(b"diagnostic base", context)
    result = SigmaKdfResult.bind(parameters, salt, digest)
    assert SigmaKdfResult.from_bytes(result.to_bytes()) == result
    with pytest.raises(ValueError, match="inconsistent"):
        SigmaKdfResult(parameters, salt, digest, bytes(len(result.final_key)))


def test_default_kdf_policy_rejects_weak_profile_before_argon() -> None:
    parameters = Argon2idParameters(1024, 1, 1)
    with pytest.raises(ValueError, match="policy"):
        derive_argon2id(b"password", b"01234567", parameters)
    testing = ResourcePolicy(
        min_argon2_memory_kib=1024,
        min_argon2_time_cost=1,
    )
    testing.validate_argon2(parameters.memory_kib, parameters.time_cost)


@pytest.mark.skipif(
    importlib.util.find_spec("argon2") is None, reason="optional argon2-cffi absent"
)
@pytest.mark.parametrize(
    "preset",
    ["lightweight-v2-2", "paranoid-deep-v2-2", "paranoid-deep-vector-v2-2"],
)
def test_kdf_composition_verifies_the_recorded_v22_preset(preset: str) -> None:
    parameters = Argon2idParameters(1024, 1, 1)
    policy = ResourcePolicy(min_argon2_memory_kib=1024, min_argon2_time_cost=1)
    result = derive_argon2id_sigma(
        b"password",
        b"0123456789abcdef",
        parameters,
        policy=policy,
        preset=preset,
    )
    assert verify_password(b"password", result, policy=policy)
    assert not verify_password(b"wrong", result, policy=policy)


def test_kdf_rejects_unregistered_composition_preset() -> None:
    parameters = Argon2idParameters(1024, 1, 1)
    policy = ResourcePolicy(min_argon2_memory_kib=1024, min_argon2_time_cost=1)
    with pytest.raises(ValueError, match="unsupported Sigma KDF preset"):
        derive_argon2id_sigma(
            b"password",
            b"0123456789abcdef",
            parameters,
            policy=policy,
            preset="lightweight-v2",
        )
