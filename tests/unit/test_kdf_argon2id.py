import importlib.util
import pickle

import pytest

from sigma.applications.kdf_argon2id import (
    KDF_FINAL_DOMAIN,
    KDF_RECORD_MAGIC,
    Argon2idParameters,
    SigmaDerivedKey,
    SigmaPasswordRecord,
    compose_argon2id_output,
    derive_argon2id,
    derive_argon2id_sigma,
    derive_key_from_password,
    verify_password,
)
from sigma.policy import ResourcePolicy
from sigma.presets import lightweight_v2_2, reference_v2_2
from sigma.spec.encoding import DecodeError, encode_tlv
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
    record = result.password_record()
    assert not hasattr(result, "to_bytes")
    assert result.final_key.hex() not in repr(result)
    with pytest.raises(TypeError, match="must not be pickled"):
        pickle.dumps(result)
    assert not hasattr(record, "final_key")
    assert result.final_key not in record.to_bytes()
    assert SigmaPasswordRecord.from_bytes(record.to_bytes()) == record
    assert verify_password(b"password", record)
    assert not verify_password(b"wrong", record)
    restored = derive_key_from_password(b"password", record)
    assert restored is not None
    assert restored.final_key == result.final_key


def test_kdf_record_rejects_unregistered_suites() -> None:
    parameters = Argon2idParameters(19_456, 2, 1)
    salt = b"0123456789abcdef"
    application_context = KDF_FINAL_DOMAIN + parameters.to_bytes()
    unregistered_context = reference_v2_2(
        salt=salt,
        application_context=application_context,
    )
    unregistered_digest = hash_bytes(b"diagnostic base", unregistered_context)
    with pytest.raises(ValueError, match="not registered"):
        SigmaPasswordRecord(parameters, salt, unregistered_digest)
    encoded = KDF_RECORD_MAGIC + encode_tlv(
        ((1, parameters.to_bytes()), (2, salt), (3, unregistered_digest.to_bytes()))
    )
    with pytest.raises(DecodeError, match="not registered"):
        SigmaPasswordRecord.from_bytes(encoded)


def test_derived_key_validates_secret_length() -> None:
    parameters = Argon2idParameters(19_456, 2, 1)
    salt = b"0123456789abcdef"
    composed = compose_argon2id_output(bytes(32), salt, parameters)
    with pytest.raises(ValueError, match="length"):
        SigmaDerivedKey(parameters, salt, composed.sigma_digest, b"short")


def test_kdf_record_rejects_salt_and_parameter_binding_mismatches() -> None:
    parameters = Argon2idParameters(19_456, 2, 1)
    salt = b"0123456789abcdef"
    wrong_salt_context = lightweight_v2_2(
        salt=b"fedcba9876543210",
        application_context=KDF_FINAL_DOMAIN + parameters.to_bytes(),
    )
    with pytest.raises(ValueError, match="salt differs"):
        SigmaPasswordRecord(parameters, salt, hash_bytes(b"base", wrong_salt_context))

    other_parameters = Argon2idParameters(19_456, 3, 1)
    wrong_parameters_context = lightweight_v2_2(
        salt=salt,
        application_context=KDF_FINAL_DOMAIN + other_parameters.to_bytes(),
    )
    with pytest.raises(ValueError, match="does not bind"):
        SigmaPasswordRecord(parameters, salt, hash_bytes(b"base", wrong_parameters_context))


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
    [
        "lightweight-v2-2",
        "paranoid-wide-v2-2",
        "paranoid-deep-v2-2",
        "paranoid-deep-vector-v2-2",
    ],
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
    record = result.password_record()
    assert verify_password(b"password", record, policy=policy)
    assert not verify_password(b"wrong", record, policy=policy)


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


def test_kdf_rejects_context_policy_before_argon2_work() -> None:
    parameters = Argon2idParameters(19_456, 2, 1)
    policy = ResourcePolicy(max_target_round=0)
    with pytest.raises(ValueError, match="target_round"):
        derive_argon2id_sigma(
            b"password",
            b"0123456789abcdef",
            parameters,
            policy=policy,
        )
