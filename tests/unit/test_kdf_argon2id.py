import importlib.util

import pytest

from sigma.applications.kdf_argon2id import (
    Argon2idParameters,
    derive_argon2id,
    derive_argon2id_sigma,
)


def test_kdf_parameters_are_canonical_and_validated() -> None:
    parameters = Argon2idParameters(1024, 2, 1)
    assert parameters.to_bytes().startswith(b"SIGMAKDF2")
    assert Argon2idParameters.from_bytes(parameters.to_bytes()) == parameters
    with pytest.raises(ValueError, match=r"8 \* parallelism"):
        Argon2idParameters(7, 1, 1)


@pytest.mark.skipif(
    importlib.util.find_spec("argon2") is None, reason="optional argon2-cffi absent"
)
def test_argon2_composition_preserves_base_and_binds_parameters() -> None:
    parameters = Argon2idParameters(1024, 1, 1)
    salt = b"0123456789abcdef"
    base = derive_argon2id(b"password", salt, parameters)
    composed_base, digest = derive_argon2id_sigma(b"password", salt, parameters)
    assert composed_base == base
    assert digest.context.salt == salt
    assert digest.context.application_context == parameters.to_bytes()
