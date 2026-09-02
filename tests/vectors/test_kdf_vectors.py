import importlib.util
import json
from pathlib import Path

import pytest

from sigma.applications.kdf_argon2id import SigmaKdfResult, derive_argon2id_sigma

VECTOR_PATH = (
    Path(__file__).parents[2] / "specification" / "test-vectors" / "argon2id-sigma-v2-2.json"
)


def test_kdf_vector_result_codec_is_frozen() -> None:
    vector = json.loads(VECTOR_PATH.read_text(encoding="utf-8"))
    result = SigmaKdfResult.from_bytes(bytes.fromhex(vector["result_hex"]))
    assert result.to_bytes().hex() == vector["result_hex"]
    assert result.final_key.hex() == vector["final_key_hex"]
    assert result.sigma_digest.to_bytes().hex() == vector["sigma_digest_hex"]
    assert result.parameters.to_bytes().hex() == vector["parameters_hex"]


@pytest.mark.skipif(
    importlib.util.find_spec("argon2") is None, reason="optional argon2-cffi absent"
)
def test_kdf_vector_recomputes_from_password() -> None:
    vector = json.loads(VECTOR_PATH.read_text(encoding="utf-8"))
    expected = SigmaKdfResult.from_bytes(bytes.fromhex(vector["result_hex"]))
    actual = derive_argon2id_sigma(
        bytes.fromhex(vector["password_hex"]),
        bytes.fromhex(vector["salt_hex"]),
        expected.parameters,
    )
    assert actual == expected
