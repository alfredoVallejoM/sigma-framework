import json
from pathlib import Path

from sigma.applications.kdf_argon2id import (
    Argon2idParameters,
    SigmaPasswordRecord,
    compose_argon2id_output,
)

VECTOR_PATH = Path(__file__).parents[2] / "specification" / "test-vectors" / "conformance-v2-2.json"


def _vectors() -> list[dict[str, str]]:
    return json.loads(VECTOR_PATH.read_text(encoding="utf-8"))["applications"]["kdf"]


def test_kdf_vectors_cover_every_registered_composition_and_codec() -> None:
    vectors = _vectors()
    assert {vector["preset"] for vector in vectors} == {
        "lightweight-v2-2",
        "paranoid-wide-v2-2",
        "paranoid-deep-v2-2",
        "paranoid-deep-vector-v2-2",
    }
    for vector in vectors:
        record = SigmaPasswordRecord.from_bytes(bytes.fromhex(vector["password_record_hex"]))
        assert record.to_bytes().hex() == vector["password_record_hex"]
        assert record.sigma_digest.to_bytes().hex() == vector["sigma_digest_hex"]
        assert record.parameters.to_bytes().hex() == vector["parameters_hex"]
        assert not hasattr(record, "final_key")


def test_kdf_vectors_recompute_from_registered_base_key() -> None:
    for vector in _vectors():
        parameters = Argon2idParameters.from_bytes(bytes.fromhex(vector["parameters_hex"]))
        actual = compose_argon2id_output(
            bytes.fromhex(vector["base_key_hex"]),
            bytes.fromhex(vector["salt_hex"]),
            parameters,
            preset=vector["preset"],
        )
        assert actual.final_key.hex() == vector["final_key_hex"]
        assert actual.sigma_digest.to_bytes().hex() == vector["sigma_digest_hex"]
        assert actual.password_record().to_bytes().hex() == vector["password_record_hex"]
