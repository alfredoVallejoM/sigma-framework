"""Deliberately regenerate the public Sigma KDF interoperability vector."""

import argparse
import json
from pathlib import Path

from sigma.applications.kdf_argon2id import Argon2idParameters, derive_argon2id_sigma


def generate() -> dict[str, object]:
    password = b"correct horse battery staple"
    salt = bytes.fromhex("000102030405060708090a0b0c0d0e0f")
    parameters = Argon2idParameters(memory_kib=19_456, time_cost=2, parallelism=1)
    result = derive_argon2id_sigma(password, salt, parameters)
    return {
        "final_key_hex": result.final_key.hex(),
        "parameters_hex": parameters.to_bytes().hex(),
        "password_hex": password.hex(),
        "result_hex": result.to_bytes().hex(),
        "salt_hex": salt.hex(),
        "sigma_digest_hex": result.sigma_digest.to_bytes().hex(),
        "suite": "lightweight-stream-wide-v2-2",
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("output", type=Path)
    args = parser.parse_args()
    if args.output.exists():
        parser.error(f"refusing to overwrite existing vector: {args.output}")
    args.output.write_text(
        json.dumps(generate(), indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
