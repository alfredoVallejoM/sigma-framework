"""Deterministic mutation fuzz harness for every public v2 binary parser."""

import argparse
import random
from collections.abc import Callable
from typing import Any

from sigma.anchors import AnchorEvidence, CrossWide, CrossWideEvidence, StreamWide
from sigma.applications.kdf_argon2id import (
    KDF_FINAL_DOMAIN,
    Argon2idParameters,
    SigmaPasswordRecord,
)
from sigma.applications.pow import PowParameters, PowPredicate
from sigma.applications.signed import SigmaSignedCommitmentV2
from sigma.outputs import SigmaDigestV2
from sigma.presets import lightweight_v2_2, paranoid_wide_v2_2
from sigma.spec import SigmaContextV2
from sigma.spec.encoding import DecodeError
from sigma.spec.ids import SignatureAlgorithmId
from sigma.v2 import hash_bytes


def _mutate(rng: random.Random, data: bytes) -> bytes:
    changed = bytearray(data)
    operation = rng.randrange(4)
    if operation == 0 and changed:
        del changed[rng.randrange(len(changed)) :]
    elif operation == 1 and changed:
        changed[rng.randrange(len(changed))] ^= 1 << rng.randrange(8)
    elif operation == 2:
        changed.extend(rng.randbytes(rng.randrange(1, 9)))
    else:
        changed = bytearray(rng.randbytes(rng.randrange(0, len(changed) + 9)))
    return bytes(changed)


def _exercise(
    rng: random.Random,
    encoded: bytes,
    parser: Callable[[bytes], Any],
    serializer: Callable[[Any], bytes],
    iterations: int,
) -> int:
    accepted = 0
    for _ in range(iterations):
        candidate = _mutate(rng, encoded)
        try:
            parsed = parser(candidate)
        except DecodeError:
            continue
        assert serializer(parsed) == candidate, "parser accepted a non-canonical representation"
        accepted += 1
    return accepted


def canonical_codec_cases() -> tuple[tuple[str, bytes, Callable[[bytes], Any]], ...]:
    """Build one valid seed and its parser for every public binary codec."""

    context = SigmaContextV2(salt=b"salt", challenge=b"challenge")
    digest = hash_bytes(b"fuzz-seed", context)
    pow_parameters = PowParameters(b"challenge", 2, 2, PowPredicate.DUAL_STATE, 3)
    kdf_parameters = Argon2idParameters(1024, 2, 1)
    kdf_salt = b"fuzz-salt-value"
    kdf_context = lightweight_v2_2(
        salt=kdf_salt,
        application_context=KDF_FINAL_DOMAIN + kdf_parameters.to_bytes(),
    )
    kdf_record = SigmaPasswordRecord(
        kdf_parameters, kdf_salt, hash_bytes(b"diagnostic-base", kdf_context)
    )
    wide_context = lightweight_v2_2()
    wide_evidence = StreamWide.compute(wide_context, (b"fuzz-seed",))
    cross_context = paranoid_wide_v2_2()
    cross_evidence = CrossWide.compute(cross_context, (b"fuzz-seed",))
    signed_digest = hash_bytes(b"fuzz-seed", wide_context)
    signed = SigmaSignedCommitmentV2(
        wide_context,
        wide_evidence,
        signed_digest.states,
        SignatureAlgorithmId.ED25519,
        b"fuzz-key",
        b"\x00" * 64,
    )
    return (
        ("context", context.to_bytes(), SigmaContextV2.from_bytes),
        ("digest", digest.to_bytes(), SigmaDigestV2.from_bytes),
        ("pow", pow_parameters.to_bytes(), PowParameters.from_bytes),
        ("kdf", kdf_parameters.to_bytes(), Argon2idParameters.from_bytes),
        ("kdf-record", kdf_record.to_bytes(), SigmaPasswordRecord.from_bytes),
        (
            "evidence-wide",
            wide_evidence.to_bytes(),
            lambda data: AnchorEvidence.from_bytes(data, wide_context),
        ),
        (
            "evidence-cross",
            cross_evidence.to_bytes(),
            lambda data: CrossWideEvidence.from_bytes(data, cross_context),
        ),
        ("signed", signed.to_bytes(), SigmaSignedCommitmentV2.from_bytes),
    )


def fuzz(seed: int = 0x51A6A, iterations: int = 10_000) -> dict[str, int]:
    if iterations <= 0:
        raise ValueError("iterations must be positive")
    rng = random.Random(seed)
    return {
        name: _exercise(rng, encoded, parser, lambda value: value.to_bytes(), iterations)
        for name, encoded, parser in canonical_codec_cases()
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--seed", type=int, default=0x51A6A)
    parser.add_argument("--iterations", type=int, default=10_000)
    args = parser.parse_args()
    results = fuzz(args.seed, args.iterations)
    print(f"completed {args.iterations} mutations per codec; accepted canonical cases: {results}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
