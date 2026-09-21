"""Bounded Argon2id + Sigma v3 composition.

Argon2id supplies password-hardening. Sigma adds a public, domain-separated
binding step and is not described as memory-hard.
"""

from __future__ import annotations

import hashlib
import hmac
from dataclasses import dataclass, field
from enum import IntEnum
from typing import NoReturn

from sigma.crypto.primitives import domain_tag_v3
from sigma.outputs.digest_v3 import SigmaDigestV3, digest_from_evaluation_v3
from sigma.policy import DEFAULT_RESOURCE_POLICY, ResourcePolicy
from sigma.rounds.evaluate_v3 import evaluate_v3
from sigma.sources import BytesSource
from sigma.spec.codec_v3 import decode_record, encode_record, validate_record_prefix
from sigma.spec.context_v3 import SigmaContextV3
from sigma.spec.encoding import DecodeError, decode_uint, encode_uint
from sigma.spec.ids_v3 import DomainIdV3, SuiteIdV3
from sigma.suites.registry_v3 import get_suite_v3
from sigma.validation import require_int


class _ParameterField(IntEnum):
    DOMAIN = 1
    SUITE = 2
    MEMORY_KIB = 3
    TIME_COST = 4
    PARALLELISM = 5
    OUTPUT_LENGTH = 6
    VERSION = 7


class _RecordField(IntEnum):
    DOMAIN = 1
    PARAMETERS = 2
    SALT = 3
    DIGEST = 4


@dataclass(frozen=True)
class Argon2idParametersV3:
    memory_kib: int
    time_cost: int
    parallelism: int
    output_length: int = 32
    version: int = 0x13
    suite_id: SuiteIdV3 = SuiteIdV3.REFERENCE_IAP_V3

    def __post_init__(self) -> None:
        require_int("memory_kib", self.memory_kib, minimum=8, maximum=0xFFFFFFFF)
        require_int("time_cost", self.time_cost, minimum=1, maximum=0xFFFFFFFF)
        require_int("parallelism", self.parallelism, minimum=1, maximum=0xFFFF)
        require_int("output_length", self.output_length, minimum=16, maximum=1024)
        require_int("version", self.version, minimum=0, maximum=0xFF)
        if self.memory_kib < 8 * self.parallelism:
            raise ValueError("memory_kib must be at least 8 times parallelism")
        if self.version != 0x13:
            raise ValueError("only Argon2 version 1.3 is supported")
        if not isinstance(self.suite_id, SuiteIdV3):
            raise TypeError("suite_id must be SuiteIdV3")
        descriptor = get_suite_v3(self.suite_id)
        if descriptor.t_max > MAX_KDF_T_MAX or descriptor.k_max > MAX_KDF_K_MAX:
            raise ValueError("Sigma v3 suite exceeds the KDF work bound")

    def to_bytes(self) -> bytes:
        return encode_record(
            KDF_PARAMETERS_V3_MAGIC,
            (
                (_ParameterField.DOMAIN, domain_tag_v3(DomainIdV3.KDF_BINDING)),
                (_ParameterField.SUITE, encode_uint(self.suite_id, 2)),
                (_ParameterField.MEMORY_KIB, encode_uint(self.memory_kib, 4)),
                (_ParameterField.TIME_COST, encode_uint(self.time_cost, 4)),
                (_ParameterField.PARALLELISM, encode_uint(self.parallelism, 2)),
                (_ParameterField.OUTPUT_LENGTH, encode_uint(self.output_length, 2)),
                (_ParameterField.VERSION, encode_uint(self.version, 1)),
            ),
        )

    @classmethod
    def from_bytes(cls, data: bytes) -> Argon2idParametersV3:
        validate_record_prefix(
            data,
            magic=KDF_PARAMETERS_V3_MAGIC,
            expected_fields=((int(_ParameterField.DOMAIN), domain_tag_v3(DomainIdV3.KDF_BINDING)),),
        )
        fields = decode_record(
            data,
            magic=KDF_PARAMETERS_V3_MAGIC,
            allowed_tags=_PARAMETER_FIELDS,
            required_tags=_PARAMETER_FIELDS,
        )
        try:
            return cls(
                memory_kib=decode_uint(fields[_ParameterField.MEMORY_KIB], 4),
                time_cost=decode_uint(fields[_ParameterField.TIME_COST], 4),
                parallelism=decode_uint(fields[_ParameterField.PARALLELISM], 2),
                output_length=decode_uint(fields[_ParameterField.OUTPUT_LENGTH], 2),
                version=decode_uint(fields[_ParameterField.VERSION], 1),
                suite_id=SuiteIdV3(decode_uint(fields[_ParameterField.SUITE], 2)),
            )
        except DecodeError:
            raise
        except (TypeError, ValueError) as exc:
            raise DecodeError("invalid Sigma v3 Argon2id parameters") from exc


@dataclass(frozen=True)
class SigmaPasswordRecordV3:
    parameters: Argon2idParametersV3
    salt: bytes
    sigma_digest: SigmaDigestV3

    def __post_init__(self) -> None:
        _validate_composition(self.parameters, self.salt, self.sigma_digest)

    def to_bytes(self) -> bytes:
        return encode_record(
            KDF_RECORD_V3_MAGIC,
            (
                (_RecordField.DOMAIN, domain_tag_v3(DomainIdV3.KDF_BINDING)),
                (_RecordField.PARAMETERS, self.parameters.to_bytes()),
                (_RecordField.SALT, self.salt),
                (_RecordField.DIGEST, self.sigma_digest.to_bytes()),
            ),
        )

    @classmethod
    def from_bytes(cls, data: bytes) -> SigmaPasswordRecordV3:
        validate_record_prefix(
            data,
            magic=KDF_RECORD_V3_MAGIC,
            expected_fields=((int(_RecordField.DOMAIN), domain_tag_v3(DomainIdV3.KDF_BINDING)),),
        )
        fields = decode_record(
            data,
            magic=KDF_RECORD_V3_MAGIC,
            allowed_tags=_RECORD_FIELDS,
            required_tags=_RECORD_FIELDS,
        )
        try:
            return cls(
                Argon2idParametersV3.from_bytes(fields[_RecordField.PARAMETERS]),
                fields[_RecordField.SALT],
                SigmaDigestV3.from_bytes(fields[_RecordField.DIGEST]),
            )
        except DecodeError:
            raise
        except (TypeError, ValueError) as exc:
            raise DecodeError("invalid Sigma v3 password record") from exc


@dataclass(frozen=True)
class SigmaDerivedKeyV3:
    """Secret result: intentionally no byte-wire method and no pickle support."""

    parameters: Argon2idParametersV3
    salt: bytes
    sigma_digest: SigmaDigestV3
    final_key: bytes = field(repr=False)

    def __post_init__(self) -> None:
        _validate_composition(self.parameters, self.salt, self.sigma_digest)
        if (
            not isinstance(self.final_key, bytes)
            or len(self.final_key) != self.parameters.output_length
        ):
            raise ValueError("final_key length must match output_length")

    def password_record(self) -> SigmaPasswordRecordV3:
        return SigmaPasswordRecordV3(self.parameters, self.salt, self.sigma_digest)

    def __reduce_ex__(self, _protocol: object) -> NoReturn:
        raise TypeError("SigmaDerivedKeyV3 must not be pickled; derive it again")


def derive_argon2id_v3(
    password: bytes,
    salt: bytes,
    parameters: Argon2idParametersV3,
    *,
    policy: ResourcePolicy = DEFAULT_RESOURCE_POLICY,
) -> bytes:
    if not isinstance(password, bytes):
        raise TypeError("password must be bytes")
    _validate_parameters_and_salt(parameters, salt, policy)
    try:
        from argon2.low_level import Type, hash_secret_raw
    except ImportError as exc:  # pragma: no cover - dependency-specific
        raise RuntimeError("Argon2id support requires the kdf extra") from exc
    return hash_secret_raw(
        password,
        salt,
        time_cost=parameters.time_cost,
        memory_cost=parameters.memory_kib,
        parallelism=parameters.parallelism,
        hash_len=parameters.output_length,
        type=Type.ID,
        version=parameters.version,
    )


def compose_argon2id_output_v3(
    base_key: bytes,
    salt: bytes,
    parameters: Argon2idParametersV3,
    *,
    policy: ResourcePolicy = DEFAULT_RESOURCE_POLICY,
) -> SigmaDerivedKeyV3:
    if not isinstance(base_key, bytes):
        raise TypeError("base_key must be bytes")
    _validate_parameters_and_salt(parameters, salt, policy)
    if len(base_key) != parameters.output_length:
        raise ValueError("base_key length must match output_length")
    context = _kdf_context(parameters, salt)
    digest = digest_from_evaluation_v3(evaluate_v3(context, BytesSource(base_key)))
    final_key = _derive_final_key(base_key, parameters, salt, digest)
    return SigmaDerivedKeyV3(parameters, salt, digest, final_key)


def derive_argon2id_sigma_v3(
    password: bytes,
    salt: bytes,
    parameters: Argon2idParametersV3,
    *,
    policy: ResourcePolicy = DEFAULT_RESOURCE_POLICY,
) -> SigmaDerivedKeyV3:
    base_key = derive_argon2id_v3(password, salt, parameters, policy=policy)
    return compose_argon2id_output_v3(base_key, salt, parameters, policy=policy)


def derive_key_from_password_v3(
    password: bytes,
    record: SigmaPasswordRecordV3,
    *,
    policy: ResourcePolicy = DEFAULT_RESOURCE_POLICY,
) -> SigmaDerivedKeyV3 | None:
    if not isinstance(record, SigmaPasswordRecordV3):
        raise TypeError("record must be SigmaPasswordRecordV3")
    base_key = derive_argon2id_v3(password, record.salt, record.parameters, policy=policy)
    candidate = compose_argon2id_output_v3(
        base_key,
        record.salt,
        record.parameters,
        policy=policy,
    )
    if not hmac.compare_digest(
        candidate.sigma_digest.to_bytes(),
        record.sigma_digest.to_bytes(),
    ):
        return None
    return candidate


def verify_password_v3(
    password: bytes,
    record: SigmaPasswordRecordV3,
    *,
    policy: ResourcePolicy = DEFAULT_RESOURCE_POLICY,
) -> bool:
    return derive_key_from_password_v3(password, record, policy=policy) is not None


def _validate_parameters_and_salt(
    parameters: Argon2idParametersV3,
    salt: bytes,
    policy: ResourcePolicy,
) -> None:
    if not isinstance(parameters, Argon2idParametersV3):
        raise TypeError("parameters must be Argon2idParametersV3")
    if not isinstance(salt, bytes) or not 8 <= len(salt) <= MAX_KDF_SALT_BYTES:
        raise ValueError("salt must contain 8..1024 bytes")
    if not isinstance(policy, ResourcePolicy):
        raise TypeError("policy must be ResourcePolicy")
    policy.validate_argon2(parameters.memory_kib, parameters.time_cost)


def _kdf_context(parameters: Argon2idParametersV3, salt: bytes) -> SigmaContextV3:
    return SigmaContextV3.for_suite(
        parameters.suite_id,
        salt=salt,
        challenge=domain_tag_v3(DomainIdV3.KDF_BINDING),
        application_context=parameters.to_bytes(),
    )


def _validate_composition(
    parameters: Argon2idParametersV3,
    salt: bytes,
    digest: SigmaDigestV3,
) -> None:
    if not isinstance(parameters, Argon2idParametersV3):
        raise TypeError("parameters must be Argon2idParametersV3")
    if not isinstance(salt, bytes) or not 8 <= len(salt) <= MAX_KDF_SALT_BYTES:
        raise ValueError("salt must contain 8..1024 bytes")
    if not isinstance(digest, SigmaDigestV3):
        raise TypeError("sigma_digest must be SigmaDigestV3")
    if digest.context.to_bytes() != _kdf_context(parameters, salt).to_bytes():
        raise ValueError("digest context does not bind KDF parameters and salt")


def _derive_final_key(
    base_key: bytes,
    parameters: Argon2idParametersV3,
    salt: bytes,
    digest: SigmaDigestV3,
) -> bytes:
    framed = encode_record(
        KDF_SECRET_V3_MAGIC,
        (
            (1, domain_tag_v3(DomainIdV3.KDF_FINAL_KEY)),
            (2, base_key),
            (3, parameters.to_bytes()),
            (4, salt),
            (5, digest.to_bytes()),
        ),
    )
    return hashlib.shake_256(framed).digest(parameters.output_length)


KDF_PARAMETERS_V3_MAGIC = b"SIG3KDFP"
KDF_RECORD_V3_MAGIC = b"SIG3KDFR"
KDF_SECRET_V3_MAGIC = b"SIG3KDFS"
MAX_KDF_SALT_BYTES = 1024
MAX_KDF_T_MAX = 32
MAX_KDF_K_MAX = 4
_PARAMETER_FIELDS = frozenset(int(field) for field in _ParameterField)
_RECORD_FIELDS = frozenset(int(field) for field in _RecordField)

__all__ = [
    "Argon2idParametersV3",
    "SigmaDerivedKeyV3",
    "SigmaPasswordRecordV3",
    "compose_argon2id_output_v3",
    "derive_argon2id_sigma_v3",
    "derive_argon2id_v3",
    "derive_key_from_password_v3",
    "verify_password_v3",
]
