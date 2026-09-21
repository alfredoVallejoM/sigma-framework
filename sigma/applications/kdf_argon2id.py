"""Optional Argon2id composition; Sigma adds binding and overhead, not entropy."""

import hashlib
import hmac
from dataclasses import dataclass, field
from typing import NoReturn

from sigma.outputs import SigmaDigestV2
from sigma.policy import DEFAULT_RESOURCE_POLICY, ResourcePolicy
from sigma.presets import get_preset
from sigma.spec import SigmaContextV2
from sigma.spec.encoding import DecodeError, decode_tlv, decode_uint, encode_tlv, encode_uint
from sigma.spec.ids import SuiteId
from sigma.suites.registry import get_suite
from sigma.v2 import hash_bytes
from sigma.validation import require_int

ARGON2_VERSION_13 = 0x13
KDF_MAGIC = b"SIGMAKDF2"
KDF_RECORD_MAGIC = b"SIGMAKVR2"
KDF_FINAL_DOMAIN = b"SIGMA-KDF-BIND-V2"
KDF_KEY_DOMAIN = b"SIGMA-KDF-KEY-V2"
KDF_PRESETS = frozenset(
    {
        "lightweight-v2-2",
        "paranoid-wide-v2-2",
        "paranoid-deep-v2-2",
        "paranoid-deep-vector-v2-2",
    }
)
KDF_SUITE_IDS = frozenset(
    {
        SuiteId.LIGHTWEIGHT_STREAM_WIDE_V2_2,
        SuiteId.PARANOID_CROSS_WIDE_V2_2,
        SuiteId.PARANOID_DEEP_V2_2,
        SuiteId.PARANOID_DEEP_VECTOR_V2_2,
    }
)


@dataclass(frozen=True)
class Argon2idParameters:
    memory_kib: int
    time_cost: int
    parallelism: int
    output_length: int = 32
    version: int = ARGON2_VERSION_13

    def __post_init__(self) -> None:
        require_int("parallelism", self.parallelism, minimum=1, maximum=0xFFFF)
        require_int("memory_kib", self.memory_kib, minimum=1, maximum=0xFFFFFFFF)
        require_int("time_cost", self.time_cost, minimum=1, maximum=0xFFFFFFFF)
        require_int("output_length", self.output_length, minimum=16, maximum=1024)
        require_int("version", self.version, minimum=0, maximum=0xFF)
        if self.memory_kib < 8 * self.parallelism:
            raise ValueError("memory_kib must be at least 8 * parallelism and fit uint32")
        if self.version != ARGON2_VERSION_13:
            raise ValueError("only Argon2 version 1.3 is supported")

    def to_bytes(self) -> bytes:
        return KDF_MAGIC + encode_tlv(
            (
                (1, encode_uint(self.memory_kib, 4)),
                (2, encode_uint(self.time_cost, 4)),
                (3, encode_uint(self.parallelism, 2)),
                (4, encode_uint(self.output_length, 2)),
                (5, encode_uint(self.version, 1)),
            )
        )

    @classmethod
    def from_bytes(cls, data: bytes) -> "Argon2idParameters":
        if not isinstance(data, bytes) or not data.startswith(KDF_MAGIC):
            raise DecodeError("invalid KDF parameter magic")
        fields = decode_tlv(data[len(KDF_MAGIC) :], allowed_tags=frozenset(range(1, 6)))
        if set(fields) != set(range(1, 6)):
            raise DecodeError("missing KDF parameter fields")
        try:
            return cls(
                memory_kib=decode_uint(fields[1], 4),
                time_cost=decode_uint(fields[2], 4),
                parallelism=decode_uint(fields[3], 2),
                output_length=decode_uint(fields[4], 2),
                version=decode_uint(fields[5], 1),
            )
        except (TypeError, ValueError) as exc:
            raise DecodeError(f"invalid KDF parameters: {exc}") from exc


def derive_argon2id(
    password: bytes,
    salt: bytes,
    parameters: Argon2idParameters,
    *,
    policy: ResourcePolicy = DEFAULT_RESOURCE_POLICY,
) -> bytes:
    if not isinstance(password, bytes):
        raise TypeError("password must be bytes")
    if not isinstance(salt, bytes) or len(salt) < 8:
        raise ValueError("salt must contain at least 8 bytes")
    policy.validate_argon2(parameters.memory_kib, parameters.time_cost)
    try:
        from argon2.low_level import Type, hash_secret_raw
    except ImportError as exc:
        raise RuntimeError("install sigma-framework[kdf] to use Argon2id") from exc
    return hash_secret_raw(
        secret=password,
        salt=salt,
        time_cost=parameters.time_cost,
        memory_cost=parameters.memory_kib,
        parallelism=parameters.parallelism,
        hash_len=parameters.output_length,
        type=Type.ID,
        version=parameters.version,
    )


def _validate_composition(
    parameters: Argon2idParameters,
    salt: bytes,
    digest: SigmaDigestV2,
) -> None:
    if not isinstance(parameters, Argon2idParameters):
        raise TypeError("parameters must be Argon2idParameters")
    if not isinstance(salt, bytes) or len(salt) < 8:
        raise ValueError("salt must contain at least 8 bytes")
    if not isinstance(digest, SigmaDigestV2):
        raise TypeError("sigma_digest must be SigmaDigestV2")
    if digest.context.suite_id not in KDF_SUITE_IDS:
        raise ValueError("Sigma digest suite is not registered for KDF composition")
    suite = get_suite(digest.context.suite_id)
    if suite.suite_family != "v2-2":
        raise ValueError("Sigma KDF composition requires a v2.2 suite")
    suite.validate_context(digest.context)
    if digest.context.salt != salt:
        raise ValueError("Sigma digest salt differs from KDF record")
    expected_application = KDF_FINAL_DOMAIN + parameters.to_bytes()
    if digest.context.application_context != expected_application:
        raise ValueError("Sigma digest does not bind the KDF parameters")


def _derive_final_key(
    base_key: bytes,
    parameters: Argon2idParameters,
    salt: bytes,
    digest: SigmaDigestV2,
) -> bytes:
    framed = encode_tlv(
        (
            (1, base_key),
            (2, parameters.to_bytes()),
            (3, salt),
            (4, digest.to_bytes()),
        )
    )
    return hashlib.shake_256(KDF_KEY_DOMAIN + framed).digest(parameters.output_length)


@dataclass(frozen=True)
class SigmaPasswordRecord:
    parameters: Argon2idParameters
    salt: bytes
    sigma_digest: SigmaDigestV2

    def __post_init__(self) -> None:
        _validate_composition(self.parameters, self.salt, self.sigma_digest)

    def to_bytes(self) -> bytes:
        return KDF_RECORD_MAGIC + encode_tlv(
            (
                (1, self.parameters.to_bytes()),
                (2, self.salt),
                (3, self.sigma_digest.to_bytes()),
            )
        )

    @classmethod
    def from_bytes(cls, data: bytes) -> "SigmaPasswordRecord":
        if not isinstance(data, bytes) or not data.startswith(KDF_RECORD_MAGIC):
            raise DecodeError("invalid KDF password-record magic")
        fields = decode_tlv(data[len(KDF_RECORD_MAGIC) :], allowed_tags=frozenset(range(1, 4)))
        if set(fields) != set(range(1, 4)):
            raise DecodeError("missing KDF password-record fields")
        try:
            return cls(
                parameters=Argon2idParameters.from_bytes(fields[1]),
                salt=fields[2],
                sigma_digest=SigmaDigestV2.from_bytes(fields[3]),
            )
        except (TypeError, ValueError) as exc:
            raise DecodeError(f"invalid KDF password record: {exc}") from exc


@dataclass(frozen=True)
class SigmaDerivedKey:
    """Secret KDF output. Deliberately has no binary serialization method."""

    parameters: Argon2idParameters
    salt: bytes
    sigma_digest: SigmaDigestV2
    final_key: bytes = field(repr=False)

    def __post_init__(self) -> None:
        _validate_composition(self.parameters, self.salt, self.sigma_digest)
        if not isinstance(self.final_key, bytes):
            raise TypeError("final_key must be bytes")
        if len(self.final_key) != self.parameters.output_length:
            raise ValueError("final key length differs from KDF parameters")

    def password_record(self) -> SigmaPasswordRecord:
        return SigmaPasswordRecord(self.parameters, self.salt, self.sigma_digest)

    def __reduce_ex__(self, _protocol: object) -> NoReturn:
        raise TypeError("SigmaDerivedKey must not be pickled; derive it again when needed")


def _kdf_context(
    parameters: Argon2idParameters,
    salt: bytes,
    preset: str,
    policy: ResourcePolicy,
) -> SigmaContextV2:
    if not isinstance(parameters, Argon2idParameters):
        raise TypeError("parameters must be Argon2idParameters")
    if not isinstance(salt, bytes) or len(salt) < 8:
        raise ValueError("salt must contain at least 8 bytes")
    if preset not in KDF_PRESETS:
        raise ValueError(f"unsupported Sigma KDF preset: {preset}")
    context = get_preset(
        preset,
        salt=salt,
        application_context=KDF_FINAL_DOMAIN + parameters.to_bytes(),
    )
    if context.suite_id not in KDF_SUITE_IDS:
        raise ValueError("Sigma preset is not registered for KDF composition")
    policy.validate_context(context)
    return context


def compose_argon2id_output(
    base_key: bytes,
    salt: bytes,
    parameters: Argon2idParameters,
    *,
    policy: ResourcePolicy = DEFAULT_RESOURCE_POLICY,
    preset: str = "lightweight-v2-2",
) -> SigmaDerivedKey:
    """Compose an already-derived Argon2id output with a registered Sigma mode."""

    if not isinstance(base_key, bytes):
        raise TypeError("base_key must be bytes")
    context = _kdf_context(parameters, salt, preset, policy)
    if len(base_key) != parameters.output_length:
        raise ValueError("base_key length differs from KDF parameters")
    digest = hash_bytes(base_key, context, policy=policy)
    final_key = _derive_final_key(base_key, parameters, salt, digest)
    return SigmaDerivedKey(parameters, salt, digest, final_key)


def derive_argon2id_sigma(
    password: bytes,
    salt: bytes,
    parameters: Argon2idParameters,
    *,
    policy: ResourcePolicy = DEFAULT_RESOURCE_POLICY,
    preset: str = "lightweight-v2-2",
) -> SigmaDerivedKey:
    """Return only the composed result; the intermediate Argon2 key is not exposed."""

    context = _kdf_context(parameters, salt, preset, policy)
    base_key = derive_argon2id(password, salt, parameters, policy=policy)
    digest = hash_bytes(base_key, context, policy=policy)
    final_key = _derive_final_key(base_key, parameters, salt, digest)
    return SigmaDerivedKey(parameters, salt, digest, final_key)


def derive_key_from_password(
    password: bytes,
    record: SigmaPasswordRecord,
    *,
    policy: ResourcePolicy = DEFAULT_RESOURCE_POLICY,
) -> SigmaDerivedKey | None:
    if not isinstance(record, SigmaPasswordRecord):
        raise TypeError("record must be SigmaPasswordRecord")
    try:
        policy.validate_context(record.sigma_digest.context)
        base_key = derive_argon2id(password, record.salt, record.parameters, policy=policy)
        digest = hash_bytes(base_key, record.sigma_digest.context, policy=policy)
    except ValueError:
        return None
    if not hmac.compare_digest(digest.to_bytes(), record.sigma_digest.to_bytes()):
        return None
    final_key = _derive_final_key(base_key, record.parameters, record.salt, digest)
    return SigmaDerivedKey(record.parameters, record.salt, digest, final_key)


def verify_password(
    password: bytes,
    record: SigmaPasswordRecord,
    *,
    policy: ResourcePolicy = DEFAULT_RESOURCE_POLICY,
) -> bool:
    return derive_key_from_password(password, record, policy=policy) is not None
