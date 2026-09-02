"""Optional Argon2id composition; Sigma adds binding and overhead, not entropy."""

import hashlib
import hmac
from dataclasses import dataclass

from sigma.outputs import SigmaDigestV2
from sigma.policy import DEFAULT_RESOURCE_POLICY, ResourcePolicy
from sigma.presets import get_preset
from sigma.spec.encoding import DecodeError, decode_tlv, decode_uint, encode_tlv, encode_uint
from sigma.v2 import hash_bytes
from sigma.validation import require_int

ARGON2_VERSION_13 = 0x13
KDF_MAGIC = b"SIGMAKDF2"
KDF_RESULT_MAGIC = b"SIGMAKDR2"
KDF_FINAL_DOMAIN = b"SIGMA-KDF-FINAL-V1"
KDF_PRESETS = frozenset(
    {
        "lightweight-v2-2",
        "paranoid-wide-v2-2",
        "paranoid-deep-v2-2",
        "paranoid-deep-vector-v2-2",
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


def _final_key(parameters: Argon2idParameters, salt: bytes, digest: SigmaDigestV2) -> bytes:
    framed = encode_tlv(
        (
            (1, parameters.to_bytes()),
            (2, salt),
            (3, digest.to_bytes()),
        )
    )
    return hashlib.shake_256(KDF_FINAL_DOMAIN + framed).digest(parameters.output_length)


@dataclass(frozen=True)
class SigmaKdfResult:
    parameters: Argon2idParameters
    salt: bytes
    sigma_digest: SigmaDigestV2
    final_key: bytes

    def __post_init__(self) -> None:
        if not isinstance(self.parameters, Argon2idParameters):
            raise TypeError("parameters must be Argon2idParameters")
        if not isinstance(self.salt, bytes) or len(self.salt) < 8:
            raise ValueError("salt must contain at least 8 bytes")
        if not isinstance(self.sigma_digest, SigmaDigestV2):
            raise TypeError("sigma_digest must be SigmaDigestV2")
        if not isinstance(self.final_key, bytes):
            raise TypeError("final_key must be bytes")
        if self.sigma_digest.context.salt != self.salt:
            raise ValueError("Sigma digest salt differs from KDF result")
        expected_application = KDF_FINAL_DOMAIN + self.parameters.to_bytes()
        if self.sigma_digest.context.application_context != expected_application:
            raise ValueError("Sigma digest does not bind the KDF parameters")
        if len(self.final_key) != self.parameters.output_length:
            raise ValueError("final key length differs from KDF parameters")
        if not hmac.compare_digest(
            self.final_key, _final_key(self.parameters, self.salt, self.sigma_digest)
        ):
            raise ValueError("final key is inconsistent with the Sigma digest")

    def to_bytes(self) -> bytes:
        return KDF_RESULT_MAGIC + encode_tlv(
            (
                (1, self.parameters.to_bytes()),
                (2, self.salt),
                (3, self.sigma_digest.to_bytes()),
                (4, self.final_key),
            )
        )

    @classmethod
    def bind(
        cls,
        parameters: Argon2idParameters,
        salt: bytes,
        sigma_digest: SigmaDigestV2,
    ) -> "SigmaKdfResult":
        return cls(
            parameters,
            salt,
            sigma_digest,
            _final_key(parameters, salt, sigma_digest),
        )

    @classmethod
    def from_bytes(cls, data: bytes) -> "SigmaKdfResult":
        if not isinstance(data, bytes) or not data.startswith(KDF_RESULT_MAGIC):
            raise DecodeError("invalid KDF result magic")
        fields = decode_tlv(data[len(KDF_RESULT_MAGIC) :], allowed_tags=frozenset(range(1, 5)))
        if set(fields) != set(range(1, 5)):
            raise DecodeError("missing KDF result fields")
        try:
            return cls(
                parameters=Argon2idParameters.from_bytes(fields[1]),
                salt=fields[2],
                sigma_digest=SigmaDigestV2.from_bytes(fields[3]),
                final_key=fields[4],
            )
        except (TypeError, ValueError) as exc:
            raise DecodeError(f"invalid KDF result: {exc}") from exc


def derive_argon2id_sigma(
    password: bytes,
    salt: bytes,
    parameters: Argon2idParameters,
    *,
    policy: ResourcePolicy = DEFAULT_RESOURCE_POLICY,
    preset: str = "lightweight-v2-2",
) -> SigmaKdfResult:
    """Return only the composed result; the intermediate Argon2 key is not exposed."""

    base_key = derive_argon2id(password, salt, parameters, policy=policy)
    if preset not in KDF_PRESETS:
        raise ValueError(f"unsupported Sigma KDF preset: {preset}")
    context = get_preset(
        preset,
        salt=salt,
        application_context=KDF_FINAL_DOMAIN + parameters.to_bytes(),
    )
    digest = hash_bytes(base_key, context, policy=policy)
    return SigmaKdfResult.bind(parameters, salt, digest)


def verify_password(
    password: bytes,
    result: SigmaKdfResult,
    *,
    policy: ResourcePolicy = DEFAULT_RESOURCE_POLICY,
) -> bool:
    if not isinstance(result, SigmaKdfResult):
        raise TypeError("result must be SigmaKdfResult")
    try:
        base_key = derive_argon2id(password, result.salt, result.parameters, policy=policy)
        digest = hash_bytes(base_key, result.sigma_digest.context, policy=policy)
        candidate = SigmaKdfResult.bind(result.parameters, result.salt, digest)
    except ValueError:
        return False
    return hmac.compare_digest(candidate.final_key, result.final_key)
