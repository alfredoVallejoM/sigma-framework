"""Optional Argon2id composition; Sigma adds binding and overhead, not entropy."""

from dataclasses import dataclass

from sigma.outputs import SigmaDigestV2
from sigma.spec import SigmaContextV2
from sigma.spec.encoding import DecodeError, decode_tlv, decode_uint, encode_tlv, encode_uint
from sigma.v2 import hash_bytes

ARGON2_VERSION_13 = 0x13
KDF_MAGIC = b"SIGMAKDF2"


@dataclass(frozen=True)
class Argon2idParameters:
    memory_kib: int
    time_cost: int
    parallelism: int
    output_length: int = 32
    version: int = ARGON2_VERSION_13

    def __post_init__(self) -> None:
        for name in ("memory_kib", "time_cost", "parallelism", "output_length", "version"):
            value = getattr(self, name)
            if isinstance(value, bool) or not isinstance(value, int):
                raise TypeError(f"{name} must be an integer")
        if self.parallelism < 1 or self.parallelism > 0xFFFF:
            raise ValueError("parallelism must be in [1, 65535]")
        if self.memory_kib < 8 * self.parallelism or self.memory_kib > 0xFFFFFFFF:
            raise ValueError("memory_kib must be at least 8 * parallelism and fit uint32")
        if self.time_cost < 1 or self.time_cost > 0xFFFFFFFF:
            raise ValueError("time_cost must be in [1, 2^32-1]")
        if self.output_length < 16 or self.output_length > 1024:
            raise ValueError("output_length must be in [16, 1024]")
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


def derive_argon2id(password: bytes, salt: bytes, parameters: Argon2idParameters) -> bytes:
    if not isinstance(password, bytes):
        raise TypeError("password must be bytes")
    if not isinstance(salt, bytes) or len(salt) < 8:
        raise ValueError("salt must contain at least 8 bytes")
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


def derive_argon2id_sigma(
    password: bytes, salt: bytes, parameters: Argon2idParameters
) -> tuple[bytes, SigmaDigestV2]:
    base_key = derive_argon2id(password, salt, parameters)
    context = SigmaContextV2(
        salt=salt,
        application_context=parameters.to_bytes(),
    )
    return base_key, hash_bytes(base_key, context)
