"""Immutable Sigma v2 context and its canonical wire representation."""

from dataclasses import dataclass
from typing import Tuple

from .encoding import (
    DecodeError,
    decode_tlv,
    decode_u16_sequence,
    decode_uint,
    encode_tlv,
    encode_u16_sequence,
    encode_uint,
)
from .ids import (
    CONTEXT_MAGIC,
    CONTEXT_VERSION,
    AlgorithmId,
    AnchorProfileId,
    ContextFieldId,
    OutputProfileId,
    RoundProfileId,
    SuiteId,
)

MAX_TARGET_ROUND = 1_000_000
MAX_STATE_COUNT = 16
MAX_CONTEXT_BYTES = 4096
DEFAULT_BRANCHES = (
    AlgorithmId.SHA512,
    AlgorithmId.SHA3_512,
    AlgorithmId.BLAKE2B_512,
    AlgorithmId.SHAKE256_512,
)
_FIELDS = frozenset(int(field) for field in ContextFieldId)


@dataclass(frozen=True)
class SigmaContextV2:
    suite_id: SuiteId = SuiteId.REFERENCE_STREAM_WIDE_V2
    anchor_profile: AnchorProfileId = AnchorProfileId.STREAM_WIDE
    round_profile: RoundProfileId = RoundProfileId.WIDE_ONCE
    output_profile: OutputProfileId = OutputProfileId.MULTI_STATE
    target_round: int = 1
    state_count: int = 2
    branches: Tuple[AlgorithmId, ...] = DEFAULT_BRANCHES
    chunk_size: int = 0
    salt: bytes = b""
    challenge: bytes = b""
    application_context: bytes = b""

    def __post_init__(self) -> None:
        for name, enum_type in (
            ("suite_id", SuiteId),
            ("anchor_profile", AnchorProfileId),
            ("round_profile", RoundProfileId),
            ("output_profile", OutputProfileId),
        ):
            if not isinstance(getattr(self, name), enum_type):
                raise TypeError(f"{name} must be {enum_type.__name__}")
        if isinstance(self.target_round, bool) or not 0 <= self.target_round <= MAX_TARGET_ROUND:
            raise ValueError(f"target_round must be in [0, {MAX_TARGET_ROUND}]")
        if isinstance(self.state_count, bool) or not 1 <= self.state_count <= MAX_STATE_COUNT:
            raise ValueError(f"state_count must be in [1, {MAX_STATE_COUNT}]")
        if isinstance(self.chunk_size, bool) or not 0 <= self.chunk_size <= 0xFFFFFFFF:
            raise ValueError("chunk_size must fit in an unsigned 32-bit integer")
        if not self.branches or len(set(self.branches)) != len(self.branches):
            raise ValueError("branches must be non-empty and contain no duplicates")
        if not all(isinstance(branch, AlgorithmId) for branch in self.branches):
            raise TypeError("branches must contain AlgorithmId values")
        for name in ("salt", "challenge", "application_context"):
            value = getattr(self, name)
            if not isinstance(value, bytes):
                raise TypeError(f"{name} must be bytes")
            if len(value) > MAX_CONTEXT_BYTES:
                raise ValueError(f"{name} exceeds {MAX_CONTEXT_BYTES} bytes")

    def to_bytes(self) -> bytes:
        body = encode_tlv(
            (
                (ContextFieldId.SUITE, encode_uint(self.suite_id, 2)),
                (ContextFieldId.ANCHOR_PROFILE, encode_uint(self.anchor_profile, 2)),
                (ContextFieldId.ROUND_PROFILE, encode_uint(self.round_profile, 2)),
                (ContextFieldId.OUTPUT_PROFILE, encode_uint(self.output_profile, 2)),
                (ContextFieldId.TARGET_ROUND, encode_uint(self.target_round, 4)),
                (ContextFieldId.STATE_COUNT, encode_uint(self.state_count, 2)),
                (ContextFieldId.BRANCHES, encode_u16_sequence(self.branches)),
                (ContextFieldId.CHUNK_SIZE, encode_uint(self.chunk_size, 4)),
                (ContextFieldId.SALT, self.salt),
                (ContextFieldId.CHALLENGE, self.challenge),
                (ContextFieldId.APPLICATION_CONTEXT, self.application_context),
            )
        )
        return CONTEXT_MAGIC + encode_uint(CONTEXT_VERSION, 2) + encode_uint(len(body), 4) + body

    @classmethod
    def from_bytes(cls, data: bytes) -> "SigmaContextV2":
        prefix_size = len(CONTEXT_MAGIC) + 6
        if not isinstance(data, bytes):
            raise TypeError("context encoding must be bytes")
        if len(data) < prefix_size or not data.startswith(CONTEXT_MAGIC):
            raise DecodeError("invalid or truncated context magic")
        offset = len(CONTEXT_MAGIC)
        version = decode_uint(data[offset : offset + 2], 2)
        if version != CONTEXT_VERSION:
            raise DecodeError(f"unsupported context version: {version}")
        body_length = decode_uint(data[offset + 2 : offset + 6], 4)
        if body_length != len(data) - prefix_size:
            raise DecodeError("context length mismatch or trailing bytes")
        fields = decode_tlv(data[prefix_size:], allowed_tags=_FIELDS)
        required = set(_FIELDS)
        if set(fields) != required:
            missing = sorted(required - set(fields))
            raise DecodeError(f"missing context fields: {missing}")
        try:
            return cls(
                suite_id=SuiteId(decode_uint(fields[ContextFieldId.SUITE], 2)),
                anchor_profile=AnchorProfileId(
                    decode_uint(fields[ContextFieldId.ANCHOR_PROFILE], 2)
                ),
                round_profile=RoundProfileId(decode_uint(fields[ContextFieldId.ROUND_PROFILE], 2)),
                output_profile=OutputProfileId(
                    decode_uint(fields[ContextFieldId.OUTPUT_PROFILE], 2)
                ),
                target_round=decode_uint(fields[ContextFieldId.TARGET_ROUND], 4),
                state_count=decode_uint(fields[ContextFieldId.STATE_COUNT], 2),
                branches=tuple(
                    AlgorithmId(item)
                    for item in decode_u16_sequence(fields[ContextFieldId.BRANCHES])
                ),
                chunk_size=decode_uint(fields[ContextFieldId.CHUNK_SIZE], 4),
                salt=fields[ContextFieldId.SALT],
                challenge=fields[ContextFieldId.CHALLENGE],
                application_context=fields[ContextFieldId.APPLICATION_CONTEXT],
            )
        except (TypeError, ValueError) as exc:
            raise DecodeError(f"invalid context field: {exc}") from exc
