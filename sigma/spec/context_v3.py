"""Immutable pre-input context for the incompatible Sigma v3 family."""

from __future__ import annotations

from dataclasses import dataclass
from enum import IntEnum

from sigma.spec.codec_v3 import decode_record, encode_record
from sigma.spec.encoding import (
    DecodeError,
    decode_u16_sequence,
    decode_uint,
    encode_u16_sequence,
    encode_uint,
)
from sigma.spec.ids import AlgorithmId
from sigma.spec.ids_v3 import (
    AnchorProfileIdV3,
    CardinalityProfileIdV3,
    InputProfileIdV3,
    JointProfileIdV3,
    LayoutProfileIdV3,
    OutputProfileIdV3,
    RoundProfileIdV3,
    SuiteIdV3,
    TrajectoryProfileIdV3,
)
from sigma.suites.registry_v3 import get_suite_v3

CONTEXT_V3_MAGIC = b"SIGMACT3"
MAX_CONTEXT_COMPONENT_BYTES = 4096
MAX_STATE_SIZE = 4096
MAX_TARGET_ROUND = 1_000_000
MAX_STATE_COUNT = 64


class ContextFieldIdV3(IntEnum):
    SUITE = 1
    INPUT_PROFILE = 2
    ANCHOR_PROFILE = 3
    ROUND_PROFILE = 4
    OUTPUT_PROFILE = 5
    CARDINALITY_PROFILE = 6
    JOINT_PROFILE = 7
    LAYOUT_PROFILE = 8
    TRAJECTORY_PROFILE = 9
    ANCHOR_ALGORITHMS = 10
    JOINT_ALGORITHMS = 11
    STATE_ALGORITHM = 12
    BRANCH_COUNT = 13
    CHUNK_SIZE = 14
    STATE_SIZE = 15
    T_MIN = 16
    T_MAX = 17
    K_MIN = 18
    K_MAX = 19
    SALT = 20
    CHALLENGE = 21
    APPLICATION_CONTEXT = 22
    LENGTH_ALGORITHM = 23


_FIELDS = frozenset(int(field) for field in ContextFieldIdV3)


@dataclass(frozen=True)
class SigmaContextV3:
    suite_id: SuiteIdV3
    input_profile: InputProfileIdV3
    anchor_profile: AnchorProfileIdV3
    round_profile: RoundProfileIdV3
    output_profile: OutputProfileIdV3
    cardinality_profile: CardinalityProfileIdV3
    joint_profile: JointProfileIdV3
    layout_profile: LayoutProfileIdV3
    trajectory_profile: TrajectoryProfileIdV3
    anchor_algorithms: tuple[AlgorithmId, ...]
    joint_algorithms: tuple[AlgorithmId, ...]
    length_algorithm: AlgorithmId
    state_algorithm: AlgorithmId
    branch_count: int
    chunk_size: int
    state_size: int
    t_min: int
    t_max: int
    k_min: int
    k_max: int
    salt: bytes
    challenge: bytes
    application_context: bytes

    def __post_init__(self) -> None:
        enum_fields = (
            ("suite_id", SuiteIdV3),
            ("input_profile", InputProfileIdV3),
            ("anchor_profile", AnchorProfileIdV3),
            ("round_profile", RoundProfileIdV3),
            ("output_profile", OutputProfileIdV3),
            ("cardinality_profile", CardinalityProfileIdV3),
            ("joint_profile", JointProfileIdV3),
            ("layout_profile", LayoutProfileIdV3),
            ("trajectory_profile", TrajectoryProfileIdV3),
            ("length_algorithm", AlgorithmId),
            ("state_algorithm", AlgorithmId),
        )
        for name, enum_type in enum_fields:
            if not isinstance(getattr(self, name), enum_type):
                raise TypeError(f"{name} must be {enum_type.__name__}")
        for name in ("anchor_algorithms", "joint_algorithms"):
            values = getattr(self, name)
            if not isinstance(values, tuple) or not values:
                raise ValueError(f"{name} must be a non-empty tuple")
            if any(not isinstance(value, AlgorithmId) for value in values):
                raise TypeError(f"{name} must contain AlgorithmId values")
            if len(values) != len(set(values)):
                raise ValueError(f"{name} must not contain duplicates")
        integer_ranges = (
            ("branch_count", 1, 64),
            ("chunk_size", 0, 1 << 30),
            ("state_size", 1, MAX_STATE_SIZE),
            ("t_min", 0, MAX_TARGET_ROUND),
            ("t_max", 0, MAX_TARGET_ROUND),
            ("k_min", 1, MAX_STATE_COUNT),
            ("k_max", 1, MAX_STATE_COUNT),
        )
        for name, minimum, maximum in integer_ranges:
            value = getattr(self, name)
            if isinstance(value, bool) or not isinstance(value, int):
                raise TypeError(f"{name} must be int")
            if not minimum <= value <= maximum:
                raise ValueError(f"{name} is out of range")
        if self.t_min > self.t_max or self.k_min > self.k_max:
            raise ValueError("trajectory parameter range is inverted")
        if self.branch_count != len(self.anchor_algorithms):
            raise ValueError("branch_count must match anchor_algorithms")
        for name in ("salt", "challenge", "application_context"):
            value = getattr(self, name)
            if not isinstance(value, bytes):
                raise TypeError(f"{name} must be bytes")
            if len(value) > MAX_CONTEXT_COMPONENT_BYTES:
                raise ValueError(f"{name} is too large")
        descriptor = get_suite_v3(self.suite_id)
        expected = (
            descriptor.input_profile,
            descriptor.anchor_profile,
            descriptor.round_profile,
            descriptor.output_profile,
            descriptor.cardinality_profile,
            descriptor.joint_profile,
            descriptor.layout_profile,
            descriptor.trajectory_profile,
            descriptor.anchor_algorithms,
            descriptor.joint_algorithms,
            descriptor.length_algorithm,
            descriptor.state_algorithm,
            len(descriptor.anchor_algorithms),
            descriptor.chunk_size,
            descriptor.state_size,
            descriptor.t_min,
            descriptor.t_max,
            descriptor.k_min,
            descriptor.k_max,
        )
        actual = (
            self.input_profile,
            self.anchor_profile,
            self.round_profile,
            self.output_profile,
            self.cardinality_profile,
            self.joint_profile,
            self.layout_profile,
            self.trajectory_profile,
            self.anchor_algorithms,
            self.joint_algorithms,
            self.length_algorithm,
            self.state_algorithm,
            self.branch_count,
            self.chunk_size,
            self.state_size,
            self.t_min,
            self.t_max,
            self.k_min,
            self.k_max,
        )
        if actual != expected:
            raise ValueError("context does not match its registered v3 suite")

    @classmethod
    def reference(
        cls,
        *,
        salt: bytes,
        challenge: bytes,
        application_context: bytes,
    ) -> "SigmaContextV3":
        return cls.for_suite(
            SuiteIdV3.REFERENCE_IAP_V3,
            salt=salt,
            challenge=challenge,
            application_context=application_context,
        )

    @classmethod
    def for_suite(
        cls,
        suite_id: SuiteIdV3,
        *,
        salt: bytes,
        challenge: bytes,
        application_context: bytes,
    ) -> "SigmaContextV3":
        descriptor = get_suite_v3(suite_id)
        return cls(
            suite_id=descriptor.suite_id,
            input_profile=descriptor.input_profile,
            anchor_profile=descriptor.anchor_profile,
            round_profile=descriptor.round_profile,
            output_profile=descriptor.output_profile,
            cardinality_profile=descriptor.cardinality_profile,
            joint_profile=descriptor.joint_profile,
            layout_profile=descriptor.layout_profile,
            trajectory_profile=descriptor.trajectory_profile,
            anchor_algorithms=descriptor.anchor_algorithms,
            joint_algorithms=descriptor.joint_algorithms,
            length_algorithm=descriptor.length_algorithm,
            state_algorithm=descriptor.state_algorithm,
            branch_count=len(descriptor.anchor_algorithms),
            chunk_size=descriptor.chunk_size,
            state_size=descriptor.state_size,
            t_min=descriptor.t_min,
            t_max=descriptor.t_max,
            k_min=descriptor.k_min,
            k_max=descriptor.k_max,
            salt=salt,
            challenge=challenge,
            application_context=application_context,
        )

    def to_bytes(self) -> bytes:
        fields = (
            (ContextFieldIdV3.SUITE, encode_uint(self.suite_id, 2)),
            (ContextFieldIdV3.INPUT_PROFILE, encode_uint(self.input_profile, 2)),
            (ContextFieldIdV3.ANCHOR_PROFILE, encode_uint(self.anchor_profile, 2)),
            (ContextFieldIdV3.ROUND_PROFILE, encode_uint(self.round_profile, 2)),
            (ContextFieldIdV3.OUTPUT_PROFILE, encode_uint(self.output_profile, 2)),
            (ContextFieldIdV3.CARDINALITY_PROFILE, encode_uint(self.cardinality_profile, 2)),
            (ContextFieldIdV3.JOINT_PROFILE, encode_uint(self.joint_profile, 2)),
            (ContextFieldIdV3.LAYOUT_PROFILE, encode_uint(self.layout_profile, 2)),
            (ContextFieldIdV3.TRAJECTORY_PROFILE, encode_uint(self.trajectory_profile, 2)),
            (ContextFieldIdV3.ANCHOR_ALGORITHMS, encode_u16_sequence(self.anchor_algorithms)),
            (ContextFieldIdV3.JOINT_ALGORITHMS, encode_u16_sequence(self.joint_algorithms)),
            (ContextFieldIdV3.STATE_ALGORITHM, encode_uint(self.state_algorithm, 2)),
            (ContextFieldIdV3.BRANCH_COUNT, encode_uint(self.branch_count, 2)),
            (ContextFieldIdV3.CHUNK_SIZE, encode_uint(self.chunk_size, 4)),
            (ContextFieldIdV3.STATE_SIZE, encode_uint(self.state_size, 2)),
            (ContextFieldIdV3.T_MIN, encode_uint(self.t_min, 4)),
            (ContextFieldIdV3.T_MAX, encode_uint(self.t_max, 4)),
            (ContextFieldIdV3.K_MIN, encode_uint(self.k_min, 2)),
            (ContextFieldIdV3.K_MAX, encode_uint(self.k_max, 2)),
            (ContextFieldIdV3.SALT, self.salt),
            (ContextFieldIdV3.CHALLENGE, self.challenge),
            (ContextFieldIdV3.APPLICATION_CONTEXT, self.application_context),
            (ContextFieldIdV3.LENGTH_ALGORITHM, encode_uint(self.length_algorithm, 2)),
        )
        return encode_record(CONTEXT_V3_MAGIC, fields)

    @classmethod
    def from_bytes(cls, data: bytes) -> "SigmaContextV3":
        try:
            return cls._decode_bytes(data)
        except DecodeError:
            raise
        except (TypeError, ValueError) as exc:
            raise DecodeError("invalid Sigma v3 context") from exc

    @classmethod
    def _decode_bytes(cls, data: bytes) -> "SigmaContextV3":
        fields = decode_record(data, magic=CONTEXT_V3_MAGIC, allowed_tags=_FIELDS)

        def enum(field: ContextFieldIdV3, enum_type: type[IntEnum]) -> IntEnum:
            try:
                return enum_type(decode_uint(fields[field], 2))
            except ValueError as exc:
                raise DecodeError(f"unknown {field.name.lower()}") from exc

        try:
            anchor_algorithms = tuple(
                AlgorithmId(value)
                for value in decode_u16_sequence(fields[ContextFieldIdV3.ANCHOR_ALGORITHMS])
            )
            joint_algorithms = tuple(
                AlgorithmId(value)
                for value in decode_u16_sequence(fields[ContextFieldIdV3.JOINT_ALGORITHMS])
            )
        except ValueError as exc:
            raise DecodeError("unknown algorithm identifier") from exc
        return cls(
            suite_id=SuiteIdV3(enum(ContextFieldIdV3.SUITE, SuiteIdV3)),
            input_profile=InputProfileIdV3(enum(ContextFieldIdV3.INPUT_PROFILE, InputProfileIdV3)),
            anchor_profile=AnchorProfileIdV3(
                enum(ContextFieldIdV3.ANCHOR_PROFILE, AnchorProfileIdV3)
            ),
            round_profile=RoundProfileIdV3(enum(ContextFieldIdV3.ROUND_PROFILE, RoundProfileIdV3)),
            output_profile=OutputProfileIdV3(
                enum(ContextFieldIdV3.OUTPUT_PROFILE, OutputProfileIdV3)
            ),
            cardinality_profile=CardinalityProfileIdV3(
                enum(ContextFieldIdV3.CARDINALITY_PROFILE, CardinalityProfileIdV3)
            ),
            joint_profile=JointProfileIdV3(enum(ContextFieldIdV3.JOINT_PROFILE, JointProfileIdV3)),
            layout_profile=LayoutProfileIdV3(
                enum(ContextFieldIdV3.LAYOUT_PROFILE, LayoutProfileIdV3)
            ),
            trajectory_profile=TrajectoryProfileIdV3(
                enum(ContextFieldIdV3.TRAJECTORY_PROFILE, TrajectoryProfileIdV3)
            ),
            anchor_algorithms=anchor_algorithms,
            joint_algorithms=joint_algorithms,
            length_algorithm=AlgorithmId(enum(ContextFieldIdV3.LENGTH_ALGORITHM, AlgorithmId)),
            state_algorithm=AlgorithmId(enum(ContextFieldIdV3.STATE_ALGORITHM, AlgorithmId)),
            branch_count=decode_uint(fields[ContextFieldIdV3.BRANCH_COUNT], 2),
            chunk_size=decode_uint(fields[ContextFieldIdV3.CHUNK_SIZE], 4),
            state_size=decode_uint(fields[ContextFieldIdV3.STATE_SIZE], 2),
            t_min=decode_uint(fields[ContextFieldIdV3.T_MIN], 4),
            t_max=decode_uint(fields[ContextFieldIdV3.T_MAX], 4),
            k_min=decode_uint(fields[ContextFieldIdV3.K_MIN], 2),
            k_max=decode_uint(fields[ContextFieldIdV3.K_MAX], 2),
            salt=fields[ContextFieldIdV3.SALT],
            challenge=fields[ContextFieldIdV3.CHALLENGE],
            application_context=fields[ContextFieldIdV3.APPLICATION_CONTEXT],
        )
