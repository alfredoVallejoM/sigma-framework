"""Immutable Sigma v3 binding and public-header types."""

from __future__ import annotations

from dataclasses import dataclass
from enum import IntEnum
from typing import Callable, TypeVar

from sigma.spec.codec_v3 import (
    decode_bytes_sequence,
    decode_record,
    encode_bytes_sequence,
    encode_record,
)
from sigma.spec.encoding import (
    DecodeError,
    decode_u16_sequence,
    decode_uint,
    encode_u16_sequence,
    encode_uint,
)
from sigma.spec.ids import AlgorithmId
from sigma.spec.ids_v3 import ALGORITHM_OUTPUT_SIZE_V3, SuiteIdV3
from sigma.suites.registry_v3 import get_suite_v3

MAX_U64 = (1 << 64) - 1
MAX_STATE_SIZE = 4096
_T = TypeVar("_T")


class _AnchorField(IntEnum):
    SUITE = 1
    MESSAGE_LENGTH = 2
    ALGORITHMS = 3
    COMPONENTS = 4


class _LengthField(IntEnum):
    DESCRIPTOR = 1
    DIGEST = 2


class _JointField(IntEnum):
    ALGORITHMS = 1
    COMPONENTS = 2


class _BindingField(IntEnum):
    ANCHOR = 1
    CARDINALITY = 2
    LENGTH_SIGNATURE = 3
    JOINT_SIGNATURE = 4


class _ParameterField(IntEnum):
    TARGET_ROUND = 1
    STATE_COUNT = 2


class _HeaderField(IntEnum):
    CARDINALITY = 1
    ANCHOR = 2
    LENGTH_SIGNATURE = 3
    PARAMETERS = 4


class _WindowField(IntEnum):
    PARAMETERS = 1
    STATES = 2


_ANCHOR_MAGIC = b"SIGMA3AN"
_CARDINALITY_MAGIC = b"SIGMA3CD"
_LENGTH_MAGIC = b"SIGMA3LS"
_JOINT_MAGIC = b"SIGMA3JS"
_BINDING_MAGIC = b"SIGMA3BI"
_PARAMETERS_MAGIC = b"SIGMA3TP"
_HEADER_MAGIC = b"SIGMA3PH"
_WINDOW_MAGIC = b"SIGMA3TW"


def _field_set(enum_type: type[IntEnum]) -> frozenset[int]:
    return frozenset(int(field) for field in enum_type)


def _validate_bytes(name: str, value: bytes, *, maximum: int) -> None:
    if not isinstance(value, bytes):
        raise TypeError(f"{name} must be bytes")
    if not value or len(value) > maximum:
        raise ValueError(f"{name} length is out of range")


def _decode_value(name: str, constructor: Callable[[], _T]) -> _T:
    try:
        return constructor()
    except DecodeError:
        raise
    except (TypeError, ValueError) as exc:
        raise DecodeError(f"invalid {name}") from exc


def _decode_algorithms(data: bytes) -> tuple[AlgorithmId, ...]:
    try:
        return tuple(AlgorithmId(value) for value in decode_u16_sequence(data))
    except ValueError as exc:
        raise DecodeError("unknown algorithm identifier") from exc


@dataclass(frozen=True)
class CardinalityDescriptor:
    byte_length: int

    def __post_init__(self) -> None:
        if isinstance(self.byte_length, bool) or not isinstance(self.byte_length, int):
            raise TypeError("byte_length must be int")
        if not 0 <= self.byte_length <= MAX_U64:
            raise ValueError("byte_length is out of range")

    def to_bytes(self) -> bytes:
        return encode_record(_CARDINALITY_MAGIC, ((1, encode_uint(self.byte_length, 8)),))

    @classmethod
    def from_bytes(cls, data: bytes) -> "CardinalityDescriptor":
        fields = decode_record(data, magic=_CARDINALITY_MAGIC, allowed_tags=frozenset({1}))
        return cls(decode_uint(fields[1], 8))


@dataclass(frozen=True)
class AnchorV3:
    suite_id: SuiteIdV3
    message_length: int
    algorithms: tuple[AlgorithmId, ...]
    components: tuple[bytes, ...]

    def __post_init__(self) -> None:
        if not isinstance(self.suite_id, SuiteIdV3):
            raise TypeError("suite_id must be SuiteIdV3")
        CardinalityDescriptor(self.message_length)
        if not isinstance(self.algorithms, tuple) or not self.algorithms:
            raise ValueError("algorithms must be a non-empty tuple")
        if any(not isinstance(value, AlgorithmId) for value in self.algorithms):
            raise TypeError("algorithms must contain AlgorithmId values")
        if len(self.algorithms) != len(set(self.algorithms)):
            raise ValueError("algorithms must not contain duplicates")
        if self.algorithms != get_suite_v3(self.suite_id).anchor_algorithms:
            raise ValueError("anchor algorithms do not match suite")
        if not isinstance(self.components, tuple) or len(self.components) != len(self.algorithms):
            raise ValueError("components must match algorithms")
        for component in self.components:
            _validate_bytes("anchor component", component, maximum=ALGORITHM_OUTPUT_SIZE_V3)
            if len(component) != ALGORITHM_OUTPUT_SIZE_V3:
                raise ValueError("anchor component must match algorithm output size")

    def to_bytes(self) -> bytes:
        return encode_record(
            _ANCHOR_MAGIC,
            (
                (_AnchorField.SUITE, encode_uint(self.suite_id, 2)),
                (_AnchorField.MESSAGE_LENGTH, encode_uint(self.message_length, 8)),
                (_AnchorField.ALGORITHMS, encode_u16_sequence(self.algorithms)),
                (_AnchorField.COMPONENTS, encode_bytes_sequence(self.components)),
            ),
        )

    @classmethod
    def from_bytes(cls, data: bytes) -> "AnchorV3":
        fields = decode_record(data, magic=_ANCHOR_MAGIC, allowed_tags=_field_set(_AnchorField))
        try:
            suite_id = SuiteIdV3(decode_uint(fields[_AnchorField.SUITE], 2))
        except ValueError as exc:
            raise DecodeError("unknown v3 suite identifier") from exc
        return _decode_value(
            "anchor",
            lambda: cls(
                suite_id=suite_id,
                message_length=decode_uint(fields[_AnchorField.MESSAGE_LENGTH], 8),
                algorithms=_decode_algorithms(fields[_AnchorField.ALGORITHMS]),
                components=decode_bytes_sequence(fields[_AnchorField.COMPONENTS]),
            ),
        )


@dataclass(frozen=True)
class LengthSignature:
    descriptor: CardinalityDescriptor
    digest: bytes

    def __post_init__(self) -> None:
        if not isinstance(self.descriptor, CardinalityDescriptor):
            raise TypeError("descriptor must be CardinalityDescriptor")
        _validate_bytes("length signature digest", self.digest, maximum=ALGORITHM_OUTPUT_SIZE_V3)
        if len(self.digest) != ALGORITHM_OUTPUT_SIZE_V3:
            raise ValueError("length signature must match algorithm output size")

    def to_bytes(self) -> bytes:
        return encode_record(
            _LENGTH_MAGIC,
            (
                (_LengthField.DESCRIPTOR, self.descriptor.to_bytes()),
                (_LengthField.DIGEST, self.digest),
            ),
        )

    @classmethod
    def from_bytes(cls, data: bytes) -> "LengthSignature":
        fields = decode_record(data, magic=_LENGTH_MAGIC, allowed_tags=_field_set(_LengthField))
        return _decode_value(
            "length signature",
            lambda: cls(
                CardinalityDescriptor.from_bytes(fields[_LengthField.DESCRIPTOR]),
                fields[_LengthField.DIGEST],
            ),
        )


@dataclass(frozen=True)
class JointSignature:
    algorithms: tuple[AlgorithmId, ...]
    components: tuple[bytes, ...]

    def __post_init__(self) -> None:
        if not isinstance(self.algorithms, tuple) or not self.algorithms:
            raise ValueError("algorithms must be a non-empty tuple")
        if any(not isinstance(value, AlgorithmId) for value in self.algorithms):
            raise TypeError("algorithms must contain AlgorithmId values")
        if len(self.algorithms) != len(set(self.algorithms)):
            raise ValueError("algorithms must not contain duplicates")
        if not isinstance(self.components, tuple) or len(self.components) != len(self.algorithms):
            raise ValueError("components must match algorithms")
        for component in self.components:
            _validate_bytes("joint component", component, maximum=ALGORITHM_OUTPUT_SIZE_V3)
            if len(component) != ALGORITHM_OUTPUT_SIZE_V3:
                raise ValueError("joint component must match algorithm output size")

    def to_bytes(self) -> bytes:
        return encode_record(
            _JOINT_MAGIC,
            (
                (_JointField.ALGORITHMS, encode_u16_sequence(self.algorithms)),
                (_JointField.COMPONENTS, encode_bytes_sequence(self.components)),
            ),
        )

    @classmethod
    def from_bytes(cls, data: bytes) -> "JointSignature":
        fields = decode_record(data, magic=_JOINT_MAGIC, allowed_tags=_field_set(_JointField))
        return _decode_value(
            "joint signature",
            lambda: cls(
                _decode_algorithms(fields[_JointField.ALGORITHMS]),
                decode_bytes_sequence(fields[_JointField.COMPONENTS]),
            ),
        )


@dataclass(frozen=True)
class PersistentBinding:
    anchor: AnchorV3
    cardinality: CardinalityDescriptor
    length_signature: LengthSignature
    joint_signature: JointSignature

    def __post_init__(self) -> None:
        if not isinstance(self.anchor, AnchorV3):
            raise TypeError("anchor must be AnchorV3")
        if not isinstance(self.cardinality, CardinalityDescriptor):
            raise TypeError("cardinality must be CardinalityDescriptor")
        if not isinstance(self.length_signature, LengthSignature):
            raise TypeError("length_signature must be LengthSignature")
        if not isinstance(self.joint_signature, JointSignature):
            raise TypeError("joint_signature must be JointSignature")
        if self.anchor.message_length != self.cardinality.byte_length:
            raise ValueError("anchor length must match cardinality")
        if self.length_signature.descriptor != self.cardinality:
            raise ValueError("length signature descriptor must match cardinality")
        if self.joint_signature.algorithms != get_suite_v3(self.anchor.suite_id).joint_algorithms:
            raise ValueError("joint algorithms do not match suite")

    def to_bytes(self) -> bytes:
        return encode_record(
            _BINDING_MAGIC,
            (
                (_BindingField.ANCHOR, self.anchor.to_bytes()),
                (_BindingField.CARDINALITY, self.cardinality.to_bytes()),
                (_BindingField.LENGTH_SIGNATURE, self.length_signature.to_bytes()),
                (_BindingField.JOINT_SIGNATURE, self.joint_signature.to_bytes()),
            ),
        )

    @classmethod
    def from_bytes(cls, data: bytes) -> "PersistentBinding":
        fields = decode_record(data, magic=_BINDING_MAGIC, allowed_tags=_field_set(_BindingField))
        return _decode_value(
            "persistent binding",
            lambda: cls(
                AnchorV3.from_bytes(fields[_BindingField.ANCHOR]),
                CardinalityDescriptor.from_bytes(fields[_BindingField.CARDINALITY]),
                LengthSignature.from_bytes(fields[_BindingField.LENGTH_SIGNATURE]),
                JointSignature.from_bytes(fields[_BindingField.JOINT_SIGNATURE]),
            ),
        )


@dataclass(frozen=True)
class TrajectoryParameters:
    target_round: int
    state_count: int

    def __post_init__(self) -> None:
        for name, value, minimum in (
            ("target_round", self.target_round, 0),
            ("state_count", self.state_count, 1),
        ):
            if isinstance(value, bool) or not isinstance(value, int):
                raise TypeError(f"{name} must be int")
            maximum = 1_000_000 if name == "target_round" else 64
            if not minimum <= value <= maximum:
                raise ValueError(f"{name} is out of range")

    def to_bytes(self) -> bytes:
        return encode_record(
            _PARAMETERS_MAGIC,
            (
                (_ParameterField.TARGET_ROUND, encode_uint(self.target_round, 8)),
                (_ParameterField.STATE_COUNT, encode_uint(self.state_count, 8)),
            ),
        )

    @classmethod
    def from_bytes(cls, data: bytes) -> "TrajectoryParameters":
        fields = decode_record(
            data, magic=_PARAMETERS_MAGIC, allowed_tags=_field_set(_ParameterField)
        )
        return _decode_value(
            "trajectory parameters",
            lambda: cls(
                decode_uint(fields[_ParameterField.TARGET_ROUND], 8),
                decode_uint(fields[_ParameterField.STATE_COUNT], 8),
            ),
        )


@dataclass(frozen=True)
class PublicTrajectoryHeader:
    cardinality: CardinalityDescriptor
    anchor: AnchorV3
    length_signature: LengthSignature
    parameters: TrajectoryParameters

    def __post_init__(self) -> None:
        if not isinstance(self.cardinality, CardinalityDescriptor):
            raise TypeError("cardinality must be CardinalityDescriptor")
        if not isinstance(self.anchor, AnchorV3):
            raise TypeError("anchor must be AnchorV3")
        if not isinstance(self.length_signature, LengthSignature):
            raise TypeError("length_signature must be LengthSignature")
        if not isinstance(self.parameters, TrajectoryParameters):
            raise TypeError("parameters must be TrajectoryParameters")
        if self.anchor.message_length != self.cardinality.byte_length:
            raise ValueError("anchor length must match cardinality")
        if self.length_signature.descriptor != self.cardinality:
            raise ValueError("length signature descriptor must match cardinality")
        descriptor = get_suite_v3(self.anchor.suite_id)
        if not (
            descriptor.t_min <= self.parameters.target_round <= descriptor.t_max
            and descriptor.k_min <= self.parameters.state_count <= descriptor.k_max
        ):
            raise ValueError("trajectory parameters do not match the registered suite")

    def to_bytes(self) -> bytes:
        return encode_record(
            _HEADER_MAGIC,
            (
                (_HeaderField.CARDINALITY, self.cardinality.to_bytes()),
                (_HeaderField.ANCHOR, self.anchor.to_bytes()),
                (_HeaderField.LENGTH_SIGNATURE, self.length_signature.to_bytes()),
                (_HeaderField.PARAMETERS, self.parameters.to_bytes()),
            ),
        )

    @classmethod
    def from_bytes(cls, data: bytes) -> "PublicTrajectoryHeader":
        fields = decode_record(data, magic=_HEADER_MAGIC, allowed_tags=_field_set(_HeaderField))
        return _decode_value(
            "public trajectory header",
            lambda: cls(
                CardinalityDescriptor.from_bytes(fields[_HeaderField.CARDINALITY]),
                AnchorV3.from_bytes(fields[_HeaderField.ANCHOR]),
                LengthSignature.from_bytes(fields[_HeaderField.LENGTH_SIGNATURE]),
                TrajectoryParameters.from_bytes(fields[_HeaderField.PARAMETERS]),
            ),
        )


@dataclass(frozen=True)
class TrajectoryWindow:
    parameters: TrajectoryParameters
    states: tuple[bytes, ...]

    def __post_init__(self) -> None:
        if not isinstance(self.parameters, TrajectoryParameters):
            raise TypeError("parameters must be TrajectoryParameters")
        if not isinstance(self.states, tuple) or len(self.states) != self.parameters.state_count:
            raise ValueError("states must match state_count")
        for state in self.states:
            _validate_bytes("state", state, maximum=MAX_STATE_SIZE)
        if len({len(state) for state in self.states}) != 1:
            raise ValueError("states must have a uniform size")

    def to_bytes(self) -> bytes:
        return encode_record(
            _WINDOW_MAGIC,
            (
                (_WindowField.PARAMETERS, self.parameters.to_bytes()),
                (_WindowField.STATES, encode_bytes_sequence(self.states)),
            ),
        )

    @classmethod
    def from_bytes(cls, data: bytes) -> "TrajectoryWindow":
        fields = decode_record(data, magic=_WINDOW_MAGIC, allowed_tags=_field_set(_WindowField))
        return _decode_value(
            "trajectory window",
            lambda: cls(
                TrajectoryParameters.from_bytes(fields[_WindowField.PARAMETERS]),
                decode_bytes_sequence(fields[_WindowField.STATES]),
            ),
        )
