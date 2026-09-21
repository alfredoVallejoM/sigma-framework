"""Validated, serializable Sigma v3 layout plans."""

from __future__ import annotations

from dataclasses import dataclass
from enum import IntEnum

from sigma.spec.codec_v3 import decode_record, encode_record
from sigma.spec.encoding import DecodeError, decode_tlv, decode_uint, encode_tlv, encode_uint
from sigma.spec.ids_v3 import BindingFieldIdV3, LayoutKindV3

_PLACEMENT_MAGIC = b"SIGMA3LP"
_PLAN_MAGIC = b"SIGMA3PL"
_REQUIRED_FIELDS = frozenset(BindingFieldIdV3)


class _PlacementField(IntEnum):
    FIELD = 1
    SLOT = 2


class _PlanField(IntEnum):
    ROUND_INDEX = 1
    BASE_LENGTH = 2
    PLACEMENTS = 3
    KIND = 4


@dataclass(frozen=True)
class LayoutPlacement:
    field: BindingFieldIdV3
    slot: int

    def __post_init__(self) -> None:
        if not isinstance(self.field, BindingFieldIdV3):
            raise TypeError("field must be BindingFieldIdV3")
        if isinstance(self.slot, bool) or not isinstance(self.slot, int):
            raise TypeError("slot must be int")
        if not 0 <= self.slot <= (1 << 64) - 1:
            raise ValueError("slot is out of range")

    def to_bytes(self) -> bytes:
        return encode_record(
            _PLACEMENT_MAGIC,
            (
                (_PlacementField.FIELD, encode_uint(self.field, 2)),
                (_PlacementField.SLOT, encode_uint(self.slot, 8)),
            ),
        )

    @classmethod
    def from_bytes(cls, data: bytes) -> "LayoutPlacement":
        fields = decode_record(
            data,
            magic=_PLACEMENT_MAGIC,
            allowed_tags=frozenset(int(field) for field in _PlacementField),
        )
        try:
            field = BindingFieldIdV3(decode_uint(fields[_PlacementField.FIELD], 2))
        except ValueError as exc:
            raise DecodeError("unknown binding field identifier") from exc
        return cls(field, decode_uint(fields[_PlacementField.SLOT], 8))


@dataclass(frozen=True)
class LayoutPlan:
    kind: LayoutKindV3
    round_index: int
    base_length: int
    placements: tuple[LayoutPlacement, ...]

    def __post_init__(self) -> None:
        if not isinstance(self.kind, LayoutKindV3):
            raise TypeError("kind must be LayoutKindV3")
        if self.kind is LayoutKindV3.INIT and self.round_index != 0:
            raise ValueError("initial layout must use round_index zero")
        for name, value in (("round_index", self.round_index), ("base_length", self.base_length)):
            if isinstance(value, bool) or not isinstance(value, int):
                raise TypeError(f"{name} must be int")
            if not 0 <= value <= (1 << 64) - 1:
                raise ValueError(f"{name} is out of range")
        if not isinstance(self.placements, tuple):
            raise TypeError("placements must be tuple")
        if any(not isinstance(item, LayoutPlacement) for item in self.placements):
            raise TypeError("placements must contain LayoutPlacement values")
        fields = tuple(item.field for item in self.placements)
        if frozenset(fields) != _REQUIRED_FIELDS or len(fields) != len(_REQUIRED_FIELDS):
            raise ValueError("placements must contain every binding field exactly once")
        if any(item.slot > self.base_length for item in self.placements):
            raise ValueError("placement slot exceeds base length")
        expected_order = tuple(
            sorted(self.placements, key=lambda item: (item.slot, int(item.field)))
        )
        if self.placements != expected_order:
            raise ValueError("placements must use canonical slot/type order")

    def to_bytes(self) -> bytes:
        placement_fields = tuple(
            (index + 1, item.to_bytes()) for index, item in enumerate(self.placements)
        )
        return encode_record(
            _PLAN_MAGIC,
            (
                (_PlanField.ROUND_INDEX, encode_uint(self.round_index, 8)),
                (_PlanField.BASE_LENGTH, encode_uint(self.base_length, 8)),
                (_PlanField.PLACEMENTS, encode_tlv(placement_fields)),
                (_PlanField.KIND, encode_uint(self.kind, 2)),
            ),
        )

    @classmethod
    def from_bytes(cls, data: bytes) -> "LayoutPlan":
        fields = decode_record(
            data,
            magic=_PLAN_MAGIC,
            allowed_tags=frozenset(int(field) for field in _PlanField),
        )
        encoded_placements = fields[_PlanField.PLACEMENTS]
        count = len(_REQUIRED_FIELDS)
        placement_map = decode_tlv(
            encoded_placements,
            allowed_tags=frozenset(range(1, count + 1)),
        )
        if set(placement_map) != set(range(1, count + 1)):
            raise DecodeError("missing layout placement")
        placements = tuple(
            LayoutPlacement.from_bytes(placement_map[index]) for index in range(1, count + 1)
        )
        try:
            kind = LayoutKindV3(decode_uint(fields[_PlanField.KIND], 2))
            return cls(
                kind,
                decode_uint(fields[_PlanField.ROUND_INDEX], 8),
                decode_uint(fields[_PlanField.BASE_LENGTH], 8),
                placements,
            )
        except (TypeError, ValueError) as exc:
            raise DecodeError("invalid layout plan") from exc
