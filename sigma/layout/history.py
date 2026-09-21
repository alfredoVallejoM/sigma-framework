"""History-adaptive round layout and placement for Sigma v3 R12.5."""

from __future__ import annotations

from collections.abc import Iterable, Iterator
from dataclasses import dataclass
from enum import IntEnum

from sigma.binding.history import RoundBindingV3
from sigma.binding.parameters import sample_uniform
from sigma.binding.prepare import derive_length_signature_v3
from sigma.binding.types import MAX_U64
from sigma.crypto.primitives import ShakeReader, domain_tag_v3
from sigma.spec.codec_v3 import decode_record, encode_record
from sigma.spec.context_v3 import SigmaContextV3
from sigma.spec.encoding import (
    DecodeError,
    decode_tlv,
    decode_uint,
    encode_tlv,
    encode_uint,
)
from sigma.spec.ids_v3 import (
    DomainIdV3,
    LayoutKindV3,
    RoundBindingFieldIdV3,
    TrajectoryProfileIdV3,
)
from sigma.spec.transcript import encode_transcript

_HISTORY_PLACEMENT_MAGIC = b"SIG3HPLC"
_HISTORY_PLAN_MAGIC = b"SIG3HPLN"
_HISTORY_PLACED_STREAM_MAGIC = b"SIG3HPS0"
_HISTORY_PLACED_STREAM_VERSION = 3
_HISTORY_FIELD_MAGIC = b"SIG3HFLD"
_MAX_MATERIALIZED_PLACEMENT = 1 << 20
_REQUIRED_FIELDS = frozenset(RoundBindingFieldIdV3)


class _PlacementField(IntEnum):
    FIELD = 1
    SLOT = 2


class _PlanField(IntEnum):
    ROUND_INDEX = 1
    BASE_LENGTH = 2
    PLACEMENTS = 3
    KIND = 4


@dataclass(frozen=True)
class HistoryLayoutPlacement:
    field: RoundBindingFieldIdV3
    slot: int

    def __post_init__(self) -> None:
        if not isinstance(self.field, RoundBindingFieldIdV3):
            raise TypeError("field must be RoundBindingFieldIdV3")
        if isinstance(self.slot, bool) or not isinstance(self.slot, int):
            raise TypeError("slot must be int")
        if not 0 <= self.slot <= MAX_U64:
            raise ValueError("slot is out of range")

    def to_bytes(self) -> bytes:
        return encode_record(
            _HISTORY_PLACEMENT_MAGIC,
            (
                (_PlacementField.FIELD, encode_uint(self.field, 2)),
                (_PlacementField.SLOT, encode_uint(self.slot, 8)),
            ),
        )

    @classmethod
    def from_bytes(cls, data: bytes) -> "HistoryLayoutPlacement":
        fields = decode_record(
            data,
            magic=_HISTORY_PLACEMENT_MAGIC,
            allowed_tags=frozenset(int(field) for field in _PlacementField),
        )
        try:
            return cls(
                RoundBindingFieldIdV3(decode_uint(fields[_PlacementField.FIELD], 2)),
                decode_uint(fields[_PlacementField.SLOT], 8),
            )
        except (KeyError, TypeError, ValueError) as exc:
            raise DecodeError("invalid history layout placement") from exc


@dataclass(frozen=True)
class HistoryLayoutPlan:
    round_index: int
    base_length: int
    placements: tuple[HistoryLayoutPlacement, ...]

    @property
    def kind(self) -> LayoutKindV3:
        return LayoutKindV3.ROUND

    def __post_init__(self) -> None:
        for name, value in (("round_index", self.round_index), ("base_length", self.base_length)):
            if isinstance(value, bool) or not isinstance(value, int):
                raise TypeError(f"{name} must be int")
            if not 0 <= value <= MAX_U64:
                raise ValueError(f"{name} is out of range")
        if not isinstance(self.placements, tuple):
            raise TypeError("placements must be tuple")
        if any(not isinstance(item, HistoryLayoutPlacement) for item in self.placements):
            raise TypeError("placements must contain HistoryLayoutPlacement")
        fields = tuple(item.field for item in self.placements)
        if frozenset(fields) != _REQUIRED_FIELDS or len(fields) != len(_REQUIRED_FIELDS):
            raise ValueError("history layout must contain every round binding field exactly once")
        if any(item.slot > self.base_length for item in self.placements):
            raise ValueError("placement slot exceeds base length")
        expected = tuple(sorted(self.placements, key=lambda item: (item.slot, int(item.field))))
        if self.placements != expected:
            raise ValueError("placements must use canonical slot/type order")

    def to_bytes(self) -> bytes:
        encoded = encode_tlv(
            tuple((index + 1, item.to_bytes()) for index, item in enumerate(self.placements))
        )
        return encode_record(
            _HISTORY_PLAN_MAGIC,
            (
                (_PlanField.ROUND_INDEX, encode_uint(self.round_index, 8)),
                (_PlanField.BASE_LENGTH, encode_uint(self.base_length, 8)),
                (_PlanField.PLACEMENTS, encoded),
                (_PlanField.KIND, encode_uint(LayoutKindV3.ROUND, 2)),
            ),
        )

    @classmethod
    def from_bytes(cls, data: bytes) -> "HistoryLayoutPlan":
        fields = decode_record(
            data,
            magic=_HISTORY_PLAN_MAGIC,
            allowed_tags=frozenset(int(field) for field in _PlanField),
        )
        count = len(_REQUIRED_FIELDS)
        placements = decode_tlv(
            fields[_PlanField.PLACEMENTS],
            allowed_tags=frozenset(range(1, count + 1)),
        )
        if set(placements) != set(range(1, count + 1)):
            raise DecodeError("missing history layout placement")
        if decode_uint(fields[_PlanField.KIND], 2) != int(LayoutKindV3.ROUND):
            raise DecodeError("history layout must be ROUND")
        try:
            return cls(
                decode_uint(fields[_PlanField.ROUND_INDEX], 8),
                decode_uint(fields[_PlanField.BASE_LENGTH], 8),
                tuple(
                    HistoryLayoutPlacement.from_bytes(placements[index])
                    for index in range(1, count + 1)
                ),
            )
        except (KeyError, TypeError, ValueError) as exc:
            raise DecodeError("invalid history layout plan") from exc


def _validate_context(context: SigmaContextV3, binding: RoundBindingV3) -> None:
    if not isinstance(context, SigmaContextV3):
        raise TypeError("context must be SigmaContextV3")
    if context.trajectory_profile is not TrajectoryProfileIdV3.HISTORY_FEEDBACK:
        raise ValueError("context does not use history feedback")
    if not isinstance(binding, RoundBindingV3):
        raise TypeError("binding must be RoundBindingV3")
    if binding.persistent.anchor.suite_id != context.suite_id:
        raise ValueError("round binding and context suites differ")
    if binding.persistent.length_signature != derive_length_signature_v3(
        context, binding.persistent.cardinality
    ):
        raise ValueError("round binding length signature does not match context")


def derive_history_layout_v3(
    context: SigmaContextV3,
    binding: RoundBindingV3,
    *,
    round_index: int,
    base_length: int,
) -> HistoryLayoutPlan:
    """Derive five unbiased placements from context, length and H_i."""

    _validate_context(context, binding)
    for name, value in (("round_index", round_index), ("base_length", base_length)):
        if isinstance(value, bool) or not isinstance(value, int):
            raise TypeError(f"{name} must be int")
        if not 0 <= value <= MAX_U64:
            raise ValueError(f"{name} is out of range")
    if binding.history.round_index != round_index:
        raise ValueError("history and layout round indices differ")

    seed = encode_transcript(
        DomainIdV3.HISTORY_LAYOUT_ROUND,
        (
            (1, context.to_bytes()),
            (2, binding.persistent.length_signature.to_bytes()),
            (3, binding.history.to_bytes()),
            (4, encode_uint(LayoutKindV3.ROUND, 2)),
            (5, encode_uint(round_index, 8)),
            (6, encode_uint(base_length, 8)),
        ),
    )
    reader = ShakeReader(DomainIdV3.HISTORY_LAYOUT_ROUND, seed)
    placements = tuple(
        sorted(
            (
                HistoryLayoutPlacement(field, sample_uniform(reader, 0, base_length))
                for field in RoundBindingFieldIdV3
            ),
            key=lambda item: (item.slot, int(item.field)),
        )
    )
    return HistoryLayoutPlan(round_index, base_length, placements)


def _binding_values(binding: RoundBindingV3) -> dict[RoundBindingFieldIdV3, bytes]:
    persistent = binding.persistent
    return {
        RoundBindingFieldIdV3.ANCHOR: persistent.anchor.to_bytes(),
        RoundBindingFieldIdV3.CARDINALITY: persistent.cardinality.to_bytes(),
        RoundBindingFieldIdV3.LENGTH_SIGNATURE: persistent.length_signature.to_bytes(),
        RoundBindingFieldIdV3.JOINT_SIGNATURE: persistent.joint_signature.to_bytes(),
        RoundBindingFieldIdV3.HISTORY: binding.history.to_bytes(),
    }


def _field_record(field: RoundBindingFieldIdV3, value: bytes) -> bytes:
    return (
        _HISTORY_FIELD_MAGIC
        + domain_tag_v3(DomainIdV3.HISTORY_BINDING_FIELD)
        + encode_uint(field, 2)
        + encode_uint(len(value), 8)
        + value
    )


def history_placed_length_v3(binding: RoundBindingV3, plan: HistoryLayoutPlan) -> int:
    if not isinstance(binding, RoundBindingV3):
        raise TypeError("binding must be RoundBindingV3")
    if not isinstance(plan, HistoryLayoutPlan):
        raise TypeError("plan must be HistoryLayoutPlan")
    records = {
        field: _field_record(field, value) for field, value in _binding_values(binding).items()
    }
    body_length = plan.base_length + sum(len(value) for value in records.values())
    if body_length > MAX_U64:
        raise ValueError("placed body length is out of range")
    return 8 + 2 + 4 + len(plan.to_bytes()) + 8 + body_length


def iter_placed_round_binding_v3(
    base_chunks: Iterable[bytes],
    binding: RoundBindingV3,
    plan: HistoryLayoutPlan,
) -> Iterator[bytes]:
    """Yield S_i with P_X and H_i inserted at history-adaptive slots."""

    if not isinstance(binding, RoundBindingV3):
        raise TypeError("binding must be RoundBindingV3")
    if not isinstance(plan, HistoryLayoutPlan):
        raise TypeError("plan must be HistoryLayoutPlan")
    if binding.history.round_index != plan.round_index:
        raise ValueError("history and plan round indices differ")
    values = _binding_values(binding)
    records = {field: _field_record(field, value) for field, value in values.items()}
    body_length = plan.base_length + sum(len(value) for value in records.values())
    history_placed_length_v3(binding, plan)
    plan_bytes = plan.to_bytes()
    yield (
        _HISTORY_PLACED_STREAM_MAGIC
        + encode_uint(_HISTORY_PLACED_STREAM_VERSION, 2)
        + encode_uint(len(plan_bytes), 4)
        + plan_bytes
        + encode_uint(body_length, 8)
    )

    placements = iter(plan.placements)
    pending = next(placements, None)
    offset = 0

    def emit_at(slot: int) -> Iterator[bytes]:
        nonlocal pending
        while pending is not None and pending.slot == slot:
            yield records[pending.field]
            pending = next(placements, None)

    yield from emit_at(0)
    for chunk in base_chunks:
        if not isinstance(chunk, bytes):
            raise TypeError("base chunks must be bytes")
        if offset + len(chunk) > plan.base_length:
            raise ValueError("base is longer than layout base_length")
        position = 0
        while pending is not None and pending.slot <= offset + len(chunk):
            relative = pending.slot - offset
            if relative > position:
                yield chunk[position:relative]
                position = relative
            yield from emit_at(pending.slot)
        if position < len(chunk):
            yield chunk[position:]
        offset += len(chunk)
    if offset != plan.base_length:
        raise ValueError("base is shorter than layout base_length")
    if pending is not None:
        yield from emit_at(plan.base_length)
    if pending is not None:  # pragma: no cover
        raise RuntimeError("unconsumed history layout placement")


def place_round_binding_v3(
    base: bytes,
    binding: RoundBindingV3,
    plan: HistoryLayoutPlan,
) -> bytes:
    if not isinstance(base, bytes):
        raise TypeError("base must be bytes")
    if len(base) > _MAX_MATERIALIZED_PLACEMENT:
        raise ValueError("base is too large to materialize")
    chunks = () if not base else (base,)
    return b"".join(iter_placed_round_binding_v3(chunks, binding, plan))


__all__ = [
    "HistoryLayoutPlacement",
    "HistoryLayoutPlan",
    "derive_history_layout_v3",
    "history_placed_length_v3",
    "iter_placed_round_binding_v3",
    "place_round_binding_v3",
]
