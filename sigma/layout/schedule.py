"""Canonical Sigma v3 layout scheduling and typed placement."""

from __future__ import annotations

from collections.abc import Iterable, Iterator

from sigma.binding.parameters import sample_uniform
from sigma.binding.prepare import derive_length_signature_v3
from sigma.binding.types import MAX_U64, PersistentBinding
from sigma.crypto.primitives import ShakeReader, domain_tag_v3
from sigma.layout.types import LayoutPlacement, LayoutPlan
from sigma.spec.context_v3 import SigmaContextV3
from sigma.spec.encoding import encode_uint
from sigma.spec.ids_v3 import BindingFieldIdV3, DomainIdV3, LayoutKindV3
from sigma.spec.transcript import encode_transcript

PLACED_STREAM_MAGIC = b"SIGMA3PS"
PLACED_STREAM_VERSION = 3
_FIELD_MAGIC = b"SIGMA3BF"
_MAX_MATERIALIZED_PLACEMENT = 1 << 20


def _domain_for_kind(kind: LayoutKindV3) -> DomainIdV3:
    if kind is LayoutKindV3.INIT:
        return DomainIdV3.LAYOUT_INIT
    if kind is LayoutKindV3.ROUND:
        return DomainIdV3.LAYOUT_ROUND
    raise TypeError("kind must be LayoutKindV3")


def derive_layout_v3(
    context: SigmaContextV3,
    binding: PersistentBinding,
    *,
    kind: LayoutKindV3,
    round_index: int,
    base_length: int,
) -> LayoutPlan:
    """Derive one unbiased placement per typed binding field."""

    if not isinstance(context, SigmaContextV3):
        raise TypeError("context must be SigmaContextV3")
    if not isinstance(binding, PersistentBinding):
        raise TypeError("binding must be PersistentBinding")
    if binding.anchor.suite_id != context.suite_id:
        raise ValueError("binding and context suites differ")
    if binding.length_signature != derive_length_signature_v3(context, binding.cardinality):
        raise ValueError("binding length signature does not match context")
    if not isinstance(kind, LayoutKindV3):
        raise TypeError("kind must be LayoutKindV3")
    for name, value in (("round_index", round_index), ("base_length", base_length)):
        if isinstance(value, bool) or not isinstance(value, int):
            raise TypeError(f"{name} must be int")
        if not 0 <= value <= MAX_U64:
            raise ValueError(f"{name} is out of range")
    if kind is LayoutKindV3.INIT and round_index != 0:
        raise ValueError("initial layout round_index must be zero")

    domain = _domain_for_kind(kind)
    seed = encode_transcript(
        domain,
        (
            (1, context.to_bytes()),
            (2, binding.length_signature.to_bytes()),
            (3, encode_uint(kind, 2)),
            (4, encode_uint(round_index, 8)),
            (5, encode_uint(base_length, 8)),
        ),
    )
    reader = ShakeReader(domain, seed)
    placements = tuple(
        sorted(
            (
                LayoutPlacement(field, sample_uniform(reader, 0, base_length))
                for field in BindingFieldIdV3
            ),
            key=lambda item: (item.slot, int(item.field)),
        )
    )
    return LayoutPlan(kind, round_index, base_length, placements)


def _binding_values(binding: PersistentBinding) -> dict[BindingFieldIdV3, bytes]:
    return {
        BindingFieldIdV3.ANCHOR: binding.anchor.to_bytes(),
        BindingFieldIdV3.CARDINALITY: binding.cardinality.to_bytes(),
        BindingFieldIdV3.LENGTH_SIGNATURE: binding.length_signature.to_bytes(),
        BindingFieldIdV3.JOINT_SIGNATURE: binding.joint_signature.to_bytes(),
    }


def _field_record(field: BindingFieldIdV3, value: bytes) -> bytes:
    return (
        _FIELD_MAGIC
        + domain_tag_v3(DomainIdV3.BINDING_FIELD)
        + encode_uint(field, 2)
        + encode_uint(len(value), 8)
        + value
    )


def placed_binding_length_v3(binding: PersistentBinding, plan: LayoutPlan) -> int:
    """Return the exact encoded length without reading the base stream."""

    if not isinstance(binding, PersistentBinding):
        raise TypeError("binding must be PersistentBinding")
    if not isinstance(plan, LayoutPlan):
        raise TypeError("plan must be LayoutPlan")
    records = {
        field: _field_record(field, value) for field, value in _binding_values(binding).items()
    }
    body_length = plan.base_length + sum(len(value) for value in records.values())
    if body_length > MAX_U64:
        raise ValueError("placed body length is out of range")
    return 8 + 2 + 4 + len(plan.to_bytes()) + 8 + body_length


def iter_placed_binding_v3(
    base_chunks: Iterable[bytes],
    binding: PersistentBinding,
    plan: LayoutPlan,
) -> Iterator[bytes]:
    """Yield injective placement; slots refer to the unmodified base bytes."""

    if not isinstance(binding, PersistentBinding):
        raise TypeError("binding must be PersistentBinding")
    if not isinstance(plan, LayoutPlan):
        raise TypeError("plan must be LayoutPlan")
    values = _binding_values(binding)
    records = {field: _field_record(field, value) for field, value in values.items()}
    body_length = plan.base_length + sum(len(value) for value in records.values())
    placed_binding_length_v3(binding, plan)
    plan_bytes = plan.to_bytes()
    yield (
        PLACED_STREAM_MAGIC
        + encode_uint(PLACED_STREAM_VERSION, 2)
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
        if not chunk:
            raise ValueError("base chunks must be non-empty")
        if offset + len(chunk) > plan.base_length:
            raise ValueError("base exceeds layout base_length")
        local = 0
        while pending is not None and pending.slot <= offset + len(chunk):
            boundary = pending.slot - offset
            if boundary > local:
                yield chunk[local:boundary]
                local = boundary
            yield from emit_at(pending.slot)
        if local < len(chunk):
            yield chunk[local:]
        offset += len(chunk)
    if offset != plan.base_length:
        raise ValueError("base is shorter than layout base_length")
    if pending is not None:
        yield from emit_at(plan.base_length)
    if pending is not None:  # pragma: no cover - guarded by LayoutPlan invariants
        raise RuntimeError("unconsumed layout placement")


def place_binding_v3(base: bytes, binding: PersistentBinding, plan: LayoutPlan) -> bytes:
    """Materialized placement helper for bounded states and test vectors."""

    if not isinstance(base, bytes):
        raise TypeError("base must be bytes")
    if len(base) > _MAX_MATERIALIZED_PLACEMENT:
        raise ValueError("base is too large to materialize")
    chunks = () if not base else (base,)
    return b"".join(iter_placed_binding_v3(chunks, binding, plan))
