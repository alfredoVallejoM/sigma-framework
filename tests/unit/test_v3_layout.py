from __future__ import annotations

import hashlib

import pytest

from sigma.binding import prepare_binding_v3
from sigma.layout import (
    LayoutPlacement,
    LayoutPlan,
    derive_layout_v3,
    iter_placed_binding_v3,
    place_binding_v3,
)
from sigma.sources import BytesSource
from sigma.spec.context_v3 import SigmaContextV3
from sigma.spec.ids_v3 import BindingFieldIdV3, LayoutKindV3


def _context() -> SigmaContextV3:
    return SigmaContextV3.reference(
        salt=b"R5-salt",
        challenge=b"R5-challenge",
        application_context=b"tests/v3/layout",
    )


def _binding(message: bytes = b"layout-message"):
    context = _context()
    return context, prepare_binding_v3(context, BytesSource(message))


def test_layout_is_deterministic_bounded_sorted_and_kind_separated() -> None:
    context, binding = _binding()
    init = derive_layout_v3(
        context,
        binding,
        kind=LayoutKindV3.INIT,
        round_index=0,
        base_length=binding.cardinality.byte_length,
    )
    repeated = derive_layout_v3(
        context,
        binding,
        kind=LayoutKindV3.INIT,
        round_index=0,
        base_length=binding.cardinality.byte_length,
    )
    round_plan = derive_layout_v3(
        context,
        binding,
        kind=LayoutKindV3.ROUND,
        round_index=0,
        base_length=context.state_size,
    )

    assert init == repeated
    assert init != round_plan
    assert all(0 <= item.slot <= init.base_length for item in init.placements)
    assert init.placements == tuple(
        sorted(init.placements, key=lambda item: (item.slot, int(item.field)))
    )


def test_placement_is_chunk_invariant_and_measures_original_slots() -> None:
    _, binding = _binding(b"abc")
    placements = tuple(LayoutPlacement(field, 1) for field in BindingFieldIdV3)
    plan = LayoutPlan(LayoutKindV3.INIT, 0, 3, placements)

    materialized = place_binding_v3(b"abc", binding, plan)
    streamed = b"".join(iter_placed_binding_v3((b"a", b"b", b"c"), binding, plan))
    assert streamed == materialized

    prefix_length = 8 + 2 + 4 + len(plan.to_bytes()) + 8
    body = materialized[prefix_length:]
    assert body.startswith(b"aSIGMA3BF")
    assert body.endswith(b"bc")
    positions = [body.index(int(field).to_bytes(2, "big")) for field in BindingFieldIdV3]
    assert positions == sorted(positions)


def test_placement_is_injective_for_supported_mutations() -> None:
    context, binding = _binding(b"base")
    plan0 = derive_layout_v3(
        context,
        binding,
        kind=LayoutKindV3.ROUND,
        round_index=0,
        base_length=4,
    )
    plan1 = derive_layout_v3(
        context,
        binding,
        kind=LayoutKindV3.ROUND,
        round_index=1,
        base_length=4,
    )
    other_binding = prepare_binding_v3(context, BytesSource(b"else"))

    encodings = {
        place_binding_v3(b"base", binding, plan0),
        place_binding_v3(b"case", binding, plan0),
        place_binding_v3(b"base", binding, plan1),
        place_binding_v3(b"base", other_binding, plan0),
    }
    assert len(encodings) == 4


def test_layout_and_placement_known_answer() -> None:
    context, binding = _binding(b"Sigma v3 R5 KAT")
    plan = derive_layout_v3(
        context,
        binding,
        kind=LayoutKindV3.ROUND,
        round_index=7,
        base_length=64,
    )
    placed = place_binding_v3(bytes(range(64)), binding, plan)

    assert plan.to_bytes().hex() == (
        "5349474d4133504c0003000000d20001000000080000000000000007000200000008"
        "00000000000000400003000000a80001000000245349474d41334c50000300000016"
        "000100000002030100020000000800000000000000070002000000245349474d4133"
        "4c500003000000160001000000020302000200000008000000000000002800030000"
        "00245349474d41334c50000300000016000100000002030400020000000800000000"
        "000000340004000000245349474d41334c5000030000001600010000000203030002"
        "0000000800000000000000400004000000020302"
    )
    assert hashlib.sha256(placed).hexdigest() == (
        "4a58974e720a7227fbbb43b6de3da341b13b21199cff641879bdd95d145a0816"
    )


def test_layout_and_placement_reject_invalid_inputs() -> None:
    context, binding = _binding()
    with pytest.raises(ValueError, match="round_index"):
        derive_layout_v3(
            context,
            binding,
            kind=LayoutKindV3.INIT,
            round_index=1,
            base_length=1,
        )
    other_context = SigmaContextV3.reference(
        salt=b"different",
        challenge=context.challenge,
        application_context=context.application_context,
    )
    with pytest.raises(ValueError, match="does not match context"):
        derive_layout_v3(
            other_context,
            binding,
            kind=LayoutKindV3.INIT,
            round_index=0,
            base_length=binding.cardinality.byte_length,
        )
    plan = derive_layout_v3(
        context,
        binding,
        kind=LayoutKindV3.ROUND,
        round_index=0,
        base_length=2,
    )
    with pytest.raises(ValueError, match="shorter"):
        b"".join(iter_placed_binding_v3((b"x",), binding, plan))
    with pytest.raises(ValueError, match="exceeds"):
        b"".join(iter_placed_binding_v3((b"xxx",), binding, plan))
