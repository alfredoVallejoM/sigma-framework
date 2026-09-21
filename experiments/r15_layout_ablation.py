"""Three-way R15 layout/history ablation: fixed, values-only and adaptive."""

from __future__ import annotations

from collections import Counter
from dataclasses import dataclass
from typing import Literal

from .reduced_oracle import ReducedOracle, encode_integer

LayoutVariantV3 = Literal["fixed", "values-only", "adaptive"]


@dataclass(frozen=True)
class LayoutVariantProfileV3:
    variant: LayoutVariantV3
    histories: int
    unique_plans: int
    plan_collision_pairs: int
    frame_collision_pairs: int
    tie_count: int


def _plan(
    oracle: ReducedOracle,
    *,
    history: int,
    history_bits: int,
    field_count: int,
    slots: int,
    adaptive: bool,
) -> tuple[int, ...]:
    history_bytes = encode_integer(history, history_bits) if adaptive else b""
    label = "r15-layout-adaptive" if adaptive else "r15-layout-fixed"
    return tuple(
        oracle.query(label, 16, history_bytes, field.to_bytes(2, "big")) % slots
        for field in range(field_count)
    )


def profile_layout_variant_v3(
    oracle: ReducedOracle,
    *,
    history_bits: int,
    field_count: int,
    slots: int,
    variant: LayoutVariantV3,
) -> LayoutVariantProfileV3:
    if variant not in ("fixed", "values-only", "adaptive"):
        raise ValueError("unsupported layout variant")
    if not 1 <= history_bits <= 20:
        raise ValueError("history_bits must be in [1,20]")
    if field_count <= 0 or slots <= 0:
        raise ValueError("field_count and slots must be positive")

    plans: list[tuple[int, ...]] = []
    frames: list[tuple[tuple[int, ...], int | None]] = []
    ties = 0
    for history in range(1 << history_bits):
        plan = _plan(
            oracle,
            history=history,
            history_bits=history_bits,
            field_count=field_count,
            slots=slots,
            adaptive=variant == "adaptive",
        )
        plans.append(plan)
        ties += int(len(set(plan)) != len(plan))
        frame_history: int | None = None if variant == "fixed" else history
        frames.append((plan, frame_history))

    plan_counts = Counter(plans)
    frame_counts = Counter(frames)
    return LayoutVariantProfileV3(
        variant=variant,
        histories=len(plans),
        unique_plans=len(plan_counts),
        plan_collision_pairs=sum(v * (v - 1) // 2 for v in plan_counts.values()),
        frame_collision_pairs=sum(v * (v - 1) // 2 for v in frame_counts.values()),
        tie_count=ties,
    )


def profile_layout_ablation_three_way_v3(
    oracle: ReducedOracle,
    *,
    history_bits: int,
    field_count: int,
    slots: int,
) -> tuple[LayoutVariantProfileV3, ...]:
    return tuple(
        profile_layout_variant_v3(
            oracle,
            history_bits=history_bits,
            field_count=field_count,
            slots=slots,
            variant=variant,
        )
        for variant in ("fixed", "values-only", "adaptive")
    )


__all__ = [
    "LayoutVariantProfileV3",
    "LayoutVariantV3",
    "profile_layout_ablation_three_way_v3",
    "profile_layout_variant_v3",
]
