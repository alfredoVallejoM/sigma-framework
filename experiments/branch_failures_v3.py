"""Reduced Deep/DeepVector failure controls for R13."""

from __future__ import annotations

from collections import Counter
from dataclasses import dataclass
from typing import Literal

from .reduced_oracle import ReducedOracle, encode_integer

BranchModeV3 = Literal["deep", "deep-vector"]
BranchFaultV3 = Literal[
    "normal",
    "constant-first",
    "copied-first-two",
    "truncated-first",
    "omitted-last",
    "permuted",
    "constant-fold",
    "truncated-fold",
]


@dataclass(frozen=True)
class BranchFailureConfigV3:
    bits: int
    branch_count: int = 4
    candidates: int = 256

    def __post_init__(self) -> None:
        for name in ("bits", "branch_count", "candidates"):
            value = getattr(self, name)
            if isinstance(value, bool) or not isinstance(value, int):
                raise TypeError(f"{name} must be int")
            if value <= 0:
                raise ValueError(f"{name} must be positive")
        if self.bits > 32:
            raise ValueError("reduced branch width is capped at 32 bits")
        if self.branch_count < 2 or self.branch_count > 16:
            raise ValueError("branch_count must be in [2,16]")


@dataclass(frozen=True)
class BranchFailureProfileV3:
    mode: BranchModeV3
    fault: BranchFaultV3
    inputs: int
    image_size: int
    collision_pairs: int
    physical_bits: int
    conservative_bits: int


def _branches(
    oracle: ReducedOracle,
    config: BranchFailureConfigV3,
    candidate: int,
    fault: BranchFaultV3,
) -> tuple[int, ...]:
    base = encode_integer(candidate, max(config.bits, candidate.bit_length() or 1))
    values = [
        oracle.query(
            f"r13-branch-{index}",
            config.bits,
            base,
            index.to_bytes(2, "big"),
        )
        for index in range(config.branch_count)
    ]
    if fault == "constant-first":
        values[0] = 0
    elif fault == "copied-first-two":
        values[1] = values[0]
    elif fault == "truncated-first":
        values[0] &= (1 << max(1, config.bits // 2)) - 1
    elif fault == "omitted-last":
        values[-1] = 0
    elif fault == "permuted":
        values = values[1:] + values[:1]
    elif fault in ("normal", "constant-fold", "truncated-fold"):
        pass
    else:
        raise ValueError("unsupported branch fault")
    return tuple(values)


def _deep_output(
    oracle: ReducedOracle,
    config: BranchFailureConfigV3,
    candidate: int,
    fault: BranchFaultV3,
) -> int:
    values = _branches(oracle, config, candidate, fault)
    if fault == "constant-fold":
        return 0
    encoded = b"".join(encode_integer(value, config.bits) for value in values)
    output = oracle.query("r13-deep-fold", config.bits, encoded)
    if fault == "truncated-fold":
        output &= (1 << max(1, config.bits // 2)) - 1
    return output


def _vector_output(
    oracle: ReducedOracle,
    config: BranchFailureConfigV3,
    candidate: int,
    fault: BranchFaultV3,
) -> tuple[int, ...]:
    if fault in ("constant-fold", "truncated-fold"):
        raise ValueError("fold faults do not apply to DeepVector")
    return _branches(oracle, config, candidate, fault)


def _pairs(values: list[int] | list[tuple[int, ...]]) -> int:
    counts = Counter(values)
    return sum(count * (count - 1) // 2 for count in counts.values())


def profile_branch_failure_v3(
    oracle: ReducedOracle,
    config: BranchFailureConfigV3,
    mode: BranchModeV3,
    fault: BranchFaultV3,
) -> BranchFailureProfileV3:
    if mode not in ("deep", "deep-vector"):
        raise ValueError("unsupported branch mode")
    outputs: list[int] | list[tuple[int, ...]]
    if mode == "deep":
        outputs = [
            _deep_output(oracle, config, candidate, fault) for candidate in range(config.candidates)
        ]
        conservative_bits = 0 if fault == "constant-fold" else config.bits
        if fault == "truncated-fold":
            conservative_bits = max(1, config.bits // 2)
        physical_bits = config.bits
    else:
        outputs = [
            _vector_output(oracle, config, candidate, fault)
            for candidate in range(config.candidates)
        ]
        conservative_bits = config.bits
        physical_bits = config.branch_count * config.bits
    return BranchFailureProfileV3(
        mode=mode,
        fault=fault,
        inputs=config.candidates,
        image_size=len(set(outputs)),
        collision_pairs=_pairs(outputs),
        physical_bits=physical_bits,
        conservative_bits=conservative_bits,
    )


__all__ = [
    "BranchFailureConfigV3",
    "BranchFailureProfileV3",
    "BranchFaultV3",
    "BranchModeV3",
    "profile_branch_failure_v3",
]
