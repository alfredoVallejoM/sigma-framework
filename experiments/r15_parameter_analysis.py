"""R15 parameter-dependence estimators fixed before confirmatory data."""

from __future__ import annotations

import hashlib
import math
import random
from collections import Counter
from dataclasses import dataclass

from .parameter_grinding_v3 import ParameterSpaceV3, derive_parameters_reduced
from .reduced_oracle import ReducedOracle


@dataclass(frozen=True)
class MutualInformationProfileV3:
    samples: int
    candidate_bucket_bits: int
    persistent_bucket_bits: int
    mi_candidate: float
    mi_persistent: float
    permutation_p_candidate: float
    permutation_p_persistent: float
    permutations: int


def _mutual_information(xs: list[int], ys: list[tuple[int, int]]) -> float:
    if len(xs) != len(ys) or not xs:
        raise ValueError("MI inputs must be equal and non-empty")
    n = len(xs)
    joint = Counter(zip(xs, ys, strict=True))
    left = Counter(xs)
    right = Counter(ys)
    total = 0.0
    for (x, y), count in joint.items():
        pxy = count / n
        px = left[x] / n
        py = right[y] / n
        total += pxy * math.log2(pxy / (px * py))
    return total


def _rng(seed: bytes, label: bytes) -> random.Random:
    digest = hashlib.sha256(b"sigma-v3-r15-mi\0" + seed + b"\0" + label).digest()
    return random.Random(int.from_bytes(digest, "big"))


def _permutation_p(
    xs: list[int],
    ys: list[tuple[int, int]],
    *,
    observed: float,
    permutations: int,
    seed: bytes,
    label: bytes,
) -> float:
    randomizer = _rng(seed, label)
    ge = 0
    for _ in range(permutations):
        shuffled = list(ys)
        randomizer.shuffle(shuffled)
        ge += int(_mutual_information(xs, shuffled) >= observed)
    return (ge + 1) / (permutations + 1)


def parameter_mutual_information_profile_v3(
    oracle: ReducedOracle,
    samples: int,
    *,
    permutations: int,
    seed: bytes,
    persistent_bits: int = 16,
    candidate_bucket_bits: int = 6,
    persistent_bucket_bits: int = 6,
    space: ParameterSpaceV3 = ParameterSpaceV3(),
) -> MutualInformationProfileV3:
    if samples < 2:
        raise ValueError("samples must be at least two")
    if permutations <= 0:
        raise ValueError("permutations must be positive")
    if not 1 <= candidate_bucket_bits <= 16:
        raise ValueError("candidate_bucket_bits must be in [1,16]")
    if not 1 <= persistent_bucket_bits <= persistent_bits:
        raise ValueError("persistent_bucket_bits is out of range")

    values = [
        derive_parameters_reduced(oracle, candidate, persistent_bits=persistent_bits, space=space)
        for candidate in range(samples)
    ]
    candidate_mask = (1 << candidate_bucket_bits) - 1
    shift = persistent_bits - persistent_bucket_bits
    candidate_buckets = [value.candidate & candidate_mask for value in values]
    persistent_buckets = [value.persistent >> shift for value in values]
    outcomes = [(value.t, value.k) for value in values]

    mi_candidate = _mutual_information(candidate_buckets, outcomes)
    mi_persistent = _mutual_information(persistent_buckets, outcomes)
    return MutualInformationProfileV3(
        samples=samples,
        candidate_bucket_bits=candidate_bucket_bits,
        persistent_bucket_bits=persistent_bucket_bits,
        mi_candidate=mi_candidate,
        mi_persistent=mi_persistent,
        permutation_p_candidate=_permutation_p(
            candidate_buckets,
            outcomes,
            observed=mi_candidate,
            permutations=permutations,
            seed=seed,
            label=b"candidate",
        ),
        permutation_p_persistent=_permutation_p(
            persistent_buckets,
            outcomes,
            observed=mi_persistent,
            permutations=permutations,
            seed=seed,
            label=b"persistent",
        ),
        permutations=permutations,
    )


__all__ = [
    "MutualInformationProfileV3",
    "parameter_mutual_information_profile_v3",
]
