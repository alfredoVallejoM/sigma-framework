"""Vectorized deterministic PARAM-02 engine for the pre-execution R15 amendment.

The statistical procedure is unchanged:
- same 32,768 observations per confirmatory replicate;
- same candidate/persistent bucket widths;
- same joint outcome Y=(t,k);
- same number of complete permutations;
- same add-one permutation p-value.

Only the implementation changes from Python Counter/shuffle loops to NumPy
categorical contingency tables and PCG64 permutations.  No PARAM-02
confirmatory seed was consumed before this amendment.
"""

from __future__ import annotations

import hashlib
import importlib
from typing import Any

from .parameter_grinding_v3 import (
    DEFAULT_PARAMETER_SPACE_V3,
    ParameterSpaceV3,
    derive_parameters_reduced,
)
from .r15_parameter_analysis import MutualInformationProfileV3
from .reduced_oracle import ReducedOracle


def _np() -> Any:
    try:
        return importlib.import_module("numpy")
    except ModuleNotFoundError as exc:
        raise RuntimeError(
            "PARAM-02 vectorized engine requires the frozen analysis dependency numpy"
        ) from exc


def _mi_from_codes(
    np: Any,
    x_codes: Any,
    y_codes: Any,
    *,
    x_cardinality: int,
    y_cardinality: int,
) -> float:
    n = int(x_codes.size)
    joint = np.bincount(
        x_codes * y_cardinality + y_codes,
        minlength=x_cardinality * y_cardinality,
    ).reshape((x_cardinality, y_cardinality))
    row = joint.sum(axis=1)
    column = joint.sum(axis=0)
    mask = joint > 0
    counts = joint[mask].astype(np.float64)
    denominator = (row[:, None] * column[None, :])[mask].astype(np.float64)
    terms = (counts / n) * np.log2((counts * n) / denominator)
    return float(terms.sum(dtype=np.float64))


def _rng(np: Any, seed: bytes, label: bytes) -> Any:
    digest = hashlib.sha256(b"sigma-v3-r15-mi-vectorized-v1\0" + seed + b"\0" + label).digest()
    return np.random.Generator(np.random.PCG64(int.from_bytes(digest, "big")))


def _permutation_p(
    np: Any,
    x_codes: Any,
    y_codes: Any,
    *,
    x_cardinality: int,
    y_cardinality: int,
    observed: float,
    permutations: int,
    seed: bytes,
    label: bytes,
) -> float:
    randomizer = _rng(np, seed, label)
    ge = 0
    for _ in range(permutations):
        permuted = y_codes[randomizer.permutation(y_codes.size)]
        statistic = _mi_from_codes(
            np,
            x_codes,
            permuted,
            x_cardinality=x_cardinality,
            y_cardinality=y_cardinality,
        )
        ge += int(statistic >= observed)
    return (ge + 1) / (permutations + 1)


def parameter_mutual_information_profile_vectorized_v3(
    oracle: ReducedOracle,
    samples: int,
    *,
    permutations: int,
    seed: bytes,
    persistent_bits: int = 16,
    candidate_bucket_bits: int = 6,
    persistent_bucket_bits: int = 6,
    space: ParameterSpaceV3 = DEFAULT_PARAMETER_SPACE_V3,
) -> MutualInformationProfileV3:
    if samples < 2:
        raise ValueError("samples must be at least two")
    if permutations <= 0:
        raise ValueError("permutations must be positive")
    if not 1 <= candidate_bucket_bits <= 16:
        raise ValueError("candidate_bucket_bits must be in [1,16]")
    if not 1 <= persistent_bucket_bits <= persistent_bits:
        raise ValueError("persistent_bucket_bits is out of range")

    np = _np()
    values = [
        derive_parameters_reduced(
            oracle,
            candidate,
            persistent_bits=persistent_bits,
            space=space,
        )
        for candidate in range(samples)
    ]

    candidate_cardinality = 1 << candidate_bucket_bits
    persistent_cardinality = 1 << persistent_bucket_bits
    candidate_mask = candidate_cardinality - 1
    shift = persistent_bits - persistent_bucket_bits
    k_cardinality = space.k_max - space.k_min + 1
    y_cardinality = space.pair_count

    candidate_codes = np.fromiter(
        (value.candidate & candidate_mask for value in values),
        dtype=np.int64,
        count=samples,
    )
    persistent_codes = np.fromiter(
        (value.persistent >> shift for value in values),
        dtype=np.int64,
        count=samples,
    )
    outcome_codes = np.fromiter(
        ((value.t - space.t_min) * k_cardinality + (value.k - space.k_min) for value in values),
        dtype=np.int64,
        count=samples,
    )

    mi_candidate = _mi_from_codes(
        np,
        candidate_codes,
        outcome_codes,
        x_cardinality=candidate_cardinality,
        y_cardinality=y_cardinality,
    )
    mi_persistent = _mi_from_codes(
        np,
        persistent_codes,
        outcome_codes,
        x_cardinality=persistent_cardinality,
        y_cardinality=y_cardinality,
    )

    return MutualInformationProfileV3(
        samples=samples,
        candidate_bucket_bits=candidate_bucket_bits,
        persistent_bucket_bits=persistent_bucket_bits,
        mi_candidate=mi_candidate,
        mi_persistent=mi_persistent,
        permutation_p_candidate=_permutation_p(
            np,
            candidate_codes,
            outcome_codes,
            x_cardinality=candidate_cardinality,
            y_cardinality=y_cardinality,
            observed=mi_candidate,
            permutations=permutations,
            seed=seed,
            label=b"candidate",
        ),
        permutation_p_persistent=_permutation_p(
            np,
            persistent_codes,
            outcome_codes,
            x_cardinality=persistent_cardinality,
            y_cardinality=y_cardinality,
            observed=mi_persistent,
            permutations=permutations,
            seed=seed,
            label=b"persistent",
        ),
        permutations=permutations,
    )


__all__ = ["parameter_mutual_information_profile_vectorized_v3"]
