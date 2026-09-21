"""R15 application execution closure for KDF, PoW and mitigations.

Uses production Sigma v3, Argon2id and PoW primitives. Confirmatory invocation
remains blocked until R14.1 and TAG-01.
"""

from __future__ import annotations

import statistics
import time
from collections.abc import Callable, Iterable
from dataclasses import dataclass

from sigma.applications.kdf_argon2id_v3 import (
    Argon2idParametersV3,
    compose_argon2id_output_v3,
    derive_argon2id_v3,
)
from sigma.applications.pow_v3 import PowParametersV3, evaluate_nonce_v3, pow_input_v3
from sigma.binding.parameters import derive_trajectory_parameters
from sigma.binding.prepare import prepare_binding_v3
from sigma.crypto.primitives import domain_tag_v3
from sigma.sources import BytesSource
from sigma.spec.context_v3 import SigmaContextV3
from sigma.spec.ids_v3 import DomainIdV3

ClockNs = Callable[[], int]
COST_BUCKET_UPPER_BOUNDS = (8, 16, 24, 35)
CONTEXT_FIXED_T = 17
CONTEXT_FIXED_K = 3


@dataclass(frozen=True)
class KDFCampaignResultV3:
    mode: str
    guesses: int
    early_rejected: int
    full_sigma_guesses: int
    argon_ns: int
    parameter_ns: int
    sigma_ns: int

    @property
    def total_ns(self) -> int:
        return self.argon_ns + self.parameter_ns + self.sigma_ns

    @property
    def work_per_guess_ns(self) -> float:
        return self.total_ns / self.guesses

    @property
    def early_reject_rate(self) -> float:
        return self.early_rejected / self.guesses


@dataclass(frozen=True)
class PowSelectionResultV3:
    nonces: int
    selected_nonce: int
    selected_cost: int
    mean_cost: float
    preparation_ns: int
    selected_evaluation_ns: int
    full_evaluation_ns: int

    @property
    def selection_total_ns(self) -> int:
        return self.preparation_ns + self.selected_evaluation_ns


@dataclass(frozen=True)
class MitigationCostResultV3:
    mode: str
    samples: int
    mean_cost: float
    variance: float
    minimum: int
    maximum: int


def _kdf_context(parameters: Argon2idParametersV3, salt: bytes) -> SigmaContextV3:
    return SigmaContextV3.for_suite(
        parameters.suite_id,
        salt=salt,
        challenge=domain_tag_v3(DomainIdV3.KDF_BINDING),
        application_context=parameters.to_bytes(),
    )


def _parameters_for_base_key(
    base_key: bytes,
    salt: bytes,
    parameters: Argon2idParametersV3,
) -> tuple[int, int]:
    context = _kdf_context(parameters, salt)
    binding = prepare_binding_v3(context, BytesSource(base_key))
    trajectory = derive_trajectory_parameters(context, binding)
    return trajectory.target_round, trajectory.state_count


def run_kdf_campaign_mode_v3(
    guesses: Iterable[bytes],
    *,
    target_password: bytes,
    salt: bytes,
    parameters: Argon2idParametersV3,
    mode: str,
    clock_ns: ClockNs = time.perf_counter_ns,
) -> KDFCampaignResultV3:
    """Run argon-only, full-Sigma or early-reject-Sigma treatment."""

    if mode not in ("argon2id", "full-sigma", "early-reject-sigma"):
        raise ValueError("unsupported KDF campaign mode")
    values = tuple(guesses)
    if not values:
        raise ValueError("guesses must be non-empty")
    if any(not isinstance(value, bytes) for value in values):
        raise TypeError("guesses must contain bytes")

    target_base = derive_argon2id_v3(target_password, salt, parameters)
    target_tk = _parameters_for_base_key(target_base, salt, parameters)

    argon_ns = 0
    parameter_ns = 0
    sigma_ns = 0
    early = 0
    full = 0
    for guess in values:
        started = clock_ns()
        base_key = derive_argon2id_v3(guess, salt, parameters)
        argon_ns += clock_ns() - started
        if mode == "argon2id":
            continue
        if mode == "early-reject-sigma":
            started = clock_ns()
            guess_tk = _parameters_for_base_key(base_key, salt, parameters)
            parameter_ns += clock_ns() - started
            if guess_tk != target_tk:
                early += 1
                continue
        started = clock_ns()
        compose_argon2id_output_v3(base_key, salt, parameters)
        sigma_ns += clock_ns() - started
        full += 1

    return KDFCampaignResultV3(
        mode,
        len(values),
        early,
        full,
        argon_ns,
        parameter_ns,
        sigma_ns,
    )


def _pow_parameters_for_nonce(
    payload: bytes,
    nonce: int,
    parameters: PowParametersV3,
) -> tuple[int, int]:
    canonical_input = pow_input_v3(payload, nonce)
    context = parameters.context()
    binding = prepare_binding_v3(context, BytesSource(canonical_input))
    trajectory = derive_trajectory_parameters(context, binding)
    return trajectory.target_round, trajectory.state_count


def profile_pow_nonce_selection_v3(
    payload: bytes,
    *,
    nonce_start: int,
    nonces: int,
    parameters: PowParametersV3,
    clock_ns: ClockNs = time.perf_counter_ns,
) -> PowSelectionResultV3:
    if nonces <= 0:
        raise ValueError("nonces must be positive")
    costs: list[tuple[int, int]] = []
    started = clock_ns()
    for offset in range(nonces):
        nonce = nonce_start + offset
        t, k = _pow_parameters_for_nonce(payload, nonce, parameters)
        costs.append((t + k - 1, nonce))
    preparation_ns = clock_ns() - started
    selected_cost, selected_nonce = min(costs)

    started = clock_ns()
    evaluate_nonce_v3(payload, selected_nonce, parameters)
    selected_ns = clock_ns() - started

    started = clock_ns()
    for _cost, nonce in costs:
        evaluate_nonce_v3(payload, nonce, parameters)
    full_ns = clock_ns() - started

    return PowSelectionResultV3(
        nonces,
        selected_nonce,
        selected_cost,
        statistics.fmean(cost for cost, _nonce in costs),
        preparation_ns,
        selected_ns,
        full_ns,
    )


def _bucketed_cost(cost: int) -> int:
    for upper in COST_BUCKET_UPPER_BOUNDS:
        if cost <= upper:
            return upper
    return COST_BUCKET_UPPER_BOUNDS[-1]


def mitigation_cost_profile_v3(
    derived_costs: Iterable[int],
    *,
    mode: str,
) -> MitigationCostResultV3:
    values = tuple(derived_costs)
    if not values:
        raise ValueError("derived_costs must be non-empty")
    if any(
        isinstance(value, bool) or not isinstance(value, int) or value <= 0
        for value in values
    ):
        raise ValueError("derived_costs must contain positive integers")
    if mode == "input-derived":
        effective = values
    elif mode == "context-fixed":
        effective = tuple(CONTEXT_FIXED_T + CONTEXT_FIXED_K - 1 for _ in values)
    elif mode == "cost-bucketed":
        effective = tuple(_bucketed_cost(value) for value in values)
    else:
        raise ValueError("unsupported mitigation mode")
    return MitigationCostResultV3(
        mode,
        len(effective),
        statistics.fmean(effective),
        statistics.pvariance(effective),
        min(effective),
        max(effective),
    )


__all__ = [
    "CONTEXT_FIXED_K",
    "CONTEXT_FIXED_T",
    "COST_BUCKET_UPPER_BOUNDS",
    "KDFCampaignResultV3",
    "MitigationCostResultV3",
    "PowSelectionResultV3",
    "mitigation_cost_profile_v3",
    "profile_pow_nonce_selection_v3",
    "run_kdf_campaign_mode_v3",
]
