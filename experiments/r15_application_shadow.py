"""R15-E application-economics shadow rehearsal with production primitives."""

from __future__ import annotations

import hashlib
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any

from sigma.applications.kdf_argon2id_v3 import Argon2idParametersV3
from sigma.applications.pow_v3 import PowParametersV3, pow_input_v3
from sigma.binding.parameters import derive_trajectory_parameters
from sigma.binding.prepare import prepare_binding_v3
from sigma.sources import BytesSource
from sigma.spec.ids_v3 import SuiteIdV3

from .common import canonical_json
from .r15_application_campaigns import (
    mitigation_cost_profile_v3,
    profile_pow_nonce_selection_v3,
    run_kdf_campaign_mode_v3,
)
from .r15_data import RunKeyV3, atomic_write_record_v3, build_ledger_v3

SHADOW_E_NAMESPACE = "sigma-v3-r15-shadow-e-v1"
SHADOW_E_FREEZE_ID = "synthetic-r15e-shadow"


@dataclass(frozen=True)
class ApplicationShadowResultV3:
    attack_id: str
    primary_metric: str
    primary_value: float
    metrics: dict[str, int | float | str | bool | None]


def _application_seed(label: str) -> bytes:
    return hashlib.sha256(
        SHADOW_E_NAMESPACE.encode("ascii") + b"\0" + label.encode("ascii")
    ).digest()


def _pow_costs(
    *,
    payload: bytes,
    parameters: PowParametersV3,
    nonces: int,
) -> tuple[int, ...]:
    context = parameters.context()
    costs: list[int] = []
    for nonce in range(nonces):
        binding = prepare_binding_v3(
            context,
            BytesSource(pow_input_v3(payload, nonce)),
        )
        trajectory = derive_trajectory_parameters(context, binding)
        costs.append(trajectory.target_round + trajectory.state_count - 1)
    return tuple(costs)


def run_application_shadow_suite_v3(root: Path) -> dict[str, object]:
    results: list[ApplicationShadowResultV3] = []
    keys: list[RunKeyV3] = []

    kdf_parameters = Argon2idParametersV3(
        memory_kib=64,
        time_cost=1,
        parallelism=1,
        output_length=32,
        suite_id=SuiteIdV3.REFERENCE_IAP_HISTORY_V3,
    )
    salt = _application_seed("kdf-salt")[:16]
    guesses = (b"shadow-wrong-0", b"shadow-wrong-1")
    target = b"shadow-target"

    argon = run_kdf_campaign_mode_v3(
        guesses,
        target_password=target,
        salt=salt,
        parameters=kdf_parameters,
        mode="argon2id",
    )
    full = run_kdf_campaign_mode_v3(
        guesses,
        target_password=target,
        salt=salt,
        parameters=kdf_parameters,
        mode="full-sigma",
    )
    early = run_kdf_campaign_mode_v3(
        guesses,
        target_password=target,
        salt=salt,
        parameters=kdf_parameters,
        mode="early-reject-sigma",
    )
    kdf_ratio = early.work_per_guess_ns / full.work_per_guess_ns
    results.append(
        ApplicationShadowResultV3(
            "PARAM-04",
            "work_per_guess_ratio",
            kdf_ratio,
            {
                "guesses": len(guesses),
                "argon_only_ns": argon.total_ns,
                "full_sigma_ns": full.total_ns,
                "early_reject_ns": early.total_ns,
                "early_reject_rate": early.early_reject_rate,
                "full_sigma_guesses_early_mode": early.full_sigma_guesses,
            },
        )
    )

    pow_parameters = PowParametersV3(
        challenge=_application_seed("pow-challenge"),
        difficulty_bits=0,
        suite_id=SuiteIdV3.REFERENCE_IAP_HISTORY_V3,
    )
    payload = b"r15-shadow-pow"
    pow_result = profile_pow_nonce_selection_v3(
        payload,
        nonce_start=0,
        nonces=4,
        parameters=pow_parameters,
    )
    pow_ratio = pow_result.full_evaluation_ns / max(1, pow_result.selection_total_ns)
    results.append(
        ApplicationShadowResultV3(
            "PARAM-05",
            "throughput_cost_ratio",
            pow_ratio,
            {
                "nonces": pow_result.nonces,
                "selected_nonce": pow_result.selected_nonce,
                "selected_cost": pow_result.selected_cost,
                "mean_cost": pow_result.mean_cost,
                "preparation_ns": pow_result.preparation_ns,
                "selected_evaluation_ns": pow_result.selected_evaluation_ns,
                "full_evaluation_ns": pow_result.full_evaluation_ns,
            },
        )
    )

    costs = _pow_costs(payload=payload, parameters=pow_parameters, nonces=8)
    derived = mitigation_cost_profile_v3(costs, mode="input-derived")
    fixed = mitigation_cost_profile_v3(costs, mode="context-fixed")
    bucketed = mitigation_cost_profile_v3(costs, mode="cost-bucketed")
    mitigation_ratio = fixed.mean_cost / derived.mean_cost
    results.append(
        ApplicationShadowResultV3(
            "PARAM-06",
            "work_ratio",
            mitigation_ratio,
            {
                "samples": len(costs),
                "input_derived_mean": derived.mean_cost,
                "input_derived_variance": derived.variance,
                "context_fixed_mean": fixed.mean_cost,
                "cost_bucketed_mean": bucketed.mean_cost,
                "derived_minimum": derived.minimum,
                "derived_maximum": derived.maximum,
            },
        )
    )

    for index, result in enumerate(results):
        key = RunKeyV3(
            SHADOW_E_FREEZE_ID,
            result.attack_id,
            f"{result.attack_id.lower()}-shadow",
            index,
        )
        record: dict[str, Any] = {
            "schema": "sigma-v3-r15-application-shadow-record-v1",
            "namespace": SHADOW_E_NAMESPACE,
            "confirmatory": False,
            "run_key": key.stable_id,
            "result": asdict(result),
        }
        atomic_write_record_v3(root, key, record)
        keys.append(key)

    ledger = build_ledger_v3(root, keys)
    return {
        "schema": "sigma-v3-r15-application-shadow-v1",
        "namespace": SHADOW_E_NAMESPACE,
        "confirmatory": False,
        "records": len(results),
        "attacks": [result.attack_id for result in results],
        "ledger_root": ledger["root_sha256"],
        "results": [asdict(result) for result in results],
    }


__all__ = [
    "ApplicationShadowResultV3",
    "SHADOW_E_FREEZE_ID",
    "SHADOW_E_NAMESPACE",
    "run_application_shadow_suite_v3",
]
