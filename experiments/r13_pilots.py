"""Deterministic design-pilot harness for Sigma v3 R13.

R13 pilots validate attacker interfaces, resource accounting and output schemas.
Their observations are disposable and MUST NOT be used as confirmatory evidence.
"""

from __future__ import annotations

from dataclasses import asdict
from typing import Any

from .branch_failures_v3 import BranchFailureConfigV3, profile_branch_failure_v3
from .history_attackers_v3 import (
    find_same_persistent_crossings_v3,
    profile_crossing_outcome_v3,
    profile_history_collisions_v3,
    profile_history_truncation_v3,
    profile_layout_ablation_v3,
)
from .history_reduced import ReducedHistoryConfig
from .parameter_grinding_v3 import (
    ParameterSpaceV3,
    find_cheapest_stratum,
    kdf_early_rejection_profile,
    parameter_distribution,
    pow_nonce_grinding_profile,
)
from .r13_registry import ATTACK_REGISTRY_V3
from .reduced_oracle import ReducedOracle
from .tmto_v3 import TMTOConfigV3, measure_tmto_v3


def _record(attack_id: str, payload: dict[str, Any]) -> dict[str, Any]:
    if attack_id not in ATTACK_REGISTRY_V3:
        raise ValueError(f"unregistered R13 attack: {attack_id}")
    return {
        "attack_id": attack_id,
        "campaign": "r13-design-pilot",
        "confirmatory": False,
        **payload,
    }


def run_history_design_pilots(seed: bytes) -> list[dict[str, Any]]:
    oracle = ReducedOracle(seed + b"/history")
    config = ReducedHistoryConfig(
        state_bits=4,
        history_bits=6,
        persistent_bits=3,
        target_round=2,
        state_count=2,
    )
    crossings = find_same_persistent_crossings_v3(
        oracle,
        config,
        round_index=1,
        candidates=512,
        limit=8,
    )
    records: list[dict[str, Any]] = []
    for crossing in crossings:
        outcome = profile_crossing_outcome_v3(oracle, config, crossing)
        records.append(
            _record(
                "HIST-01",
                {
                    "state_bits": config.state_bits,
                    "history_bits": config.history_bits,
                    "round_index": crossing.round_index,
                    "queries": 512,
                    "crossing_found": True,
                    "next_state_equal": outcome.r125_successors_equal,
                    "next_full_state_equal": outcome.next_full_states_equal,
                    "r12_coalesces": outcome.r12_successors_equal,
                },
            )
        )

    history = profile_history_collisions_v3(
        oracle,
        config,
        persistent=3,
        state=5,
        round_index=0,
    )
    records.append(
        _record(
            "HIST-03",
            {
                "history_bits": history.history_bits,
                "queries": history.inputs,
                "attack": "collision-enumeration",
                "success": history.collision_pairs > 0,
                "image_size": history.image_size,
                "collision_pairs": history.collision_pairs,
            },
        )
    )

    for point in profile_history_truncation_v3(
        seed + b"/truncation",
        (3, 4, 5, 6),
        state_bits=5,
        persistent_bits=5,
        persistent=3,
        state=7,
        round_index=0,
    ):
        records.append(
            _record(
                "HIST-05",
                {
                    "history_bits": point.history_bits,
                    "visible_pairs": point.visible_collision_pairs,
                    "full_pairs": point.full_collision_pairs,
                    "inputs": 1 << point.history_bits,
                    "visible_image_size": point.visible_image_size,
                    "full_image_size": point.full_image_size,
                },
            )
        )

    layout = profile_layout_ablation_v3(
        ReducedOracle(seed + b"/layout"),
        history_bits=6,
        field_count=5,
        slots=17,
    )
    records.append(
        _record(
            "HIST-06",
            {
                "history_bits": layout.history_bits,
                "slots": 17,
                "fixed_unique": layout.fixed_unique_layouts,
                "adaptive_unique": layout.adaptive_unique_layouts,
                "adaptive_collision_pairs": layout.adaptive_collision_pairs,
            },
        )
    )
    return records


def run_parameter_design_pilots(seed: bytes) -> list[dict[str, Any]]:
    oracle = ReducedOracle(seed + b"/parameters")
    space = ParameterSpaceV3(2, 8, 2, 4)
    counts = parameter_distribution(oracle, 512, persistent_bits=10, space=space)
    records = [
        _record(
            "PARAM-01",
            {
                "samples": 512,
                "pair": [t, k],
                "count": count,
                "expected_probability": 1.0 / space.pair_count,
            },
        )
        for (t, k), count in sorted(counts.items())
    ]
    records.append(
        _record(
            "PARAM-03",
            asdict(
                find_cheapest_stratum(
                    oracle,
                    512,
                    persistent_bits=10,
                    space=space,
                )
            ),
        )
    )
    records.append(
        _record(
            "PARAM-04",
            asdict(
                kdf_early_rejection_profile(
                    oracle,
                    target_candidate=17,
                    guesses=512,
                    persistent_bits=10,
                    space=space,
                )
            ),
        )
    )
    records.append(
        _record(
            "PARAM-05",
            asdict(
                pow_nonce_grinding_profile(
                    oracle,
                    512,
                    persistent_bits=10,
                    space=space,
                )
            ),
        )
    )
    return records


def run_tmto_design_pilots(seed: bytes) -> list[dict[str, Any]]:
    records: list[dict[str, Any]] = []
    config = TMTOConfigV3(
        bits=6,
        history_bits=6,
        entries=64,
        chain_length=4,
        distinguished_bits=2,
        targets=3,
    )
    for construction in ("r12", "r125"):
        for strategy in ("direct", "distinguished", "rho", "hellman", "rainbow"):
            result = measure_tmto_v3(
                ReducedOracle(
                    seed + f"/tmto/{construction}/{strategy}".encode("ascii")
                ),
                config,
                strategy,  # type: ignore[arg-type]
                construction,  # type: ignore[arg-type]
            )
            records.append(_record("TMTO-01", asdict(result)))
    return records


def run_branch_design_pilots(seed: bytes) -> list[dict[str, Any]]:
    oracle = ReducedOracle(seed + b"/branch")
    config = BranchFailureConfigV3(bits=6, branch_count=4, candidates=128)
    records: list[dict[str, Any]] = []
    for mode, faults in (
        (
            "deep",
            (
                "normal",
                "constant-first",
                "copied-first-two",
                "truncated-first",
                "omitted-last",
                "permuted",
                "constant-fold",
                "truncated-fold",
            ),
        ),
        (
            "deep-vector",
            (
                "normal",
                "constant-first",
                "copied-first-two",
                "truncated-first",
                "omitted-last",
                "permuted",
            ),
        ),
    ):
        for fault in faults:
            records.append(
                _record(
                    "BRANCH-01",
                    asdict(
                        profile_branch_failure_v3(
                            oracle,
                            config,
                            mode,  # type: ignore[arg-type]
                            fault,  # type: ignore[arg-type]
                        )
                    ),
                )
            )
    return records


def run_r13_design_pilots(seed: bytes = b"sigma-r13-design-pilots") -> list[dict[str, Any]]:
    if not isinstance(seed, bytes) or not seed:
        raise ValueError("seed must be non-empty bytes")
    return [
        *run_history_design_pilots(seed),
        *run_parameter_design_pilots(seed),
        *run_tmto_design_pilots(seed),
        *run_branch_design_pilots(seed),
    ]


def validate_r13_design_records(records: list[dict[str, Any]]) -> None:
    if not records:
        raise ValueError("R13 design records must be non-empty")
    observed = {str(record.get("attack_id")) for record in records}
    required = {
        "HIST-01",
        "HIST-03",
        "HIST-05",
        "HIST-06",
        "PARAM-01",
        "PARAM-03",
        "PARAM-04",
        "PARAM-05",
        "TMTO-01",
        "BRANCH-01",
    }
    if not required <= observed:
        raise ValueError(f"missing R13 design attacks: {sorted(required - observed)}")
    for record in records:
        attack_id = str(record["attack_id"])
        spec = ATTACK_REGISTRY_V3[attack_id]
        missing = [field for field in spec.output_fields if field not in record]
        if missing:
            raise ValueError(f"{attack_id} missing output fields: {missing}")
        if record.get("confirmatory") is not False:
            raise ValueError("R13 design pilots must never be confirmatory")


__all__ = [
    "run_branch_design_pilots",
    "run_history_design_pilots",
    "run_parameter_design_pilots",
    "run_r13_design_pilots",
    "run_tmto_design_pilots",
    "validate_r13_design_records",
]
