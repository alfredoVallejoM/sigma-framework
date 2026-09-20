"""Deterministic R13 design-pilot harness.

These pilots validate attacker interfaces, resource accounting and schemas.
They are disposable and never constitute paper evidence.
"""

from __future__ import annotations

import math
from typing import Any

from .branch_failures_v3 import BranchFailureConfigV3, profile_branch_failure_v3
from .history_attackers_v3 import (
    find_same_persistent_crossings_v3,
    profile_crossing_outcome_v3,
    profile_history_collisions_v3,
    profile_history_truncation_v3,
    profile_layout_ablation_v3,
)
from .history_reduced import ReducedHistoryConfig, find_full_state_collisions
from .parameter_grinding_v3 import (
    ParameterSpaceV3,
    derive_parameters_reduced,
    find_cheapest_stratum,
    kdf_early_rejection_profile,
    mitigation_profile,
    parameter_correlation_profile,
    parameter_distribution,
    pow_nonce_grinding_profile,
)
from .r13_attack_registry import ATTACK_REGISTRY, get_attack
from .r13_schema import AttackRunRecord, AttackRunStatus, ResourceBudget
from .reduced_oracle import ReducedOracle
from .tmto_v3 import TMTOConfigV3, measure_tmto_v3
from .trajectory_attacks_v3 import (
    collision_scaling_v3,
    find_window_preimage_v3,
    find_window_second_preimage_v3,
    multi_target_window_attack_v3,
)

CORE_EXECUTABLE_ATTACKS = frozenset(
    {
        "HIST-01",
        "HIST-02",
        "HIST-03",
        "HIST-05",
        "HIST-06",
        "RED-02",
        "RED-03",
        "RED-04",
        "RED-05",
        "TMTO-01",
        "TMTO-02",
        "PARAM-01",
        "PARAM-02",
        "PARAM-03",
        "PARAM-04",
        "PARAM-05",
        "PARAM-06",
        "LAYOUT-04",
        "BRANCH-05",
        "BRANCH-06",
    }
)


def _resources(
    *,
    W: int,
    Q_A: int = 0,
    Q_J: int = 0,
    Q_H: int = 0,
    Q_R: int = 0,
    d: int = 1,
    p: int = 1,
    mu: int = 0,
    u: int = 1,
) -> ResourceBudget:
    return ResourceBudget(W, Q_A, Q_J, Q_H, Q_R, d, p, mu, u)


def _record(
    attack_id: str,
    *,
    construction: str,
    seed_label: str,
    status: AttackRunStatus,
    observed: ResourceBudget,
    metrics: dict[str, int | float | str | bool | None],
) -> AttackRunRecord:
    spec = get_attack(attack_id)
    missing = [metric for metric in spec.metrics if metric not in metrics]
    if missing:
        raise ValueError(f"{attack_id} missing declared metrics: {missing}")
    metrics = {"confirmatory": False, **metrics}
    budget = _resources(
        W=max(observed.W, 1) * 2 + 1024,
        Q_A=max(observed.Q_A, 0) * 2 + 1024,
        Q_J=max(observed.Q_J, 0) * 2 + 1024,
        Q_H=max(observed.Q_H, 0) * 2 + 1024,
        Q_R=max(observed.Q_R, 0) * 2 + 1024,
        d=max(observed.d, 1) * 2 + 64,
        p=max(observed.p, 1),
        mu=max(observed.mu, 0) * 2 + 4096,
        u=max(observed.u, 1),
    )
    return AttackRunRecord.create(
        attack_id=attack_id,
        construction=construction,
        seed_label=seed_label,
        status=status,
        budget=budget,
        observed=observed,
        metrics=metrics,
    )


def run_history_design_pilots(seed: bytes) -> list[AttackRunRecord]:
    oracle = ReducedOracle(seed + b"/history")
    config = ReducedHistoryConfig(4, 6, 3, target_round=2, state_count=2)
    crossings = find_same_persistent_crossings_v3(
        oracle, config, round_index=1, candidates=512, limit=16
    )
    outcomes = [profile_crossing_outcome_v3(oracle, config, item) for item in crossings]
    records = [
        _record(
            "HIST-01",
            construction="R12-vs-R12.5",
            seed_label="history/crossing",
            status=AttackRunStatus.SUCCESS if crossings else AttackRunStatus.NO_SUCCESS,
            observed=_resources(
                W=512,
                Q_A=512,
                Q_H=len(outcomes) * 2,
                Q_R=len(outcomes) * 4,
                d=2,
                mu=512,
            ),
            metrics={
                "crossings": len(crossings),
                "next_state_matches": sum(item.r125_successors_equal for item in outcomes),
                "run_length": max(
                    (1 if item.r125_successors_equal else 0 for item in outcomes),
                    default=0,
                ),
                "Q_H": len(outcomes) * 2,
                "Q_R": len(outcomes) * 4,
            },
        )
    ]

    full = find_full_state_collisions(
        oracle, config, round_index=1, candidates=1024, limit=32
    )
    records.append(
        _record(
            "HIST-02",
            construction="R12.5-full-state",
            seed_label="history/full-state",
            status=AttackRunStatus.SUCCESS if full else AttackRunStatus.NO_SUCCESS,
            observed=_resources(W=1024, Q_A=1024, Q_H=1024, Q_R=1024, mu=1024),
            metrics={
                "queries_to_first": None if not full else 1024,
                "collision_pairs": len(full),
                "effective_exponent": None,
            },
        )
    )

    hprofile = profile_history_collisions_v3(
        oracle, config, persistent=3, state=5, round_index=0
    )
    records.append(
        _record(
            "HIST-03",
            construction="reduced-HistoryStep",
            seed_label="history/map",
            status=(
                AttackRunStatus.SUCCESS
                if hprofile.collision_pairs
                else AttackRunStatus.NO_SUCCESS
            ),
            observed=_resources(W=hprofile.inputs, Q_H=hprofile.inputs, mu=hprofile.inputs),
            metrics={
                "queries": hprofile.inputs,
                "cycles": None,
                "tails": None,
                "collision_pairs": hprofile.collision_pairs,
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
                construction="R12.5-history-truncation",
                seed_label=f"history/truncation/{point.history_bits}",
                status=AttackRunStatus.SUCCESS,
                observed=_resources(
                    W=1 << point.history_bits,
                    Q_H=1 << point.history_bits,
                    Q_R=1 << point.history_bits,
                    mu=1 << point.history_bits,
                ),
                metrics={
                    "history_bits": point.history_bits,
                    "state_bits": 5,
                    "queries": 1 << point.history_bits,
                    "collision_pairs": point.full_collision_pairs,
                },
            )
        )

    layout = profile_layout_ablation_v3(
        ReducedOracle(seed + b"/layout"), history_bits=6, field_count=5, slots=17
    )
    layout_metrics = {
        "slot_distribution": f"{layout.adaptive_unique_layouts}/{layout.histories}",
        "ties": None,
        "plan_collisions": layout.adaptive_collision_pairs,
        "frame_collisions": None,
    }
    observed = _resources(W=layout.histories, Q_H=layout.histories, mu=layout.histories)
    records.append(
        _record(
            "HIST-06",
            construction="history-adaptive-layout",
            seed_label="history/layout",
            status=AttackRunStatus.SUCCESS,
            observed=observed,
            metrics=layout_metrics,
        )
    )
    records.append(
        _record(
            "LAYOUT-04",
            construction="R12-vs-R12.5-layout",
            seed_label="layout/history-mutation",
            status=AttackRunStatus.SUCCESS,
            observed=observed,
            metrics={
                "changed_slots": max(0, layout.adaptive_unique_layouts - 1),
                "plan_collisions": layout.adaptive_collision_pairs,
                "ties": None,
            },
        )
    )
    return records


def run_parameter_design_pilots(seed: bytes) -> list[AttackRunRecord]:
    oracle = ReducedOracle(seed + b"/parameters")
    space = ParameterSpaceV3(2, 8, 2, 4)
    counts = parameter_distribution(oracle, 512, persistent_bits=10, space=space)
    expected = 512.0 / space.pair_count
    chi_square = sum(
        (counts.get((t, k), 0) - expected) ** 2 / expected
        for t in range(space.t_min, space.t_max + 1)
        for k in range(space.k_min, space.k_max + 1)
    )
    max_deviation = max(
        abs(counts.get((t, k), 0) - expected)
        for t in range(space.t_min, space.t_max + 1)
        for k in range(space.k_min, space.k_max + 1)
    )
    records = [
        _record(
            "PARAM-01",
            construction="reduced-parameter-derivation",
            seed_label="parameters/uniformity",
            status=AttackRunStatus.SUCCESS,
            observed=_resources(W=512, Q_A=512, Q_J=512),
            metrics={
                "counts": str(dict(sorted(counts.items()))),
                "chi_square": chi_square,
                "max_deviation": max_deviation,
            },
        )
    ]

    correlation = parameter_correlation_profile(
        oracle, 512, persistent_bits=10, space=space
    )
    records.append(
        _record(
            "PARAM-02",
            construction="reduced-parameter-derivation",
            seed_label="parameters/correlation",
            status=AttackRunStatus.SUCCESS,
            observed=_resources(W=512, Q_A=512, Q_J=512),
            metrics={
                "mutual_information": None,
                "correlation": max(
                    abs(correlation.candidate_t),
                    abs(correlation.candidate_k),
                    abs(correlation.persistent_t),
                    abs(correlation.persistent_k),
                ),
                "stratum_counts": len(counts),
            },
        )
    )

    grind = find_cheapest_stratum(oracle, 512, persistent_bits=10, space=space)
    records.append(
        _record(
            "PARAM-03",
            construction="cheapest-stratum",
            seed_label="parameters/grinding",
            status=AttackRunStatus.SUCCESS,
            observed=_resources(
                W=grind.preparation_queries + grind.parameter_queries,
                Q_A=grind.preparation_queries,
                Q_J=grind.preparation_queries,
            ),
            metrics={
                "preparations": grind.attempts,
                "selected_cost": grind.transition_cost,
                "net_work": grind.preparation_queries
                + grind.parameter_queries
                + grind.transition_cost,
                "speedup": None,
            },
        )
    )

    early = kdf_early_rejection_profile(
        oracle,
        target_candidate=17,
        guesses=512,
        persistent_bits=10,
        space=space,
    )
    records.append(
        _record(
            "PARAM-04",
            construction="KDF-early-rejection",
            seed_label="parameters/kdf",
            status=AttackRunStatus.SUCCESS,
            observed=_resources(
                W=early.parameter_queries + early.full_trajectory_guesses,
                Q_A=early.guesses,
                Q_J=early.guesses,
                Q_R=early.full_trajectory_guesses,
            ),
            metrics={
                "guesses_per_second": None,
                "early_reject_rate": early.early_rejected / early.guesses,
                "work_per_guess": (
                    early.parameter_queries + early.full_trajectory_guesses
                )
                / early.guesses,
            },
        )
    )

    nonce = pow_nonce_grinding_profile(
        oracle, 512, persistent_bits=10, space=space
    )
    records.append(
        _record(
            "PARAM-05",
            construction="PoW-nonce-grinding",
            seed_label="parameters/pow",
            status=AttackRunStatus.SUCCESS,
            observed=_resources(
                W=nonce.parameter_queries,
                Q_A=nonce.nonces,
                Q_J=nonce.nonces,
                p=1,
            ),
            metrics={
                "nonces": nonce.nonces,
                "cost_distribution": f"mean={nonce.mean_cost:.6f}",
                "selected_cost": nonce.best_cost,
                "throughput": None,
            },
        )
    )

    mitigation = mitigation_profile(
        oracle,
        512,
        fixed_t=5,
        fixed_k=3,
        persistent_bits=10,
        space=space,
    )
    records.append(
        _record(
            "PARAM-06",
            construction="fixed-cost-mitigation",
            seed_label="parameters/mitigation",
            status=AttackRunStatus.SUCCESS,
            observed=_resources(W=512, Q_A=512, Q_J=512),
            metrics={
                "speedup": None,
                "variance": mitigation.derived_variance,
                "latency": None,
                "memory": None,
            },
        )
    )
    return records


def run_reduced_design_pilots(seed: bytes) -> list[AttackRunRecord]:
    records: list[AttackRunRecord] = []
    for point in collision_scaling_v3(
        seed + b"/collision-scaling",
        (3, 4, 5, 6),
        construction="r125",
        history_bits=6,
        persistent_bits=4,
        target_round=1,
        state_count=2,
        max_candidates=2048,
    ):
        q = point.candidates_to_first_window_collision
        records.append(
            _record(
                "RED-02",
                construction="R12.5-window",
                seed_label=f"reduced/collision/{point.state_bits}",
                status=AttackRunStatus.CENSORED if point.censored else AttackRunStatus.SUCCESS,
                observed=_resources(
                    W=point.max_candidates if q is None else q,
                    Q_A=point.max_candidates if q is None else q,
                    Q_H=point.max_candidates if q is None else q,
                    Q_R=point.max_candidates if q is None else q,
                    mu=point.max_candidates if q is None else q,
                ),
                metrics={
                    "Q50": None,
                    "log2_Q50": None if q is None else math.log2(q),
                    "slope": None,
                    "confidence_interval": None,
                },
                censor_reason="candidate budget" if point.censored else None,
            )
        )

    config = ReducedHistoryConfig(4, 5, 3, target_round=1, state_count=2)
    oracle = ReducedOracle(seed + b"/reduced-family")
    target_window = tuple(
        oracle.query(
            "r13-external-target-window",
            config.state_bits,
            index.to_bytes(2, "big"),
        )
        for index in range(config.state_count)
    )
    preimage = find_window_preimage_v3(
        oracle,
        config,
        construction="r125",
        target_window=target_window,
        candidates=4096,
    )
    records.append(
        _record(
            "RED-03",
            construction="R12.5-window",
            seed_label="reduced/preimage",
            status=AttackRunStatus.NO_SUCCESS if preimage is None else AttackRunStatus.SUCCESS,
            observed=_resources(
                W=4096 if preimage is None else int(preimage["evaluated_candidates"]),
                Q_A=4096 if preimage is None else int(preimage["evaluated_candidates"]),
                Q_H=4096 if preimage is None else int(preimage["evaluated_candidates"]),
                Q_R=4096 if preimage is None else int(preimage["evaluated_candidates"]),
            ),
            metrics={
                "queries": 4096 if preimage is None else int(preimage["evaluated_candidates"]),
                "success": preimage is not None,
                "censoring": "budget" if preimage is None else "none",
            },
        )
    )

    second = find_window_second_preimage_v3(
        oracle,
        config,
        construction="r125",
        target_candidate=0,
        candidates=4096,
        persistent_policy="same",
    )
    records.append(
        _record(
            "RED-04",
            construction="R12.5-same-persistent",
            seed_label="reduced/second-preimage",
            status=AttackRunStatus.NO_SUCCESS if second is None else AttackRunStatus.SUCCESS,
            observed=_resources(
                W=4096 if second is None else second.evaluated_candidates,
                Q_A=4096 if second is None else second.evaluated_candidates,
                Q_H=4096 if second is None else second.evaluated_candidates,
                Q_R=4096 if second is None else second.evaluated_candidates,
            ),
            metrics={
                "queries": 4096 if second is None else second.evaluated_candidates,
                "success": second is not None,
                "same_P": False if second is None else second.persistent_equal,
                "same_header": None,
                "first_divergence": (
                    None if second is None else second.first_state_divergence
                ),
            },
        )
    )

    multi = multi_target_window_attack_v3(
        oracle,
        config,
        construction="r125",
        targets=8,
        search_candidates=2048,
    )
    records.append(
        _record(
            "RED-05",
            construction="R12.5-multi-target",
            seed_label="reduced/multi-target",
            status=(
                AttackRunStatus.SUCCESS
                if bool(multi["success"])
                else AttackRunStatus.NO_SUCCESS
            ),
            observed=_resources(
                W=int(multi["evaluated"]),
                Q_A=int(multi["evaluated"]),
                Q_H=int(multi["evaluated"]),
                Q_R=int(multi["evaluated"]),
                u=8,
            ),
            metrics={
                "targets": 8,
                "queries": int(multi["evaluated"]),
                "success": bool(multi["success"]),
                "union_factor": 8,
            },
        )
    )
    return records


def run_tmto_design_pilots(seed: bytes) -> list[AttackRunRecord]:
    records: list[AttackRunRecord] = []
    config = TMTOConfigV3(6, 6, entries=64, chain_length=4, distinguished_bits=2, targets=3)
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
            attack_id = "TMTO-02" if strategy in ("hellman", "rainbow") else "TMTO-01"
            metrics: dict[str, int | float | str | bool | None]
            if attack_id == "TMTO-01":
                metrics = {
                    "offline_work": result.offline_queries,
                    "online_work": result.online_queries,
                    "memory": result.memory_entries,
                    "speedup": None,
                }
            else:
                metrics = {
                    "offline_work": result.offline_queries,
                    "online_work": result.online_queries,
                    "memory": result.memory_entries,
                    "targets": result.targets,
                }
            records.append(
                _record(
                    attack_id,
                    construction=construction,
                    seed_label=f"tmto/{construction}/{strategy}",
                    status=AttackRunStatus.SUCCESS,
                    observed=_resources(
                        W=result.offline_queries + result.online_queries,
                        Q_H=result.history_queries,
                        Q_R=result.offline_queries + result.online_queries,
                        d=result.parallel_depth,
                        mu=result.memory_entries,
                        u=result.targets,
                    ),
                    metrics=metrics,
                )
            )
    return records


def run_branch_design_pilots(seed: bytes) -> list[AttackRunRecord]:
    oracle = ReducedOracle(seed + b"/branch")
    config = BranchFailureConfigV3(bits=6, branch_count=4, candidates=128)
    records: list[AttackRunRecord] = []
    for fault in ("normal", "constant-fold", "truncated-fold"):
        result = profile_branch_failure_v3(
            oracle, config, "deep", fault  # type: ignore[arg-type]
        )
        records.append(
            _record(
                "BRANCH-05",
                construction=f"Deep/{fault}",
                seed_label=f"branch/deep/{fault}",
                status=AttackRunStatus.SUCCESS,
                observed=_resources(W=config.candidates, Q_R=config.candidates, mu=result.image_size),
                metrics={
                    "attack_success": result.image_size < config.candidates,
                    "effective_width": result.conservative_bits,
                    "queries": config.candidates,
                },
            )
        )
    for fault in ("normal", "constant-first", "copied-first-two", "permuted"):
        result = profile_branch_failure_v3(
            oracle, config, "deep-vector", fault  # type: ignore[arg-type]
        )
        records.append(
            _record(
                "BRANCH-06",
                construction=f"DeepVector/{fault}",
                seed_label=f"branch/vector/{fault}",
                status=AttackRunStatus.SUCCESS,
                observed=_resources(W=config.candidates, Q_R=config.candidates, mu=result.image_size),
                metrics={
                    "affected_branches": None,
                    "hamming_distance": None,
                    "first_divergence": None,
                },
            )
        )
    return records


def run_r13_design_pilots(
    seed: bytes = b"sigma-r13-design-pilots",
) -> list[AttackRunRecord]:
    if not isinstance(seed, bytes) or not seed:
        raise ValueError("seed must be non-empty bytes")
    return [
        *run_history_design_pilots(seed),
        *run_parameter_design_pilots(seed),
        *run_reduced_design_pilots(seed),
        *run_tmto_design_pilots(seed),
        *run_branch_design_pilots(seed),
    ]


def validate_r13_design_records(records: list[AttackRunRecord]) -> None:
    if not records:
        raise ValueError("R13 design records must be non-empty")
    observed_ids = {record.attack_id for record in records}
    missing = sorted(CORE_EXECUTABLE_ATTACKS - observed_ids)
    if missing:
        raise ValueError(f"missing R13 design attacks: {missing}")
    for record in records:
        spec = ATTACK_REGISTRY[record.attack_id]
        missing_metrics = [metric for metric in spec.metrics if metric not in record.metrics]
        if missing_metrics:
            raise ValueError(
                f"{record.attack_id} missing registered metrics: {missing_metrics}"
            )
        if record.metrics.get("confirmatory") is not False:
            raise ValueError("R13 design pilots must be marked confirmatory=false")


__all__ = [
    "CORE_EXECUTABLE_ATTACKS",
    "run_branch_design_pilots",
    "run_history_design_pilots",
    "run_parameter_design_pilots",
    "run_r13_design_pilots",
    "run_reduced_design_pilots",
    "run_tmto_design_pilots",
    "validate_r13_design_records",
]
