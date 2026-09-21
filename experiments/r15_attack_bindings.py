"""Closed mapping from frozen R15 attack ids to executable endpoints."""

from __future__ import annotations

from dataclasses import dataclass
from types import MappingProxyType


@dataclass(frozen=True)
class R15ExecutorBinding:
    attack_id: str
    module: str
    executor: str
    primary_metric: str
    confirmatory_capable: bool = True


_BINDINGS = (
    R15ExecutorBinding(
        "HIST-01",
        "experiments.r15_history_games",
        "conditional_crossing_trials_v3",
        "next_state_match_rate",
    ),
    R15ExecutorBinding(
        "HIST-02",
        "experiments.r15_endpoint_wrappers",
        "find_first_full_state_collision_v3",
        "queries_to_first_full_state_collision",
    ),
    R15ExecutorBinding(
        "HIST-03",
        "experiments.r15_history_games",
        "profile_history_game_v3",
        "queries",
    ),
    R15ExecutorBinding(
        "HIST-05",
        "experiments.history_attackers_v3",
        "profile_history_truncation_v3",
        "full_collision_pairs",
    ),
    R15ExecutorBinding(
        "HIST-06",
        "experiments.r15_layout_ablation",
        "profile_layout_ablation_three_way_v3",
        "plan_collision_rate",
    ),
    R15ExecutorBinding(
        "RED-02",
        "experiments.trajectory_attacks_v3",
        "collision_scaling_v3",
        "queries_to_first_window_collision",
    ),
    R15ExecutorBinding(
        "RED-03",
        "experiments.trajectory_attacks_v3",
        "find_window_preimage_v3",
        "queries",
    ),
    R15ExecutorBinding(
        "RED-04",
        "experiments.trajectory_attacks_v3",
        "find_window_second_preimage_v3",
        "queries",
    ),
    R15ExecutorBinding(
        "RED-05",
        "experiments.trajectory_attacks_v3",
        "multi_target_window_attack_v3",
        "queries",
    ),
    R15ExecutorBinding(
        "TMTO-01",
        "experiments.tmto_v3",
        "measure_tmto_v3",
        "online_queries",
    ),
    R15ExecutorBinding(
        "TMTO-02",
        "experiments.tmto_v3",
        "measure_tmto_v3",
        "online_queries",
    ),
    R15ExecutorBinding(
        "PARAM-01",
        "experiments.r15_endpoint_wrappers",
        "parameter_uniformity_profile_v3",
        "max_deviation",
    ),
    R15ExecutorBinding(
        "PARAM-02",
        "experiments.r15_parameter_analysis",
        "parameter_mutual_information_profile_v3",
        "mutual_information",
    ),
    R15ExecutorBinding(
        "PARAM-03",
        "experiments.r15_endpoint_wrappers",
        "parameter_grinding_work_ratio_v3",
        "net_work_ratio",
    ),
    R15ExecutorBinding(
        "PARAM-04",
        "experiments.r15_application_campaigns",
        "run_kdf_campaign_mode_v3",
        "work_per_guess",
    ),
    R15ExecutorBinding(
        "PARAM-05",
        "experiments.r15_application_campaigns",
        "profile_pow_nonce_selection_v3",
        "throughput_ratio",
    ),
    R15ExecutorBinding(
        "PARAM-06",
        "experiments.r15_application_campaigns",
        "mitigation_cost_profile_v3",
        "work_ratio",
    ),
    R15ExecutorBinding(
        "LAYOUT-04",
        "experiments.r15_layout_ablation",
        "profile_layout_ablation_three_way_v3",
        "plan_collision_rate",
    ),
    R15ExecutorBinding(
        "BRANCH-05",
        "experiments.branch_failures_v3",
        "profile_branch_failure_v3",
        "collision_pairs",
    ),
    R15ExecutorBinding(
        "BRANCH-06",
        "experiments.r15_branch_dependency",
        "profile_deep_vector_dependency_v3",
        "affected_branches",
    ),
    R15ExecutorBinding(
        "STAT-01",
        "experiments.r15_stat_adapters",
        "BATTERIES_V3",
        "adjusted_anomaly_rate",
    ),
)

R15_EXECUTOR_BINDINGS = MappingProxyType({item.attack_id: item for item in _BINDINGS})

if len(R15_EXECUTOR_BINDINGS) != len(_BINDINGS):
    raise RuntimeError("R15 executor bindings contain duplicate attack ids")


__all__ = ["R15_EXECUTOR_BINDINGS", "R15ExecutorBinding"]
