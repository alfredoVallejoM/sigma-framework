"""Closed R13 attacker/claim registry.

The registry is metadata for experiment design. It is deliberately independent
from product code and from confirmatory data collection.
"""

from __future__ import annotations

from dataclasses import dataclass
from types import MappingProxyType


@dataclass(frozen=True)
class AttackSpecV3:
    attack_id: str
    family: str
    claims: tuple[str, ...]
    baselines: tuple[str, ...]
    resources: tuple[str, ...]
    success: str
    censoring: str
    output_fields: tuple[str, ...]
    confirmatory_eligible: bool = True

    def __post_init__(self) -> None:
        for name in ("attack_id", "family", "success", "censoring"):
            value = getattr(self, name)
            if not isinstance(value, str) or not value:
                raise ValueError(f"{name} must be non-empty")
        for name in ("claims", "baselines", "resources", "output_fields"):
            value = getattr(self, name)
            if not isinstance(value, tuple) or not value:
                raise ValueError(f"{name} must be a non-empty tuple")
            if any(not isinstance(item, str) or not item for item in value):
                raise ValueError(f"{name} entries must be non-empty strings")


_SPECS = (
    AttackSpecV3(
        "HIST-01",
        "history",
        ("C03", "C04"),
        ("r12", "r12.5"),
        ("W", "Q_H", "Q_R", "d", "mu"),
        "equal visible S_i with distinct H_i, then measure successor equality",
        "candidate budget exhausted before a crossing is found",
        (
            "state_bits",
            "history_bits",
            "round_index",
            "queries",
            "crossing_found",
            "next_state_equal",
            "next_full_state_equal",
        ),
    ),
    AttackSpecV3(
        "HIST-02",
        "history",
        ("C05", "C06"),
        ("r12.5",),
        ("W", "Q_H", "Q_R", "d", "mu"),
        "find a collision in the complete reduced state (H_i,S_i)",
        "candidate budget exhausted",
        (
            "state_bits",
            "history_bits",
            "round_index",
            "queries",
            "collision_found",
        ),
    ),
    AttackSpecV3(
        "HIST-03",
        "history",
        ("C02", "C04", "C06"),
        ("history-step",),
        ("W", "Q_H", "mu"),
        "collision or second-preimage in reduced HistoryStep",
        "history-input budget exhausted",
        ("history_bits", "queries", "attack", "success"),
    ),
    AttackSpecV3(
        "HIST-04",
        "history",
        ("C02", "C03"),
        ("canonical-history",),
        ("W", "Q_H", "Q_R"),
        "accept stale/replayed/skipped/reordered history",
        "all malformed causal transitions rejected",
        ("case", "accepted", "round_index"),
        confirmatory_eligible=False,
    ),
    AttackSpecV3(
        "HIST-05",
        "history",
        ("C04", "C06"),
        ("r12", "r12.5"),
        ("W", "Q_H", "Q_R", "mu"),
        "measure image/collision scaling as history width changes",
        "configured width exceeds exhaustive bound",
        ("history_bits", "visible_pairs", "full_pairs", "inputs"),
    ),
    AttackSpecV3(
        "HIST-06",
        "history",
        ("C08", "C09"),
        ("fixed-layout", "history-layout"),
        ("W", "Q_H", "mu"),
        "measure layout-signature reuse across distinct histories",
        "history enumeration bound exhausted",
        ("history_bits", "slots", "fixed_unique", "adaptive_unique"),
    ),
    AttackSpecV3(
        "PARAM-01",
        "parameters",
        ("C13",),
        ("ideal-uniform",),
        ("W",),
        "enumerate/simulate derived (t,k) frequencies",
        "candidate budget exhausted",
        ("samples", "pair", "count", "expected_probability"),
    ),
    AttackSpecV3(
        "PARAM-02",
        "parameters",
        ("C13", "C14"),
        ("derived-parameters",),
        ("W", "Q_A", "Q_J"),
        "measure correlations of t,k with candidate and reduced persistent binding",
        "sample budget exhausted",
        ("samples", "candidate_t", "candidate_k", "persistent_t", "persistent_k"),
    ),
    AttackSpecV3(
        "PARAM-03",
        "parameters",
        ("C14",),
        ("unfiltered", "cheapest-stratum"),
        ("W", "Q_A", "Q_J"),
        "find a candidate in the minimum-cost trajectory stratum",
        "candidate budget exhausted",
        ("attempts", "t", "k", "transition_cost"),
    ),
    AttackSpecV3(
        "PARAM-04",
        "applications",
        ("C15", "C16"),
        ("argon2id", "argon2id+sigma"),
        ("W", "Q_A", "Q_J", "Q_R"),
        "reject wrong guesses from public (t,k) before full Sigma evaluation",
        "guess budget exhausted",
        ("guesses", "early_rejected", "full_trajectory_guesses", "round_queries_saved"),
    ),
    AttackSpecV3(
        "PARAM-05",
        "applications",
        ("C17",),
        ("unfiltered-nonce", "cost-filtered-nonce"),
        ("W", "Q_A", "Q_J", "Q_R", "p"),
        "select nonces with lower derived trajectory cost",
        "nonce budget exhausted",
        ("nonces", "best_t", "best_k", "best_cost", "mean_cost"),
    ),
    AttackSpecV3(
        "PARAM-06",
        "parameters",
        ("C14", "C16", "C17"),
        ("derived-cost", "fixed-cost"),
        ("W", "Q_A", "Q_J", "Q_R"),
        "compare derived-cost variance with fixed public trajectory parameters",
        "sample budget exhausted",
        (
            "samples",
            "derived_mean_cost",
            "derived_variance",
            "derived_min_cost",
            "derived_max_cost",
            "fixed_cost",
            "fixed_variance",
        ),
    ),
    AttackSpecV3(
        "RED-02",
        "reduced",
        ("C06",),
        ("r12", "r12.5"),
        ("W", "Q_H", "Q_R", "d", "mu"),
        "measure candidates to first reduced window collision across widths",
        "max candidate budget reached without collision",
        (
            "state_bits",
            "history_bits",
            "construction",
            "candidates_to_first_window_collision",
            "censored",
            "max_candidates",
        ),
    ),
    AttackSpecV3(
        "RED-03",
        "reduced",
        ("C06",),
        ("r12.5",),
        ("W", "Q_H", "Q_R"),
        "find a preimage for an externally fixed reduced target window",
        "candidate budget exhausted",
        ("evaluated_candidates", "success", "candidate"),
    ),
    AttackSpecV3(
        "RED-04",
        "reduced",
        ("C04", "C06"),
        ("same-persistent", "any-persistent"),
        ("W", "Q_A", "Q_J", "Q_H", "Q_R"),
        "find a second preimage of a fixed reduced target window",
        "candidate budget exhausted",
        (
            "target_candidate",
            "candidate",
            "persistent_equal",
            "evaluated_candidates",
        ),
    ),
    AttackSpecV3(
        "RED-05",
        "reduced",
        ("C06",),
        ("single-target", "multi-target"),
        ("W", "Q_H", "Q_R", "u"),
        "hit any of u fixed reduced target windows",
        "search budget exhausted",
        ("targets", "search_candidates", "evaluated", "success"),
    ),
    AttackSpecV3(
        "TMTO-01",
        "tmto",
        ("C04", "C06"),
        ("r12", "r12.5"),
        ("W", "Q_H", "Q_R", "d", "mu", "u"),
        "reuse offline table/path work across persistent/history contexts",
        "online target budget exhausted",
        (
            "strategy",
            "construction",
            "offline_queries",
            "online_queries",
            "memory_entries",
            "reuse_rate",
        ),
    ),
    AttackSpecV3(
        "BRANCH-01",
        "branch",
        ("C10", "C11", "C12"),
        ("deep", "deep-vector"),
        ("W", "Q_R", "mu"),
        "measure output collapse under broken/correlated branch or fold controls",
        "candidate budget exhausted",
        ("mode", "fault", "inputs", "image_size", "collision_pairs"),
    ),
)

ATTACK_REGISTRY_V3 = MappingProxyType({spec.attack_id: spec for spec in _SPECS})


def get_attack_spec_v3(attack_id: str) -> AttackSpecV3:
    try:
        return ATTACK_REGISTRY_V3[attack_id]
    except KeyError as exc:
        raise ValueError(f"unknown R13 attack: {attack_id}") from exc


__all__ = ["ATTACK_REGISTRY_V3", "AttackSpecV3", "get_attack_spec_v3"]
