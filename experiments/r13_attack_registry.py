"""Declarative R13 attack registry for the Sigma v3 paper.

The registry fixes semantics before pilots/preregistration. It does not execute
attacks and contains no confirmatory results.
"""

from __future__ import annotations

from dataclasses import dataclass
from types import MappingProxyType
from typing import Literal

EvidenceClass = Literal["E1", "E2", "E3", "boundary", "open"]
Stage = Literal["reduced", "pilot", "confirmatory", "conditional"]

RESOURCE_FIELDS = ("W", "Q_A", "Q_J", "Q_H", "Q_R", "d", "p", "mu", "u")


@dataclass(frozen=True)
class AttackSpec:
    attack_id: str
    family: str
    stage: Stage
    claims: tuple[str, ...]
    evidence_class: EvidenceClass
    success_event: str
    metrics: tuple[str, ...]
    baselines: tuple[str, ...]
    resources: tuple[str, ...] = RESOURCE_FIELDS
    negative_result_meaning: str = "No success within the declared budget only."

    def __post_init__(self) -> None:
        if not self.attack_id or "-" not in self.attack_id:
            raise ValueError("attack_id must be a stable family-number identifier")
        if not self.family:
            raise ValueError("family must be non-empty")
        if not self.claims:
            raise ValueError("claims must be non-empty")
        if not self.success_event:
            raise ValueError("success_event must be non-empty")
        if not self.metrics:
            raise ValueError("metrics must be non-empty")
        if not self.baselines:
            raise ValueError("baselines must be non-empty")
        if set(self.resources) != set(RESOURCE_FIELDS):
            raise ValueError("every attack must publish the full R13 resource vector")
        if self.family == "STAT" and self.evidence_class == "E1":
            raise ValueError("statistical batteries cannot be theorem-level evidence")


def _a(
    attack_id: str,
    family: str,
    stage: Stage,
    claims: tuple[str, ...],
    evidence: EvidenceClass,
    success: str,
    metrics: tuple[str, ...],
    baselines: tuple[str, ...],
) -> AttackSpec:
    return AttackSpec(
        attack_id,
        family,
        stage,
        claims,
        evidence,
        success,
        metrics,
        baselines,
    )


ATTACKS = (
    _a(
        "HIST-01",
        "HIST",
        "reduced",
        ("C03", "C04", "C06"),
        "E2",
        "Find S_i=S'_i with H_i!=H'_i and measure whether later visible states coincide.",
        ("crossings", "next_state_matches", "run_length", "Q_H", "Q_R"),
        ("R12-fixed-binding", "R12.5-history"),
    ),
    _a(
        "HIST-02",
        "HIST",
        "reduced",
        ("C05", "C06"),
        "E2",
        "Find (H_i,S_i)=(H'_i,S'_i) for distinct candidates.",
        ("queries_to_first", "collision_pairs", "effective_exponent"),
        ("visible-state-only", "full-dynamic-state"),
    ),
    _a(
        "HIST-03",
        "HIST",
        "reduced",
        ("C04", "C05"),
        "E2",
        "Collision, 2-preimage, cycle or fixed point in reduced HistoryStep.",
        ("queries", "cycles", "tails", "collision_pairs"),
        ("ideal-random-map",),
    ),
    _a(
        "HIST-04",
        "HIST",
        "pilot",
        ("C02", "C03"),
        "E3",
        "Any stale/replayed/skipped/reordered history is silently accepted.",
        ("silent_acceptance", "first_rejection_layer"),
        ("canonical-history",),
    ),
    _a(
        "HIST-05",
        "HIST",
        "reduced",
        ("C04", "C05", "C06"),
        "E2",
        "Reduced history width changes the best collision/full-state attack scaling.",
        ("history_bits", "state_bits", "queries", "collision_pairs"),
        ("history-4", "history-8", "history-12"),
    ),
    _a(
        "HIST-06",
        "HIST",
        "pilot",
        ("C08", "C09"),
        "E3",
        "History-aware layout creates an unintended equivalence or weak placement class.",
        ("slot_distribution", "ties", "plan_collisions", "frame_collisions"),
        ("history-in-values-only", "history-in-layout-and-values"),
    ),
    _a(
        "RED-01",
        "REDUCED",
        "reduced",
        ("C04", "C05", "C06"),
        "E2",
        "Exhaustively enumerate images, preimages, collisions and functional components.",
        ("image_size", "preimage_histogram", "cycle_lengths", "tail_lengths"),
        ("simple-chain", "R12-fixed-binding", "R12.5-history"),
    ),
    _a(
        "RED-02",
        "REDUCED",
        "reduced",
        ("C06",),
        "E2",
        "Estimate collision exponent over geometric reduced widths.",
        ("Q50", "log2_Q50", "slope", "confidence_interval"),
        ("birthday-model", "R12", "R12.5"),
    ),
    _a(
        "RED-03",
        "REDUCED",
        "reduced",
        ("C06",),
        "E2",
        "Target-preimage success against a target fixed before attacker randomness.",
        ("queries", "success", "censoring"),
        ("uniform-random-map",),
    ),
    _a(
        "RED-04",
        "REDUCED",
        "reduced",
        ("C06",),
        "E2",
        "Second preimage for a fixed challenge message.",
        ("queries", "success", "same_P", "same_header", "first_divergence"),
        ("R12", "R12.5"),
    ),
    _a(
        "RED-05",
        "REDUCED",
        "reduced",
        ("C06",),
        "E2",
        "Win against any of u fixed targets.",
        ("targets", "queries", "success", "union_factor"),
        ("single-target",),
    ),
    _a(
        "RED-06",
        "REDUCED",
        "reduced",
        ("C01", "C03"),
        "E2",
        "Chosen-prefix or related-input structure lowers attack work.",
        ("prefix_class", "queries", "success"),
        ("unrelated-input",),
    ),
    _a(
        "RED-07",
        "REDUCED",
        "reduced",
        ("C04", "C06"),
        "E2",
        "Multicollision work is reusable across history-separated levels.",
        ("reused_work", "queries", "levels"),
        ("simple-chain", "R12.5"),
    ),
    _a(
        "RED-08",
        "REDUCED",
        "reduced",
        ("C04", "C06"),
        "E2",
        "Herding bridge can connect an adaptively chosen prefix to a committed target.",
        ("offline_work", "online_work", "memory", "success"),
        ("simple-chain", "R12.5"),
    ),
    _a(
        "RED-09",
        "REDUCED",
        "conditional",
        ("C06",),
        "open",
        "Expandable-message/long-message 2-preimage applies under comparable cardinality semantics.",
        ("queries", "message_length", "success"),
        ("long-message-hash",),
    ),
    _a(
        "TMTO-01",
        "TMTO",
        "reduced",
        ("C06",),
        "E2",
        "Pollard-rho or distinguished-point attack improves online work.",
        ("offline_work", "online_work", "memory", "speedup"),
        ("bruteforce",),
    ),
    _a(
        "TMTO-02",
        "TMTO",
        "reduced",
        ("C06",),
        "E2",
        "Hellman/rainbow precomputation amortizes across targets.",
        ("offline_work", "online_work", "memory", "targets"),
        ("no-precomputation",),
    ),
    _a(
        "TMTO-03",
        "TMTO",
        "pilot",
        ("C14",),
        "E3",
        "Tables indexed by (t,k) materially reduce online trajectory cost.",
        ("table_size", "hit_rate", "online_work"),
        ("unstratified-table",),
    ),
    _a(
        "PARAM-01",
        "PARAM",
        "reduced",
        ("C13",),
        "E2",
        "Rejection sampling deviates from uniformity in exhaustive small ranges.",
        ("counts", "chi_square", "max_deviation"),
        ("exact-uniform",),
    ),
    _a(
        "PARAM-02",
        "PARAM",
        "pilot",
        ("C13", "C14"),
        "E3",
        "(t,k) correlates with binding/history/layout observables.",
        ("mutual_information", "correlation", "stratum_counts"),
        ("permuted-control",),
    ),
    _a(
        "PARAM-03",
        "PARAM",
        "pilot",
        ("C14",),
        "E3",
        "Generate candidates until a cheap stratum yields positive net savings.",
        ("preparations", "selected_cost", "net_work", "speedup"),
        ("no-selection",),
    ),
    _a(
        "PARAM-04",
        "PARAM",
        "pilot",
        ("C15", "C16"),
        "E3",
        "Offline KDF guess can be rejected by public (t,k) before full Sigma trajectory.",
        ("guesses_per_second", "early_reject_rate", "work_per_guess"),
        ("Argon2id", "Argon2id+fixed-cost-Sigma", "Argon2id+derived-Sigma"),
    ),
    _a(
        "PARAM-05",
        "PARAM",
        "pilot",
        ("C17",),
        "E3",
        "Nonce selection finds lower-cost trajectories and changes effective PoW throughput.",
        ("nonces", "cost_distribution", "selected_cost", "throughput"),
        ("fixed-trajectory-PoW", "derived-trajectory-PoW"),
    ),
    _a(
        "PARAM-06",
        "PARAM",
        "pilot",
        ("C16", "C17"),
        "E3",
        "A mitigation removes grinding advantage without unacceptable cost.",
        ("speedup", "variance", "latency", "memory"),
        ("input-derived", "context-fixed", "cost-bucketed"),
    ),
    _a(
        "LAYOUT-04",
        "LAYOUT",
        "pilot",
        ("C08", "C09"),
        "E3",
        "History mutation fails to alter placement or exposes structured collisions.",
        ("changed_slots", "plan_collisions", "ties"),
        ("R12-layout", "R12.5-layout"),
    ),
    _a(
        "BRANCH-05",
        "BRANCH",
        "reduced",
        ("C10",),
        "E2",
        "Broken/truncated/constant fold invalidates claimed Deep property.",
        ("attack_success", "effective_width", "queries"),
        ("sound-fold", "constant-fold", "truncated-fold"),
    ),
    _a(
        "BRANCH-06",
        "BRANCH",
        "pilot",
        ("C11", "C12"),
        "E3",
        "Changing one vector component fails to affect a later branch input.",
        ("affected_branches", "hamming_distance", "first_divergence"),
        ("DeepVector",),
    ),
    _a(
        "FAULT-01",
        "FAULT",
        "pilot",
        ("C02", "C03", "C07"),
        "E3",
        "Injected state/history/index/branch fault is silently accepted.",
        ("detection_rate", "first_divergence", "silent_acceptance"),
        ("fault-free",),
    ),
    _a(
        "APP-SIG-01",
        "APP-SIG",
        "pilot",
        ("C18",),
        "E3",
        "Digest/key-id/suite substitution or replay verifies unexpectedly.",
        ("acceptance", "verification_mode"),
        ("attestation", "full-verification"),
    ),
    _a(
        "STAT-01",
        "STAT",
        "confirmatory",
        ("C12",),
        "E3",
        "External statistical battery detects a reproducible output anomaly.",
        ("p_values", "failures", "stream_bytes"),
        ("SHA512", "SHA3-512", "BLAKE2b-512", "SHAKE256", "broken-control"),
    ),
)

ATTACK_REGISTRY = MappingProxyType({attack.attack_id: attack for attack in ATTACKS})
if len(ATTACK_REGISTRY) != len(ATTACKS):
    raise RuntimeError("duplicate R13 attack identifier")


def get_attack(attack_id: str) -> AttackSpec:
    try:
        return ATTACK_REGISTRY[attack_id]
    except KeyError as exc:
        raise ValueError(f"unknown R13 attack: {attack_id}") from exc


__all__ = [
    "ATTACKS",
    "ATTACK_REGISTRY",
    "RESOURCE_FIELDS",
    "AttackSpec",
    "EvidenceClass",
    "Stage",
    "get_attack",
]
