"""Frozen R14 protocol design for the Sigma v3 confirmatory campaign.

This module contains no observed confirmatory data. It fixes campaign
dispositions, cells, budgets, sample sizes and analysis choices before R15.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass
from typing import Literal

from .r13_attack_registry import ATTACK_REGISTRY
from .r13_schema import ResourceBudget

R12_5_BASELINE = "5ac306bb23acae0e0a4ef03eb56b3062343c2127"
R13_BASELINE = "8a71de3d350ea8215c481e16c9eadbeed54066ef"
FREEZE_ID = "sigma-v3-r14-20260920-v1"
DISCOVERY_NAMESPACE = "sigma-v3-r14-discovery"
CONFIRMATORY_NAMESPACE = "sigma-v3-r15"

Disposition = Literal[
    "confirmatory",
    "reduced-only",
    "conditional",
    "boundary",
    "out-of-scope",
]
ExecutionKind = Literal["internal", "external"]
ClaimPriority = Literal["primary", "secondary", "boundary"]


@dataclass(frozen=True)
class ClaimDisposition:
    claim_id: str
    disposition: Disposition
    priority: ClaimPriority
    attacks: tuple[str, ...]
    rationale: str

    def __post_init__(self) -> None:
        if not self.claim_id.startswith("C"):
            raise ValueError("claim_id must be a Cxx identifier")
        if not self.attacks:
            raise ValueError("claim disposition must name at least one attack/evidence source")
        if not self.rationale:
            raise ValueError("claim disposition requires rationale")


@dataclass(frozen=True)
class AttackDisposition:
    attack_id: str
    disposition: Disposition
    execution: ExecutionKind
    rationale: str

    def __post_init__(self) -> None:
        if self.attack_id not in ATTACK_REGISTRY:
            raise ValueError(f"unknown R13 attack: {self.attack_id}")
        if not self.rationale:
            raise ValueError("attack disposition requires rationale")


@dataclass(frozen=True)
class AnalysisPlan:
    estimator: str
    interval: str
    multiplicity_family: str
    correction: str
    primary_metric: str
    secondary_metrics: tuple[str, ...]

    def __post_init__(self) -> None:
        for name in (
            "estimator",
            "interval",
            "multiplicity_family",
            "correction",
            "primary_metric",
        ):
            if not getattr(self, name):
                raise ValueError(f"{name} must be non-empty")


@dataclass(frozen=True)
class CellSpec:
    cell_id: str
    factors: dict[str, int | float | str | bool]
    budget: ResourceBudget
    replicates: int
    timeout_seconds: int
    stopping_rule: str
    censoring_rule: str
    analysis: AnalysisPlan

    def __post_init__(self) -> None:
        if not self.cell_id or "/" in self.cell_id or "\\" in self.cell_id:
            raise ValueError("cell_id must be a portable path-free identifier")
        if not isinstance(self.factors, dict) or not self.factors:
            raise ValueError("factors must be a non-empty dict")
        if not isinstance(self.budget, ResourceBudget):
            raise TypeError("budget must be ResourceBudget")
        if self.replicates <= 0:
            raise ValueError("replicates must be positive")
        if self.timeout_seconds <= 0:
            raise ValueError("timeout_seconds must be positive")
        if not self.stopping_rule or not self.censoring_rule:
            raise ValueError("stopping and censoring rules must be explicit")


# fmt: off
CLAIMS: tuple[ClaimDisposition, ...] = (
    ClaimDisposition("C01", "reduced-only", "secondary", ("G-CONFORM",), "Canonicality is E1+engineering evidence; no new confirmatory hardness claim."),
    ClaimDisposition("C02", "reduced-only", "secondary", ("HIST-04",), "Causal prefix semantics are proved and exercised by R12.5 adversarial tests."),
    ClaimDisposition("C03", "reduced-only", "secondary", ("HIST-01",), "Frame separation is an encoding theorem; HIST-01 supplies mechanism evidence."),
    ClaimDisposition("C04", "confirmatory", "primary", ("HIST-01", "HIST-05", "TMTO-01"), "Central claim: visible state equality need not coalesce distinct histories."),
    ClaimDisposition("C05", "confirmatory", "primary", ("HIST-02", "HIST-03"), "Full dynamic-state collision is the correct coalescence target."),
    ClaimDisposition("C06", "confirmatory", "primary", ("RED-02", "RED-03", "RED-04", "RED-05", "TMTO-01", "TMTO-02"), "Window/security scaling requires direct reduced attack evidence."),
    ClaimDisposition("C07", "reduced-only", "secondary", ("G-CONFORM",), "Backend/I-O equality already belongs to the R12.5 conformance gate."),
    ClaimDisposition("C08", "confirmatory", "secondary", ("HIST-06", "LAYOUT-04"), "History-adaptive placement receives a direct ablation."),
    ClaimDisposition("C09", "confirmatory", "secondary", ("HIST-06", "LAYOUT-04"), "Layout collisions must not erase serialized history separation."),
    ClaimDisposition("C10", "confirmatory", "primary", ("BRANCH-05",), "Deep security is bottlenecked by fold/composition and needs broken-fold controls."),
    ClaimDisposition("C11", "confirmatory", "primary", ("BRANCH-06",), "DeepVector must preserve full-vector dependence."),
    ClaimDisposition("C12", "confirmatory", "secondary", ("BRANCH-06", "STAT-01"), "No additive branch strength is assumed; controls look for correlation/anomaly."),
    ClaimDisposition("C13", "confirmatory", "secondary", ("PARAM-01", "PARAM-02"), "Parameter uniformity/correlation are empirical instantiation questions."),
    ClaimDisposition("C14", "confirmatory", "primary", ("PARAM-03", "TMTO-02"), "Grinding/precomputation can alter effective cost despite unbiased sampling."),
    ClaimDisposition("C15", "boundary", "boundary", ("PARAM-04",), "Sigma is not credited with entropy or memory-hardness; this is a claim boundary."),
    ClaimDisposition("C16", "confirmatory", "primary", ("PARAM-04", "PARAM-06"), "KDF early rejection can reduce Sigma work per wrong guess."),
    ClaimDisposition("C17", "confirmatory", "primary", ("PARAM-05", "PARAM-06"), "Nonce selection can bias PoW trajectory cost."),
    ClaimDisposition("C18", "reduced-only", "secondary", ("APP-SIG-01",), "Signature semantics are application/conformance evidence, not a new signature theorem."),
    ClaimDisposition("C19", "boundary", "boundary", ("SIDE",), "Python constant-time is explicitly not claimed."),
    ClaimDisposition("C20", "boundary", "boundary", ("HW",), "ASIC/GPU/VDF/PoSW properties are explicitly not claimed."),
)

ATTACK_DISPOSITIONS: tuple[AttackDisposition, ...] = (
    AttackDisposition("HIST-01", "confirmatory", "internal", "Central state-crossing experiment."),
    AttackDisposition("HIST-02", "confirmatory", "internal", "Central full-state collision experiment."),
    AttackDisposition("HIST-03", "confirmatory", "internal", "Direct reduced HistoryStep analysis."),
    AttackDisposition("HIST-04", "reduced-only", "internal", "Covered as adversarial conformance; no separate R15 statistical claim."),
    AttackDisposition("HIST-05", "confirmatory", "internal", "History-width ablation identifies bottlenecks."),
    AttackDisposition("HIST-06", "confirmatory", "internal", "Layout/history ablation."),
    AttackDisposition("RED-01", "reduced-only", "internal", "Exhaustive maps are design/reference evidence; RED-02..05 are primary quantitative tests."),
    AttackDisposition("RED-02", "confirmatory", "internal", "Primary collision scaling."),
    AttackDisposition("RED-03", "confirmatory", "internal", "Primary target-preimage family."),
    AttackDisposition("RED-04", "confirmatory", "internal", "Primary second-preimage family."),
    AttackDisposition("RED-05", "confirmatory", "internal", "Primary multi-target family."),
    AttackDisposition("RED-06", "conditional", "internal", "No frozen tested attacker in R13; remains future work."),
    AttackDisposition("RED-07", "conditional", "internal", "No frozen tested multicollision harness in R13."),
    AttackDisposition("RED-08", "conditional", "internal", "No frozen tested herding harness in R13."),
    AttackDisposition("RED-09", "conditional", "internal", "Cardinality comparability is not established."),
    AttackDisposition("TMTO-01", "confirmatory", "internal", "Direct/distinguished/rho frontier."),
    AttackDisposition("TMTO-02", "confirmatory", "internal", "Hellman/rainbow multi-target frontier."),
    AttackDisposition("TMTO-03", "conditional", "internal", "Stratum-indexed table design was not closed in R13."),
    AttackDisposition("PARAM-01", "confirmatory", "internal", "Joint (t,k) distribution."),
    AttackDisposition("PARAM-02", "confirmatory", "internal", "Correlation/permutation controls."),
    AttackDisposition("PARAM-03", "confirmatory", "internal", "Cheapest-stratum grinding."),
    AttackDisposition("PARAM-04", "confirmatory", "internal", "KDF early-rejection cost."),
    AttackDisposition("PARAM-05", "confirmatory", "internal", "PoW nonce-cost grinding."),
    AttackDisposition("PARAM-06", "confirmatory", "internal", "Frozen mitigation comparison."),
    AttackDisposition("LAYOUT-04", "confirmatory", "internal", "History-aware placement control."),
    AttackDisposition("BRANCH-05", "confirmatory", "internal", "Deep fold bottleneck controls."),
    AttackDisposition("BRANCH-06", "confirmatory", "internal", "DeepVector dependency controls."),
    AttackDisposition("FAULT-01", "reduced-only", "internal", "Engineering/adversarial safety, not a statistical hardness claim."),
    AttackDisposition("APP-SIG-01", "reduced-only", "internal", "Application conformance boundary."),
    AttackDisposition("STAT-01", "confirmatory", "external", "Secondary descriptive batteries only."),
)

if {item.attack_id for item in ATTACK_DISPOSITIONS} != set(ATTACK_REGISTRY):
    raise RuntimeError("R14 dispositions must cover every R13 attack exactly once")
if {item.claim_id for item in CLAIMS} != {f"C{index:02d}" for index in range(1, 21)}:
    raise RuntimeError("R14 claim dispositions must cover C01..C20 exactly once")


def _budget(work: int, *, qh: int = 0, qr: int = 0, qa: int = 0, qj: int = 0, mu: int = 0, u: int = 1) -> ResourceBudget:
    return ResourceBudget(work, qa, qj, qh, qr, max(1, qr), 1, mu, u)


def _analysis(
    primary: str,
    *,
    estimator: str,
    interval: str,
    family: str,
    correction: str = "Holm",
    secondary: tuple[str, ...] = (),
) -> AnalysisPlan:
    return AnalysisPlan(estimator, interval, family, correction, primary, secondary)


def _cell(
    attack: str,
    index: int,
    factors: dict[str, int | float | str | bool],
    budget: ResourceBudget,
    replicates: int,
    timeout: int,
    analysis: AnalysisPlan,
    *,
    stopping: str = "first-success-or-budget",
    censoring: str = "right-censor at declared budget; timeout/error separate",
) -> CellSpec:
    return CellSpec(
        f"{attack.lower()}-{index:03d}",
        factors,
        budget,
        replicates,
        timeout,
        stopping,
        censoring,
        analysis,
    )


def confirmatory_cells(attack_id: str) -> tuple[CellSpec, ...]:
    disposition = next(item for item in ATTACK_DISPOSITIONS if item.attack_id == attack_id)
    if disposition.disposition != "confirmatory":
        raise ValueError(f"{attack_id} is not a confirmatory R14 attack")

    cells: list[CellSpec] = []
    if attack_id == "HIST-01":
        analysis = _analysis("next_state_match_rate", estimator="exact-binomial", interval="Clopper-Pearson 95%", family="history-crossing")
        index = 0
        for bits in (8, 12, 16):
            for round_index in (1, 2):
                work = 1 << min(20, bits + 3)
                cells.append(_cell(attack_id, index, {"state_bits": bits, "history_bits": bits, "round_index": round_index, "candidate_budget": work}, _budget(work, qa=work, qh=work * 2, qr=work * 2, mu=work), 256, 3600, analysis, stopping="collect-crossings-until-target-or-budget"))
                index += 1
    elif attack_id == "HIST-02":
        analysis = _analysis("queries_to_first_full_state_collision", estimator="Kaplan-Meier median/RMST", interval="bootstrap 95%", family="full-state-collision")
        for index, bits in enumerate((6, 8, 10, 12)):
            work = 1 << min(20, bits + 4)
            cells.append(_cell(attack_id, index, {"state_bits": bits, "history_bits": bits, "round_index": 1, "candidate_budget": work}, _budget(work, qa=work, qh=work, qr=work, mu=work), 128, 3600, analysis))
    elif attack_id == "HIST-03":
        analysis = _analysis("queries", estimator="first-hit/exhaustive-map", interval="exact or right-censored 95%", family="history-step")
        index = 0
        for bits in (6, 8, 10, 12):
            for game in ("collision", "second-preimage", "fixed-point", "cycle"):
                work = 1 << min(20, bits + 3)
                cells.append(_cell(attack_id, index, {"history_bits": bits, "game": game, "input_budget": work}, _budget(work, qh=work, mu=min(work, 1 << 18)), 128, 3600, analysis))
                index += 1
    elif attack_id == "HIST-05":
        analysis = _analysis("full_collision_pairs", estimator="width-scaling regression", interval="bootstrap slope 95%", family="history-truncation")
        for index, bits in enumerate((4, 6, 8, 10, 12)):
            work = 1 << bits
            cells.append(_cell(attack_id, index, {"state_bits": 8, "history_bits": bits, "round_index": 0}, _budget(work, qh=work, qr=work, mu=work), 128, 1800, analysis, stopping="exhaustive-history-map"))
    elif attack_id in ("HIST-06", "LAYOUT-04"):
        analysis = _analysis("plan_collision_rate", estimator="exact proportion + occupancy", interval="bootstrap 95%", family="layout-history")
        index = 0
        for bits in (8, 10, 12):
            for slots in (17, 65):
                work = 1 << bits
                cells.append(_cell(attack_id, index, {"history_bits": bits, "field_count": 5, "slots": slots, "variants": "fixed,values-only,adaptive"}, _budget(work, qh=work, mu=work), 128, 1800, analysis, stopping="exhaustive-history-enumeration"))
                index += 1
    elif attack_id == "RED-02":
        analysis = _analysis("queries_to_first_window_collision", estimator="Kaplan-Meier Q50 + log2 slope", interval="bootstrap slope 95%", family="collision-scaling")
        index = 0
        for construction in ("r12", "r125"):
            for bits in (6, 8, 10, 12, 14, 16):
                for state_count in (1, 2, 3):
                    work = 1 << min(22, max(10, (bits * state_count) // 2 + 6))
                    cells.append(_cell(attack_id, index, {"construction": construction, "state_bits": bits, "history_bits": bits, "state_count": state_count, "target_round": 2, "max_candidates": work}, _budget(work, qa=work, qh=work if construction == "r125" else 0, qr=work, mu=work), 128, 7200, analysis))
                    index += 1
    elif attack_id in ("RED-03", "RED-04"):
        family = "preimage" if attack_id == "RED-03" else "second-preimage"
        analysis = _analysis("queries", estimator="Kaplan-Meier median/RMST", interval="bootstrap 95%", family=family)
        index = 0
        policies = ("fixed-target",) if attack_id == "RED-03" else ("same-persistent", "any-persistent")
        for construction in ("r12", "r125"):
            for bits in (6, 8, 10, 12):
                for policy in policies:
                    work = 1 << min(20, bits + 5)
                    cells.append(_cell(attack_id, index, {"construction": construction, "state_bits": bits, "history_bits": bits, "state_count": 2, "target_round": 2, "policy": policy, "max_candidates": work}, _budget(work, qa=work, qh=work if construction == "r125" else 0, qr=work), 128, 7200, analysis))
                    index += 1
    elif attack_id == "RED-05":
        analysis = _analysis("queries", estimator="Kaplan-Meier by target count", interval="bootstrap 95%", family="multi-target")
        index = 0
        for construction in ("r12", "r125"):
            for bits in (8, 10, 12):
                for targets in (1, 4, 16, 64):
                    work = 1 << min(20, bits + 5)
                    cells.append(_cell(attack_id, index, {"construction": construction, "state_bits": bits, "history_bits": bits, "targets": targets, "state_count": 2, "max_candidates": work}, _budget(work, qa=work, qh=work if construction == "r125" else 0, qr=work, u=targets), 128, 7200, analysis))
                    index += 1
    elif attack_id in ("TMTO-01", "TMTO-02"):
        analysis = _analysis("online_queries", estimator="Pareto frontier", interval="bootstrap 95% by cell", family="tmto", correction="none", secondary=("offline_queries", "memory_entries", "reuse_rate"))
        strategies = ("direct", "distinguished", "rho") if attack_id == "TMTO-01" else ("hellman", "rainbow")
        index = 0
        for construction in ("r12", "r125"):
            for bits in (8, 12, 16):
                for strategy in strategies:
                    entries = 1024
                    chain = 64
                    work = entries * chain * 9
                    cells.append(_cell(attack_id, index, {"construction": construction, "state_bits": bits, "history_bits": bits, "strategy": strategy, "entries": entries, "chain_length": chain, "distinguished_bits": 4, "targets": 8}, _budget(work, qh=work if construction == "r125" else 0, qr=work, mu=entries, u=8), 64, 7200, analysis, stopping="fixed-offline-and-online-budget"))
                    index += 1
    elif attack_id == "PARAM-01":
        analysis = _analysis("max_deviation", estimator="joint GOF; Monte-Carlo exact fallback", interval="simultaneous 95%", family="parameter-uniformity")
        cells.append(_cell(attack_id, 0, {"samples": 93000, "t_min": 2, "t_max": 32, "k_min": 2, "k_max": 4}, _budget(93000, qa=93000, qj=93000), 32, 3600, analysis, stopping="fixed-sample"))
    elif attack_id == "PARAM-02":
        analysis = _analysis("mutual_information", estimator="permutation-controlled MI/correlation", interval="permutation 95%", family="parameter-correlation")
        cells.append(_cell(attack_id, 0, {"samples": 16384, "permutations": 2000}, _budget(16384, qa=16384, qj=16384), 64, 3600, analysis, stopping="fixed-sample"))
    elif attack_id == "PARAM-03":
        analysis = _analysis("net_work_ratio", estimator="paired ratio", interval="paired bootstrap 95%", family="parameter-grinding")
        for index, candidates in enumerate((93, 930, 9300)):
            cells.append(_cell(attack_id, index, {"candidate_budget": candidates, "cost": "t+k-1"}, _budget(candidates * 4, qa=candidates, qj=candidates), 128, 3600, analysis, stopping="minimum-cost-stratum-or-budget"))
    elif attack_id == "PARAM-04":
        analysis = _analysis("work_per_guess", estimator="paired fixed-vs-derived ratio", interval="paired bootstrap 95%", family="kdf")
        cells.append(_cell(attack_id, 0, {"guesses": 4096, "argon_memory_kib": 19456, "argon_time_cost": 2, "modes": "argon2id,fixed-sigma,derived-sigma"}, _budget(4096 * 64, qa=4096, qj=4096, qr=4096 * 32, mu=19456 * 1024), 64, 14400, analysis, stopping="fixed-guess-budget"))
    elif attack_id == "PARAM-05":
        analysis = _analysis("throughput_ratio", estimator="paired nonce-cost ratio", interval="paired bootstrap 95%", family="pow")
        for index, nonces in enumerate((4096, 16384)):
            cells.append(_cell(attack_id, index, {"nonces": nonces, "modes": "fixed-trajectory,derived-trajectory"}, _budget(nonces * 64, qa=nonces, qj=nonces, qr=nonces * 32), 64, 7200, analysis, stopping="fixed-nonce-budget"))
    elif attack_id == "PARAM-06":
        analysis = _analysis("work_ratio", estimator="paired mitigation comparison", interval="paired bootstrap 95%", family="mitigation")
        for index, mode in enumerate(("input-derived", "context-fixed", "cost-bucketed")):
            cells.append(_cell(attack_id, index, {"mode": mode, "samples": 4096}, _budget(4096 * 64, qa=4096, qj=4096, qr=4096 * 32), 64, 7200, analysis, stopping="fixed-sample"))
    elif attack_id == "BRANCH-05":
        analysis = _analysis("collision_pairs", estimator="image/collision profile", interval="bootstrap 95%", family="deep-fold")
        faults = ("normal", "constant-first", "copied-first-two", "truncated-first", "omitted-last", "permuted", "constant-fold", "truncated-fold")
        for index, fault in enumerate(faults):
            cells.append(_cell(attack_id, index, {"mode": "deep", "fault": fault, "state_bits": 8, "branch_count": 4, "candidates": 65536}, _budget(65536, qr=65536, mu=65536), 64, 3600, analysis, stopping="fixed-candidate-budget"))
    elif attack_id == "BRANCH-06":
        analysis = _analysis("affected_branches", estimator="dependency coverage", interval="simultaneous 95%", family="deep-vector")
        faults = ("normal", "constant-first", "copied-first-two", "truncated-first", "omitted-last", "permuted")
        for index, fault in enumerate(faults):
            cells.append(_cell(attack_id, index, {"mode": "deep-vector", "fault": fault, "state_bits": 8, "branch_count": 4, "candidates": 65536}, _budget(65536, qr=65536, mu=65536), 64, 3600, analysis, stopping="fixed-candidate-budget"))
    elif attack_id == "STAT-01":
        analysis = _analysis("adjusted_anomaly_rate", estimator="external battery family summary", interval="descriptive calibrated intervals", family="statistical-controls", correction="Holm primary / BH exploratory", secondary=("p_value_distribution", "stream_bytes"))
        index = 0
        for construction in ("SHA512", "SHA3-512", "BLAKE2b-512", "SHAKE256-512", "R12.5-wide", "R12.5-deep", "R12.5-vector", "broken-control"):
            for corpus in ("counter", "ff-tail", "alternating"):
                cells.append(_cell(attack_id, index, {"construction": construction, "corpus": corpus, "streams": 32, "aggregate_bytes": 1 << 30, "batteries": "NIST-STS,PractRand,TestU01-SmallCrush,TestU01-Crush"}, _budget(1 << 30, mu=1 << 26), 1, 28800, analysis, stopping="complete-declared-external-batteries", censoring="unavailable tests reported as not-applicable, never omitted"))
                index += 1
    else:
        raise ValueError(f"no R14 confirmatory cell design for {attack_id}")
    return tuple(cells)


def confirmatory_attack_ids() -> tuple[str, ...]:
    return tuple(
        item.attack_id
        for item in ATTACK_DISPOSITIONS
        if item.disposition == "confirmatory"
    )


def protocol_summary() -> dict[str, object]:
    attacks = confirmatory_attack_ids()
    return {
        "freeze_id": FREEZE_ID,
        "r12_5_baseline": R12_5_BASELINE,
        "r13_baseline": R13_BASELINE,
        "discovery_namespace": DISCOVERY_NAMESPACE,
        "confirmatory_namespace": CONFIRMATORY_NAMESPACE,
        "claims": [asdict(item) for item in CLAIMS],
        "attacks": [asdict(item) for item in ATTACK_DISPOSITIONS],
        "confirmatory": {
            attack_id: [asdict(cell) for cell in confirmatory_cells(attack_id)]
            for attack_id in attacks
        },
    }


# fmt: on

__all__ = [
    "ATTACK_DISPOSITIONS",
    "CLAIMS",
    "CONFIRMATORY_NAMESPACE",
    "DISCOVERY_NAMESPACE",
    "FREEZE_ID",
    "R12_5_BASELINE",
    "R13_BASELINE",
    "AnalysisPlan",
    "AttackDisposition",
    "CellSpec",
    "ClaimDisposition",
    "confirmatory_attack_ids",
    "confirmatory_cells",
    "protocol_summary",
]
