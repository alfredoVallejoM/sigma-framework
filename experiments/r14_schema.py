"""R14/R15 canonical schemas and seed derivation."""

from __future__ import annotations

import hashlib
from dataclasses import asdict, dataclass
from typing import Any, Literal

from .r13_schema import RESOURCE_FIELDS, ResourceBudget
from .r14_protocol import CONFIRMATORY_NAMESPACE, FREEZE_ID, confirmatory_attack_ids

RunPhase = Literal["discovery", "holdout", "confirmatory"]
TerminalStatus = Literal["success", "no-success", "censored", "timeout", "error"]


@dataclass(frozen=True)
class ConfirmatoryConfigV3:
    schema: str
    campaign: str
    freeze_id: str
    attack_id: str
    seed_namespace: str
    execution_kind: str
    claims: tuple[str, ...]
    cells: tuple[dict[str, Any], ...]

    def __post_init__(self) -> None:
        if self.schema != "sigma-v3-r15-config-v1":
            raise ValueError("unexpected v3 confirmatory config schema")
        if self.campaign != "confirmatory-v3":
            raise ValueError("campaign must be confirmatory-v3")
        if self.freeze_id != FREEZE_ID:
            raise ValueError("unexpected R14 freeze_id")
        if self.attack_id not in confirmatory_attack_ids():
            raise ValueError("attack is not frozen for confirmatory execution")
        if self.seed_namespace != CONFIRMATORY_NAMESPACE:
            raise ValueError("confirmatory config uses wrong seed namespace")
        if self.execution_kind not in ("internal", "external"):
            raise ValueError("execution_kind must be internal or external")
        if not self.claims:
            raise ValueError("confirmatory config must bind claims")
        if not self.cells:
            raise ValueError("confirmatory config must contain cells")
        ids = []
        for cell in self.cells:
            validate_cell(cell)
            ids.append(str(cell["cell_id"]))
        if len(ids) != len(set(ids)):
            raise ValueError("duplicate cell_id")

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def validate_cell(cell: dict[str, Any]) -> None:
    required = {
        "cell_id",
        "factors",
        "budget",
        "replicates",
        "timeout_seconds",
        "stopping_rule",
        "censoring_rule",
        "analysis",
    }
    if not isinstance(cell, dict) or set(cell) != required:
        raise ValueError("invalid R14 cell fields")
    if not isinstance(cell["cell_id"], str) or not cell["cell_id"]:
        raise ValueError("invalid cell_id")
    if not isinstance(cell["factors"], dict) or not cell["factors"]:
        raise ValueError("cell factors must be non-empty")
    budget = cell["budget"]
    if not isinstance(budget, dict) or set(budget) != set(RESOURCE_FIELDS):
        raise ValueError("cell budget must contain full R13 resource vector")
    ResourceBudget(**budget)
    for key in ("replicates", "timeout_seconds"):
        value = cell[key]
        if isinstance(value, bool) or not isinstance(value, int) or value <= 0:
            raise ValueError(f"{key} must be positive int")
    for key in ("stopping_rule", "censoring_rule"):
        if not isinstance(cell[key], str) or not cell[key]:
            raise ValueError(f"{key} must be non-empty")
    analysis = cell["analysis"]
    expected_analysis = {
        "estimator",
        "interval",
        "multiplicity_family",
        "correction",
        "primary_metric",
        "secondary_metrics",
    }
    if not isinstance(analysis, dict) or set(analysis) != expected_analysis:
        raise ValueError("invalid analysis plan")
    if not isinstance(analysis["secondary_metrics"], (list, tuple)):
        raise ValueError("secondary_metrics must be a sequence")


def config_from_dict(data: dict[str, Any]) -> ConfirmatoryConfigV3:
    required = {
        "schema",
        "campaign",
        "freeze_id",
        "attack_id",
        "seed_namespace",
        "execution_kind",
        "claims",
        "cells",
    }
    if not isinstance(data, dict) or set(data) != required:
        raise ValueError("invalid v3 confirmatory config fields")
    return ConfirmatoryConfigV3(
        schema=data["schema"],
        campaign=data["campaign"],
        freeze_id=data["freeze_id"],
        attack_id=data["attack_id"],
        seed_namespace=data["seed_namespace"],
        execution_kind=data["execution_kind"],
        claims=tuple(data["claims"]),
        cells=tuple(data["cells"]),
    )


def derive_confirmatory_seed(
    attack_id: str,
    cell_id: str,
    replicate_id: int,
    *,
    freeze_id: str = FREEZE_ID,
) -> bytes:
    if attack_id not in confirmatory_attack_ids():
        raise ValueError("attack is not confirmatory")
    if not isinstance(cell_id, str) or not cell_id:
        raise ValueError("cell_id must be non-empty")
    if isinstance(replicate_id, bool) or not isinstance(replicate_id, int) or replicate_id < 0:
        raise ValueError("replicate_id must be a non-negative int")
    fields = (
        CONFIRMATORY_NAMESPACE.encode("ascii"),
        freeze_id.encode("ascii"),
        attack_id.encode("ascii"),
        cell_id.encode("ascii"),
        replicate_id.to_bytes(8, "big"),
    )
    framed = b"".join(len(field).to_bytes(4, "big") + field for field in fields)
    return hashlib.sha256(framed).digest()


@dataclass(frozen=True)
class ConfirmatoryRecordV3:
    schema: str
    campaign_id: str
    freeze_id: str
    attack_id: str
    claim_ids: tuple[str, ...]
    construction: str
    cell_id: str
    replicate_id: int
    seed_hex: str
    phase: RunPhase
    declared: ResourceBudget
    observed: ResourceBudget
    status: TerminalStatus
    metrics: dict[str, int | float | str | bool | None]
    censor_reason: str | None
    error_class: str | None
    code_commit: str
    artifact_sha256: str
    config_sha256: str
    preregistration_sha256: str
    host_id: str

    def __post_init__(self) -> None:
        if self.schema != "sigma-v3-r15-record-v1":
            raise ValueError("unexpected confirmatory record schema")
        if self.freeze_id != FREEZE_ID:
            raise ValueError("record freeze_id mismatch")
        if self.attack_id not in confirmatory_attack_ids():
            raise ValueError("record attack is not confirmatory")
        if self.phase != "confirmatory":
            raise ValueError("R15 record must be confirmatory")
        if self.observed.W > self.declared.W:
            raise ValueError("observed work exceeds budget")
        for field in RESOURCE_FIELDS:
            if getattr(self.observed, field) > getattr(self.declared, field):
                raise ValueError("observed resources exceed declared budget")
        expected_seed = derive_confirmatory_seed(
            self.attack_id, self.cell_id, self.replicate_id
        ).hex()
        if self.seed_hex != expected_seed:
            raise ValueError("record seed is not the frozen deterministic seed")
        if self.status == "censored" and not self.censor_reason:
            raise ValueError("censored result requires reason")
        if self.status == "error" and not self.error_class:
            raise ValueError("error result requires error_class")
        for value in (
            self.code_commit,
            self.artifact_sha256,
            self.config_sha256,
            self.preregistration_sha256,
        ):
            if len(value) != 64 or any(ch not in "0123456789abcdef" for ch in value):
                raise ValueError("integrity identifiers must be lowercase SHA-256 hex")


__all__ = [
    "ConfirmatoryConfigV3",
    "ConfirmatoryRecordV3",
    "RunPhase",
    "TerminalStatus",
    "config_from_dict",
    "derive_confirmatory_seed",
    "validate_cell",
]
