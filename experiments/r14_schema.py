"""R14/R15 canonical schemas, seed derivation and record integrity."""

from __future__ import annotations

import hashlib
import json
from dataclasses import asdict, dataclass
from datetime import datetime
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
        if not self.claims or any(
            not isinstance(claim, str) or not claim.startswith("C") for claim in self.claims
        ):
            raise ValueError("confirmatory config must bind claim identifiers")
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
    for key in (
        "estimator",
        "interval",
        "multiplicity_family",
        "correction",
        "primary_metric",
    ):
        if not isinstance(analysis[key], str) or not analysis[key]:
            raise ValueError(f"analysis {key} must be non-empty")


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


def _is_sha256(value: str) -> bool:
    return (
        isinstance(value, str)
        and len(value) == 64
        and all(character in "0123456789abcdef" for character in value)
    )


def _timestamp(value: str) -> datetime:
    if not isinstance(value, str) or not value:
        raise ValueError("timestamp must be non-empty")
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise ValueError("timestamp must be ISO-8601") from exc
    if parsed.tzinfo is None:
        raise ValueError("timestamp must include timezone")
    return parsed


def _canonical_integrity_payload(data: dict[str, Any]) -> bytes:
    return json.dumps(data, sort_keys=True, separators=(",", ":")).encode("utf-8")


def _record_hash(data: dict[str, Any]) -> str:
    return hashlib.sha256(_canonical_integrity_payload(data)).hexdigest()


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
    dependency_lock_sha256: str
    host_id: str
    platform_name: str
    architecture: str
    python_version: str
    started_utc: str
    completed_utc: str
    record_sha256: str

    @classmethod
    def create(
        cls,
        *,
        campaign_id: str,
        attack_id: str,
        claim_ids: tuple[str, ...],
        construction: str,
        cell_id: str,
        replicate_id: int,
        declared: ResourceBudget,
        observed: ResourceBudget,
        status: TerminalStatus,
        metrics: dict[str, int | float | str | bool | None],
        censor_reason: str | None,
        error_class: str | None,
        code_commit: str,
        artifact_sha256: str,
        config_sha256: str,
        preregistration_sha256: str,
        dependency_lock_sha256: str,
        host_id: str,
        platform_name: str,
        architecture: str,
        python_version: str,
        started_utc: str,
        completed_utc: str,
    ) -> "ConfirmatoryRecordV3":
        seed_hex = derive_confirmatory_seed(attack_id, cell_id, replicate_id).hex()
        base: dict[str, Any] = {
            "schema": "sigma-v3-r15-record-v1",
            "campaign_id": campaign_id,
            "freeze_id": FREEZE_ID,
            "attack_id": attack_id,
            "claim_ids": list(claim_ids),
            "construction": construction,
            "cell_id": cell_id,
            "replicate_id": replicate_id,
            "seed_hex": seed_hex,
            "phase": "confirmatory",
            "declared": asdict(declared),
            "observed": asdict(observed),
            "status": status,
            "metrics": metrics,
            "censor_reason": censor_reason,
            "error_class": error_class,
            "code_commit": code_commit,
            "artifact_sha256": artifact_sha256,
            "config_sha256": config_sha256,
            "preregistration_sha256": preregistration_sha256,
            "dependency_lock_sha256": dependency_lock_sha256,
            "host_id": host_id,
            "platform_name": platform_name,
            "architecture": architecture,
            "python_version": python_version,
            "started_utc": started_utc,
            "completed_utc": completed_utc,
        }
        digest = _record_hash(base)
        return cls(
            schema="sigma-v3-r15-record-v1",
            campaign_id=campaign_id,
            freeze_id=FREEZE_ID,
            attack_id=attack_id,
            claim_ids=claim_ids,
            construction=construction,
            cell_id=cell_id,
            replicate_id=replicate_id,
            seed_hex=seed_hex,
            phase="confirmatory",
            declared=declared,
            observed=observed,
            status=status,
            metrics=metrics,
            censor_reason=censor_reason,
            error_class=error_class,
            code_commit=code_commit,
            artifact_sha256=artifact_sha256,
            config_sha256=config_sha256,
            preregistration_sha256=preregistration_sha256,
            dependency_lock_sha256=dependency_lock_sha256,
            host_id=host_id,
            platform_name=platform_name,
            architecture=architecture,
            python_version=python_version,
            started_utc=started_utc,
            completed_utc=completed_utc,
            record_sha256=digest,
        )

    def __post_init__(self) -> None:
        if self.schema != "sigma-v3-r15-record-v1":
            raise ValueError("unexpected confirmatory record schema")
        if not self.campaign_id:
            raise ValueError("campaign_id must be non-empty")
        if self.freeze_id != FREEZE_ID:
            raise ValueError("record freeze_id mismatch")
        if self.attack_id not in confirmatory_attack_ids():
            raise ValueError("record attack is not confirmatory")
        if self.phase != "confirmatory":
            raise ValueError("R15 record must be confirmatory")
        if self.status not in ("success", "no-success", "censored", "timeout", "error"):
            raise ValueError("invalid terminal status")
        if not self.claim_ids or any(
            not isinstance(claim, str) or not claim.startswith("C") for claim in self.claim_ids
        ):
            raise ValueError("record must bind claim identifiers")
        if not self.construction or not self.cell_id:
            raise ValueError("construction and cell_id must be non-empty")
        if isinstance(self.replicate_id, bool) or not isinstance(self.replicate_id, int):
            raise TypeError("replicate_id must be int")
        if self.replicate_id < 0:
            raise ValueError("replicate_id must be non-negative")
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
        if self.status not in ("censored", "error") and (
            self.censor_reason is not None or self.error_class is not None
        ):
            raise ValueError("terminal annotations do not match status")
        if len(self.code_commit) not in (40, 64) or any(
            character not in "0123456789abcdef" for character in self.code_commit
        ):
            raise ValueError("code_commit must be a lowercase Git object id")
        for value in (
            self.artifact_sha256,
            self.config_sha256,
            self.preregistration_sha256,
            self.dependency_lock_sha256,
        ):
            if not _is_sha256(value):
                raise ValueError("artifact/config/prereg/dependency ids must be SHA-256 hex")
        for value in (
            self.host_id,
            self.platform_name,
            self.architecture,
            self.python_version,
        ):
            if not isinstance(value, str) or not value:
                raise ValueError("environment identity fields must be non-empty")
        started = _timestamp(self.started_utc)
        completed = _timestamp(self.completed_utc)
        if completed < started:
            raise ValueError("completed_utc precedes started_utc")

        payload = asdict(self)
        provided = payload.pop("record_sha256")
        if not _is_sha256(provided) or provided != _record_hash(payload):
            raise ValueError("record integrity hash mismatch")


__all__ = [
    "ConfirmatoryConfigV3",
    "ConfirmatoryRecordV3",
    "RunPhase",
    "TerminalStatus",
    "config_from_dict",
    "derive_confirmatory_seed",
    "validate_cell",
]
