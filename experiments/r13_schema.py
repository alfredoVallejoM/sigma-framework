"""Canonical R13 attack-record schema.

R13 fixes what must be recorded before R14 freezes concrete configurations.
The schema deliberately distinguishes success, no-success, censoring, timeout
and execution error.
"""

from __future__ import annotations

import json
from dataclasses import asdict, dataclass
from enum import Enum
from typing import Any

from .r13_attack_registry import RESOURCE_FIELDS, get_attack


class AttackRunStatus(str, Enum):
    SUCCESS = "success"
    NO_SUCCESS = "no-success"
    CENSORED = "censored"
    TIMEOUT = "timeout"
    ERROR = "error"


@dataclass(frozen=True)
class ResourceBudget:
    W: int
    Q_A: int
    Q_J: int
    Q_H: int
    Q_R: int
    d: int
    p: int
    mu: int
    u: int

    def __post_init__(self) -> None:
        for name in RESOURCE_FIELDS:
            value = getattr(self, name)
            if isinstance(value, bool) or not isinstance(value, int):
                raise TypeError(f"{name} must be int")
            if value < 0:
                raise ValueError(f"{name} must be non-negative")
        if self.p < 1:
            raise ValueError("p must be at least one")
        if self.u < 1:
            raise ValueError("u must be at least one")


MetricValue = int | float | str | bool | None


@dataclass(frozen=True)
class AttackRunRecord:
    schema: str
    attack_id: str
    construction: str
    seed_label: str
    status: AttackRunStatus
    budget: ResourceBudget
    observed: ResourceBudget
    metrics: dict[str, MetricValue]
    censor_reason: str | None = None
    error_class: str | None = None

    def __post_init__(self) -> None:
        if self.schema != "sigma-r13-attack-record-v1":
            raise ValueError("unexpected R13 attack record schema")
        get_attack(self.attack_id)
        if not self.construction:
            raise ValueError("construction must be non-empty")
        if not self.seed_label:
            raise ValueError("seed_label must be non-empty")
        if not isinstance(self.status, AttackRunStatus):
            raise TypeError("status must be AttackRunStatus")
        if not isinstance(self.budget, ResourceBudget):
            raise TypeError("budget must be ResourceBudget")
        if not isinstance(self.observed, ResourceBudget):
            raise TypeError("observed must be ResourceBudget")
        if any(
            getattr(self.observed, name) > getattr(self.budget, name)
            for name in RESOURCE_FIELDS
        ):
            raise ValueError("observed resources exceed declared budget")
        if not isinstance(self.metrics, dict):
            raise TypeError("metrics must be dict")
        if any(not isinstance(key, str) or not key for key in self.metrics):
            raise ValueError("metric keys must be non-empty strings")
        if self.status is AttackRunStatus.CENSORED and not self.censor_reason:
            raise ValueError("censored runs require censor_reason")
        if self.status is AttackRunStatus.ERROR and not self.error_class:
            raise ValueError("error runs require error_class")
        if (
            self.status not in (AttackRunStatus.CENSORED, AttackRunStatus.ERROR)
            and (self.censor_reason is not None or self.error_class is not None)
        ):
            raise ValueError("terminal annotations do not match run status")

    @classmethod
    def create(
        cls,
        *,
        attack_id: str,
        construction: str,
        seed_label: str,
        status: AttackRunStatus,
        budget: ResourceBudget,
        observed: ResourceBudget,
        metrics: dict[str, MetricValue],
        censor_reason: str | None = None,
        error_class: str | None = None,
    ) -> "AttackRunRecord":
        return cls(
            "sigma-r13-attack-record-v1",
            attack_id,
            construction,
            seed_label,
            status,
            budget,
            observed,
            metrics,
            censor_reason,
            error_class,
        )

    def to_dict(self) -> dict[str, Any]:
        data = asdict(self)
        data["status"] = self.status.value
        return data

    def to_json(self) -> str:
        return json.dumps(self.to_dict(), sort_keys=True, separators=(",", ":"))


__all__ = [
    "AttackRunRecord",
    "AttackRunStatus",
    "MetricValue",
    "ResourceBudget",
]
