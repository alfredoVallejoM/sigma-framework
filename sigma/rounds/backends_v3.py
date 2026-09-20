"""Scheduling-only backends for canonical Sigma v3 Deep branch tasks."""

from __future__ import annotations

import hmac
import os
from abc import ABC, abstractmethod
from concurrent.futures import ProcessPoolExecutor, ThreadPoolExecutor
from dataclasses import dataclass

from sigma.crypto.primitives import hash_bytes
from sigma.spec.ids import AlgorithmId
from sigma.spec.ids_v3 import ALGORITHM_OUTPUT_SIZE_V3, DomainIdV3

MAX_DEEP_WORKERS_V3 = 64


@dataclass(frozen=True)
class DeepBranchTaskV3:
    position: int
    algorithm: AlgorithmId
    frame: bytes

    def __post_init__(self) -> None:
        if isinstance(self.position, bool) or not isinstance(self.position, int):
            raise TypeError("position must be int")
        if not 0 <= self.position <= 0xFFFF:
            raise ValueError("position out of range")
        if not isinstance(self.algorithm, AlgorithmId):
            raise TypeError("algorithm must be AlgorithmId")
        if not isinstance(self.frame, bytes) or not self.frame:
            raise ValueError("frame must be non-empty bytes")


@dataclass(frozen=True)
class DeepBranchResultV3:
    position: int
    value: bytes

    def __post_init__(self) -> None:
        if isinstance(self.position, bool) or not isinstance(self.position, int):
            raise TypeError("position must be int")
        if not 0 <= self.position <= 0xFFFF:
            raise ValueError("position out of range")
        if not isinstance(self.value, bytes) or not self.value:
            raise ValueError("value must be non-empty bytes")


class DeepBranchExecutionError(RuntimeError):
    """A backend failed or returned an invalid component set."""


class DeepBranchBackendV3(ABC):
    """Schedule canonical tasks without knowing Sigma binding semantics."""

    @property
    @abstractmethod
    def name(self) -> str:
        raise NotImplementedError

    @abstractmethod
    def execute(self, tasks: tuple[DeepBranchTaskV3, ...]) -> tuple[DeepBranchResultV3, ...]:
        raise NotImplementedError


def _evaluate_task_v3(task: DeepBranchTaskV3) -> DeepBranchResultV3:
    return DeepBranchResultV3(
        task.position,
        hash_bytes(task.algorithm, DomainIdV3.DEEP_BRANCH_FRAME, task.frame),
    )


class SerialDeepBranchBackendV3(DeepBranchBackendV3):
    @property
    def name(self) -> str:
        return "serial-v3"

    def execute(self, tasks: tuple[DeepBranchTaskV3, ...]) -> tuple[DeepBranchResultV3, ...]:
        return tuple(_evaluate_task_v3(task) for task in tasks)


def _validate_workers(workers: int) -> int:
    if isinstance(workers, bool) or not isinstance(workers, int):
        raise TypeError("workers must be int")
    selected = workers or min(os.cpu_count() or 1, MAX_DEEP_WORKERS_V3)
    if not 1 <= selected <= MAX_DEEP_WORKERS_V3:
        raise ValueError("workers out of range")
    return selected


@dataclass(frozen=True)
class ThreadDeepBranchBackendV3(DeepBranchBackendV3):
    workers: int = 0

    def __post_init__(self) -> None:
        object.__setattr__(self, "workers", _validate_workers(self.workers))

    @property
    def name(self) -> str:
        return "thread-v3"

    def execute(self, tasks: tuple[DeepBranchTaskV3, ...]) -> tuple[DeepBranchResultV3, ...]:
        with ThreadPoolExecutor(max_workers=self.workers) as executor:
            return tuple(executor.map(_evaluate_task_v3, tasks))


@dataclass(frozen=True)
class ProcessDeepBranchBackendV3(DeepBranchBackendV3):
    workers: int = 0

    def __post_init__(self) -> None:
        object.__setattr__(self, "workers", _validate_workers(self.workers))

    @property
    def name(self) -> str:
        return "process-v3"

    def execute(self, tasks: tuple[DeepBranchTaskV3, ...]) -> tuple[DeepBranchResultV3, ...]:
        with ProcessPoolExecutor(max_workers=self.workers) as executor:
            return tuple(executor.map(_evaluate_task_v3, tasks))


def execute_deep_tasks_v3(
    backend: DeepBranchBackendV3,
    tasks: tuple[DeepBranchTaskV3, ...],
) -> tuple[bytes, ...]:
    if not isinstance(backend, DeepBranchBackendV3):
        raise TypeError("backend must be DeepBranchBackendV3")
    if not isinstance(tasks, tuple) or not tasks:
        raise ValueError("tasks must be a non-empty tuple")
    if any(not isinstance(task, DeepBranchTaskV3) for task in tasks):
        raise TypeError("tasks must contain DeepBranchTaskV3 values")
    positions = tuple(task.position for task in tasks)
    if positions != tuple(range(len(tasks))):
        raise ValueError("task positions must be canonical")

    try:
        results = backend.execute(tasks)
    except Exception as exc:
        raise DeepBranchExecutionError(f"{backend.name} branch execution failed") from exc
    if not isinstance(results, tuple):
        raise DeepBranchExecutionError("backend results must be a tuple")
    if len(results) != len(tasks):
        raise DeepBranchExecutionError("backend returned incomplete component set")
    if any(not isinstance(result, DeepBranchResultV3) for result in results):
        raise DeepBranchExecutionError("backend returned invalid result type")
    if len({result.position for result in results}) != len(results):
        raise DeepBranchExecutionError("backend returned duplicate component")

    ordered = sorted(results, key=lambda result: result.position)
    if tuple(result.position for result in ordered) != positions:
        raise DeepBranchExecutionError("backend returned unexpected component")
    if any(
        not isinstance(result.value, bytes) or len(result.value) != ALGORITHM_OUTPUT_SIZE_V3
        for result in ordered
    ):
        raise DeepBranchExecutionError("backend returned invalid component width")
    expected = tuple(_evaluate_task_v3(task).value for task in tasks)
    if any(
        not hmac.compare_digest(result.value, canonical)
        for result, canonical in zip(ordered, expected, strict=True)
    ):
        raise DeepBranchExecutionError("backend returned incorrect component")
    return tuple(result.value for result in ordered)


SERIAL_DEEP_BRANCH_BACKEND_V3 = SerialDeepBranchBackendV3()


__all__ = [
    "MAX_DEEP_WORKERS_V3",
    "SERIAL_DEEP_BRANCH_BACKEND_V3",
    "DeepBranchBackendV3",
    "DeepBranchExecutionError",
    "DeepBranchResultV3",
    "DeepBranchTaskV3",
    "ProcessDeepBranchBackendV3",
    "SerialDeepBranchBackendV3",
    "ThreadDeepBranchBackendV3",
    "execute_deep_tasks_v3",
]
