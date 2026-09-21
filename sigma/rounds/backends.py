"""Scheduling policies for independent branches within one Deep level."""

import os
from abc import ABC, abstractmethod
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass

from sigma.anchors.base import CrossWideEvidence
from sigma.instrumentation import OracleInput, active_capture, extend_oracle_inputs
from sigma.spec import SigmaContextV2
from sigma.validation import require_int

from .deep_math import evaluate_deep_branch

DeepBranchResult = tuple[int, bytes]
MAX_DEEP_WORKERS = 256


def _captured_deep_branch(
    position: int,
    algorithm,
    context: SigmaContextV2,
    anchor: CrossWideEvidence,
    index: int,
    state: bytes,
) -> tuple[DeepBranchResult, list[OracleInput]]:
    from sigma.instrumentation import capture_oracle_inputs

    with capture_oracle_inputs() as records:
        result = evaluate_deep_branch(position, algorithm, context, anchor, index, state)
    return result, records


class DeepBranchBackend(ABC):
    """Execute branch tasks; result order is explicitly unspecified."""

    @property
    @abstractmethod
    def name(self) -> str:
        pass

    @abstractmethod
    def execute(
        self,
        context: SigmaContextV2,
        anchor: CrossWideEvidence,
        index: int,
        state: bytes,
    ) -> list[DeepBranchResult]:
        pass


class SerialDeepBranchBackend(DeepBranchBackend):
    @property
    def name(self) -> str:
        return "serial-deep-branches"

    def execute(
        self,
        context: SigmaContextV2,
        anchor: CrossWideEvidence,
        index: int,
        state: bytes,
    ) -> list[DeepBranchResult]:
        return [
            evaluate_deep_branch(position, algorithm, context, anchor, index, state)
            for position, algorithm in enumerate(context.branches)
        ]


@dataclass(frozen=True)
class ThreadedDeepBranchBackend(DeepBranchBackend):
    workers: int = 0

    def __post_init__(self) -> None:
        require_int("workers", self.workers, minimum=0, maximum=MAX_DEEP_WORKERS)
        selected = self.workers or (os.cpu_count() or 1)
        require_int("workers", selected, minimum=1, maximum=MAX_DEEP_WORKERS)
        object.__setattr__(self, "workers", selected)

    @property
    def name(self) -> str:
        return "threaded-deep-branches"

    def execute(
        self,
        context: SigmaContextV2,
        anchor: CrossWideEvidence,
        index: int,
        state: bytes,
    ) -> list[DeepBranchResult]:
        if not context.branches:
            return []
        capture = active_capture() is not None
        with ThreadPoolExecutor(max_workers=min(self.workers, len(context.branches))) as executor:
            if not capture:
                futures = [
                    executor.submit(
                        evaluate_deep_branch,
                        position,
                        algorithm,
                        context,
                        anchor,
                        index,
                        state,
                    )
                    for position, algorithm in enumerate(context.branches)
                ]
                return [future.result() for future in as_completed(futures)]
            captured_futures = [
                executor.submit(
                    _captured_deep_branch,
                    position,
                    algorithm,
                    context,
                    anchor,
                    index,
                    state,
                )
                for position, algorithm in enumerate(context.branches)
            ]
            captured = sorted(
                (future.result() for future in as_completed(captured_futures)),
                key=lambda item: item[0][0],
            )
        results = []
        for result, records in captured:
            extend_oracle_inputs(records)
            results.append(result)
        return results


SERIAL_DEEP_BRANCH_BACKEND = SerialDeepBranchBackend()

__all__ = [
    "MAX_DEEP_WORKERS",
    "SERIAL_DEEP_BRANCH_BACKEND",
    "DeepBranchBackend",
    "DeepBranchResult",
    "SerialDeepBranchBackend",
    "ThreadedDeepBranchBackend",
]
