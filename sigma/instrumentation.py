"""Opt-in primitive-input capture for conformance audits, inactive by default."""

from __future__ import annotations

from contextlib import contextmanager
from contextvars import ContextVar
from dataclasses import dataclass
from typing import Iterator

from sigma.spec.ids import AlgorithmId


@dataclass(frozen=True)
class OracleInput:
    algorithm: AlgorithmId
    data: bytes


_CAPTURE: ContextVar[list[OracleInput] | None] = ContextVar("sigma_oracle_capture", default=None)


def active_capture() -> list[OracleInput] | None:
    return _CAPTURE.get()


def record_oracle_input(algorithm: AlgorithmId, data: bytes) -> None:
    target = _CAPTURE.get()
    if target is not None:
        target.append(OracleInput(algorithm, data))


@contextmanager
def capture_oracle_inputs() -> Iterator[list[OracleInput]]:
    records: list[OracleInput] = []
    token = _CAPTURE.set(records)
    try:
        yield records
    finally:
        _CAPTURE.reset(token)
