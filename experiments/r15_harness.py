"""Synthetic R15-B harness validation primitives.

This module never derives or consumes confirmatory R15 seeds. It exercises
crash/resume, timeout, duplicate RunKeys, integrity checks and budget semantics
under a separate namespace.
"""

from __future__ import annotations

import hashlib
import json
import os
import tempfile
from dataclasses import asdict, dataclass
from pathlib import Path

from .common import canonical_json
from .r13_schema import RESOURCE_FIELDS, ResourceBudget
from .r15_data import RunKeyV3, atomic_write_record_v3, verify_record_v3

HARNESS_NAMESPACE = "sigma-v3-r15-harness-v1"


class SyntheticCrash(RuntimeError):
    """Intentional harness-only crash used to validate deterministic resume."""


@dataclass(frozen=True)
class HarnessCheckpointV3:
    schema: str
    run_key: str
    seed_hex: str
    next_step: int
    state_hex: str
    total_steps: int
    checkpoint_sha256: str

    def __post_init__(self) -> None:
        if self.schema != "sigma-v3-r15-harness-checkpoint-v1":
            raise ValueError("unexpected harness checkpoint schema")
        if self.next_step < 0 or self.total_steps <= 0 or self.next_step > self.total_steps:
            raise ValueError("invalid harness checkpoint progress")
        if len(self.seed_hex) != 64 or len(self.state_hex) != 64:
            raise ValueError("checkpoint seed/state must be 32-byte hex values")
        if len(self.checkpoint_sha256) != 64:
            raise ValueError("checkpoint integrity hash must be SHA-256")


@dataclass(frozen=True)
class HarnessOutcomeV3:
    status: str
    steps_completed: int
    final_state_hex: str
    resumed: bool

    def __post_init__(self) -> None:
        if self.status not in ("success", "timeout"):
            raise ValueError("unsupported harness outcome")
        if self.steps_completed < 0:
            raise ValueError("steps_completed must be non-negative")
        if len(self.final_state_hex) != 64:
            raise ValueError("final_state_hex must be SHA-256 sized")


@dataclass(frozen=True)
class RetryPolicyV3:
    max_transient_retries: int = 2

    def __post_init__(self) -> None:
        if self.max_transient_retries < 0:
            raise ValueError("max_transient_retries must be non-negative")

    def may_retry(self, error_class: str, attempt: int) -> bool:
        if attempt < 0:
            raise ValueError("attempt must be non-negative")
        return error_class == "transient-infrastructure" and attempt < self.max_transient_retries


def derive_harness_seed_v3(key: RunKeyV3) -> bytes:
    fields = (
        HARNESS_NAMESPACE.encode("ascii"),
        key.freeze_id.encode("utf-8"),
        key.attack_id.encode("utf-8"),
        key.cell_id.encode("utf-8"),
        key.replicate_id.to_bytes(8, "big"),
    )
    framed = b"".join(len(field).to_bytes(4, "big") + field for field in fields)
    return hashlib.sha256(framed).digest()


def validate_harness_seed_v3(key: RunKeyV3, seed_hex: str) -> None:
    expected = derive_harness_seed_v3(key).hex()
    if seed_hex != expected:
        raise ValueError("harness seed mismatch")


def _checkpoint_payload(
    key: RunKeyV3,
    seed_hex: str,
    next_step: int,
    state_hex: str,
    total_steps: int,
) -> dict[str, object]:
    return {
        "schema": "sigma-v3-r15-harness-checkpoint-v1",
        "run_key": key.stable_id,
        "seed_hex": seed_hex,
        "next_step": next_step,
        "state_hex": state_hex,
        "total_steps": total_steps,
    }


def _checkpoint_hash(payload: dict[str, object]) -> str:
    return hashlib.sha256(canonical_json(payload)).hexdigest()


def write_checkpoint_v3(
    path: Path,
    key: RunKeyV3,
    *,
    seed_hex: str,
    next_step: int,
    state_hex: str,
    total_steps: int,
) -> HarnessCheckpointV3:
    validate_harness_seed_v3(key, seed_hex)
    payload = _checkpoint_payload(key, seed_hex, next_step, state_hex, total_steps)
    checkpoint = HarnessCheckpointV3(
        **payload,
        checkpoint_sha256=_checkpoint_hash(payload),
    )
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary_name = tempfile.mkstemp(
        prefix=path.name + ".",
        suffix=".tmp",
        dir=path.parent,
    )
    temporary = Path(temporary_name)
    try:
        with os.fdopen(descriptor, "wb") as writer:
            writer.write(canonical_json(asdict(checkpoint)) + b"\n")
            writer.flush()
            os.fsync(writer.fileno())
        os.replace(temporary, path)
    finally:
        if temporary.exists():
            temporary.unlink()
    return checkpoint


def read_checkpoint_v3(path: Path, key: RunKeyV3) -> HarnessCheckpointV3:
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise ValueError("checkpoint must be a JSON object")
    checkpoint = HarnessCheckpointV3(**value)
    if checkpoint.run_key != key.stable_id:
        raise ValueError("checkpoint RunKey mismatch")
    validate_harness_seed_v3(key, checkpoint.seed_hex)
    payload = _checkpoint_payload(
        key,
        checkpoint.seed_hex,
        checkpoint.next_step,
        checkpoint.state_hex,
        checkpoint.total_steps,
    )
    if checkpoint.checkpoint_sha256 != _checkpoint_hash(payload):
        raise ValueError("checkpoint integrity mismatch")
    return checkpoint


def _step(seed: bytes, state: bytes, index: int) -> bytes:
    return hashlib.sha256(
        b"sigma-v3-r15-harness-step\0" + seed + index.to_bytes(8, "big") + state
    ).digest()


def run_synthetic_task_v3(
    key: RunKeyV3,
    *,
    total_steps: int,
    checkpoint_path: Path | None = None,
    checkpoint_interval: int = 8,
    crash_after_step: int | None = None,
    timeout_after_steps: int | None = None,
    resume: bool = False,
) -> HarnessOutcomeV3:
    if total_steps <= 0 or checkpoint_interval <= 0:
        raise ValueError("total_steps/checkpoint_interval must be positive")
    if crash_after_step is not None and crash_after_step <= 0:
        raise ValueError("crash_after_step must be positive")
    if timeout_after_steps is not None and timeout_after_steps < 0:
        raise ValueError("timeout_after_steps must be non-negative")

    seed = derive_harness_seed_v3(key)
    seed_hex = seed.hex()
    state = hashlib.sha256(b"sigma-v3-r15-harness-genesis\0" + seed).digest()
    start = 0
    resumed = False

    if resume:
        if checkpoint_path is None or not checkpoint_path.is_file():
            raise ValueError("resume requires an existing checkpoint")
        checkpoint = read_checkpoint_v3(checkpoint_path, key)
        if checkpoint.total_steps != total_steps:
            raise ValueError("checkpoint total_steps mismatch")
        state = bytes.fromhex(checkpoint.state_hex)
        start = checkpoint.next_step
        resumed = True

    for completed_this_attempt, index in enumerate(range(start, total_steps)):
        if timeout_after_steps is not None and completed_this_attempt >= timeout_after_steps:
            if checkpoint_path is not None:
                write_checkpoint_v3(
                    checkpoint_path,
                    key,
                    seed_hex=seed_hex,
                    next_step=index,
                    state_hex=state.hex(),
                    total_steps=total_steps,
                )
            return HarnessOutcomeV3("timeout", index, state.hex(), resumed)

        state = _step(seed, state, index)
        next_step = index + 1
        if checkpoint_path is not None and (
            next_step % checkpoint_interval == 0
            or next_step == total_steps
            or crash_after_step == next_step
        ):
            write_checkpoint_v3(
                checkpoint_path,
                key,
                seed_hex=seed_hex,
                next_step=next_step,
                state_hex=state.hex(),
                total_steps=total_steps,
            )
        if crash_after_step == next_step:
            raise SyntheticCrash(f"synthetic crash after step {next_step}")

    return HarnessOutcomeV3("success", total_steps, state.hex(), resumed)


def validate_observed_budget_v3(
    declared: ResourceBudget,
    observed: ResourceBudget,
) -> None:
    for field in RESOURCE_FIELDS:
        if getattr(observed, field) > getattr(declared, field):
            raise ValueError(f"observed {field} exceeds declared budget")


def write_harness_record_v3(
    root: Path,
    key: RunKeyV3,
    outcome: HarnessOutcomeV3,
    *,
    declared: ResourceBudget,
    observed: ResourceBudget,
    execution_manifest_sha256: str,
) -> str:
    validate_observed_budget_v3(declared, observed)
    if len(execution_manifest_sha256) != 64 or any(
        ch not in "0123456789abcdef" for ch in execution_manifest_sha256
    ):
        raise ValueError("execution_manifest_sha256 must be lowercase SHA-256")
    seed_hex = derive_harness_seed_v3(key).hex()
    record = {
        "schema": "sigma-v3-r15-harness-record-v1",
        "namespace": HARNESS_NAMESPACE,
        "confirmatory": False,
        "run_key": key.stable_id,
        "seed_hex": seed_hex,
        "status": outcome.status,
        "steps_completed": outcome.steps_completed,
        "final_state_hex": outcome.final_state_hex,
        "declared": asdict(declared),
        "observed": asdict(observed),
        "execution_manifest_sha256": execution_manifest_sha256,
    }
    _path, digest = atomic_write_record_v3(root, key, record)
    return digest


def verify_harness_record_v3(
    root: Path,
    key: RunKeyV3,
    *,
    execution_manifest_sha256: str,
) -> str:
    digest = verify_record_v3(root, key)
    path = root / "raw" / key.attack_id / key.cell_id / f"{key.replicate_id:08d}.json"
    value = json.loads(path.read_text(encoding="utf-8"))
    if value.get("schema") != "sigma-v3-r15-harness-record-v1":
        raise ValueError("unexpected harness record schema")
    if value.get("namespace") != HARNESS_NAMESPACE or value.get("confirmatory") is not False:
        raise ValueError("harness record crossed the confirmatory boundary")
    validate_harness_seed_v3(key, str(value.get("seed_hex")))
    if value.get("execution_manifest_sha256") != execution_manifest_sha256:
        raise ValueError("harness execution-manifest hash mismatch")
    return digest


__all__ = [
    "HARNESS_NAMESPACE",
    "HarnessCheckpointV3",
    "HarnessOutcomeV3",
    "RetryPolicyV3",
    "SyntheticCrash",
    "derive_harness_seed_v3",
    "read_checkpoint_v3",
    "run_synthetic_task_v3",
    "validate_harness_seed_v3",
    "validate_observed_budget_v3",
    "verify_harness_record_v3",
    "write_checkpoint_v3",
    "write_harness_record_v3",
]
