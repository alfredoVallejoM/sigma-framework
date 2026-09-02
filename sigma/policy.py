"""Local resource acceptance policy, deliberately absent from digest bytes."""

from dataclasses import asdict, dataclass
from typing import Optional

from sigma.spec.context import (
    MAX_STATE_COUNT,
    MAX_TARGET_ROUND,
    SigmaContextV2,
    validate_registered_context,
)
from sigma.validation import ValidationError, require_int


class PolicyViolation(ValidationError):
    """A valid Sigma object exceeds or downgrades a local resource policy."""


@dataclass(frozen=True)
class ValidationStatus:
    well_formed: bool
    suite_valid: bool
    policy_acceptable: bool
    reason: Optional[str] = None


@dataclass(frozen=True)
class ResourcePolicy:
    name: str = "sigma-default-v1"
    min_target_round: int = 0
    max_target_round: int = 65_536
    min_state_count: int = 1
    max_state_count: int = 16
    max_message_bytes: int = 1 << 30
    max_pow_difficulty_bits: int = 512
    max_pow_attempts: int = 10_000_000
    min_argon2_memory_kib: int = 19_456
    max_argon2_memory_kib: int = 1 << 20
    min_argon2_time_cost: int = 2
    max_argon2_time_cost: int = 64

    def __post_init__(self) -> None:
        if not isinstance(self.name, str) or not self.name:
            raise ValidationError("policy name must be non-empty text")
        require_int("min_target_round", self.min_target_round, minimum=0, maximum=MAX_TARGET_ROUND)
        require_int("max_target_round", self.max_target_round, minimum=0, maximum=MAX_TARGET_ROUND)
        require_int("min_state_count", self.min_state_count, minimum=1, maximum=MAX_STATE_COUNT)
        require_int("max_state_count", self.max_state_count, minimum=1, maximum=MAX_STATE_COUNT)
        for name in (
            "max_message_bytes",
            "max_pow_difficulty_bits",
            "max_pow_attempts",
            "min_argon2_memory_kib",
            "max_argon2_memory_kib",
            "min_argon2_time_cost",
            "max_argon2_time_cost",
        ):
            require_int(name, getattr(self, name), minimum=0, maximum=(1 << 63) - 1)
        if self.min_target_round > self.max_target_round:
            raise ValidationError("target-round policy minimum exceeds maximum")
        if self.min_state_count > self.max_state_count:
            raise ValidationError("state-count policy minimum exceeds maximum")
        if self.min_argon2_memory_kib > self.max_argon2_memory_kib:
            raise ValidationError("Argon2 memory policy minimum exceeds maximum")
        if self.min_argon2_time_cost > self.max_argon2_time_cost:
            raise ValidationError("Argon2 time policy minimum exceeds maximum")

    def as_dict(self) -> dict[str, object]:
        return asdict(self)

    def validate_context(self, context: SigmaContextV2) -> None:
        validate_registered_context(context)
        if not self.min_target_round <= context.target_round <= self.max_target_round:
            raise PolicyViolation("target_round is outside the local resource policy")
        if not self.min_state_count <= context.state_count <= self.max_state_count:
            raise PolicyViolation("state_count is outside the local resource policy")

    def validate_message_size(self, size: int) -> None:
        checked = require_int("message size", size, minimum=0, maximum=(1 << 64) - 1)
        if checked > self.max_message_bytes:
            raise PolicyViolation("message size exceeds the local resource policy")

    def validate_pow(self, difficulty_bits: int, max_attempts: Optional[int] = None) -> None:
        difficulty = require_int("difficulty_bits", difficulty_bits, minimum=0, maximum=0xFFFF)
        if difficulty > self.max_pow_difficulty_bits:
            raise PolicyViolation("PoW difficulty exceeds the local resource policy")
        if max_attempts is not None:
            attempts = require_int("max_attempts", max_attempts, minimum=1, maximum=(1 << 64) - 1)
            if attempts > self.max_pow_attempts:
                raise PolicyViolation("PoW attempts exceed the local resource policy")

    def validate_argon2(self, memory_kib: int, time_cost: int) -> None:
        memory = require_int("memory_kib", memory_kib, minimum=1, maximum=0xFFFFFFFF)
        time = require_int("time_cost", time_cost, minimum=1, maximum=0xFFFFFFFF)
        if not self.min_argon2_memory_kib <= memory <= self.max_argon2_memory_kib:
            raise PolicyViolation("Argon2 memory is outside the local resource policy")
        if not self.min_argon2_time_cost <= time <= self.max_argon2_time_cost:
            raise PolicyViolation("Argon2 time cost is outside the local resource policy")


DEFAULT_RESOURCE_POLICY = ResourcePolicy()


def classify_context(
    context: object, policy: ResourcePolicy = DEFAULT_RESOURCE_POLICY
) -> ValidationStatus:
    if not isinstance(context, SigmaContextV2):
        return ValidationStatus(False, False, False, "context is not SigmaContextV2")
    try:
        validate_registered_context(context)
    except (TypeError, ValueError) as exc:
        return ValidationStatus(True, False, False, str(exc))
    try:
        policy.validate_context(context)
    except PolicyViolation as exc:
        return ValidationStatus(True, True, False, str(exc))
    return ValidationStatus(True, True, True)
