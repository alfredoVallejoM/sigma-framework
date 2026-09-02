"""Shared validation primitives for public Sigma v2 numeric boundaries."""

from typing import Any


class ValidationError(ValueError, TypeError):
    """Unified public rejection compatible with historic value/type handlers."""


def require_int(
    name: str,
    value: Any,
    *,
    minimum: int,
    maximum: int,
) -> int:
    """Return a bounded integer, rejecting bool and implicit coercions."""

    if isinstance(value, bool) or not isinstance(value, int):
        raise ValidationError(f"{name} must be an integer")
    if not minimum <= value <= maximum:
        raise ValidationError(f"{name} must be in [{minimum}, {maximum}]")
    return value
