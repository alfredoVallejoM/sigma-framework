"""Independent side verification reference for SA1.

This module intentionally imports no code from sigma.
"""

from __future__ import annotations

from reference.independent_v3 import evaluate_suite
from reference.tree_v1 import root_wire as tree_root_wire


def verify_tree_side(data: bytes, expected_tree_root_wire: bytes) -> bool:
    if not isinstance(data, bytes):
        raise TypeError("data must be bytes")
    if not isinstance(expected_tree_root_wire, bytes):
        raise TypeError("expected_tree_root_wire must be bytes")
    return tree_root_wire(data) == expected_tree_root_wire


def trajectory_digest_wire(
    data: bytes,
    *,
    suite_id: int,
    salt: bytes,
    challenge: bytes,
    application_context: bytes,
) -> bytes:
    result = evaluate_suite(
        data,
        suite_id=suite_id,
        salt=salt,
        challenge=challenge,
        application_context=application_context,
    )
    return result["digest"]


def verify_trajectory_side(
    data: bytes,
    expected_digest_wire: bytes,
    *,
    suite_id: int,
    salt: bytes,
    challenge: bytes,
    application_context: bytes,
) -> bool:
    return trajectory_digest_wire(
        data,
        suite_id=suite_id,
        salt=salt,
        challenge=challenge,
        application_context=application_context,
    ) == expected_digest_wire


def verify_dual_sides(
    data: bytes,
    *,
    expected_tree_root_wire: bytes,
    expected_digest_wire: bytes,
    suite_id: int,
    salt: bytes,
    challenge: bytes,
    application_context: bytes,
) -> tuple[bool, bool, bool]:
    tree_ok = verify_tree_side(data, expected_tree_root_wire)
    trajectory_ok = verify_trajectory_side(
        data,
        expected_digest_wire,
        suite_id=suite_id,
        salt=salt,
        challenge=challenge,
        application_context=application_context,
    )
    return tree_ok, trajectory_ok, tree_ok and trajectory_ok


__all__ = [
    "trajectory_digest_wire",
    "verify_dual_sides",
    "verify_trajectory_side",
    "verify_tree_side",
]
