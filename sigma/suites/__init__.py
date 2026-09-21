"""Frozen Sigma v2.2 suite registry."""

from .registry import (
    LIGHTWEIGHT_STREAM_WIDE_V2_2,
    PARANOID_CROSS_WIDE_V2_2,
    PARANOID_DEEP_V2_2,
    PARANOID_DEEP_VECTOR_V2_2,
    REFERENCE_STREAM_WIDE_V2_2,
    SIMULTANEOUS_TREE_WIDE_V2_2,
    SuiteDescriptor,
    get_suite,
)

__all__ = [
    "LIGHTWEIGHT_STREAM_WIDE_V2_2",
    "PARANOID_CROSS_WIDE_V2_2",
    "PARANOID_DEEP_V2_2",
    "PARANOID_DEEP_VECTOR_V2_2",
    "REFERENCE_STREAM_WIDE_V2_2",
    "SIMULTANEOUS_TREE_WIDE_V2_2",
    "SuiteDescriptor",
    "get_suite",
]
