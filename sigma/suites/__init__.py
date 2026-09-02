"""Frozen Sigma v2 suite registry."""

from .registry import (
    LIGHTWEIGHT_STREAM_WIDE_V2,
    PARANOID_CROSS_WIDE_V2,
    PARANOID_DEEP_V2,
    REALTIME_STREAM_WIDE_V2,
    REFERENCE_STREAM_WIDE_V2,
    SIMULTANEOUS_TREE_WIDE_V2,
    SuiteDescriptor,
    get_suite,
)

__all__ = [
    "LIGHTWEIGHT_STREAM_WIDE_V2",
    "PARANOID_CROSS_WIDE_V2",
    "PARANOID_DEEP_V2",
    "REALTIME_STREAM_WIDE_V2",
    "REFERENCE_STREAM_WIDE_V2",
    "SIMULTANEOUS_TREE_WIDE_V2",
    "SuiteDescriptor",
    "get_suite",
]
