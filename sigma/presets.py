"""Documented Sigma v2 presets; execution backends remain separate."""

from typing import Callable, Dict

from sigma.spec import SigmaContextV2
from sigma.spec.ids import AnchorProfileId, RoundProfileId, SuiteId
from sigma.suites.registry import get_suite


def _context(suite_id, anchor_profile, round_profile, chunk_size=0, **parameters):
    suite = get_suite(suite_id)
    return SigmaContextV2(
        suite_id=suite_id,
        anchor_profile=anchor_profile,
        round_profile=round_profile,
        chunk_size=chunk_size,
        branches=suite.branches,
        **parameters,
    )


def lightweight_v2(**parameters) -> SigmaContextV2:
    return _context(
        SuiteId.LIGHTWEIGHT_STREAM_WIDE_V2,
        AnchorProfileId.STREAM_WIDE,
        RoundProfileId.WIDE_ONCE,
        **parameters,
    )


def simultaneous_v2(**parameters) -> SigmaContextV2:
    return _context(
        SuiteId.SIMULTANEOUS_TREE_WIDE_V2,
        AnchorProfileId.TREE_WIDE,
        RoundProfileId.WIDE_ONCE,
        chunk_size=65536,
        **parameters,
    )


def realtime_v2(**parameters) -> SigmaContextV2:
    return _context(
        SuiteId.REALTIME_STREAM_WIDE_V2,
        AnchorProfileId.STREAM_WIDE,
        RoundProfileId.WIDE_ONCE,
        **parameters,
    )


def paranoid_wide_v2(**parameters) -> SigmaContextV2:
    return _context(
        SuiteId.PARANOID_CROSS_WIDE_V2,
        AnchorProfileId.CROSS_WIDE,
        RoundProfileId.WIDE_ONCE,
        **parameters,
    )


def paranoid_deep_v2(**parameters) -> SigmaContextV2:
    return _context(
        SuiteId.PARANOID_DEEP_V2,
        AnchorProfileId.CROSS_WIDE,
        RoundProfileId.DEEP,
        **parameters,
    )


def lightweight_v2_2(**parameters) -> SigmaContextV2:
    return _context(
        SuiteId.LIGHTWEIGHT_STREAM_WIDE_V2_2,
        AnchorProfileId.STREAM_WIDE,
        RoundProfileId.WIDE_ONCE,
        **parameters,
    )


def simultaneous_v2_2(**parameters) -> SigmaContextV2:
    return _context(
        SuiteId.SIMULTANEOUS_TREE_WIDE_V2_2,
        AnchorProfileId.TREE_WIDE,
        RoundProfileId.WIDE_ONCE,
        chunk_size=65536,
        **parameters,
    )


def paranoid_wide_v2_2(**parameters) -> SigmaContextV2:
    return _context(
        SuiteId.PARANOID_CROSS_WIDE_V2_2,
        AnchorProfileId.CROSS_WIDE,
        RoundProfileId.WIDE_ONCE,
        **parameters,
    )


def paranoid_deep_v2_2(**parameters) -> SigmaContextV2:
    return _context(
        SuiteId.PARANOID_DEEP_V2_2,
        AnchorProfileId.CROSS_WIDE,
        RoundProfileId.DEEP,
        **parameters,
    )


def paranoid_deep_vector_v2_2(**parameters) -> SigmaContextV2:
    return _context(
        SuiteId.PARANOID_DEEP_VECTOR_V2_2,
        AnchorProfileId.CROSS_WIDE,
        RoundProfileId.DEEP_VECTOR,
        **parameters,
    )


_PRESETS: Dict[str, Callable[..., SigmaContextV2]] = {
    "lightweight-v2": lightweight_v2,
    "simultaneous-v2": simultaneous_v2,
    "realtime-v2": realtime_v2,
    "paranoid-wide-v2": paranoid_wide_v2,
    "paranoid-deep-v2": paranoid_deep_v2,
    "lightweight-v2-2": lightweight_v2_2,
    "simultaneous-v2-2": simultaneous_v2_2,
    "paranoid-wide-v2-2": paranoid_wide_v2_2,
    "paranoid-deep-v2-2": paranoid_deep_v2_2,
    "paranoid-deep-vector-v2-2": paranoid_deep_vector_v2_2,
}


def get_preset(name: str, **parameters) -> SigmaContextV2:
    try:
        constructor = _PRESETS[name]
    except KeyError as exc:
        raise ValueError(f"unknown Sigma v2 preset: {name}") from exc
    return constructor(**parameters)
