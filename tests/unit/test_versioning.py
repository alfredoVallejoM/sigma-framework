import re
from pathlib import Path

import pytest

import sigma
from sigma.spec.ids import SuiteId
from sigma.suites.registry import get_suite
from sigma.version import (
    ACTIVE_SUITE_FAMILIES,
    CONTEXT_WIRE_VERSION,
    DIGEST_WIRE_VERSION,
    EVIDENCE_WIRE_VERSION,
    KDF_PARAMETER_WIRE_VERSION,
    KDF_RECORD_WIRE_VERSION,
    PACKAGE_VERSION,
    POW_WIRE_VERSION,
    SIGNED_COMMITMENT_WIRE_VERSION,
    SUPPORTED_SUITE_FAMILIES,
    TRANSITIONAL_SUITE_FAMILIES,
)


def test_package_metadata_has_one_source_value() -> None:
    pyproject = Path("pyproject.toml").read_text(encoding="utf-8")
    match = re.search(r'^version\s*=\s*"([^"]+)"\s*$', pyproject, re.MULTILINE)
    assert match is not None
    assert match.group(1) == PACKAGE_VERSION == sigma.__version__


def test_version_axes_are_independent_and_declared() -> None:
    assert (
        CONTEXT_WIRE_VERSION,
        DIGEST_WIRE_VERSION,
        EVIDENCE_WIRE_VERSION,
        KDF_PARAMETER_WIRE_VERSION,
        KDF_RECORD_WIRE_VERSION,
        POW_WIRE_VERSION,
        SIGNED_COMMITMENT_WIRE_VERSION,
    ) == (2, 2, 2, 2, 2, 3, 2)
    assert ACTIVE_SUITE_FAMILIES == ("v3-r12.5",)
    assert TRANSITIONAL_SUITE_FAMILIES == ("v2-2", "v3-r12")
    assert SUPPORTED_SUITE_FAMILIES == ("v3-r12.5", "v2-2", "v3-r12")


def test_maturity_axes_are_independent() -> None:
    v22 = get_suite(SuiteId.REFERENCE_STREAM_WIDE_V2_2)
    assert (v22.suite_family, v22.evidence_version) == ("v2-2", 2)
    assert (v22.wire_frozen, v22.vectors_frozen, v22.suite_stable) == (True, True, True)
    assert v22.security_reviewed is False


def test_withdrawn_suite_identifiers_are_not_runtime_members() -> None:
    assert all(not suite_id.name.endswith("_V2") for suite_id in SuiteId)
    with pytest.raises(ValueError):
        SuiteId(0x0001)
