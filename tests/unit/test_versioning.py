import re
from pathlib import Path

import sigma
from sigma.spec.ids import SuiteId
from sigma.suites.registry import get_suite
from sigma.version import (
    CONTEXT_WIRE_VERSION,
    DIGEST_WIRE_VERSION,
    EVIDENCE_WIRE_VERSION,
    PACKAGE_VERSION,
    SUPPORTED_SUITE_FAMILIES,
)


def test_package_metadata_has_one_source_value() -> None:
    pyproject = Path("pyproject.toml").read_text(encoding="utf-8")
    match = re.search(r'^version\s*=\s*"([^"]+)"\s*$', pyproject, re.MULTILINE)
    assert match is not None
    assert match.group(1) == PACKAGE_VERSION == sigma.__version__


def test_version_axes_are_independent_and_declared() -> None:
    assert (CONTEXT_WIRE_VERSION, DIGEST_WIRE_VERSION, EVIDENCE_WIRE_VERSION) == (2, 2, 2)
    assert SUPPORTED_SUITE_FAMILIES == ("v2-1", "v2-2")


def test_v21_is_frozen_while_v22_remains_experimental() -> None:
    v21 = get_suite(SuiteId.REFERENCE_STREAM_WIDE_V2)
    v22 = get_suite(SuiteId.REFERENCE_STREAM_WIDE_V2_2)
    assert (v21.suite_family, v21.evidence_version, v21.stable) == ("v2-1", 1, True)
    assert (v22.suite_family, v22.evidence_version, v22.stable) == ("v2-2", 2, False)
