from pathlib import Path

import pytest

from scripts.check_v22_baseline import (
    LOCAL_ARTIFACT_MANIFEST,
    PROJECT_ROOT,
    load_manifest,
    verify_baseline,
    verify_manifest_completeness,
)


def test_frozen_v22_semantic_assets_are_unchanged() -> None:
    assert verify_manifest_completeness() == []
    assert verify_baseline() == []


def test_local_release_artifacts_match_inventory() -> None:
    targets = [PROJECT_ROOT / path for path in load_manifest(LOCAL_ARTIFACT_MANIFEST)]
    if not any(target.exists() for target in targets):
        pytest.skip("ignored local v2.2 release artifacts are not present")
    assert verify_baseline(manifest=LOCAL_ARTIFACT_MANIFEST) == []


def test_baseline_manifest_rejects_unsafe_paths(tmp_path: Path) -> None:
    manifest = tmp_path / "unsafe.sha256"
    manifest.write_text(f"{'0' * 64}  ../outside\n", encoding="utf-8")

    with pytest.raises(ValueError, match="unsafe baseline path"):
        load_manifest(manifest)


def test_manifest_completeness_detects_an_unprotected_file(tmp_path: Path) -> None:
    manifest = tmp_path / "incomplete.sha256"
    manifest.write_text(
        f"{'0' * 64}  sigma/__init__.py\n",
        encoding="utf-8",
    )

    assert any(
        failure.startswith("unprotected: ") for failure in verify_manifest_completeness(manifest)
    )
