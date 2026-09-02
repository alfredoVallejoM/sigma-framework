import hashlib
import json
import subprocess
import sys
from pathlib import Path


def test_release_artifacts_contain_auditable_hashes(tmp_path: Path) -> None:
    wheel = tmp_path / "sigma_framework-2.2.0a1-py3-none-any.whl"
    source = tmp_path / "sigma_framework-2.2.0a1.tar.gz"
    wheel.write_bytes(b"wheel")
    source.write_bytes(b"source")
    result = subprocess.run(
        [sys.executable, "scripts/release_artifacts.py", str(tmp_path)],
        check=False,
        capture_output=True,
        text=True,
    )
    assert result.returncode == 0, result.stderr

    checksums = (tmp_path / "SHA256SUMS").read_text(encoding="ascii")
    assert hashlib.sha256(b"wheel").hexdigest() in checksums
    assert hashlib.sha256(b"source").hexdigest() in checksums
    sbom = json.loads((tmp_path / "sigma-framework.cdx.json").read_text(encoding="utf-8"))
    assert sbom["bomFormat"] == "CycloneDX"
    assert sbom["metadata"]["component"]["version"] == "2.2.0a1"
    assert len(sbom["components"]) == 2
    properties = {item["name"]: item["value"] for item in sbom["metadata"]["properties"]}
    assert properties["sigma:context-wire-version"] == "2"
    assert properties["sigma:evidence-wire-version"] == "2"
    assert properties["sigma:suite-families"] == "v2-1,v2-2"
    assert len(properties["sigma:git-commit"]) == 40


def test_publishable_release_requires_clean_exact_tag(tmp_path: Path) -> None:
    (tmp_path / "sigma_framework-2.2.0a1.tar.gz").write_bytes(b"source")
    result = subprocess.run(
        [
            sys.executable,
            "scripts/release_artifacts.py",
            str(tmp_path),
            "--require-clean-tag",
        ],
        check=False,
        capture_output=True,
        text=True,
    )
    assert result.returncode == 2
    assert "clean checkout at an exact tag" in result.stderr
