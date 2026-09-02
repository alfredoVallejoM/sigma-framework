import hashlib
import json
import subprocess
import sys
from pathlib import Path


def test_release_artifacts_contain_auditable_hashes(tmp_path: Path) -> None:
    wheel = tmp_path / "sigma_framework-2.0.0a1-py3-none-any.whl"
    source = tmp_path / "sigma_framework-2.0.0a1.tar.gz"
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
    assert sbom["metadata"]["component"]["version"] == "2.0.0a1"
    assert len(sbom["components"]) == 2
