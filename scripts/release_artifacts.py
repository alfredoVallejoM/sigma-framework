#!/usr/bin/env python3
"""Generate release checksums and a minimal CycloneDX SBOM without dependencies."""

import argparse
import hashlib
import json
import platform
import re
import runpy
import subprocess
import uuid
from pathlib import Path
from typing import cast

ARTIFACT_SUFFIXES = (".whl", ".tar.gz", ".zip")
PROJECT_ROOT = Path(__file__).resolve().parents[1]


def _version_axes() -> dict[str, object]:
    return runpy.run_path(str(PROJECT_ROOT / "sigma" / "version.py"))


def _project_version() -> str:
    pyproject = (PROJECT_ROOT / "pyproject.toml").read_text(encoding="utf-8")
    match = re.search(r'^version\s*=\s*"([^"]+)"\s*$', pyproject, re.MULTILINE)
    if match is None:
        raise ValueError("project version is missing from pyproject.toml")
    return match.group(1)


def _artifacts(directory: Path) -> list[Path]:
    return sorted(
        path
        for path in directory.iterdir()
        if path.is_file() and any(path.name.endswith(suffix) for suffix in ARTIFACT_SUFFIXES)
    )


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as reader:
        for chunk in iter(lambda: reader.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _git(*args: str) -> str:
    result = subprocess.run(
        ["git", *args], cwd=PROJECT_ROOT, check=False, capture_output=True, text=True, timeout=10
    )
    return result.stdout.strip() if result.returncode == 0 else "unavailable"


def generate(directory: Path, *, require_clean_tag: bool = False) -> tuple[Path, Path]:
    version = _project_version()
    axes = _version_axes()
    suite_families = cast(tuple[str, ...], axes["SUPPORTED_SUITE_FAMILIES"])
    commit = _git("rev-parse", "HEAD")
    dirty = _git("status", "--porcelain") != ""
    tag = _git("describe", "--tags", "--exact-match")
    if require_clean_tag and (dirty or tag == "unavailable"):
        raise ValueError("publishable artifacts require a clean checkout at an exact tag")
    artifacts = _artifacts(directory)
    if not artifacts:
        raise ValueError(f"no release artifacts found in {directory}")
    checksums = {path.name: _sha256(path) for path in artifacts}

    checksum_path = directory / "SHA256SUMS"
    checksum_path.write_text(
        "".join(f"{value}  {name}\n" for name, value in checksums.items()),
        encoding="ascii",
    )
    components = [
        {
            "bom-ref": f"artifact:{name}",
            "hashes": [{"alg": "SHA-256", "content": value}],
            "name": name,
            "type": "file",
        }
        for name, value in checksums.items()
    ]
    sbom = {
        "bomFormat": "CycloneDX",
        "components": components,
        "metadata": {
            "component": {
                "bom-ref": f"pkg:pypi/sigma-framework@{version}",
                "licenses": [{"license": {"id": "AGPL-3.0-or-later"}}],
                "name": "sigma-framework",
                "purl": f"pkg:pypi/sigma-framework@{version}",
                "type": "library",
                "version": version,
            },
            "properties": [
                {"name": "sigma:generator-python", "value": platform.python_version()},
                {"name": "sigma:runtime-dependencies", "value": "none"},
                {"name": "sigma:git-commit", "value": commit},
                {"name": "sigma:git-tag", "value": tag},
                {"name": "sigma:git-dirty", "value": str(dirty).lower()},
                {
                    "name": "sigma:context-wire-version",
                    "value": str(axes["CONTEXT_WIRE_VERSION"]),
                },
                {
                    "name": "sigma:digest-wire-version",
                    "value": str(axes["DIGEST_WIRE_VERSION"]),
                },
                {
                    "name": "sigma:evidence-wire-version",
                    "value": str(axes["EVIDENCE_WIRE_VERSION"]),
                },
                {
                    "name": "sigma:suite-families",
                    "value": ",".join(suite_families),
                },
            ],
            "tools": {
                "components": [{"name": "scripts/release_artifacts.py", "type": "application"}]
            },
        },
        "serialNumber": f"urn:uuid:{uuid.uuid5(uuid.NAMESPACE_URL, f'pkg:pypi/sigma-framework@{version}')}",
        "specVersion": "1.5",
        "version": 1,
    }
    sbom_path = directory / "sigma-framework.cdx.json"
    sbom_path.write_text(json.dumps(sbom, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return checksum_path, sbom_path


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("dist", nargs="?", type=Path, default=Path("dist"))
    parser.add_argument("--require-clean-tag", action="store_true")
    args = parser.parse_args()
    try:
        checksum_path, sbom_path = generate(args.dist, require_clean_tag=args.require_clean_tag)
    except (OSError, ValueError) as exc:
        parser.error(str(exc))
    print(checksum_path)
    print(sbom_path)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
