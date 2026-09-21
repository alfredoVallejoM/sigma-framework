import hashlib
import importlib.metadata
import json
import os
import platform
import random
import subprocess
import sys
import zipfile
from contextlib import suppress
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional

from sigma.policy import DEFAULT_RESOURCE_POLICY
from sigma.version import PACKAGE_VERSION

PROJECT_ROOT = Path(__file__).resolve().parents[1]


def canonical_json(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode("utf-8")


def derived_random(master_seed: str, label: str) -> random.Random:
    material = hashlib.sha256(f"sigma-exp-v1\0{master_seed}\0{label}".encode()).digest()
    return random.Random(int.from_bytes(material, "big"))


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as reader:
        for chunk in iter(lambda: reader.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _git(args: list[str]) -> str:
    result = subprocess.run(["git", *args], check=False, capture_output=True, text=True, timeout=10)
    return result.stdout.strip() if result.returncode == 0 else "unavailable"


def _optional_text(path: Path) -> Optional[str]:
    with suppress(OSError, UnicodeError):
        value = path.read_text(encoding="utf-8").strip()
        return value or None
    return None


def _host_measurement_state() -> dict[str, Any]:
    """Best-effort host controls, with missing values represented explicitly."""
    governor = _optional_text(Path("/sys/devices/system/cpu/cpu0/cpufreq/scaling_governor"))
    frequency_khz = _optional_text(Path("/sys/devices/system/cpu/cpu0/cpufreq/scaling_cur_freq"))
    temperatures_millicelsius: dict[str, int] = {}
    for zone in sorted(Path("/sys/class/thermal").glob("thermal_zone*")):
        value = _optional_text(zone / "temp")
        if value is not None:
            with suppress(ValueError):
                temperatures_millicelsius[zone.name] = int(value)
    return {
        "cpu_frequency_khz_snapshot": int(frequency_khz) if frequency_khz else None,
        "cpu_governor": governor,
        "temperature_millicelsius": temperatures_millicelsius or None,
    }


def host_measurement_state() -> dict[str, Any]:
    """Return a timestamped, best-effort snapshot of measurement controls."""
    return {
        **_host_measurement_state(),
        "captured_utc": datetime.now(timezone.utc).isoformat(),
    }


def _microcode_version() -> Optional[str]:
    value = _optional_text(Path("/sys/devices/system/cpu/cpu0/microcode/version"))
    if value is not None:
        return value
    cpuinfo = _optional_text(Path("/proc/cpuinfo"))
    if cpuinfo is not None:
        for line in cpuinfo.splitlines():
            if line.lower().startswith("microcode") and ":" in line:
                return line.split(":", 1)[1].strip() or None
    return None


def _wheel_metadata(path: Path) -> dict[str, object] | None:
    if path.suffix != ".whl" or not path.is_file():
        return None
    try:
        with zipfile.ZipFile(path) as archive:
            metadata_names = [
                name for name in archive.namelist() if name.endswith(".dist-info/METADATA")
            ]
            if len(metadata_names) != 1:
                return None
            fields: dict[str, str] = {}
            for line in archive.read(metadata_names[0]).decode("utf-8").splitlines():
                if ": " in line:
                    key, value = line.split(": ", 1)
                    fields.setdefault(key, value)
        return {
            "filename": path.name,
            "name": fields.get("Name"),
            "path": str(path.resolve()),
            "sha256": sha256_file(path),
            "size": path.stat().st_size,
            "version": fields.get("Version"),
        }
    except (OSError, UnicodeError, zipfile.BadZipFile):
        return None


def _installed_artifact_binding(
    artifact: dict[str, object] | None, sigma_path: Path
) -> tuple[bool, str | None, str | None]:
    """Prove that the imported distribution was installed from the declared wheel."""

    if artifact is None:
        return False, None, None
    try:
        distribution = importlib.metadata.distribution("sigma-framework")
        distribution_root = Path(str(distribution.locate_file(""))).resolve()
        direct_url_text = distribution.read_text("direct_url.json")
        direct_url = json.loads(direct_url_text) if direct_url_text else {}
    except (importlib.metadata.PackageNotFoundError, json.JSONDecodeError, OSError, TypeError):
        return False, None, None
    archive_info = direct_url.get("archive_info") if isinstance(direct_url, dict) else None
    hashes = archive_info.get("hashes") if isinstance(archive_info, dict) else None
    installed_sha256 = hashes.get("sha256") if isinstance(hashes, dict) else None
    bound = (
        distribution_root in sigma_path.parents
        and isinstance(installed_sha256, str)
        and installed_sha256 == artifact.get("sha256")
    )
    return (
        bound,
        str(distribution_root),
        installed_sha256 if isinstance(installed_sha256, str) else None,
    )


def environment_manifest(config: dict[str, Any], command: list[str]) -> dict[str, Any]:
    dependencies: dict[str, Optional[str]] = {}
    for name in ("argon2-cffi", "matplotlib", "numpy", "scipy"):
        try:
            dependencies[name] = importlib.metadata.version(name)
        except importlib.metadata.PackageNotFoundError:
            dependencies[name] = None
    affinity = None
    if hasattr(os, "sched_getaffinity"):
        affinity = sorted(os.sched_getaffinity(0))
    ram_bytes = None
    with suppress(AttributeError, OSError, ValueError):
        ram_bytes = os.sysconf("SC_PAGE_SIZE") * os.sysconf("SC_PHYS_PAGES")
    git_tag = _git(["describe", "--tags", "--exact-match"])
    dirty = _git(["status", "--porcelain"]) != ""
    artifact_path = config.get("artifact_path")
    artifact = None
    if isinstance(artifact_path, str):
        artifact = _wheel_metadata(Path(artifact_path))
    sigma_file = __import__("sigma").__file__
    if sigma_file is None:
        raise RuntimeError("sigma package has no filesystem origin")
    sigma_path = Path(sigma_file).resolve()
    artifact_matches_package = (
        artifact is not None
        and artifact["name"] == "sigma-framework"
        and artifact["version"] == PACKAGE_VERSION
    )
    installed_artifact_bound, distribution_root, installed_artifact_sha256 = (
        _installed_artifact_binding(artifact, sigma_path)
    )
    return {
        "affinity": affinity,
        "command": command,
        "compiler": platform.python_compiler(),
        "config_sha256": hashlib.sha256(canonical_json(config)).hexdigest(),
        "cpu_count": os.cpu_count(),
        "dependencies": dependencies,
        "dirty": dirty,
        "executable": sys.executable,
        "experiment": config["experiment"],
        "git_commit": _git(["rev-parse", "HEAD"]),
        "git_exact_tag": None if git_tag == "unavailable" else git_tag,
        "master_seed": config["master_seed"],
        "platform": platform.platform(),
        "processor": platform.processor(),
        "microcode": _microcode_version(),
        "python": platform.python_version(),
        "ram_bytes": ram_bytes,
        "resource_policy": DEFAULT_RESOURCE_POLICY.as_dict(),
        "seed_derivation": "SHA-256('sigma-exp-v1\\0' || master_seed || '\\0' || label)",
        "host_measurement_state": host_measurement_state(),
        "release_artifact": artifact,
        "release_artifact_sha256": artifact["sha256"] if artifact else None,
        "installed_distribution_root": distribution_root,
        "installed_from_artifact_sha256": installed_artifact_sha256,
        "runner_import_path": str(Path(__file__).resolve()),
        "sigma_import_path": str(sigma_path),
        "sigma_package_version": PACKAGE_VERSION,
        "executing_installed_artifact": installed_artifact_bound and artifact_matches_package,
        "publishable_source": not dirty
        and git_tag != "unavailable"
        and installed_artifact_bound
        and artifact_matches_package,
        "schema": "sigma-experiment-manifest-v2",
        "started_utc": datetime.now(timezone.utc).isoformat(),
    }
