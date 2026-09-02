import hashlib
import importlib.metadata
import json
import os
import platform
import random
import subprocess
import sys
from contextlib import suppress
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional


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
    return {
        "affinity": affinity,
        "command": command,
        "compiler": platform.python_compiler(),
        "config_sha256": hashlib.sha256(canonical_json(config)).hexdigest(),
        "cpu_count": os.cpu_count(),
        "dependencies": dependencies,
        "dirty": _git(["status", "--porcelain"]) != "",
        "executable": sys.executable,
        "experiment": config["experiment"],
        "git_commit": _git(["rev-parse", "HEAD"]),
        "master_seed": config["master_seed"],
        "platform": platform.platform(),
        "processor": platform.processor(),
        "python": platform.python_version(),
        "ram_bytes": ram_bytes,
        "host_measurement_state": _host_measurement_state(),
        "schema": "sigma-experiment-manifest-v1",
        "started_utc": datetime.now(timezone.utc).isoformat(),
    }
