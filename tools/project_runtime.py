#!/usr/bin/env python3
from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import json
import os
from pathlib import Path
import shlex
import shutil
import subprocess
import sys
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
PROFILE_PATH = ROOT / "runtime-profile.json"
LEVELS = ["source", "execution", "regression", "adversarial", "crosscheck", "performance", "formal", "release"]


def load_profile() -> dict[str, Any]:
    if not PROFILE_PATH.exists():
        raise SystemExit(f"missing runtime profile: {PROFILE_PATH}")
    with PROFILE_PATH.open("r", encoding="utf-8") as fh:
        data = json.load(fh)
    if data.get("schema") != 1:
        raise SystemExit(f"unsupported runtime profile schema: {data.get('schema')!r}")
    return data


def cache_root() -> Path:
    root = os.environ.get("PROJECT_RUNTIME_CACHE")
    if root:
        return Path(root).expanduser().resolve()
    return Path.home() / ".cache" / "project-runtime"


def project_cache(profile: dict[str, Any]) -> Path:
    return cache_root() / profile["project"]


def prepend_path(path: Path) -> None:
    current = os.environ.get("PATH", "")
    p = str(path)
    if current.split(os.pathsep)[0] != p:
        os.environ["PATH"] = p + os.pathsep + current


def which(command: str) -> str | None:
    return shutil.which(command)


def run(command: str, *, cwd: Path = ROOT, env: dict[str, str] | None = None, check: bool = False) -> subprocess.CompletedProcess[str]:
    merged = os.environ.copy()
    if env:
        merged.update(env)
    print(f"+ {command}", flush=True)
    proc = subprocess.run(command, cwd=cwd, env=merged, shell=True, text=True)
    if check and proc.returncode != 0:
        raise subprocess.CalledProcessError(proc.returncode, command)
    return proc


def context(profile: dict[str, Any]) -> dict[str, str]:
    pcache = project_cache(profile)
    venv = pcache / "venv"
    python_bin = venv / ("Scripts/python.exe" if os.name == "nt" else "bin/python")
    return {
        "root": str(ROOT),
        "project": profile["project"],
        "cache": str(pcache),
        "shared_cache": str(cache_root()),
        "python": str(python_bin if python_bin.exists() else Path(sys.executable)),
    }


def expand(value: str, ctx: dict[str, str]) -> str:
    return value.format(**ctx)


def env_for(profile: dict[str, Any], ctx: dict[str, str]) -> dict[str, str]:
    env = {
        "PIP_CACHE_DIR": str(cache_root() / "pip"),
        "CARGO_TARGET_DIR": str(cache_root() / "cargo-target" / profile["project"]),
    }
    for key, value in profile.get("environment", {}).items():
        env[key] = expand(str(value), ctx)
    return env


def ensure_python_venv(profile: dict[str, Any]) -> None:
    if not profile.get("toolchains", {}).get("python"):
        return
    pcache = project_cache(profile)
    venv = pcache / "venv"
    python_bin = venv / ("Scripts/python.exe" if os.name == "nt" else "bin/python")
    if python_bin.exists():
        return
    pcache.mkdir(parents=True, exist_ok=True)
    print(f"[hydrate] creating shared venv: {venv}")
    subprocess.run([sys.executable, "-m", "venv", str(venv)], check=True)
    subprocess.run([str(python_bin), "-m", "pip", "install", "--upgrade", "pip", "setuptools", "wheel"], check=True)


def ensure_rust(profile: dict[str, Any]) -> None:
    if not profile.get("toolchains", {}).get("rust"):
        return
    cargo_home = Path(os.environ.get("CARGO_HOME", Path.home() / ".cargo"))
    prepend_path(cargo_home / "bin")
    if which("cargo") and which("rustc"):
        return
    if not which("curl"):
        raise RuntimeError("Rust is missing and curl is unavailable for rustup bootstrap")
    print("[hydrate] Rust missing; bootstrapping rustup (minimal profile)")
    run("curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y --profile minimal", check=True)
    prepend_path(cargo_home / "bin")
    if not which("cargo"):
        raise RuntimeError("rustup bootstrap finished but cargo is still unavailable")
    components = profile.get("toolchains", {}).get("rust_components", ["rustfmt", "clippy"])
    if components and which("rustup"):
        run("rustup component add " + " ".join(shlex.quote(str(x)) for x in components), check=False)


def ensure_lean(profile: dict[str, Any]) -> None:
    if not profile.get("toolchains", {}).get("lean"):
        return
    elan_home = Path(os.environ.get("ELAN_HOME", Path.home() / ".elan"))
    prepend_path(elan_home / "bin")
    if which("lake") and which("lean"):
        return
    if not which("curl"):
        raise RuntimeError("Lean is missing and curl is unavailable for elan bootstrap")
    print("[hydrate] Lean missing; bootstrapping elan")
    run("curl --proto '=https' --tlsv1.2 -sSf https://raw.githubusercontent.com/leanprover/elan/master/elan-init.sh | sh -s -- -y", check=True)
    prepend_path(elan_home / "bin")
    if not which("lake"):
        raise RuntimeError("elan bootstrap finished but lake is still unavailable")


def ensure_cmake(profile: dict[str, Any]) -> None:
    if not profile.get("toolchains", {}).get("cmake"):
        return
    if which("cmake"):
        return
    ensure_python_venv({**profile, "toolchains": {**profile.get("toolchains", {}), "python": True}})
    ctx = context(profile)
    run(f"{shlex.quote(ctx['python'])} -m pip install cmake ninja", check=True)
    prepend_path(Path(ctx["python"]).parent)
    if not which("cmake"):
        raise RuntimeError("cmake installation finished but cmake is still unavailable")


def tool_status(profile: dict[str, Any]) -> list[dict[str, Any]]:
    tools = profile.get("toolchains", {})
    checks: list[tuple[str, str, bool]] = [
        ("python", "python3", bool(tools.get("python"))),
        ("rust", "cargo", bool(tools.get("rust"))),
        ("lean", "lake", bool(tools.get("lean"))),
        ("agda", "agda", bool(tools.get("agda"))),
        ("cmake", "cmake", bool(tools.get("cmake"))),
        ("cxx", "c++", bool(tools.get("cxx"))),
        ("c", "cc", bool(tools.get("c"))),
    ]
    return [{"toolchain": name, "command": cmd, "required": required, "path": which(cmd)} for name, cmd, required in checks if required]


def fingerprint(step: dict[str, Any]) -> str:
    digest = hashlib.sha256()
    digest.update(json.dumps(step, sort_keys=True).encode())
    for rel in step.get("fingerprints", []):
        path = ROOT / rel
        digest.update(rel.encode())
        if path.exists() and path.is_file():
            digest.update(path.read_bytes())
        elif path.exists() and path.is_dir():
            for child in sorted(p for p in path.rglob("*") if p.is_file()):
                digest.update(str(child.relative_to(ROOT)).encode())
                digest.update(child.read_bytes())
        else:
            digest.update(b"<missing>")
    return digest.hexdigest()


def hydrate(profile: dict[str, Any]) -> int:
    pcache = project_cache(profile)
    pcache.mkdir(parents=True, exist_ok=True)
    (cache_root() / "cargo-target" / profile["project"]).mkdir(parents=True, exist_ok=True)
    ensure_python_venv(profile)
    ensure_rust(profile)
    ensure_lean(profile)
    ensure_cmake(profile)
    ctx = context(profile)
    env = env_for(profile, ctx)

    failures = 0
    for step in profile.get("hydration", []):
        sid = step["id"]
        stamp_dir = pcache / "stamps"
        stamp_dir.mkdir(parents=True, exist_ok=True)
        stamp = stamp_dir / f"{sid}.sha256"
        fp = fingerprint(step)
        if stamp.exists() and stamp.read_text(encoding="utf-8").strip() == fp:
            print(f"[hydrate] {sid}: cached")
            continue
        command = expand(step["command"], ctx)
        proc = run(command, env=env)
        if proc.returncode == 0:
            stamp.write_text(fp + "\n", encoding="utf-8")
            print(f"[hydrate] {sid}: ready")
        else:
            failures += 1
            print(f"[hydrate] {sid}: FAILED ({proc.returncode})")
            if step.get("required", True):
                break
    return 1 if failures else 0


def git_head() -> str | None:
    proc = subprocess.run(["git", "rev-parse", "HEAD"], cwd=ROOT, text=True, capture_output=True)
    return proc.stdout.strip() if proc.returncode == 0 else None


def verify(profile: dict[str, Any], level: str) -> int:
    if level not in LEVELS and level != "all":
        raise SystemExit(f"unknown verification level: {level}")
    ctx = context(profile)
    env = env_for(profile, ctx)
    selected = [o for o in profile.get("obligations", []) if level == "all" or o.get("level") == level]
    evidence: dict[str, Any] = {
        "schema": 1,
        "project": profile["project"],
        "git_head": git_head(),
        "started_at": dt.datetime.now(dt.timezone.utc).isoformat(),
        "requested_level": level,
        "results": [],
    }
    failed = False
    for ob in selected:
        oid = ob["id"]
        kind = ob.get("kind", "command")
        required = bool(ob.get("required", True))
        if kind == "manual":
            print(f"[PENDING_MANUAL] {oid}: {ob.get('description', '')}")
            evidence["results"].append({"id": oid, "kind": kind, "required": required, "status": "PENDING_MANUAL"})
            continue
        command = expand(ob["command"], ctx)
        proc = run(command, env=env)
        status = "PASS" if proc.returncode == 0 else "FAIL"
        print(f"[{status}] {oid}")
        evidence["results"].append({"id": oid, "kind": kind, "required": required, "command": command, "returncode": proc.returncode, "status": status})
        if required and proc.returncode != 0:
            failed = True
            if not ob.get("continue_on_failure", False):
                break
    evidence["finished_at"] = dt.datetime.now(dt.timezone.utc).isoformat()
    evidence_dir = project_cache(profile) / "evidence"
    evidence_dir.mkdir(parents=True, exist_ok=True)
    stamp = dt.datetime.now(dt.timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    path = evidence_dir / f"{stamp}-{level}.json"
    path.write_text(json.dumps(evidence, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(f"[evidence] {path}")
    return 1 if failed else 0


def print_plan(profile: dict[str, Any]) -> None:
    for level in LEVELS:
        obs = [o for o in profile.get("obligations", []) if o.get("level") == level]
        if not obs:
            continue
        print(f"\n{level.upper()}")
        for ob in obs:
            marker = "manual" if ob.get("kind") == "manual" else "exec"
            req = "required" if ob.get("required", True) else "optional"
            print(f"  {ob['id']}: {marker}, {req} - {ob.get('description', '')}")


def main() -> int:
    parser = argparse.ArgumentParser(description="Project-local runtime hydration and verification contract")
    sub = parser.add_subparsers(dest="command", required=True)
    sub.add_parser("doctor")
    sub.add_parser("hydrate")
    verify_parser = sub.add_parser("verify")
    verify_parser.add_argument("level", nargs="?", default="all", choices=[*LEVELS, "all"])
    sub.add_parser("plan")
    sub.add_parser("quick")
    sub.add_parser("full")
    args = parser.parse_args()
    profile = load_profile()

    if args.command == "doctor":
        missing = False
        for row in tool_status(profile):
            status = "OK" if row["path"] else "MISSING"
            print(f"[{status}] {row['toolchain']}: {row['path'] or row['command']}")
            missing |= row["required"] and not row["path"]
        return 1 if missing else 0
    if args.command == "hydrate":
        return hydrate(profile)
    if args.command == "verify":
        return verify(profile, args.level)
    if args.command == "plan":
        print_plan(profile)
        return 0
    if args.command == "quick":
        if hydrate(profile):
            return 1
        for level in ("execution", "regression"):
            if verify(profile, level):
                return 1
        return 0
    if args.command == "full":
        if hydrate(profile):
            return 1
        return verify(profile, "all")
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
