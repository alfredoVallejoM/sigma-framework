#!/usr/bin/env python3
"""Run the authoritative local Sigma validation gate in isolated work areas."""

from __future__ import annotations

import argparse
import json
import os
import shutil
import subprocess
import sys
import tempfile
import time
import venv
from dataclasses import asdict, dataclass
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
COVERAGE_TARGETS = {
    "core_formats": (("sigma/spec", "sigma/validation.py", "sigma/presets.py"), 95.0),
    "experimental_scheduler": (("experiments/runner.py", "experiments/task_worker.py"), 90.0),
    "history_feedback": (
        (
            "sigma/binding/history.py",
            "sigma/layout/history.py",
            "sigma/rounds/history_framing_v3.py",
            "sigma/rounds/history_v3.py",
        ),
        90.0,
    ),
    "release_tooling": (
        (
            "scripts/fuzz_codecs.py",
            "scripts/generate_conformance_vectors.py",
            "scripts/release_artifacts.py",
        ),
        85.0,
    ),
}


@dataclass(frozen=True)
class StageResult:
    name: str
    command: list[str]
    seconds: float
    returncode: int


def _run(
    name: str,
    command: list[str],
    *,
    cwd: Path = PROJECT_ROOT,
    env: dict[str, str] | None = None,
) -> StageResult:
    started = time.monotonic()
    completed = subprocess.run(command, cwd=cwd, env=env, check=False)
    result = StageResult(name, command, time.monotonic() - started, completed.returncode)
    if completed.returncode != 0:
        raise RuntimeError(f"gate stage failed: {name} (exit {completed.returncode})")
    return result


def _coverage_percent(report: dict[str, object], paths: tuple[str, ...]) -> float:
    files = report.get("files")
    if not isinstance(files, dict):
        raise ValueError("coverage JSON has no files object")
    covered = 0
    statements = 0
    for name, value in files.items():
        if not isinstance(name, str) or not any(
            name == path or name.startswith(path + "/") for path in paths
        ):
            continue
        if not isinstance(value, dict) or not isinstance(value.get("summary"), dict):
            raise ValueError(f"invalid coverage entry: {name}")
        summary = value["summary"]
        covered += int(summary["covered_lines"])
        statements += int(summary["num_statements"])
    if statements == 0:
        raise ValueError(f"coverage group contains no statements: {paths}")
    return covered * 100.0 / statements


def _check_coverage(path: Path) -> dict[str, float]:
    report = json.loads(path.read_text(encoding="utf-8"))
    measured = {
        label: _coverage_percent(report, paths)
        for label, (paths, _minimum) in COVERAGE_TARGETS.items()
    }
    failed = {
        label: (measured[label], minimum)
        for label, (_paths, minimum) in COVERAGE_TARGETS.items()
        if measured[label] < minimum
    }
    if failed:
        details = ", ".join(
            f"{label}={actual:.2f}% < {minimum:.2f}%" for label, (actual, minimum) in failed.items()
        )
        raise RuntimeError(f"coverage targets not met: {details}")
    measured["overall_observed"] = _coverage_percent(
        report, ("sigma", "experiments", "scripts", "reference")
    )
    return measured


def _check_artifact_cleanliness() -> None:
    completed = subprocess.run(
        ["git", "status", "--porcelain", "--untracked-files=all", "--ignored"],
        cwd=PROJECT_ROOT,
        check=True,
        capture_output=True,
        text=True,
    )
    forbidden = []
    for line in completed.stdout.splitlines():
        path = line[3:].removesuffix("/")
        if (
            path == "build"
            or path.startswith(("build/", "dist/", "htmlcov/"))
            or path.endswith(".egg-info")
            or ".egg-info/" in path
            or path in {".coverage", "coverage.json"}
        ):
            forbidden.append(path)
    if forbidden:
        raise RuntimeError(f"accidental project artifacts detected: {sorted(forbidden)}")


def _isolated_install_and_cli(wheel: Path, root: Path) -> list[StageResult]:
    environment = root / "venv"
    venv.EnvBuilder(with_pip=True, clear=True).create(environment)
    binary = "Scripts" if os.name == "nt" else "bin"
    python = environment / binary / ("python.exe" if os.name == "nt" else "python")
    sigmahash = environment / binary / ("sigmahash.exe" if os.name == "nt" else "sigmahash")
    sigmahash_v2 = (
        environment / binary / ("sigmahash-v2.exe" if os.name == "nt" else "sigmahash-v2")
    )
    scratch = root / "outside-checkout"
    scratch.mkdir()
    results = [
        _run(
            "install-wheel",
            [str(python), "-m", "pip", "install", "--no-deps", str(wheel)],
            cwd=scratch,
        ),
        _run(
            "import-installed-wheel",
            [
                str(python),
                "-I",
                "-c",
                (
                    "import pathlib,sigma,experiments,reference; "
                    "paths=(pathlib.Path(sigma.__file__).resolve(),"
                    "pathlib.Path(experiments.__file__).resolve(),"
                    "pathlib.Path(reference.__file__).resolve()); "
                    f"root=pathlib.Path({str(PROJECT_ROOT)!r}).resolve(); "
                    "assert all(root not in p.parents for p in paths), paths; print(*paths)"
                ),
            ],
            cwd=scratch,
        ),
        _run(
            "smoke-installed-experiment-runner",
            [str(python), "-I", "-m", "experiments.runner", "--help"],
            cwd=scratch,
        ),
        _run(
            "smoke-sigmahash",
            [
                str(sigmahash),
                "hash",
                "--text",
                "gate",
                "--preset",
                "lightweight-v2-2",
            ],
            cwd=scratch,
        ),
        _run(
            "smoke-sigmahash-v2",
            [
                str(sigmahash_v2),
                "hash",
                "--text",
                "gate",
                "--preset",
                "reference-v2-2",
            ],
            cwd=scratch,
        ),
        _run(
            "smoke-installed-history-v3",
            [
                str(python),
                "-I",
                "-c",
                (
                    "from sigma.sources import BytesSource; "
                    "from sigma.spec.context_v3 import SigmaContextV3; "
                    "from sigma.spec.ids_v3 import SuiteIdV3; "
                    "from sigma.v3 import evaluate_v3; "
                    "c=SigmaContextV3.for_suite("
                    "SuiteIdV3.REFERENCE_IAP_HISTORY_V3,"
                    "salt=b'gate',challenge=b'gate',application_context=b'gate'); "
                    "e=evaluate_v3(c,BytesSource(b'wheel-history-smoke')); "
                    "assert len(e.histories)==len(e.states)"
                ),
            ],
            cwd=scratch,
        ),
    ]
    return results


def validate(*, fuzz_iterations: int, report_path: Path | None = None) -> dict[str, object]:
    stages: list[StageResult] = []
    _check_artifact_cleanliness()
    with tempfile.TemporaryDirectory(prefix="sigma-local-gate-") as temporary:
        root = Path(temporary)
        coverage_data = root / ".coverage"
        coverage_json = root / "coverage.json"
        distribution = root / "dist"
        source_copy = root / "source"
        distribution.mkdir()
        shutil.copytree(
            PROJECT_ROOT,
            source_copy,
            ignore=shutil.ignore_patterns(
                ".git",
                ".coverage*",
                ".mypy_cache",
                ".pytest_cache",
                ".ruff_cache",
                "__pycache__",
                "build",
                "dist",
                "*.egg-info",
            ),
        )
        coverage_environment = {
            **os.environ,
            "COVERAGE_FILE": str(coverage_data),
            "COVERAGE_PROCESS_START": str(PROJECT_ROOT / "pyproject.toml"),
        }
        stages.extend(
            (
                _run("format", ["ruff", "format", "--check", "."]),
                _run("lint", ["ruff", "check", "."]),
                _run("types", ["mypy", "sigma", "scripts", "experiments", "reference"]),
                _run(
                    "compileall",
                    [
                        sys.executable,
                        "-m",
                        "compileall",
                        "-q",
                        "sigma",
                        "scripts",
                        "experiments",
                        "reference",
                        "tests",
                    ],
                ),
                _run(
                    "v22-baseline-check",
                    [sys.executable, "-m", "scripts.check_v22_baseline"],
                ),
                _run(
                    "r12-corpus-check",
                    [sys.executable, "-m", "scripts.generate_v3_r12_corpus", "--check"],
                ),
                _run(
                    "r125-corpus-check",
                    [sys.executable, "-m", "scripts.generate_v3_r125_corpus", "--check"],
                ),
                _run(
                    "tests-with-coverage",
                    [
                        sys.executable,
                        "-m",
                        "coverage",
                        "run",
                        "-m",
                        "pytest",
                        "-q",
                    ],
                    env=coverage_environment,
                ),
                _run(
                    "coverage-combine",
                    [
                        sys.executable,
                        "-m",
                        "coverage",
                        "combine",
                        f"--data-file={coverage_data}",
                        str(root),
                    ],
                    env=coverage_environment,
                ),
                _run(
                    "coverage-json",
                    [
                        sys.executable,
                        "-m",
                        "coverage",
                        "json",
                        f"--data-file={coverage_data}",
                        "-o",
                        str(coverage_json),
                    ],
                ),
                _run(
                    "r13-design-gate",
                    [
                        sys.executable,
                        "-m",
                        "scripts.check_r13_design",
                    ],
                ),
                _run(
                    "r14-freeze-gate",
                    [
                        sys.executable,
                        "-m",
                        "scripts.check_r14_freeze",
                    ],
                ),
                _run(
                    "r15-plan-gate",
                    [
                        sys.executable,
                        "-m",
                        "scripts.check_r15_plan",
                    ],
                ),
                _run(
                    "r15-execution-closure",
                    [
                        sys.executable,
                        "-m",
                        "scripts.check_r15_execution_closure",
                    ],
                ),
                _run(
                    "r15-data-closure",
                    [
                        sys.executable,
                        "-m",
                        "scripts.check_r15_data_closure",
                    ],
                ),
                _run(
                    "r141-freeze-gate",
                    [
                        sys.executable,
                        "-m",
                        "scripts.check_r141_freeze",
                    ],
                ),
                _run(
                    "r15-preflight-static",
                    [
                        sys.executable,
                        "-m",
                        "scripts.r15_preflight",
                        "--static",
                    ],
                ),
                _run(
                    "mutation-fuzz",
                    [
                        sys.executable,
                        "-m",
                        "scripts.fuzz_codecs",
                        "--iterations",
                        str(fuzz_iterations),
                    ],
                ),
                _run(
                    "build",
                    [
                        sys.executable,
                        "-m",
                        "build",
                        "--outdir",
                        str(distribution),
                    ],
                    cwd=source_copy,
                ),
                _run(
                    "release-metadata",
                    [sys.executable, "-m", "scripts.release_artifacts", str(distribution)],
                ),
            )
        )
        coverage = _check_coverage(coverage_json)
        wheels = sorted(distribution.glob("*.whl"))
        if len(wheels) != 1 or len(list(distribution.glob("*.tar.gz"))) != 1:
            raise RuntimeError("build must produce exactly one wheel and one source archive")
        stages.extend(_isolated_install_and_cli(wheels[0], root))
        _check_artifact_cleanliness()
    report: dict[str, object] = {
        "coverage": coverage,
        "fuzz_iterations_per_codec": fuzz_iterations,
        "passed": True,
        "schema": "sigma-local-gate-v1",
        "stages": [asdict(stage) for stage in stages],
    }
    if report_path is not None:
        report_path.write_text(
            json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8"
        )
    return report


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--fuzz-iterations", type=int, default=10_000)
    parser.add_argument("--report", type=Path)
    args = parser.parse_args()
    if args.fuzz_iterations <= 0:
        parser.error("--fuzz-iterations must be positive")
    try:
        report = validate(fuzz_iterations=args.fuzz_iterations, report_path=args.report)
    except (OSError, RuntimeError, ValueError, subprocess.SubprocessError) as exc:
        parser.error(str(exc))
    print(json.dumps(report, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
