"""Verify that frozen Sigma v2.2 semantic assets remain byte-identical."""

from __future__ import annotations

import argparse
import hashlib
import json
import subprocess
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
DEFAULT_MANIFEST = PROJECT_ROOT / "constraints" / "v2-2-baseline.sha256"
LOCAL_ARTIFACT_MANIFEST = PROJECT_ROOT / "constraints" / "v2-2-local-artifacts.sha256"
F7_SNAPSHOT = PROJECT_ROOT / "constraints" / "v2-2-f7-snapshot.json"
BASELINE_COMMIT = "19fb70356971bc1bacb94a19e5e6e48e9e070167"
BASELINE_ROOTS = ("sigma", "reference", "specification")


def load_manifest(path: Path = DEFAULT_MANIFEST) -> dict[Path, str]:
    entries: dict[Path, str] = {}
    for line_number, raw_line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        try:
            digest, relative = line.split(maxsplit=1)
        except ValueError as exc:
            raise ValueError(f"invalid baseline manifest line {line_number}") from exc
        relative_path = Path(relative)
        if relative_path.is_absolute() or ".." in relative_path.parts:
            raise ValueError(f"unsafe baseline path on line {line_number}: {relative}")
        if len(digest) != 64 or any(char not in "0123456789abcdef" for char in digest):
            raise ValueError(f"invalid SHA-256 on line {line_number}")
        if relative_path in entries:
            raise ValueError(f"duplicate baseline path on line {line_number}: {relative}")
        entries[relative_path] = digest
    if not entries:
        raise ValueError("empty v2.2 baseline manifest")
    return entries


def _git_blob(root: Path, relative: Path) -> bytes | None:
    """Return canonical Git bytes for one tracked path.

    This deliberately bypasses platform checkout transformations such as CRLF
    conversion. The v2.2 freeze protects versioned Git objects, not a runner's
    working-tree newline policy.
    """

    result = subprocess.run(
        ["git", "show", f"HEAD:{relative.as_posix()}"],
        cwd=root,
        check=False,
        capture_output=True,
    )
    return result.stdout if result.returncode == 0 else None


def verify_baseline(
    root: Path = PROJECT_ROOT,
    manifest: Path = DEFAULT_MANIFEST,
) -> list[str]:
    failures: list[str] = []
    use_git_blobs = manifest.resolve() == DEFAULT_MANIFEST.resolve() and (root / ".git").exists()
    for relative, expected in load_manifest(manifest).items():
        if use_git_blobs:
            data = _git_blob(root, relative)
            if data is None:
                failures.append(f"missing: {relative}")
                continue
        else:
            target = root / relative
            if not target.is_file():
                failures.append(f"missing: {relative}")
                continue
            data = target.read_bytes()
        actual = hashlib.sha256(data).hexdigest()
        if actual != expected:
            failures.append(f"changed: {relative} ({actual}, expected {expected})")
    return failures


def baseline_paths(root: Path = PROJECT_ROOT) -> set[Path]:
    result = subprocess.run(
        [
            "git",
            "ls-tree",
            "-r",
            "--name-only",
            BASELINE_COMMIT,
            *BASELINE_ROOTS,
        ],
        cwd=root,
        check=True,
        capture_output=True,
        text=True,
    )
    return {Path(line) for line in result.stdout.splitlines() if line}


def verify_manifest_completeness(
    manifest: Path = DEFAULT_MANIFEST,
    root: Path = PROJECT_ROOT,
) -> list[str]:
    expected = baseline_paths(root)
    actual = set(load_manifest(manifest))
    failures = [f"unprotected: {path}" for path in sorted(expected - actual)]
    failures.extend(f"not in baseline: {path}" for path in sorted(actual - expected))
    return failures


def verify_f7_snapshot(
    root: Path = PROJECT_ROOT,
    snapshot: Path = F7_SNAPSHOT,
) -> list[str]:
    record = json.loads(snapshot.read_text(encoding="utf-8"))
    command = record["tar_command"]
    if not isinstance(command, list) or not all(isinstance(item, str) for item in command):
        raise ValueError("invalid F7 tar command")
    process = subprocess.Popen(
        command,
        cwd=root,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    if process.stdout is None or process.stderr is None:  # pragma: no cover
        raise RuntimeError("failed to capture tar streams")
    stdout = process.stdout
    stderr_stream = process.stderr
    digest = hashlib.sha256()
    for chunk in iter(lambda: stdout.read(1024 * 1024), b""):
        digest.update(chunk)
    stderr = stderr_stream.read().decode("utf-8", errors="replace")
    return_code = process.wait()
    if return_code:
        return [f"F7 snapshot command failed ({return_code}): {stderr.strip()}"]
    actual = digest.hexdigest()
    expected = record["tar_sha256"]
    if actual != expected:
        return [f"F7 snapshot changed: {actual} (expected {expected})"]
    return []


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--manifest", type=Path, default=DEFAULT_MANIFEST)
    parser.add_argument(
        "--verify-local-artifacts",
        action="store_true",
        help="also verify ignored local release artifacts",
    )
    parser.add_argument(
        "--verify-f7-snapshot",
        action="store_true",
        help="also stream and verify the ignored local F7 snapshot",
    )
    args = parser.parse_args(argv)
    failures = verify_manifest_completeness(manifest=args.manifest)
    failures.extend(verify_baseline(manifest=args.manifest))
    if args.verify_local_artifacts:
        failures.extend(verify_baseline(manifest=LOCAL_ARTIFACT_MANIFEST))
    if args.verify_f7_snapshot:
        failures.extend(verify_f7_snapshot())
    if failures:
        print("Sigma v2.2 baseline verification failed:")
        for failure in failures:
            print(f"- {failure}")
        return 1
    print("Sigma v2.2 baseline verification passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
