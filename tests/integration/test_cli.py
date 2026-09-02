import subprocess
import sys


def run_cli(*arguments: str) -> subprocess.CompletedProcess:
    return subprocess.run(
        [sys.executable, "-m", "sigma.cli", *arguments],
        check=False,
        capture_output=True,
        text=True,
    )


def test_cli_help_is_explicitly_legacy_and_safe() -> None:
    result = run_cli("--help")
    assert result.returncode == 0
    assert "legacy v1 research CLI" in result.stdout
    assert "not a password KDF" in result.stdout


def test_cli_reports_failure_with_nonzero_status() -> None:
    result = run_cli("definitely-does-not-exist.sigma")
    assert result.returncode == 1
    assert "File not found" in result.stderr


def test_cli_hashes_text_with_explicit_legacy_mode() -> None:
    result = run_cli("--mode", "legacy-v1-lightweight", "--text", "abc")
    assert result.returncode == 0
    assert result.stdout.startswith("a7d9200d609e4b3b")
