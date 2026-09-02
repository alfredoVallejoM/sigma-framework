import json
import subprocess
import sys
from pathlib import Path

from sigma.outputs import SigmaDigestV2
from sigma.vectors import REFERENCE_STREAM_WIDE_ABC


def run_cli(*arguments: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, "-m", "sigma.cli_v2", *arguments],
        check=False,
        capture_output=True,
        text=True,
    )


def test_cli_hash_inspect_and_verify_round_trip() -> None:
    hashed = run_cli(
        "hash",
        "--text",
        "abc",
        "--preset",
        "lightweight-v2",
        "--target-round",
        "2",
        "--state-count",
        "3",
        "--format",
        "json",
    )
    assert hashed.returncode == 0, hashed.stderr
    digest = SigmaDigestV2.from_json(hashed.stdout)

    inspected = run_cli("inspect", digest.hex())
    assert inspected.returncode == 0, inspected.stderr
    metadata = json.loads(inspected.stdout)
    assert metadata["suite_name"] == "lightweight-stream-wide-v2-1"
    assert metadata["target_round"] == 2
    assert metadata["state_count"] == 3

    verified = run_cli("verify", digest.to_json(), "--text", "abc")
    rejected = run_cli("verify", digest.hex(), "--text", "abd")
    assert (verified.returncode, verified.stdout.strip()) == (0, "valid")
    assert (rejected.returncode, rejected.stdout.strip()) == (1, "invalid")


def test_cli_file_hash_and_verification(tmp_path: Path) -> None:
    sample = tmp_path / "sample.bin"
    sample.write_bytes(b"\x00binary\xff" * 200)
    hashed = run_cli(
        "hash",
        "--file",
        str(sample),
        "--preset",
        "simultaneous-v2",
        "--workers",
        "2",
    )
    assert hashed.returncode == 0, hashed.stderr
    verified = run_cli("verify", hashed.stdout.strip(), "--file", str(sample))
    assert (verified.returncode, verified.stdout.strip()) == (0, "valid")


def test_cli_canonical_binary_output_and_digest_file(tmp_path: Path) -> None:
    command = [
        sys.executable,
        "-m",
        "sigma.cli_v2",
        "hash",
        "--text",
        "abc",
        "--preset",
        "realtime-v2",
        "--format",
        "binary",
    ]
    hashed = subprocess.run(command, check=False, capture_output=True)
    assert hashed.returncode == 0, hashed.stderr
    digest = SigmaDigestV2.from_bytes(hashed.stdout)
    digest_path = tmp_path / "abc.sigma-v2"
    digest_path.write_bytes(hashed.stdout)

    inspected = run_cli("inspect", "--digest-file", str(digest_path))
    verified = run_cli("verify", "--digest-file", str(digest_path), "--text", "abc")
    assert json.loads(inspected.stdout)["states_hex"] == [state.hex() for state in digest.states]
    assert (verified.returncode, verified.stdout.strip()) == (0, "valid")


def test_cli_requires_digest_or_digest_file() -> None:
    result = run_cli("inspect")
    assert result.returncode == 2
    assert "provide a digest or --digest-file" in result.stderr


def test_cli_vectors_match_frozen_runtime_vector() -> None:
    result = run_cli("vectors")
    assert result.returncode == 0, result.stderr
    assert json.loads(result.stdout) == [REFERENCE_STREAM_WIDE_ABC]


def test_cli_benchmark_emits_raw_observations() -> None:
    result = run_cli(
        "benchmark",
        "--text",
        "abc",
        "--preset",
        "realtime-v2",
        "--repeats",
        "2",
    )
    assert result.returncode == 0, result.stderr
    report = json.loads(result.stdout)
    assert report["repeats"] == 2
    assert len(report["observations_ns"]) == 2
    assert all(value > 0 for value in report["observations_ns"])


def test_cli_rejects_invalid_backend_combination() -> None:
    result = run_cli(
        "hash",
        "--text",
        "abc",
        "--preset",
        "lightweight-v2",
        "--workers",
        "2",
    )
    assert result.returncode == 2
    assert "only valid with a simultaneous preset" in result.stderr


def test_cli_supports_v22_typed_evidence_suite() -> None:
    hashed = run_cli(
        "hash",
        "--text",
        "abc",
        "--preset",
        "lightweight-v2-2",
        "--format",
        "json",
    )
    assert hashed.returncode == 0, hashed.stderr
    digest = SigmaDigestV2.from_json(hashed.stdout)
    assert digest.metadata()["suite_name"] == "lightweight-stream-wide-v2-2"


def test_cli_supports_deep_vector() -> None:
    hashed = run_cli(
        "hash",
        "--text",
        "abc",
        "--preset",
        "paranoid-deep-vector-v2-2",
        "--format",
        "json",
    )
    assert hashed.returncode == 0, hashed.stderr
    digest = SigmaDigestV2.from_json(hashed.stdout)
    assert digest.metadata()["suite_name"] == "paranoid-deep-vector-v2-2"
    assert digest.metadata()["state_size"] == 256
