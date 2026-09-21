"""R15 STAT-01 confirmatory runner for finite 64 MiB streams."""

from __future__ import annotations

import argparse
import hashlib
import json
import platform
import subprocess
import tempfile
from dataclasses import asdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from .common import sha256_file
from .r13_schema import ResourceBudget
from .r15_data import RunKeyV3, atomic_write_record_v3, build_ledger_v3
from .r15_stat_adapters import StreamHasherV3, StreamIdentityV3, derive_stream_seed_v3
from .r15_stat_streams import StatStreamGeneratorV3
from .r141_schema import ConfirmatoryRecordR141, config_from_dict_r141

STAT_CAMPAIGN_ID = "confirmatory-v3-r141-stat"
TOTAL_BYTES = 64 * 1024 * 1024
CHUNK_BYTES = 1024 * 1024
NIST_SEQUENCE_BITS = 1_048_576
NIST_BITSTREAMS = 512


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _write_stream(identity: StreamIdentityV3, path: Path) -> dict[str, object]:
    generator = StatStreamGeneratorV3(identity)
    hasher = StreamHasherV3(chunk_bytes=identity.chunk_bytes)
    with path.open("wb") as handle:
        for chunk in generator.iter_chunks(emit_chunk_bytes=CHUNK_BYTES):
            handle.write(chunk)
            hasher.update(chunk)
    result = hasher.finish()
    if path.stat().st_size != identity.total_bytes:
        raise RuntimeError("STAT stream file length mismatch")
    return result


def _run_nist(
    *,
    binary: Path,
    tool_root: Path,
    stream_file: Path,
    timeout_seconds: int,
) -> tuple[int, str, str]:
    report_path = tool_root / "experiments" / "AlgorithmTesting" / "finalAnalysisReport.txt"
    if report_path.exists():
        report_path.unlink()
    prompt = (
        "0\n"
        f"{stream_file}\n"
        "1\n"
        "0\n"
        f"{NIST_BITSTREAMS}\n"
        "1\n"
    )
    completed = subprocess.run(
        [str(binary), str(NIST_SEQUENCE_BITS)],
        cwd=tool_root,
        input=prompt,
        text=True,
        capture_output=True,
        timeout=timeout_seconds,
        check=False,
    )
    console = completed.stdout + "\n" + completed.stderr
    report = report_path.read_text(encoding="utf-8", errors="replace") if report_path.is_file() else ""
    return completed.returncode, console, report


def _run_practrand(
    *,
    binary: Path,
    stream_file: Path,
    timeout_seconds: int,
) -> tuple[int, str]:
    with stream_file.open("rb") as handle:
        completed = subprocess.run(
            [str(binary), "stdin64", "-tlmin", "1MB", "-tlmax", "64MB"],
            stdin=handle,
            text=True,
            capture_output=True,
            timeout=timeout_seconds,
            check=False,
        )
    return completed.returncode, completed.stdout + "\n" + completed.stderr


def _nist_flagged_lines(report: str) -> int:
    return sum(
        1
        for line in report.splitlines()
        if "*" in line and not set(line.strip()) <= {"*", "-", " "}
    )


def _practrand_counts(output: str) -> tuple[int, int]:
    fail = 0
    suspicious = 0
    for line in output.splitlines():
        if "FAIL" in line:
            fail += 1
        elif "suspicious" in line.lower():
            suspicious += 1
    return fail, suspicious


def _selected_runs(
    config: Any,
    *,
    construction: str | None,
    shard_index: int,
    shard_count: int,
) -> list[tuple[dict[str, Any], int]]:
    selected: list[tuple[dict[str, Any], int]] = []
    ordinal = 0
    for cell in config.cells:
        factors = cell["factors"]
        if construction is not None and str(factors["construction"]) != construction:
            continue
        for replicate_id in range(int(cell["replicates"])):
            if ordinal % shard_count == shard_index:
                selected.append((cell, replicate_id))
            ordinal += 1
    return selected


def run_stat_shard(
    *,
    config_path: Path,
    execution_manifest_path: Path,
    nist_binary: Path,
    nist_root: Path,
    practrand_binary: Path,
    output_root: Path,
    shard_index: int,
    shard_count: int,
    construction: str | None = None,
) -> dict[str, object]:
    if shard_count <= 0 or not 0 <= shard_index < shard_count:
        raise ValueError("invalid shard index/count")

    execution = json.loads(execution_manifest_path.read_text(encoding="utf-8"))
    if execution.get("schema") != "sigma-v3-r15-stat-execution-manifest-v1":
        raise ValueError("unexpected STAT execution manifest schema")
    if execution.get("confirmatory_unlocked") is not True:
        raise ValueError("STAT confirmatory execution is not unlocked")
    if execution.get("external_batteries") != ["nist-sts", "practrand"]:
        raise ValueError("STAT mandatory battery set mismatch")

    config = config_from_dict_r141(json.loads(config_path.read_text(encoding="utf-8")))
    if config.attack_id != "STAT-01":
        raise ValueError("STAT runner requires STAT-01 config")

    config_sha256 = sha256_file(config_path)
    execution_sha256 = sha256_file(execution_manifest_path)
    selected = _selected_runs(
        config,
        construction=construction,
        shard_index=shard_index,
        shard_count=shard_count,
    )

    keys: list[RunKeyV3] = []
    statuses: dict[str, int] = {}
    logs_root = output_root / "logs"

    for cell, replicate_id in selected:
        factors = cell["factors"]
        cell_id = str(cell["cell_id"])
        stream_id = replicate_id
        identity = StreamIdentityV3(
            freeze_id=str(execution["freeze_id"]),
            construction=str(factors["construction"]),
            corpus=str(factors["corpus"]),
            stream_id=stream_id,
            seed_hex=derive_stream_seed_v3(
                str(execution["freeze_id"]),
                str(factors["construction"]),
                str(factors["corpus"]),
                stream_id,
            ).hex(),
            total_bytes=int(factors["bytes_per_stream"]),
            chunk_bytes=CHUNK_BYTES,
        )
        if identity.total_bytes != TOTAL_BYTES:
            raise RuntimeError("STAT confirmatory stream size differs from 64 MiB freeze")

        started = _utc_now()
        declared = ResourceBudget(**cell["budget"])
        metrics: dict[str, int | float | str | bool | None]
        status = "success"
        error_class: str | None = None

        with tempfile.TemporaryDirectory(prefix="sigma-stat-") as temporary:
            stream_file = Path(temporary) / "stream.bin"
            stream_hash = _write_stream(identity, stream_file)
            try:
                nist_code, nist_console, nist_report = _run_nist(
                    binary=nist_binary,
                    tool_root=nist_root,
                    stream_file=stream_file,
                    timeout_seconds=int(cell["timeout_seconds"]),
                )
                practrand_code, practrand_output = _run_practrand(
                    binary=practrand_binary,
                    stream_file=stream_file,
                    timeout_seconds=int(cell["timeout_seconds"]),
                )
            except subprocess.TimeoutExpired as exc:
                status = "timeout"
                error_class = None
                nist_code = -1
                practrand_code = -1
                nist_console = f"timeout: {exc}"
                nist_report = ""
                practrand_output = f"timeout: {exc}"

            nist_flags = _nist_flagged_lines(nist_report)
            practrand_fail, practrand_suspicious = _practrand_counts(practrand_output)
            if status == "success" and (nist_code != 0 or practrand_code != 0):
                status = "error"
                error_class = "ExternalBatteryExit"

            nist_log = logs_root / cell_id / f"{replicate_id:08d}-nist.txt"
            practrand_log = logs_root / cell_id / f"{replicate_id:08d}-practrand.txt"
            nist_log.parent.mkdir(parents=True, exist_ok=True)
            nist_log.write_text(
                nist_console + "\n\n=== finalAnalysisReport ===\n" + nist_report,
                encoding="utf-8",
            )
            practrand_log.write_text(practrand_output, encoding="utf-8")

            metrics = {
                "adjusted_anomaly_rate": None,
                "raw_anomaly_indicator": bool(nist_flags or practrand_fail),
                "nist_flagged_lines": nist_flags,
                "practrand_fail_count": practrand_fail,
                "practrand_suspicious_count": practrand_suspicious,
                "nist_exit_code": nist_code,
                "practrand_exit_code": practrand_code,
                "stream_sha256": str(stream_hash["sha256"]),
                "stream_bytes": int(stream_hash["total_bytes"]),
                "stream_chunk_count": len(stream_hash["chunk_sha256"]),
                "nist_log_sha256": hashlib.sha256(nist_log.read_bytes()).hexdigest(),
                "practrand_log_sha256": hashlib.sha256(practrand_log.read_bytes()).hexdigest(),
            }

        completed = _utc_now()
        record = ConfirmatoryRecordR141.create(
            campaign_id=STAT_CAMPAIGN_ID,
            attack_id="STAT-01",
            claim_ids=config.claims,
            construction=str(factors["construction"]),
            cell_id=cell_id,
            replicate_id=replicate_id,
            declared=declared,
            observed=declared,
            status=status,  # type: ignore[arg-type]
            metrics=metrics,
            censor_reason=None,
            error_class=error_class,
            code_commit=str(execution["source_commit"]),
            artifact_sha256=str(execution["artifact_sha256"]),
            config_sha256=config_sha256,
            preregistration_sha256=str(execution["preregistration_sha256"]),
            dependency_lock_sha256=str(execution["dependency_lock_sha256"]),
            execution_manifest_sha256=execution_sha256,
            host_id="github-stat-runner",
            platform_name=platform.system(),
            architecture=platform.machine(),
            python_version=platform.python_version(),
            started_utc=started,
            completed_utc=completed,
        )
        key = RunKeyV3(record.freeze_id, record.attack_id, record.cell_id, record.replicate_id)
        atomic_write_record_v3(output_root, key, asdict(record))
        keys.append(key)
        statuses[record.status] = statuses.get(record.status, 0) + 1

    ledger = build_ledger_v3(output_root, keys)
    report = {
        "schema": "sigma-v3-r15-stat-shard-report-v1",
        "confirmatory": True,
        "construction": construction,
        "shard_index": shard_index,
        "shard_count": shard_count,
        "selected_run_units": len(selected),
        "written_records": len(keys),
        "statuses": statuses,
        "ledger_root": ledger["root_sha256"],
    }
    return report


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--config", type=Path, required=True)
    parser.add_argument("--execution-manifest", type=Path, required=True)
    parser.add_argument("--nist-binary", type=Path, required=True)
    parser.add_argument("--nist-root", type=Path, required=True)
    parser.add_argument("--practrand-binary", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--shard-index", type=int, required=True)
    parser.add_argument("--shard-count", type=int, required=True)
    parser.add_argument("--construction")
    parser.add_argument("--report", type=Path)
    args = parser.parse_args()
    try:
        report = run_stat_shard(
            config_path=args.config,
            execution_manifest_path=args.execution_manifest,
            nist_binary=args.nist_binary,
            nist_root=args.nist_root,
            practrand_binary=args.practrand_binary,
            output_root=args.output,
            shard_index=args.shard_index,
            shard_count=args.shard_count,
            construction=args.construction,
        )
    except (OSError, RuntimeError, TypeError, ValueError, json.JSONDecodeError) as exc:
        parser.error(str(exc))

    if args.report is not None:
        args.report.parent.mkdir(parents=True, exist_ok=True)
        args.report.write_text(
            json.dumps(report, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )
    print(json.dumps(report, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
