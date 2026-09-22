"""Reproducible ST1 closure gate for Sigma Manifest V1."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import platform
import random
import tempfile
import time
from pathlib import Path

from reference.manifest_v1 import (
    build_directory_wire as reference_directory_wire,
    manifest_wire as reference_manifest_wire,
)
from sigma.tree import (
    ManifestEntryKind,
    ManifestEntryV1,
    ManifestV1,
    SymlinkPolicy,
    build_directory_manifest,
    build_tree,
    manifest_from_entries,
)

MIN_PATH_CASES = 50_000
MIN_DIFFERENTIAL_CASES = 1_000
MIN_PERMUTATION_CASES = 1_000
MIN_FUZZ_CASES = 50_000


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _entry(path: str, payload: bytes, trajectory: bytes | None = None) -> ManifestEntryV1:
    root = build_tree(payload)
    return ManifestEntryV1(
        path,
        ManifestEntryKind.FILE,
        len(payload),
        root,
        trajectory,
    )


def _write_fixture(root: Path) -> None:
    (root / "alpha").mkdir()
    (root / "alpha" / "empty").mkdir()
    (root / "beta").mkdir()
    (root / "alpha" / "a.bin").write_bytes(b"A" * 3)
    (root / "beta" / "chunk.bin").write_bytes(bytes(i % 251 for i in range(65_537)))
    (root / "caf\u00e9.txt").write_bytes("caf\u00e9".encode("utf-8"))
    (root / "\u03a9.txt").write_bytes(b"omega")


def _raw_fields(encoded: bytes) -> list[tuple[int, bytes]]:
    body_length = int.from_bytes(encoded[10:14], "big")
    if body_length != len(encoded) - 14:
        raise AssertionError("seed record length mismatch")
    fields = []
    offset = 14
    while offset < len(encoded):
        if offset + 6 > len(encoded):
            raise AssertionError("truncated seed TLV")
        tag = int.from_bytes(encoded[offset : offset + 2], "big")
        length = int.from_bytes(encoded[offset + 2 : offset + 6], "big")
        offset += 6
        end = offset + length
        if end > len(encoded):
            raise AssertionError("truncated seed TLV value")
        fields.append((tag, encoded[offset:end]))
        offset = end
    return fields


def _raw_record(template: bytes, fields: list[tuple[int, bytes]]) -> bytes:
    body = b"".join(
        tag.to_bytes(2, "big") + len(value).to_bytes(4, "big") + value
        for tag, value in fields
    )
    return template[:10] + len(body).to_bytes(4, "big") + body


def _schema_mutations(encoded: bytes) -> list[bytes]:
    fields = _raw_fields(encoded)
    values = []
    for index, field in enumerate(fields):
        values.append(_raw_record(encoded, fields[:index] + fields[index + 1 :]))
        values.append(
            _raw_record(
                encoded,
                fields[: index + 1] + [field] + fields[index + 1 :],
            )
        )
    if len(fields) >= 2:
        reordered = list(fields)
        reordered[0], reordered[1] = reordered[1], reordered[0]
        values.append(_raw_record(encoded, reordered))
    values.append(_raw_record(encoded, fields + [(0xFFFF, b"")]))
    return values


def _platform_reports(
    current: dict[str, object],
    peer_reports: tuple[Path, ...],
) -> tuple[bool, list[dict[str, object]]]:
    reports = [current]
    for path in peer_reports:
        value = json.loads(path.read_text(encoding="utf-8"))
        if value.get("schema") != "sigma-manifest-st1-gate-v1":
            raise ValueError(f"invalid ST1 peer report schema: {path}")
        if not value.get("local_passed"):
            raise ValueError(f"peer report did not pass locally: {path}")
        reports.append(value)

    fixture_hashes = {str(report["fixture_manifest_sha256"]) for report in reports}
    systems = {str(report["platform"]) for report in reports}
    complete = len(fixture_hashes) == 1 and {"Linux", "Darwin"} <= systems
    return complete, reports


def run_gate(
    *,
    path_cases: int,
    differential_cases: int,
    permutation_cases: int,
    fuzz_cases: int,
    peer_reports: tuple[Path, ...] = (),
) -> dict[str, object]:
    if path_cases < MIN_PATH_CASES:
        raise ValueError(f"ST1 requires at least {MIN_PATH_CASES} path cases")
    if differential_cases < MIN_DIFFERENTIAL_CASES:
        raise ValueError(
            f"ST1 requires at least {MIN_DIFFERENTIAL_CASES} differential cases"
        )
    if permutation_cases < MIN_PERMUTATION_CASES:
        raise ValueError(
            f"ST1 requires at least {MIN_PERMUTATION_CASES} permutation cases"
        )
    if fuzz_cases < MIN_FUZZ_CASES:
        raise ValueError(f"ST1 requires at least {MIN_FUZZ_CASES} codec mutations")

    started = time.perf_counter()
    rng = random.Random(0x53543147415445)

    # O01/O09: path normalization and UTF-8 byte ordering.
    path_digest = hashlib.sha256()
    alphabet = ("a", "z", "\u03a9", "\u4e2d", "\u00e9", "e\u0301")
    for index in range(path_cases):
        depth = 1 + rng.randrange(4)
        components = [
            f"{alphabet[rng.randrange(len(alphabet))]}{index:x}-{part}"
            for part in range(depth)
        ]
        raw = "/".join(components)
        entry = _entry(raw, b"")
        path_digest.update(entry.path_bytes)

    # O02: traversal/permutation independence.
    base_entries = tuple(
        _entry(f"d{i % 11}/f{i:04d}.bin", i.to_bytes(4, "big"))
        for i in range(256)
    )
    expected_permutation = manifest_from_entries(base_entries).to_bytes()
    for _ in range(permutation_cases):
        values = list(base_entries)
        rng.shuffle(values)
        if manifest_from_entries(values).to_bytes() != expected_permutation:
            raise AssertionError("manifest depends on traversal/input order")

    # O07/O08 + independent oracle.
    differential_digest = hashlib.sha256()
    for case in range(differential_cases):
        logical = []
        product = []
        count = rng.randrange(0, 48)
        for index in range(count):
            payload = rng.randbytes(rng.randrange(0, 4097))
            path = f"d{index % 7}/case-{case:04d}-{index:03d}.bin"
            trajectory = None
            if index % 13 == 0:
                trajectory = b"SIGMA3DG" + rng.randbytes(48)
            logical.append((path, 1, payload, trajectory))
            product.append(_entry(path, payload, trajectory))
        product_wire = manifest_from_entries(product).to_bytes()
        reference_wire = reference_manifest_wire(logical)
        if product_wire != reference_wire:
            raise AssertionError(f"independent manifest divergence at case {case}")
        differential_digest.update(product_wire)

    # O01/O04 plus codec canonicality under mutation.
    seed = manifest_from_entries(
        (
            _entry("a.bin", b"A"),
            _entry("dir/b.bin", b"B" * 257, b"SIGMA3DG" + b"T" * 48),
        )
    )
    seed_wire = seed.to_bytes()
    seed_entry = seed.entries[0]
    mutation_digest = hashlib.sha256()
    rejected = 0
    changed_valid = 0
    codec_seeds = (
        ("entry", seed_entry.to_bytes(), ManifestEntryV1.from_bytes, seed_entry),
        ("manifest", seed_wire, ManifestV1.from_bytes, seed),
    )
    for index in range(fuzz_cases):
        name, encoded, decoder, expected = codec_seeds[index % 2]
        mutated = bytearray(encoded)
        position = rng.randrange(len(mutated))
        mutated[position] ^= 1 << rng.randrange(8)
        raw = bytes(mutated)
        mutation_digest.update(name.encode("ascii") + b"\0" + raw)
        try:
            parsed = decoder(raw)
        except (TypeError, ValueError):
            rejected += 1
        else:
            if parsed == expected:
                raise AssertionError(f"non-injective accepted mutation at {index}")
            changed_valid += 1

    schema_mutations = 0
    for _, encoded, decoder, _ in codec_seeds:
        for raw in _schema_mutations(encoded):
            schema_mutations += 1
            try:
                decoder(raw)
            except (TypeError, ValueError):
                continue
            raise AssertionError("manifest codec accepted structural TLV mutation")

    # O03/O05/O06 and filesystem/reference behavior.
    with tempfile.TemporaryDirectory(prefix="sigma-st1-") as temp:
        temp_root = Path(temp)
        left = temp_root / "left"
        right = temp_root / "right"
        left.mkdir()
        right.mkdir()
        _write_fixture(left)
        _write_fixture(right)

        left_wire = build_directory_manifest(left).to_bytes()
        right_wire = build_directory_manifest(right).to_bytes()
        reference_wire = reference_directory_wire(left)
        if left_wire != right_wire or left_wire != reference_wire:
            raise AssertionError("root independence/reference fixture mismatch")

        os.utime(left / "alpha" / "a.bin", (1_700_000_000, 1_700_000_000))
        if os.name != "nt":
            os.chmod(left / "alpha" / "a.bin", 0o755)
        if build_directory_manifest(left).to_bytes() != left_wire:
            raise AssertionError("base manifest depends on volatile metadata")

        (left / "alpha" / "a.bin").write_bytes(b"changed")
        if build_directory_manifest(left).to_bytes() == left_wire:
            raise AssertionError("file content change did not change manifest")

        symlink_checks = "unavailable"
        if hasattr(os, "symlink"):
            link_root = temp_root / "links"
            link_root.mkdir()
            (link_root / "file").write_bytes(b"x")
            try:
                os.symlink("loop", link_root / "loop")
                os.symlink("../outside", link_root / "escape")
            except OSError:
                symlink_checks = "unavailable"
            else:
                try:
                    build_directory_manifest(link_root)
                except ValueError:
                    pass
                else:
                    raise AssertionError("default symlink policy accepted a link")
                product_links = build_directory_manifest(
                    link_root,
                    symlink_policy=SymlinkPolicy.TEXT,
                ).to_bytes()
                reference_links = reference_directory_wire(
                    link_root,
                    allow_symlinks=True,
                )
                if product_links != reference_links:
                    raise AssertionError("symlink text-mode reference divergence")
                symlink_checks = "passed"

        fixture_hash = _sha256(right_wire)

    current = {
        "schema": "sigma-manifest-st1-gate-v1",
        "platform": platform.system(),
        "python": platform.python_version(),
        "fixture_manifest_sha256": fixture_hash,
        "local_passed": True,
    }
    cross_platform_complete, reports = _platform_reports(current, peer_reports)

    return {
        **current,
        "path_cases": path_cases,
        "differential_cases": differential_cases,
        "permutation_cases": permutation_cases,
        "fuzz_cases": fuzz_cases,
        "fuzz_rejected": rejected,
        "fuzz_changed_valid": changed_valid,
        "schema_mutation_cases": schema_mutations,
        "path_stream_sha256": path_digest.hexdigest(),
        "differential_manifest_stream_sha256": differential_digest.hexdigest(),
        "mutation_stream_sha256": mutation_digest.hexdigest(),
        "symlink_checks": symlink_checks,
        "cross_platform_complete": cross_platform_complete,
        "platform_reports": [
            {
                "platform": report["platform"],
                "fixture_manifest_sha256": report["fixture_manifest_sha256"],
            }
            for report in reports
        ],
        "closure_eligible": cross_platform_complete,
        "elapsed_seconds": time.perf_counter() - started,
        "passed": True,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--path-cases", type=int, default=MIN_PATH_CASES)
    parser.add_argument("--differential-cases", type=int, default=MIN_DIFFERENTIAL_CASES)
    parser.add_argument("--permutation-cases", type=int, default=MIN_PERMUTATION_CASES)
    parser.add_argument("--fuzz-cases", type=int, default=MIN_FUZZ_CASES)
    parser.add_argument("--peer-report", action="append", type=Path, default=[])
    parser.add_argument("--report", type=Path)
    parser.add_argument(
        "--require-cross-platform",
        action="store_true",
        help="fail unless matching Linux and macOS fixture reports are supplied",
    )
    args = parser.parse_args()

    try:
        report = run_gate(
            path_cases=args.path_cases,
            differential_cases=args.differential_cases,
            permutation_cases=args.permutation_cases,
            fuzz_cases=args.fuzz_cases,
            peer_reports=tuple(args.peer_report),
        )
    except ValueError as exc:
        parser.error(str(exc))

    payload = json.dumps(report, indent=2, sort_keys=True) + "\n"
    if args.report is not None:
        args.report.parent.mkdir(parents=True, exist_ok=True)
        args.report.write_text(payload, encoding="utf-8")
    print(payload, end="")
    if args.require_cross_platform and not report["closure_eligible"]:
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
