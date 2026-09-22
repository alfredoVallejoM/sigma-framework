from __future__ import annotations

import os
import random
from pathlib import Path

import pytest

from reference.manifest_v1 import build_directory_wire as reference_directory_wire
from reference.manifest_v1 import manifest_wire as reference_manifest_wire
from sigma.tree import (
    ManifestEntryKind,
    ManifestEntryV1,
    SymlinkPolicy,
    build_directory_manifest,
    build_tree,
    empty_root,
    manifest_from_entries,
)


def test_independent_manifest_matches_logical_entries_random_corpus():
    rng = random.Random(0x53543144494646)
    for case in range(250):
        logical = []
        product = []
        count = rng.randrange(0, 40)
        for index in range(count):
            payload = rng.randbytes(rng.randrange(0, 4096))
            path = f"d{index % 5}/case-{case:03d}-{index:03d}.bin"
            trajectory = None
            if index % 11 == 0:
                trajectory = b"SIGMA3DG" + rng.randbytes(48)
            logical.append((path, 1, payload, trajectory))
            root = build_tree(payload)
            product.append(
                ManifestEntryV1(
                    path,
                    ManifestEntryKind.FILE,
                    len(payload),
                    root,
                    trajectory,
                )
            )
        assert manifest_from_entries(tuple(product)).to_bytes() == reference_manifest_wire(logical)


def _fixture(root: Path) -> None:
    (root / "alpha").mkdir()
    (root / "alpha" / "empty").mkdir()
    (root / "alpha" / "a.bin").write_bytes(b"A" * 3)
    (root / "\u03a9.txt").write_bytes(b"omega")
    (root / "caf\u00e9.txt").write_bytes(b"unicode")


def test_independent_directory_scanner_matches_product(tmp_path: Path):
    root = tmp_path / "fixture"
    root.mkdir()
    _fixture(root)
    assert build_directory_manifest(root).to_bytes() == reference_directory_wire(root)


def test_independent_scanner_matches_symlink_text_mode(tmp_path: Path):
    if not hasattr(os, "symlink"):
        pytest.skip("symlink API unavailable")
    root = tmp_path / "fixture"
    root.mkdir()
    (root / "file").write_bytes(b"x")
    try:
        os.symlink("../target", root / "link")
    except OSError:
        pytest.skip("symlink creation unavailable")
    assert build_directory_manifest(
        root,
        symlink_policy=SymlinkPolicy.TEXT,
    ).to_bytes() == reference_directory_wire(root, allow_symlinks=True)


def test_directory_and_symlink_payload_rules_match_reference():
    product = manifest_from_entries(
        (
            ManifestEntryV1("empty", ManifestEntryKind.DIRECTORY, 0, empty_root()),
            ManifestEntryV1(
                "link",
                ManifestEntryKind.SYMLINK,
                6,
                build_tree(b"target"),
            ),
        )
    )
    reference = reference_manifest_wire(
        (
            ("empty", 2, b"", None),
            ("link", 3, b"target", None),
        )
    )
    assert product.to_bytes() == reference
