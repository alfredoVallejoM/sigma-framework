from __future__ import annotations

import os
from pathlib import Path

import pytest

from sigma.tree import (
    ManifestEntryKind,
    ManifestEntryV1,
    ManifestV1,
    SymlinkPolicy,
    TreeDecodeError,
    build_directory_manifest,
    build_tree,
    canonical_relative_path,
    empty_root,
    manifest_from_entries,
)


@pytest.mark.parametrize(
    "value",
    [
        "",
        "/absolute",
        "./dot",
        "../parent",
        "a/../b",
        "a/./b",
        "a//b",
        "a\\b",
        "C:/drive",
        "\\server\\share",
        "nul\x00byte",
        "\udcff",
    ],
)
def test_canonical_relative_path_rejects_nonportable_forms(value):
    with pytest.raises((TypeError, ValueError)):
        canonical_relative_path(value)


def test_canonical_relative_path_normalizes_nfc_without_case_folding():
    assert canonical_relative_path("cafe\u0301/A.txt") == "caf\u00e9/A.txt"
    assert canonical_relative_path("A.txt") != canonical_relative_path("a.txt")


def test_manifest_roundtrip_and_entry_types():
    entries = (
        ManifestEntryV1("dir", ManifestEntryKind.DIRECTORY, 0, empty_root()),
        ManifestEntryV1("dir/empty.bin", ManifestEntryKind.FILE, 0, build_tree(b"")),
        ManifestEntryV1("dir/x.bin", ManifestEntryKind.FILE, 3, build_tree(b"abc")),
    )
    manifest = manifest_from_entries(entries)
    encoded = manifest.to_bytes()
    assert ManifestV1.from_bytes(encoded) == manifest
    assert [entry.path for entry in manifest.entries] == [
        "dir",
        "dir/empty.bin",
        "dir/x.bin",
    ]


def test_manifest_rejects_duplicate_after_unicode_normalization():
    a = ManifestEntryV1("e\u0301.txt", ManifestEntryKind.FILE, 1, build_tree(b"a"))
    b = ManifestEntryV1("\u00e9.txt", ManifestEntryKind.FILE, 1, build_tree(b"b"))
    with pytest.raises(ValueError, match="unique canonical"):
        manifest_from_entries((a, b))


def test_directory_entry_requires_canonical_empty_root():
    with pytest.raises(ValueError, match="empty TreeRoot"):
        ManifestEntryV1("dir", ManifestEntryKind.DIRECTORY, 1, build_tree(b"x"))


def test_trajectory_wire_is_bound_exactly():
    root = build_tree(b"payload")
    a = ManifestEntryV1(
        "x.bin",
        ManifestEntryKind.FILE,
        root.byte_length,
        root,
        b"SIGMA3DG" + b"A" * 32,
    )
    b = ManifestEntryV1(
        "x.bin",
        ManifestEntryKind.FILE,
        root.byte_length,
        root,
        b"SIGMA3DG" + b"B" * 32,
    )
    assert manifest_from_entries((a,)).to_bytes() != manifest_from_entries((b,)).to_bytes()


def test_trajectory_wire_is_file_only_and_has_v3_magic():
    root = build_tree(b"x")
    with pytest.raises(ValueError, match="SigmaDigestV3"):
        ManifestEntryV1("x", ManifestEntryKind.FILE, 1, root, b"not-v3")
    with pytest.raises(ValueError, match="regular-file"):
        ManifestEntryV1(
            "dir",
            ManifestEntryKind.DIRECTORY,
            0,
            empty_root(),
            b"SIGMA3DG" + b"x",
        )


def test_manifest_parser_rejects_reordered_entries():
    a = ManifestEntryV1("a", ManifestEntryKind.FILE, 1, build_tree(b"a"))
    b = ManifestEntryV1("b", ManifestEntryKind.FILE, 1, build_tree(b"b"))
    with pytest.raises(ValueError, match="UTF-8 ordering"):
        ManifestV1((b, a))


def _write_fixture(root: Path) -> None:
    (root / "sub").mkdir()
    (root / "empty").mkdir()
    (root / "a.txt").write_bytes(b"A")
    (root / "sub" / "b.bin").write_bytes(b"B" * 70_000)


def test_directory_manifest_is_root_independent_and_metadata_independent(tmp_path: Path):
    left = tmp_path / "left"
    right = tmp_path / "right"
    left.mkdir()
    right.mkdir()
    _write_fixture(left)
    _write_fixture(right)

    before = build_directory_manifest(left).to_bytes()
    assert before == build_directory_manifest(right).to_bytes()

    os.utime(left / "a.txt", (1_700_000_000, 1_700_000_000))
    if os.name != "nt":
        os.chmod(left / "a.txt", 0o755)
    after = build_directory_manifest(left).to_bytes()
    assert before == after


def test_content_and_rename_change_manifest(tmp_path: Path):
    root = tmp_path / "tree"
    root.mkdir()
    (root / "x").write_bytes(b"one")
    original = build_directory_manifest(root).to_bytes()

    (root / "x").write_bytes(b"two")
    changed = build_directory_manifest(root).to_bytes()
    assert changed != original

    (root / "x").rename(root / "y")
    renamed = build_directory_manifest(root).to_bytes()
    assert renamed != changed


def test_empty_directory_is_committed(tmp_path: Path):
    root = tmp_path / "tree"
    root.mkdir()
    baseline = build_directory_manifest(root)
    (root / "empty").mkdir()
    with_empty = build_directory_manifest(root)
    assert baseline.to_bytes() != with_empty.to_bytes()
    assert with_empty.entries[0].kind is ManifestEntryKind.DIRECTORY


def test_symlink_rejected_by_default_and_text_mode_does_not_follow(tmp_path: Path):
    if not hasattr(os, "symlink"):
        pytest.skip("symlink API unavailable")
    root = tmp_path / "tree"
    root.mkdir()
    (root / "file").write_bytes(b"payload")
    try:
        os.symlink("loop", root / "loop")
    except OSError:
        pytest.skip("symlink creation unavailable")

    with pytest.raises(ValueError, match="symbolic link rejected"):
        build_directory_manifest(root)

    manifest = build_directory_manifest(root, symlink_policy=SymlinkPolicy.TEXT)
    loop = next(entry for entry in manifest.entries if entry.path == "loop")
    assert loop.kind is ManifestEntryKind.SYMLINK
    assert loop.tree_root == build_tree(b"loop")


def test_symlink_traversal_target_is_committed_not_followed(tmp_path: Path):
    if not hasattr(os, "symlink"):
        pytest.skip("symlink API unavailable")
    outside = tmp_path / "outside"
    outside.write_bytes(b"secret")
    root = tmp_path / "tree"
    root.mkdir()
    try:
        os.symlink("../outside", root / "escape")
    except OSError:
        pytest.skip("symlink creation unavailable")

    manifest = build_directory_manifest(root, symlink_policy=SymlinkPolicy.TEXT)
    entry = manifest.entries[0]
    assert entry.kind is ManifestEntryKind.SYMLINK
    assert entry.tree_root == build_tree(b"../outside")
    assert outside.read_bytes() == b"secret"


def test_noncanonical_wire_path_rejected():
    entry = ManifestEntryV1("\u00e9", ManifestEntryKind.FILE, 1, build_tree(b"x"))
    encoded = entry.to_bytes()
    # The path payload begins after the record header and first TLV header.
    offset = 14
    assert encoded[offset : offset + 2] == b"\x00\x01"
    length = int.from_bytes(encoded[offset + 2 : offset + 6], "big")
    assert length == len("\u00e9".encode("utf-8"))
    noncanonical = "e\u0301".encode("utf-8")
    body = (
        b"\x00\x01"
        + len(noncanonical).to_bytes(4, "big")
        + noncanonical
        + encoded[offset + 6 + length :]
    )
    mutated = encoded[:10] + len(body).to_bytes(4, "big") + body
    with pytest.raises(TreeDecodeError):
        ManifestEntryV1.from_bytes(mutated)
