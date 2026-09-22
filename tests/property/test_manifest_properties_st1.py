from __future__ import annotations

import random

from sigma.tree import (
    ManifestEntryKind,
    ManifestEntryV1,
    build_tree,
    manifest_from_entries,
)


def _entry(path: str, payload: bytes) -> ManifestEntryV1:
    root = build_tree(payload)
    return ManifestEntryV1(path, ManifestEntryKind.FILE, len(payload), root)


def test_manifest_is_invariant_under_entry_permutations():
    rng = random.Random(0x5354315045524D)
    entries = tuple(
        _entry(f"d{i % 7}/f{i:03d}.bin", rng.randbytes((i * 17) % 257))
        for i in range(120)
    )
    expected = manifest_from_entries(entries).to_bytes()
    for _ in range(250):
        shuffled = list(entries)
        rng.shuffle(shuffled)
        assert manifest_from_entries(tuple(shuffled)).to_bytes() == expected


def test_manifest_utf8_order_is_byte_lexicographic_after_nfc():
    entries = (
        _entry("z", b"1"),
        _entry("\u03a9", b"2"),
        _entry("\u00e9", b"3"),
        _entry("a", b"4"),
        _entry("\u4e2d", b"5"),
    )
    manifest = manifest_from_entries(entries)
    keys = [entry.path.encode("utf-8") for entry in manifest.entries]
    assert keys == sorted(keys)


def test_manifest_content_binding_random_corpus():
    rng = random.Random(0x53543142494E44)
    for index in range(200):
        payload = rng.randbytes(rng.randrange(0, 8192))
        path = f"data/{index:04d}.bin"
        first = manifest_from_entries((_entry(path, payload),)).to_bytes()
        changed = bytearray(payload or b"\x00")
        changed[rng.randrange(len(changed))] ^= 1
        second = manifest_from_entries((_entry(path, bytes(changed)),)).to_bytes()
        assert first != second


def test_manifest_trajectory_binding_random_corpus():
    rng = random.Random(0x5354315452414A)
    for index in range(100):
        payload = rng.randbytes(rng.randrange(0, 1024))
        root = build_tree(payload)
        a = b"SIGMA3DG" + rng.randbytes(64)
        b = bytearray(a)
        b[-1] ^= 1
        left = ManifestEntryV1(
            f"x/{index}",
            ManifestEntryKind.FILE,
            len(payload),
            root,
            a,
        )
        right = ManifestEntryV1(
            f"x/{index}",
            ManifestEntryKind.FILE,
            len(payload),
            root,
            bytes(b),
        )
        assert manifest_from_entries((left,)).to_bytes() != manifest_from_entries((right,)).to_bytes()
