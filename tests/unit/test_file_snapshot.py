import os
from pathlib import Path

import pytest

from sigma.anchors import StreamWide
from sigma.backends.base import FileExecutionBackend
from sigma.file_snapshot import immutable_snapshot, stable_open
from sigma.presets import lightweight_v2
from sigma.v2 import hash_bytes, hash_file_with_snapshot


def test_file_hash_returns_auditable_source_identity(tmp_path: Path) -> None:
    path = tmp_path / "input.bin"
    path.write_bytes(b"snapshot bytes")
    result = hash_file_with_snapshot(path, lightweight_v2())
    assert result.digest == hash_bytes(b"snapshot bytes", lightweight_v2())
    assert result.source.size == len(b"snapshot bytes")
    assert set(result.source.as_dict()) == {
        "ctime_ns",
        "device",
        "file_id",
        "mtime_ns",
        "size",
    }


@pytest.mark.parametrize("operation", ("modify", "truncate", "replace"))
def test_stable_open_rejects_concurrent_file_changes(tmp_path: Path, operation: str) -> None:
    path = tmp_path / "input.bin"
    path.write_bytes(b"original content")
    with pytest.raises(RuntimeError, match="changed"), stable_open(path) as (source, identity):
        assert source.read() == b"original content"
        assert identity.size == len(b"original content")
        if operation == "modify":
            path.write_bytes(b"modified content")
        elif operation == "truncate":
            path.write_bytes(b"")
        else:
            replacement = tmp_path / "replacement.bin"
            replacement.write_bytes(b"original content")
            os.replace(replacement, path)


def test_private_snapshot_is_immutable_after_source_change_detection(tmp_path: Path) -> None:
    path = tmp_path / "input.bin"
    path.write_bytes(b"original")
    with (
        pytest.raises(RuntimeError, match="changed"),
        immutable_snapshot(path) as (
            snapshot,
            identity,
        ),
    ):
        assert snapshot != path
        assert snapshot.read_bytes() == b"original"
        assert identity.size == 8
        path.write_bytes(b"changed!")
        assert snapshot.read_bytes() == b"original"


class SourceMutatingBackend(FileExecutionBackend):
    def __init__(self, source: Path):
        self.source = source

    def compute_anchor_file(self, path, context):
        snapshot_bytes = Path(path).read_bytes()
        self.source.write_bytes(b"tampered")
        return StreamWide.compute(context, (snapshot_bytes,))


def test_file_facade_rejects_source_change_during_backend_work(tmp_path: Path) -> None:
    path = tmp_path / "input.bin"
    path.write_bytes(b"original")
    with pytest.raises(RuntimeError, match="changed"):
        hash_file_with_snapshot(path, lightweight_v2(), SourceMutatingBackend(path))


def test_non_regular_files_are_rejected(tmp_path: Path) -> None:
    with pytest.raises(ValueError, match="regular file"), stable_open(tmp_path):
        pass
