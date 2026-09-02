"""Stable file identity and private snapshots for file hashing."""

import os
import stat
import tempfile
from contextlib import contextmanager
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import BinaryIO, Iterator, Union


@dataclass(frozen=True)
class FileIdentity:
    device: int
    file_id: int
    size: int
    mtime_ns: int
    ctime_ns: int

    @classmethod
    def from_stat(cls, value: os.stat_result) -> "FileIdentity":
        if not stat.S_ISREG(value.st_mode):
            raise ValueError("Sigma file hashing requires a regular file")
        return cls(
            device=int(value.st_dev),
            file_id=int(value.st_ino),
            size=int(value.st_size),
            mtime_ns=int(value.st_mtime_ns),
            ctime_ns=int(value.st_ctime_ns),
        )

    def as_dict(self) -> dict[str, int]:
        return asdict(self)


def _path_identity(path: str) -> FileIdentity:
    try:
        return FileIdentity.from_stat(os.stat(path))
    except OSError as exc:
        raise RuntimeError("input file disappeared or became inaccessible") from exc


@contextmanager
def stable_open(path: Union[str, os.PathLike[str]]) -> Iterator[tuple[BinaryIO, FileIdentity]]:
    """Hold one descriptor and reject metadata or pathname identity changes."""

    path_string = os.fspath(path)
    initial = _path_identity(path_string)
    with open(path_string, "rb") as source:
        before = FileIdentity.from_stat(os.fstat(source.fileno()))
        if initial != before or _path_identity(path_string) != before:
            raise RuntimeError("input path changed while it was being opened")
        try:
            yield source, before
        finally:
            after_descriptor = FileIdentity.from_stat(os.fstat(source.fileno()))
            after_path = _path_identity(path_string)
            if after_descriptor != before or after_path != before:
                raise RuntimeError("input file changed while it was being hashed")


@contextmanager
def immutable_snapshot(
    path: Union[str, os.PathLike[str]],
) -> Iterator[tuple[Path, FileIdentity]]:
    """Copy a stable source into a private file retained for the operation."""

    with (
        stable_open(path) as (source, identity),
        tempfile.TemporaryDirectory(prefix="sigma-file-snapshot-") as directory,
    ):
        snapshot = Path(directory) / "input.bin"
        with snapshot.open("xb") as target:
            for chunk in iter(lambda: source.read(1024 * 1024), b""):
                target.write(chunk)
        yield snapshot, identity
