# sigma/adapters/streams.py
import os
import mmap
import io
from typing import Optional, Union, BinaryIO
from sigma.interfaces.i_stream import IDataStream


class FileStream(IDataStream):
    """
    Optimized adapter for disk files.
    Uses mmap if possible to avoid kernel-user space memory copies.
    """

    def __init__(self, path_or_obj: Union[str, BinaryIO]):
        if isinstance(path_or_obj, str):
            self._f = open(path_or_obj, "rb")
            self._close_on_exit = True
        else:
            self._f = path_or_obj
            self._close_on_exit = False

        self._size = os.fstat(self._f.fileno()).st_size

        # Optimization: Memory Map for large files (>1MB)
        if self._size > 1024 * 1024:
            self._map = mmap.mmap(self._f.fileno(), 0, access=mmap.ACCESS_READ)
            self._use_mmap = True
        else:
            self._map = None
            self._use_mmap = False

    def read(self, size: int) -> bytes:
        if self._use_mmap:
            return self._map.read(size)
        return self._f.read(size)

    def get_size(self) -> int:
        return self._size

    def reset(self) -> None:
        if self._use_mmap:
            self._map.seek(0)
        else:
            self._f.seek(0)

    def close(self):
        if self._map:
            self._map.close()
        if self._close_on_exit:
            self._f.close()


class MemoryStream(IDataStream):
    """Adapter for in-RAM bytes."""

    def __init__(self, data: bytes):
        self._buffer = io.BytesIO(data)
        self._size = len(data)

    def read(self, size: int) -> bytes:
        return self._buffer.read(size)

    def get_size(self) -> int:
        return self._size

    def reset(self) -> None:
        self._buffer.seek(0)
