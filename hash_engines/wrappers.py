import hashlib
from abc import ABC, abstractmethod
from typing import Any


class IHashEngine(ABC):
    """Unified interface for any digest algorithm."""

    @abstractmethod
    def update(self, data: bytes) -> None: ...

    @abstractmethod
    def digest(self) -> bytes: ...

    @property
    @abstractmethod
    def name(self) -> str: ...


class StdLibHash(IHashEngine):
    """Wrapper for hashlib (SHA2, SHA3, BLAKE2)."""

    def __init__(self, alg_name: str):
        self._h = hashlib.new(alg_name)
        self._name = alg_name

    def update(self, data: bytes) -> None:
        self._h.update(data)

    def digest(self) -> bytes:
        return self._h.digest()

    @property
    def name(self) -> str:
        return self._name


class SHAKEWrapper(IHashEngine):
    """Special wrapper for XOF (Extensible Output Functions)."""

    def __init__(self, bits: int = 512):
        self._h = hashlib.shake_256()
        self._bytes = bits // 8

    def update(self, data: bytes) -> None:
        self._h.update(data)

    def digest(self) -> bytes:
        return self._h.digest(self._bytes)

    @property
    def name(self) -> str:
        return f"shake_256_{self._bytes*8}"
