"""Exact standard primitive configurations used by registered suites."""

import hashlib
from typing import Any, Callable, Dict

from sigma.spec.ids import AlgorithmId


class BranchHasher:
    """Single-use wrapper with deterministic finalization semantics."""

    def __init__(self, algorithm_id: AlgorithmId):
        self.algorithm_id = algorithm_id
        self._hash: Any = _CONSTRUCTORS[algorithm_id]()
        self._finalized = False

    def update(self, data: bytes) -> None:
        if self._finalized:
            raise RuntimeError("hash branch is already finalized")
        if not isinstance(data, bytes):
            raise TypeError("hash input must be bytes")
        self._hash.update(data)

    def digest(self) -> bytes:
        if self._finalized:
            raise RuntimeError("hash branch is already finalized")
        self._finalized = True
        if self.algorithm_id is AlgorithmId.SHAKE256_512:
            return self._hash.digest(64)
        return self._hash.digest()

    def copy(self) -> "BranchHasher":
        if self._finalized:
            raise RuntimeError("hash branch is already finalized")
        clone = object.__new__(BranchHasher)
        clone.algorithm_id = self.algorithm_id
        clone._hash = self._hash.copy()
        clone._finalized = False
        return clone


def _blake2b_512():
    return hashlib.blake2b(digest_size=64)


_CONSTRUCTORS: Dict[AlgorithmId, Callable[[], Any]] = {
    AlgorithmId.SHA512: hashlib.sha512,
    AlgorithmId.SHA3_512: hashlib.sha3_512,
    AlgorithmId.BLAKE2B_512: _blake2b_512,
    AlgorithmId.SHAKE256_512: hashlib.shake_256,
}


def hash_once(algorithm_id: AlgorithmId, data: bytes) -> bytes:
    hasher = BranchHasher(algorithm_id)
    hasher.update(data)
    return hasher.digest()
