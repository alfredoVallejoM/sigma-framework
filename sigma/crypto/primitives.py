"""Small wrappers around the fixed Sigma v3 primitive registry."""

from __future__ import annotations

import hashlib
from typing import Any

from sigma.spec.ids import AlgorithmId
from sigma.spec.ids_v3 import ALGORITHM_OUTPUT_SIZE_V3, DomainIdV3

MAX_SHAKE_READER_BYTES = 1 << 20


def domain_tag_v3(domain: DomainIdV3) -> bytes:
    if not isinstance(domain, DomainIdV3):
        raise TypeError("domain must be DomainIdV3")
    return b"SIGMA3DS" + int(domain).to_bytes(2, "big")


def _new_hash(algorithm: AlgorithmId) -> Any:
    if not isinstance(algorithm, AlgorithmId):
        raise TypeError("algorithm must be AlgorithmId")
    if algorithm is AlgorithmId.SHA512:
        return hashlib.sha512()
    if algorithm is AlgorithmId.SHA3_512:
        return hashlib.sha3_512()
    if algorithm is AlgorithmId.BLAKE2B_512:
        return hashlib.blake2b(digest_size=ALGORITHM_OUTPUT_SIZE_V3)
    if algorithm is AlgorithmId.SHAKE256_512:
        return hashlib.shake_256()
    raise ValueError("unsupported algorithm")  # pragma: no cover


class HashAccumulator:
    """Incremental fixed-width hashing with an explicit v3 domain."""

    def __init__(self, algorithm: AlgorithmId, domain: DomainIdV3) -> None:
        self.algorithm = algorithm
        self.domain = domain
        self._hash = _new_hash(algorithm)
        self._hash.update(domain_tag_v3(domain))
        self._finished = False

    def update(self, data: bytes) -> None:
        if self._finished:
            raise RuntimeError("hash accumulator is finalized")
        if not isinstance(data, bytes):
            raise TypeError("hash input must be bytes")
        self._hash.update(data)

    def digest(self) -> bytes:
        if self._finished:
            raise RuntimeError("hash accumulator is finalized")
        self._finished = True
        if self.algorithm is AlgorithmId.SHAKE256_512:
            return self._hash.digest(ALGORITHM_OUTPUT_SIZE_V3)
        digest = self._hash.digest()
        if len(digest) != ALGORITHM_OUTPUT_SIZE_V3:  # pragma: no cover
            raise RuntimeError("unexpected primitive output size")
        return digest


def hash_bytes(algorithm: AlgorithmId, domain: DomainIdV3, data: bytes) -> bytes:
    accumulator = HashAccumulator(algorithm, domain)
    accumulator.update(data)
    return accumulator.digest()


class ShakeReader:
    """Deterministic SHAKE256 stream with a monotonic read cursor."""

    def __init__(self, domain: DomainIdV3, seed: bytes) -> None:
        if not isinstance(seed, bytes):
            raise TypeError("seed must be bytes")
        self._shake = hashlib.shake_256(domain_tag_v3(domain) + seed)
        self._output = b""
        self._offset = 0

    def read(self, length: int) -> bytes:
        if isinstance(length, bool) or not isinstance(length, int):
            raise TypeError("length must be int")
        if not 0 <= length <= MAX_SHAKE_READER_BYTES:
            raise ValueError("length is out of range")
        end = self._offset + length
        if end > MAX_SHAKE_READER_BYTES:
            raise ValueError("total SHAKE reader output exceeds limit")
        if end > len(self._output):
            # hashlib has no consuming SHAKE API. Grow geometrically so tiny
            # consumers stay tiny and repeated reads have amortized linear cost.
            target = max(64, 1 << (end - 1).bit_length())
            self._output = self._shake.digest(min(target, MAX_SHAKE_READER_BYTES))
        output = self._output[self._offset : end]
        self._offset = end
        return output

    @property
    def buffered_bytes(self) -> int:
        """Current bounded XOF cache size, exposed for resource assertions."""
        return len(self._output)
