"""Typed evidence retained by wide anchor profiles."""

from dataclasses import dataclass
from typing import Tuple

from sigma.spec.encoding import domain_tag, encode_uint
from sigma.spec.ids import AlgorithmId, DomainId


@dataclass(frozen=True)
class AnchorEvidence:
    algorithms: Tuple[AlgorithmId, ...]
    roots: Tuple[bytes, ...]
    message_length: int

    def __post_init__(self) -> None:
        if not self.algorithms or len(self.algorithms) != len(self.roots):
            raise ValueError("anchor algorithms and roots must be non-empty and aligned")
        if len(set(self.algorithms)) != len(self.algorithms):
            raise ValueError("anchor algorithms must be unique")
        if not all(isinstance(item, AlgorithmId) for item in self.algorithms):
            raise TypeError("anchor algorithms must be AlgorithmId values")
        if not all(isinstance(root, bytes) and root for root in self.roots):
            raise TypeError("anchor roots must be non-empty bytes")
        if isinstance(self.message_length, bool) or not 0 <= self.message_length < 1 << 64:
            raise ValueError("message length must fit in an unsigned 64-bit integer")

    @property
    def physical_width_bits(self) -> int:
        return sum(len(root) for root in self.roots) * 8

    def to_bytes(self) -> bytes:
        parts = [domain_tag(DomainId.ANCHOR_EVIDENCE), encode_uint(len(self.roots), 2)]
        for algorithm, root in zip(self.algorithms, self.roots, strict=False):
            parts.extend((encode_uint(algorithm, 2), encode_uint(len(root), 2), root))
        parts.append(encode_uint(self.message_length, 8))
        return b"".join(parts)


@dataclass(frozen=True)
class CrossWideEvidence:
    algorithms: Tuple[AlgorithmId, ...]
    roots: Tuple[bytes, ...]
    cross_roots: Tuple[bytes, ...]
    message_length: int

    def __post_init__(self) -> None:
        if not self.algorithms or len(self.algorithms) != len(self.roots):
            raise ValueError("cross anchor algorithms and roots must be aligned")
        if len(self.cross_roots) != len(self.roots):
            raise ValueError("cross anchor must retain one connection per root")
        if len(set(self.algorithms)) != len(self.algorithms):
            raise ValueError("cross anchor algorithms must be unique")
        if not all(isinstance(item, AlgorithmId) for item in self.algorithms):
            raise TypeError("cross anchor algorithms must be AlgorithmId values")
        if not all(isinstance(root, bytes) and root for root in self.roots + self.cross_roots):
            raise TypeError("cross anchor components must be non-empty bytes")
        if isinstance(self.message_length, bool) or not 0 <= self.message_length < 1 << 64:
            raise ValueError("message length must fit in an unsigned 64-bit integer")

    @property
    def physical_width_bits(self) -> int:
        return sum(len(root) for root in self.roots + self.cross_roots) * 8

    def to_bytes(self) -> bytes:
        parts = [
            domain_tag(DomainId.ANCHOR_EVIDENCE),
            encode_uint(3, 2),
            encode_uint(len(self.roots), 2),
        ]
        for algorithm, root in zip(self.algorithms, self.roots, strict=False):
            parts.extend((encode_uint(algorithm, 2), encode_uint(len(root), 2), root))
        parts.append(encode_uint(len(self.cross_roots), 2))
        for algorithm, root in zip(self.algorithms, self.cross_roots, strict=False):
            parts.extend((encode_uint(algorithm, 2), encode_uint(len(root), 2), root))
        parts.append(encode_uint(self.message_length, 8))
        return b"".join(parts)
