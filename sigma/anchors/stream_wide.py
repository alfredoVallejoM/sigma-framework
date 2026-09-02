"""Incremental O(m) wide input commitment, independent of API chunking."""

from typing import Iterable, List

from sigma.spec.context import SigmaContextV2
from sigma.spec.encoding import domain_tag, encode_tlv, encode_uint
from sigma.spec.ids import DomainId
from sigma.suites.registry import get_suite

from .base import AnchorEvidence
from .branches import BranchHasher


class StreamWide:
    def __init__(self, context: SigmaContextV2):
        self.context = context
        self.suite = get_suite(context.suite_id)
        self.suite.validate_context(context)
        context_bytes = context.to_bytes()
        self._hashers: List[BranchHasher] = []
        for index, algorithm in enumerate(context.branches):
            hasher = BranchHasher(algorithm)
            descriptor = encode_tlv(
                (
                    (1, encode_uint(index, 2)),
                    (2, encode_uint(algorithm, 2)),
                    (3, context_bytes),
                )
            )
            hasher.update(domain_tag(DomainId.BRANCH))
            hasher.update(descriptor)
            self._hashers.append(hasher)
        self._message_length = 0
        self._finalized = False

    def update(self, data: bytes) -> None:
        if self._finalized:
            raise RuntimeError("StreamWide is already finalized")
        if not isinstance(data, bytes):
            raise TypeError("message chunks must be bytes")
        new_length = self._message_length + len(data)
        if new_length >= 1 << 64:
            raise ValueError("message length exceeds the v2 limit")
        for hasher in self._hashers:
            hasher.update(data)
        self._message_length = new_length

    def finalize(self) -> AnchorEvidence:
        if self._finalized:
            raise RuntimeError("StreamWide is already finalized")
        self._finalized = True
        suffix = domain_tag(DomainId.BRANCH_END) + encode_uint(self._message_length, 8)
        roots = []
        for hasher in self._hashers:
            hasher.update(suffix)
            roots.append(hasher.digest())
        return AnchorEvidence(
            self.context.branches, tuple(roots), self._message_length, self.context.suite_id
        )

    def checkpoint(self) -> AnchorEvidence:
        """Snapshot the current prefix without finalizing the live stream."""

        if self._finalized:
            raise RuntimeError("StreamWide is already finalized")
        suffix = domain_tag(DomainId.BRANCH_END) + encode_uint(self._message_length, 8)
        roots = []
        for hasher in self._hashers:
            clone = hasher.copy()
            clone.update(suffix)
            roots.append(clone.digest())
        return AnchorEvidence(
            self.context.branches, tuple(roots), self._message_length, self.context.suite_id
        )

    @classmethod
    def compute(cls, context: SigmaContextV2, chunks: Iterable[bytes]) -> AnchorEvidence:
        engine = cls(context)
        for chunk in chunks:
            engine.update(chunk)
        return engine.finalize()
