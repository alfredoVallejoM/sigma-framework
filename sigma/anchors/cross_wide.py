"""CrossWide anchor: original roots plus connections over all roots."""

from typing import Iterable

from sigma.spec.context import SigmaContextV2
from sigma.spec.encoding import domain_tag, encode_tlv, encode_uint
from sigma.spec.ids import AnchorProfileId, DomainId
from sigma.suites.registry import get_suite

from .base import CrossWideEvidence
from .branches import hash_once
from .stream_wide import StreamWide


class CrossWide:
    def __init__(self, context: SigmaContextV2):
        self.context = context
        self.suite = get_suite(context.suite_id)
        self.suite.validate_context(context)
        if context.anchor_profile is not AnchorProfileId.CROSS_WIDE:
            raise ValueError("CrossWide requires the CROSS_WIDE anchor profile")
        self._stream = StreamWide(context)
        self._finalized = False

    def update(self, data: bytes) -> None:
        if self._finalized:
            raise RuntimeError("CrossWide is already finalized")
        self._stream.update(data)

    def finalize(self) -> CrossWideEvidence:
        if self._finalized:
            raise RuntimeError("CrossWide is already finalized")
        self._finalized = True
        wide = self._stream.finalize()
        return self._connect(wide)

    def checkpoint(self) -> CrossWideEvidence:
        if self._finalized:
            raise RuntimeError("CrossWide is already finalized")
        return self._connect(self._stream.checkpoint())

    def _connect(self, wide) -> CrossWideEvidence:
        encoded_roots = wide.to_bytes()
        cross_roots = []
        for index, algorithm in enumerate(wide.algorithms):
            framed = encode_tlv(
                (
                    (1, encode_uint(index, 2)),
                    (2, self.context.to_bytes()),
                    (3, encoded_roots),
                )
            )
            cross_roots.append(hash_once(algorithm, domain_tag(DomainId.CROSS) + framed))
        return CrossWideEvidence(
            wide.algorithms,
            wide.roots,
            tuple(cross_roots),
            wide.message_length,
            self.context.suite_id,
        )

    @classmethod
    def compute(cls, context: SigmaContextV2, chunks: Iterable[bytes]) -> CrossWideEvidence:
        engine = cls(context)
        for chunk in chunks:
            engine.update(chunk)
        return engine.finalize()
