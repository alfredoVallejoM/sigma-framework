"""Finalization-safe incremental API for streaming Sigma v2 suites."""

from dataclasses import dataclass
from typing import Union

from sigma.anchors import CrossWide, StreamWide
from sigma.outputs import SigmaDigestV2
from sigma.spec import SigmaContextV2
from sigma.spec.ids import AnchorProfileId
from sigma.v2 import _round_engine


@dataclass(frozen=True)
class SigmaCheckpointV2:
    offset: int
    digest: SigmaDigestV2
    provisional: bool = True


class IncrementalSigmaV2:
    def __init__(self, context: SigmaContextV2):
        self.context = context
        self._anchor: Union[StreamWide, CrossWide]
        if context.anchor_profile is AnchorProfileId.STREAM_WIDE:
            self._anchor = StreamWide(context)
        elif context.anchor_profile is AnchorProfileId.CROSS_WIDE:
            self._anchor = CrossWide(context)
        else:
            raise ValueError("incremental checkpoints require a stream-based anchor")
        self._offset = 0
        self._finalized = False

    def update(self, data: bytes) -> None:
        if self._finalized:
            raise RuntimeError("incremental digest is already finalized")
        self._anchor.update(data)
        self._offset += len(data)

    def checkpoint(self) -> SigmaCheckpointV2:
        if self._finalized:
            raise RuntimeError("incremental digest is already finalized")
        evidence = self._anchor.checkpoint()
        digest = _round_engine(self.context).evaluate_digest(evidence)
        return SigmaCheckpointV2(self._offset, digest)

    def finalize(self) -> SigmaDigestV2:
        if self._finalized:
            raise RuntimeError("incremental digest is already finalized")
        self._finalized = True
        evidence = self._anchor.finalize()
        return _round_engine(self.context).evaluate_digest(evidence)
