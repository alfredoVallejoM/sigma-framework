"""Simple reference execution backend."""

from os import PathLike
from typing import Union

from sigma.anchors import (
    AnchorEvidence,
    CrossWide,
    CrossWideEvidence,
    StreamWide,
    TreeWide,
)
from sigma.file_snapshot import stable_open
from sigma.spec import SigmaContextV2
from sigma.spec.ids import AnchorProfileId

from .base import ExecutionBackend, FileExecutionBackend


class SerialBackend(ExecutionBackend, FileExecutionBackend):
    @property
    def name(self) -> str:
        return "serial-reference"

    def compute_anchor(
        self, data: bytes, context: SigmaContextV2
    ) -> Union[AnchorEvidence, CrossWideEvidence]:
        if context.anchor_profile is AnchorProfileId.STREAM_WIDE:
            return StreamWide.compute(context, (data,))
        if context.anchor_profile is AnchorProfileId.CROSS_WIDE:
            return CrossWide.compute(context, (data,))
        if context.anchor_profile is AnchorProfileId.TREE_WIDE:
            return TreeWide.compute(context, (data,))
        raise ValueError(f"unsupported anchor profile: {context.anchor_profile.name}")

    def compute_anchor_file(
        self, path: Union[str, PathLike], context: SigmaContextV2
    ) -> Union[AnchorEvidence, CrossWideEvidence]:
        engine: Union[StreamWide, CrossWide, TreeWide]
        if context.anchor_profile is AnchorProfileId.STREAM_WIDE:
            engine = StreamWide(context)
        elif context.anchor_profile is AnchorProfileId.CROSS_WIDE:
            engine = CrossWide(context)
        elif context.anchor_profile is AnchorProfileId.TREE_WIDE:
            engine = TreeWide(context)
        else:
            raise ValueError(f"unsupported anchor profile: {context.anchor_profile.name}")
        with stable_open(path) as (reader, _identity):
            for chunk in iter(lambda: reader.read(64 * 1024), b""):
                engine.update(chunk)
        return engine.finalize()


SERIAL_BACKEND = SerialBackend()
