"""Read-only compatibility facade for historical Sigma v2.2 TreeWide.

The module deliberately does not convert historical roots into SigmaTree V1
roots. It exists only to keep regression/reproduction code explicit.
"""

from __future__ import annotations

from collections.abc import Iterable
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:  # pragma: no cover
    from sigma.spec.context import SigmaContextV2


def compute_v22_treewide(context: "SigmaContextV2", chunks: Iterable[bytes]) -> Any:
    from sigma.anchors.tree_wide import TreeWide

    return TreeWide.compute(context, chunks)


def is_sigma_tree_v1_root(value: object) -> bool:
    from .model import TreeRoot

    return isinstance(value, TreeRoot)
