"""Sigma Tree V1: canonical structural integrity primitives."""

from .codec import TreeDecodeError
from .core import TreeBuilder, build_tree, build_tree_chunks, combine_nodes, empty_root, leaf_node
from .ids import TreeAlgorithmId, TreeDomainId, TreeProfileId
from .model import DEFAULT_PROFILE, TreeFrontier, TreeNode, TreeProfileV1, TreeRoot, canonical_frontier_heights

__all__ = [
    "DEFAULT_PROFILE", "TreeAlgorithmId", "TreeBuilder", "TreeDecodeError",
    "TreeDomainId", "TreeFrontier", "TreeNode", "TreeProfileId", "TreeProfileV1",
    "TreeRoot", "build_tree", "build_tree_chunks", "canonical_frontier_heights",
    "combine_nodes", "empty_root", "leaf_node",
]
