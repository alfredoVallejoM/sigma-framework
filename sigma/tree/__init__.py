"""Sigma Tree V1: canonical structural integrity primitives."""

from .codec import TreeDecodeError
from .core import TreeBuilder, build_tree, build_tree_chunks, combine_nodes, empty_root, leaf_node
from .ids import (
    ManifestEntryKind,
    ManifestMetadataProfileId,
    ManifestProfileId,
    ProofSide,
    TreeAlgorithmId,
    TreeDomainId,
    TreeProfileId,
)
from .manifest import (
    ManifestEntryV1,
    ManifestV1,
    SymlinkPolicy,
    build_directory_manifest,
    manifest_from_entries,
)
from .proofs import (
    InclusionProofV1,
    InclusionStepV1,
    RangeProofV1,
    TreeProofIndex,
    inclusion_geometry,
    prove_leaf,
    prove_range,
    range_witness_geometry,
    verify_inclusion,
    verify_range,
)
from .model import (
    DEFAULT_PROFILE,
    TreeFrontier,
    TreeNode,
    TreeProfileV1,
    TreeRoot,
    canonical_frontier_heights,
)
from .path import canonical_relative_path

__all__ = [
    "DEFAULT_PROFILE",
    "ManifestEntryKind",
    "ManifestEntryV1",
    "ManifestMetadataProfileId",
    "ManifestProfileId",
    "ManifestV1",
    "ProofSide",
    "InclusionProofV1",
    "InclusionStepV1",
    "RangeProofV1",
    "TreeProofIndex",
    "SymlinkPolicy",
    "TreeAlgorithmId",
    "TreeBuilder",
    "TreeDecodeError",
    "TreeDomainId",
    "TreeFrontier",
    "TreeNode",
    "TreeProfileId",
    "TreeProfileV1",
    "TreeRoot",
    "build_directory_manifest",
    "build_tree",
    "build_tree_chunks",
    "canonical_frontier_heights",
    "canonical_relative_path",
    "combine_nodes",
    "empty_root",
    "leaf_node",
    "manifest_from_entries",
    "inclusion_geometry",
    "prove_leaf",
    "prove_range",
    "range_witness_geometry",
    "verify_inclusion",
    "verify_range",
]
