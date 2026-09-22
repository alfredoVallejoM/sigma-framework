"""Stable identifiers for Sigma Tree V1.

These identifiers are intentionally independent from Sigma v2/v3 suite IDs.
They name the structural product layer only; they do not create new
cryptographic primitives.
"""

from enum import IntEnum

TREE_WIRE_VERSION = 1
TREE_PROFILE_MAGIC = b"SIGTPRF1"
TREE_ROOT_MAGIC = b"SIGTROOT"
TREE_NODE_MAGIC = b"SIGTNODE"
TREE_FRONTIER_MAGIC = b"SIGTFRNT"
TREE_DOMAIN_MAGIC = b"SIGTRDS1"


class TreeProfileId(IntEnum):
    CANONICAL_V1 = 0x0001


class TreeAlgorithmId(IntEnum):
    SHA512 = 0x0001
    SHA3_512 = 0x0002
    BLAKE2B_512 = 0x0003
    SHAKE256_512 = 0x0004


class TreeDomainId(IntEnum):
    LEAF = 0x0001
    NODE = 0x0002
    EMPTY = 0x0003


DEFAULT_TREE_ALGORITHMS = (
    TreeAlgorithmId.SHA512,
    TreeAlgorithmId.SHA3_512,
    TreeAlgorithmId.BLAKE2B_512,
    TreeAlgorithmId.SHAKE256_512,
)
DEFAULT_TREE_CHUNK_SIZE = 65_536
TREE_DIGEST_SIZE = 64
MAX_TREE_FRONTIER_NODES = 64
