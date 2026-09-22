"""Stable identifiers for Sigma Tree V1.

These identifiers are intentionally independent from Sigma v2/v3 suite IDs.
They name the structural product layer only; they do not create new
cryptographic primitives.
"""

from enum import IntEnum

from sigma.version import TREE_WIRE_VERSION
TREE_PROFILE_MAGIC = b"SIGTPRF1"
TREE_ROOT_MAGIC = b"SIGTROOT"
TREE_NODE_MAGIC = b"SIGTNODE"
TREE_FRONTIER_MAGIC = b"SIGTFRNT"
TREE_DOMAIN_MAGIC = b"SIGTRDS1"
TREE_MANIFEST_ENTRY_MAGIC = b"SIGTENT1"
TREE_MANIFEST_MAGIC = b"SIGTMNF1"
TREE_PROOF_STEP_MAGIC = b"SIGTPST1"
TREE_INCLUSION_PROOF_MAGIC = b"SIGTIPF1"
TREE_RANGE_PROOF_MAGIC = b"SIGTRPF1"
TREE_CHECKPOINT_MAGIC = b"SIGTCHK1"
TREE_SOURCE_HINT_MAGIC = b"SIGTSRC1"


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


class ManifestProfileId(IntEnum):
    BASE_V1 = 0x0001


class ManifestEntryKind(IntEnum):
    FILE = 0x0001
    DIRECTORY = 0x0002
    SYMLINK = 0x0003


class ManifestMetadataProfileId(IntEnum):
    BASE = 0x0001


class ProofSide(IntEnum):
    LEFT = 0x0001
    RIGHT = 0x0002


DEFAULT_TREE_ALGORITHMS = (
    TreeAlgorithmId.SHA512,
    TreeAlgorithmId.SHA3_512,
    TreeAlgorithmId.BLAKE2B_512,
    TreeAlgorithmId.SHAKE256_512,
)
DEFAULT_TREE_CHUNK_SIZE = 65_536
TREE_DIGEST_SIZE = 64
MAX_TREE_FRONTIER_NODES = 64

MAX_MANIFEST_ENTRIES = 65_535
MAX_MANIFEST_PATH_BYTES = 4_096
MAX_MANIFEST_SYMLINK_TARGET_BYTES = 4_096

MAX_INCLUSION_STEPS = 64
MAX_RANGE_WITNESS_NODES = 128
