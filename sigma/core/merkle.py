import hashlib
from typing import List


class MerkleEngine:
    """
    Legacy v1 deterministic Merkle-like engine.
    Its odd-node duplication differs from RFC 6962 and it is not used by v2.
    """

    # Domain separation prefixes (prevents second pre-image attacks)
    PREFIX_LEAF = b"\x00"
    PREFIX_NODE = b"\x01"

    @staticmethod
    def _hash_node(left: bytes, right: bytes) -> bytes:
        """
        Combines two nodes using a domain prefix.
        H_node = SHA256(0x01 || Left || Right)
        """
        # The prefix provides syntactic domain separation from leaf inputs.
        return hashlib.sha256(MerkleEngine.PREFIX_NODE + left + right).digest()

    @staticmethod
    def compute_root(raw_leaves_hashes: List[bytes]) -> bytes:
        """
        Computes the root.
        Assumes 'raw_leaves_hashes' are already SHA-256 digests of the data.
        """
        if not raw_leaves_hashes:
            # Empty tree hash (Standard RFC)
            return hashlib.sha256(b"").digest()

        # Re-hash the legacy pre-hashed leaves with a distinct prefix.

        current_layer = [
            hashlib.sha256(MerkleEngine.PREFIX_LEAF + h).digest() for h in raw_leaves_hashes
        ]

        while len(current_layer) > 1:
            next_layer = []

            for i in range(0, len(current_layer), 2):
                left = current_layer[i]
                # If odd, duplicate the last node (Bitcoin/Merkle standard)
                right = current_layer[i + 1] if i + 1 < len(current_layer) else left

                parent = MerkleEngine._hash_node(left, right)
                next_layer.append(parent)

            current_layer = next_layer

        return current_layer[0]
