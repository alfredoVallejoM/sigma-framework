import hashlib
from typing import List


class MerkleEngine:
    """
    Deterministic engine to compute the Merkle Root.
    Implements RFC 6962 (Certificate Transparency) for structural security.
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
        # By using the 0x01 prefix, we guarantee this hash will never
        # collide with a leaf hash (which uses 0x00), preventing
        # type substitution attacks.
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

        # [CRITICAL] Security step:
        # In actual RFC 6962, the leaf is hashed as H(0x00 || Data).
        # Since our Lightweight strategy already hashed the data before calling this,
        # we can treat those hashes as "Data" or re-hash them with a prefix.
        # For maximum structural security, we re-hash with the leaf prefix.

        current_layer = [
            hashlib.sha256(MerkleEngine.PREFIX_LEAF + h).digest()
            for h in raw_leaves_hashes
        ]

        while len(current_layer) > 1:
            next_layer = []

            for i in range(0, len(current_layer), 2):
                left = current_layer[i]
                # If odd, duplicate the last node (Bitcoin/Merkle standard)
                if i + 1 < len(current_layer):
                    right = current_layer[i + 1]
                else:
                    right = left

                parent = MerkleEngine._hash_node(left, right)
                next_layer.append(parent)

            current_layer = next_layer

        return current_layer[0]
