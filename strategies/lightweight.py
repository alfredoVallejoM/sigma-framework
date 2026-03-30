import hashlib
from typing import List
from sigma.strategies.base import SigmaStrategy
from sigma.interfaces.i_stream import IDataStream
from sigma.core.merkle import MerkleEngine
from sigma.core.psi import PsiKernel


class LightweightStrategy(SigmaStrategy):
    """
    Family 3: Structural Efficiency (IoT / Mobile).
    Builds a Merkle Tree (SHA-256) and feeds the Psi core
    reduced to 256 bits.
    """

    CHUNK_SIZE = 4096

    def __init__(self, rounds: int = 5):
        # Final recursion must match the anchor size (SHA-256)
        super().__init__(rounds=rounds, recursion_alg="sha256")

    def calculate_anchor(self, stream: IDataStream) -> bytes:
        stream.reset()

        leaves: List[bytes] = []
        first_chunk_hash = None
        last_chunk_hash = None

        while True:
            chunk = stream.read(self.CHUNK_SIZE)
            if not chunk:
                break

            # Native SHA-256 hash (Hardware accelerated on ARMv8)
            h_chunk = hashlib.sha256(chunk).digest()
            leaves.append(h_chunk)

            if first_chunk_hash is None:
                first_chunk_hash = h_chunk
            last_chunk_hash = h_chunk

        # Edge case: empty file
        if not leaves:
            empty_hash = hashlib.sha256(b"").digest()
            return PsiKernel.compute_anchor_256(
                empty_hash, empty_hash, empty_hash, empty_hash
            )

        # 1. Compute Merkle Root (32 bytes)
        merkle_root = MerkleEngine.compute_root(leaves)

        # 2. Generate the 4th synthetic component (32 bytes)
        synthetic_mix = bytes(
            a ^ b ^ c for a, b, c in zip(merkle_root, first_chunk_hash, last_chunk_hash)
        )

        # 3. Non-Linear Mix in the 256-bit subspace
        # Mathematical entropy loss is eliminated
        anchor = PsiKernel.compute_anchor_256(
            merkle_root, first_chunk_hash, last_chunk_hash, synthetic_mix
        )

        return anchor
