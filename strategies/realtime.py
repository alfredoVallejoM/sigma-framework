import hashlib
from typing import Iterator
from sigma.strategies.base import SigmaStrategy
from sigma.interfaces.i_stream import IDataStream


class RealTimeStrategy(SigmaStrategy):
    """
    Family 4: Streaming / Continuous Flow.
    Implements the 'Twisted Ring Accumulator' (ARX+M) to prevent
    linear XOR vulnerabilities in sliding windows.

    Output: BLAKE2s (256 bits / 64 hex chars).
    """

    # Constants for the Ring Accumulator (FNV Prime like)
    PRIME_64 = 0x100000001B3
    MASK_64 = 0xFFFFFFFFFFFFFFFF
    CHUNK_SIZE = 1024  # Small blocks for low latency

    def __init__(self, rounds: int = 0):
        # Rounds are not used in pure streaming the same way,
        # but we maintain the signature.
        super().__init__(rounds=rounds, recursion_alg="blake2b")

    def calculate_anchor(self, stream: IDataStream) -> bytes:
        """
        In RealTime, there is no initial static 'Anchor'.
        This method acts as a placeholder to satisfy the interface.
        """
        return b"\x00" * 64

    def compute(self, stream: IDataStream) -> str:
        """
        Overrides the Template Method due to the distinct flow.
        Processes the stream and returns the signature of the LAST block.
        """
        stream.reset()

        # Ring State: 4 64-bit words
        W = [0, 0, 0, 0]
        t = 0

        # Recursive state (Current Signature)
        current_signature = b"\x00" * 32  # BLAKE2s uses 32 bytes

        while True:
            chunk = stream.read(self.CHUNK_SIZE)
            if not chunk:
                break

            # 1. Fast block hash (Input Mapping)
            # BLAKE2s is used as it outperforms MD5 on modern 64-bit CPUs
            h_chunk = hashlib.blake2s(chunk).digest()
            val_block = int.from_bytes(h_chunk[:8], "little")

            # 2. Ring Update (The Twisted Ring Logic)
            idx = t % 4
            prev_idx = (t - 1) % 4

            # Phase A: Arithmetic Non-Linear Injection
            # w_new = (w_old + input) * Prime
            mixed = ((W[idx] + val_block) * self.PRIME_64) & self.MASK_64

            # Phase B: Ring Diffusion
            # w_new = w_new XOR (neighbor <<< 19)
            neighbor = W[prev_idx]
            neighbor_rot = ((neighbor << 19) | (neighbor >> (64 - 19))) & self.MASK_64
            W[idx] = mixed ^ neighbor_rot

            # 3. Instant Anchor Derivation
            sum_left = (W[0] + W[1]) & self.MASK_64
            sum_right = (W[2] + W[3]) & self.MASK_64
            anchor_int = sum_left ^ sum_right
            anchor_bytes = anchor_int.to_bytes(8, "big")

            # 4. Signature Emission (Chain)
            # Sig_t = BLAKE2s(Sig_t-1 || Anchor_t || Chunk)
            current_signature = hashlib.blake2s(
                current_signature + anchor_bytes + chunk
            ).digest()

            t += 1

        return current_signature.hex()
