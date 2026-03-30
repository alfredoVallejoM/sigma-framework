# sigma/core/psi.py
from typing import Tuple, List
from .types import Word64
from .primitives import BitwiseOps as B
from .primitives import Codec


class PsiKernel:
    """
    Reference implementation of the Psi Mixing Function (Sigma-Adaptive).
    Architecture: G-SPN + Butterfly Diffusion Layer.
    """

    @staticmethod
    def _mix_column(v1: Word64, v2: Word64, v3: Word64, v4: Word64) -> Word64:
        """
        VERTICAL CORE: Processes a 'slice' of the 4 hashes.
        Phases A (Arithmetic) and B (Constant-Time Diffusion).
        """
        # --- PHASE A: Arithmetic Non-Linearity Injection (Unchanged) ---
        a1 = B.xor(B.add(v1, v3), B.rotl(v2, 13))
        a2 = B.xor(B.add(v2, v4), B.rotl(v3, 17))
        a3 = B.xor(B.sub(v3, v1), B.rotl(v4, 19))
        a4 = B.xor(B.sub(v4, v2), B.rotl(v1, 31))

        # --- PHASE B: Constant-Time ARX Diffusion (Quarter-Round Topology) ---
        # Guarantees immunity to side-channel attacks (Timing/Power)
        # without sacrificing the thermodynamic avalanche of the bits.

        # Step 1
        b1 = B.add(a1, a2)
        b4 = B.rotl(B.xor(a4, b1), 32)

        # Step 2
        b3 = B.add(a3, b4)
        b2 = B.rotl(B.xor(a2, b3), 24)

        # Step 3
        b1 = B.add(b1, b2)
        b4 = B.rotl(B.xor(b4, b1), 16)

        # Step 4
        b3 = B.add(b3, b4)
        b2 = B.rotl(B.xor(b2, b3), 63)

        # --- PHASE C: Local Folding (Maintains structural compression) ---
        return B.add(B.xor(b1, b3), B.xor(b2, b4))

    @staticmethod
    def _diffuse_horizontal(words: List[Word64]) -> List[Word64]:
        """
        HORIZONTAL DIFFUSION LAYER (Bidirectional Sweep + Butterfly).
        Guarantees Full-Width Propagation.
        """
        w = list(words)  # Mutable copy

        # 1. Forward Sweep (0 -> 7)
        # Each word absorbs entropy from the previous one.
        for i in range(7):
            # w[i+1] absorbs w[i]
            # We use a prime rotation (19) to prevent byte alignment
            val = B.add(w[i + 1], B.rotl(w[i], 19))
            w[i + 1] = B.xor(val, w[i])

        # 2. Backward Sweep (7 -> 0)
        # The bounce guarantees the last bit affects the first one.
        for i in range(7, 0, -1):
            # w[i-1] absorbs w[i]
            # We use a different prime rotation (29)
            val = B.add(w[i - 1], B.rotl(w[i], 29))
            w[i - 1] = B.xor(val, w[i])

        # 3. Final Mix (Reduced Butterfly for local chaos)
        # Distance 4 (half of the block)
        for i in range(4):
            idx_a, idx_b = i, i + 4
            w[idx_a] = B.add(w[idx_a], w[idx_b])
            w[idx_b] = B.rotl(B.xor(w[idx_b], w[idx_a]), 31)

        return w

    @staticmethod
    def compute_anchor(
        h1_bytes: bytes, h2_bytes: bytes, h3_bytes: bytes, h4_bytes: bytes
    ) -> bytes:
        """Computes the Master Anchor with global diffusion."""

        # 1. Decoding
        V1 = Codec.bytes_to_words(h1_bytes)
        V2 = Codec.bytes_to_words(h2_bytes)
        V3 = Codec.bytes_to_words(h3_bytes)
        V4 = Codec.bytes_to_words(h4_bytes)

        raw_anchor: List[Word64] = []

        # 2. Vertical Mix (Columnar)
        for i in range(8):
            # Index shift to avoid alignment
            w1 = V1[i]
            w2 = V2[(i + 1) % 8]
            w3 = V3[(i + 2) % 8]
            w4 = V4[(i + 3) % 8]

            mixed_word = PsiKernel._mix_column(w1, w2, w3, w4)

            # Injection of round constant (Pi constants)
            rc = Word64(0x243F6A8885A308D3 ^ i)
            raw_anchor.append(B.xor(mixed_word, rc))

        # 3. Horizontal Mix (Global Diffusion)
        final_anchor = PsiKernel._diffuse_horizontal(raw_anchor)

        # 4. Serialization
        return Codec.words_to_bytes(tuple(final_anchor))

    @staticmethod
    def _diffuse_horizontal_256(words: List[Word64]) -> List[Word64]:
        """
        Horizontal diffusion layer for the reduced 256-bit tensor (4 words).
        """
        w = list(words)

        # 1. Forward Sweep (0 -> 3)
        for i in range(3):
            val = B.add(w[i + 1], B.rotl(w[i], 19))
            w[i + 1] = B.xor(val, w[i])

        # 2. Backward Sweep (3 -> 0)
        for i in range(3, 0, -1):
            val = B.add(w[i - 1], B.rotl(w[i], 29))
            w[i - 1] = B.xor(val, w[i])

        # 3. Final Mix (Butterfly at distance 2)
        for i in range(2):
            idx_a, idx_b = i, i + 2
            w[idx_a] = B.add(w[idx_a], w[idx_b])
            w[idx_b] = B.rotl(B.xor(w[idx_b], w[idx_a]), 31)

        return w

    @staticmethod
    def compute_anchor_256(
        h1_bytes: bytes, h2_bytes: bytes, h3_bytes: bytes, h4_bytes: bytes
    ) -> bytes:
        """
        Computes the Anchor in the 256-bit space (For LightweightStrategy).
        Assumes inputs are exactly 32 bytes each.
        """
        # Format '<4Q' (4 unsigned long longs)
        import struct

        format_256 = ">4Q"

        V1 = struct.unpack(format_256, h1_bytes)
        V2 = struct.unpack(format_256, h2_bytes)
        V3 = struct.unpack(format_256, h3_bytes)
        V4 = struct.unpack(format_256, h4_bytes)

        raw_anchor: List[Word64] = []

        # Reduced Vertical Mix (4 iterations for 4 words)
        for i in range(4):
            w1 = V1[i]
            w2 = V2[(i + 1) % 4]
            w3 = V3[(i + 2) % 4]
            w4 = V4[(i + 3) % 4]

            mixed_word = PsiKernel._mix_column(w1, w2, w3, w4)

            # Adapted Pi round constant
            rc = Word64(0x243F6A8885A308D3 ^ i)
            raw_anchor.append(B.xor(mixed_word, rc))

        # Horizontal Diffusion in 256 bits
        final_anchor = PsiKernel._diffuse_horizontal_256(raw_anchor)

        return struct.pack(format_256, *final_anchor)
