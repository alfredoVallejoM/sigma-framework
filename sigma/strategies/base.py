import struct
from abc import ABC, abstractmethod
from typing import Optional

from sigma.hash_engines.wrappers import StdLibHash
from sigma.interfaces.i_stream import IDataStream


class SigmaStrategy(ABC):
    """
    Abstract Base Class for all Sigma families.
    Handles the flow: Stream -> Anchor -> Domain Separation -> Recursive Loop -> Final Hash.
    """

    def __init__(self, rounds: int = 10, recursion_alg: str = "sha3_512"):
        self.rounds = rounds
        self.recursion_alg = recursion_alg

    @abstractmethod
    def calculate_anchor(self, stream: IDataStream) -> bytes:
        """
        Family-specific logic to derive the initial macroscopic anchor.
        Must consume the stream and reset it if necessary.
        """
        pass

    def _generate_domain_header(self, stream_size: Optional[int]) -> bytes:
        """
        Generates the legacy deterministic 38-byte domain header.
        This framing predates the strict v2 TLV specification.
        """
        # 1. Magic Bytes & Version (6 bytes)
        header = b"SIGMA\x01"

        # 2. Topology Identity (16 bytes, right-padded with nulls)
        # Differentiates 'Lightweight' from 'Paranoid' algebraically.
        topo_name = self.__class__.__name__.encode("utf-8")[:16].ljust(16, b"\x00")
        header += topo_name

        # 3. Configured rounds (8 bytes, 64-bit big endian).
        header += struct.pack(">Q", self.rounds)

        # 4. Payload Size (8 bytes, 64-bit Big Endian)
        # Prevents Length Extension Attacks.
        # If infinite stream (None), use the maximum 64-bit integer (0xFFFFFFFFFFFFFFFF).
        sz = stream_size if stream_size is not None else 0xFFFFFFFFFFFFFFFF
        header += struct.pack(">Q", sz)

        return header

    def _recursive_step(self, anchor: bytes, initial_state: bytes) -> bytes:
        """
        The legacy v1 anchor-reinjected loop.
        Sᵢ₊₁ = Hash(Sᵢ ∥ Anchor ∥ 𝓣(i))
        """
        state = initial_state

        # Lambda to instantiate a fresh hasher for each round
        def hasher_cls():
            return StdLibHash(self.recursion_alg)

        for t in range(self.rounds):
            h = hasher_cls()

            # Round index as a 64-bit big-endian counter.
            t_bytes = struct.pack(">Q", t)

            h.update(state)
            h.update(anchor)
            h.update(t_bytes)

            state = h.digest()

        return state

    def compute(self, stream: IDataStream) -> str:
        """
        Main method (Template Method pattern).
        Returns the final hexdigest.
        """
        # 1. Calculate the macroscopic Anchor (Strategy dependent)
        anchor = self.calculate_anchor(stream)

        # 2. Extract Stream Size for Length Extension prevention
        stream_size = stream.get_size()

        # 3. Generate Domain Separation Header
        domain_header = self._generate_domain_header(stream_size)

        # 4. Cryptographically bind the Domain Header to State Zero (S₀)
        h = StdLibHash(self.recursion_alg)
        h.update(domain_header)
        h.update(anchor)
        initial_state = h.digest()

        # 5. Execute temporal recursion
        final_hash = self._recursive_step(anchor, initial_state)

        return final_hash.hex()
