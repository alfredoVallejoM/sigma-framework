import struct
from abc import ABC, abstractmethod
from typing import Optional
from sigma.interfaces.i_stream import IDataStream
from sigma.hash_engines.wrappers import IHashEngine, StdLibHash


class SigmaStrategy(ABC):
    """
    Abstract Base Class for all Sigma families.
    Handles the flow: Stream -> Anchor -> Recursive Loop -> Final Hash.
    """

    def __init__(self, rounds: int = 10, recursion_alg: str = "sha3_512"):
        self.rounds = rounds
        self.recursion_alg = recursion_alg

    @abstractmethod
    def calculate_anchor(self, stream: IDataStream) -> bytes:
        """
        Family-specific logic to derive the initial anchor.
        Must consume the stream and reset it if necessary.
        """
        pass

    def _recursive_step(self, anchor: bytes, initial_state: bytes) -> bytes:
        """
        The canonical Sigma recursive loop.
        State_t+1 = Hash(State_t || Anchor || t)
        """
        state = initial_state
        # Instantiate the recursion engine (usually SHA3-512)
        hasher_cls = lambda: StdLibHash(self.recursion_alg)

        for t in range(self.rounds):
            h = hasher_cls()
            # Concatenation optimization
            # TODO: In C, this would be a single mutable buffer.
            t_bytes = struct.pack(">Q", t)  # 64-bit Big Endian counter

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
        # 1. Calculate Anchor (Strategy dependent)
        anchor = self.calculate_anchor(stream)

        # 2. Initialize state (State_0 = Anchor)
        initial_state = anchor

        # 3. Execute temporal recursion
        final_hash = self._recursive_step(anchor, initial_state)

        return final_hash.hex()
