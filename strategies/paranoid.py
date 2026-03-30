from typing import List
from sigma.core.psi import PsiKernel
from sigma.strategies.base import SigmaStrategy
from sigma.interfaces.i_stream import IDataStream

from sigma.hash_engines.wrappers import StdLibHash, SHAKEWrapper


class ParanoidStrategy(SigmaStrategy):
    """
    Family 1: Maximum Security (Algebraic Orthogonality).
    Engines: SHA-512, SHA3-512, BLAKE2b, SHAKE-256.
    """

    CHUNK_SIZE = 64 * 1024  # 64KB chunks for efficient reading

    def __init__(self, rounds: int = 20):
        super().__init__(rounds=rounds, recursion_alg="sha3_512")
        # Define the 4 orthogonal engines
        self.engines = [
            lambda: StdLibHash("sha512"),
            lambda: StdLibHash("sha3_512"),
            lambda: StdLibHash("blake2b"),
            lambda: SHAKEWrapper(512),
        ]

    def calculate_anchor(self, stream: IDataStream) -> bytes:
        # 1. Instantiate all 4 engines
        active_hashers = [ctor() for ctor in self.engines]

        # 2. Read the full stream and feed it to all engines
        stream.reset()
        while True:
            chunk = stream.read(self.CHUNK_SIZE)
            if not chunk:
                break
            for h in active_hashers:
                h.update(chunk)

        # 3. Obtain final digests
        digests = [h.digest() for h in active_hashers]

        # 4. Non-Linear Mix (Psi Kernel Phase 1)
        anchor = PsiKernel.compute_anchor(
            digests[0], digests[1], digests[2], digests[3]
        )

        return anchor
