import os
import mmap
import hashlib
import multiprocessing
from concurrent.futures import ProcessPoolExecutor
from typing import List, Tuple

from sigma.core.psi import PsiKernel
from sigma.strategies.base import SigmaStrategy
from sigma.interfaces.i_stream import IDataStream
from sigma.adapters.streams import FileStream

# ==============================================================================
# WORKER KERNEL (Must be at the top-level to be serializable)
# ==============================================================================


def _worker_process_blake2b(args: Tuple[str, bytes]) -> bytes:
    """
    Function that runs on an independent CPU core.
    Opens its own file descriptor to prevent I/O blocking.
    """
    filepath, context_person = args

    # Optimized BLAKE2b configuration
    # digest_size=64 -> 512 bits
    # person -> Personalization string (Domain Separation)
    hasher = hashlib.blake2b(digest_size=64, person=context_person)

    # Efficient read with mmap (Zero-Copy in kernel space)
    with open(filepath, "rb") as f:
        # If the file is empty, mmap fails; we handle that edge case
        if os.fstat(f.fileno()).st_size == 0:
            return hasher.digest()

        with mmap.mmap(f.fileno(), 0, access=mmap.ACCESS_READ) as mm:
            # BLAKE2b internally releases the GIL when processing large buffers
            hasher.update(mm)

    return hasher.digest()


# ==============================================================================
# SIMULTANEOUS STRATEGY
# ==============================================================================


class SimultaneousStrategy(SigmaStrategy):
    """
    Family 2: Extreme Speed (Parallel SIMD Logic).
    Uses multiprocessing to saturate the memory bus and CPU.
    Ideal for servers with fast NVMe storage.
    """

    def __init__(self, rounds: int = 5):
        # Fewer recursive rounds by default to prioritize throughput
        super().__init__(rounds=rounds, recursion_alg="blake2b")

        # Define the 4 orthogonal contexts (max 16 bytes for BLAKE2b)
        self.contexts = [
            b"Sigma-Alpha-Ctx",
            b"Sigma-Beta-Ctx ",
            b"Sigma-Gamma-Ctx",
            b"Sigma-Delta-Ctx",
        ]

    def calculate_anchor(self, stream: IDataStream) -> bytes:
        """
        Computes the anchor by spawning 4 parallel processes.
        NOTE: This optimization requires the stream to originate from a physical disk file.
        """

        # 1. Stream type verification
        # If it's an in-memory or network stream, efficient multiprocessing is unfeasible
        # without copying data (which would destroy performance).
        if not isinstance(stream, FileStream):
            # Fallback: Serial execution if not a physical file
            # (A logging warning could be implemented here)
            return self._calculate_anchor_serial(stream)

        # 2. Prepare arguments for workers
        # The physical path is required so each worker can open its own mmap
        filepath = stream._f.name
        tasks = [(filepath, ctx) for ctx in self.contexts]

        # 3. Fan-Out (Map)
        # Using ProcessPoolExecutor for automatic process management
        digests: List[bytes] = []

        # Determine number of workers (max 4, or fewer if CPU cores are limited)
        max_workers = min(4, os.cpu_count() or 1)

        with ProcessPoolExecutor(max_workers=max_workers) as executor:
            # Execute hashes in true parallel
            results = executor.map(_worker_process_blake2b, tasks)
            digests = list(results)

        # 4. Fan-In (Reduce)
        # Mix the 4 results using the Psi core
        anchor = PsiKernel.compute_anchor(
            digests[0], digests[1], digests[2], digests[3]
        )

        return anchor

    def _calculate_anchor_serial(self, stream: IDataStream) -> bytes:
        """Fallback for non-file streams (e.g., memory, sockets)."""
        hashers = [hashlib.blake2b(digest_size=64, person=ctx) for ctx in self.contexts]

        stream.reset()
        while chunk := stream.read(1024 * 64):
            for h in hashers:
                h.update(chunk)

        digests = [h.digest() for h in hashers]
        return PsiKernel.compute_anchor(*digests)
