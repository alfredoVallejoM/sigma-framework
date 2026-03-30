import os
import mmap
import hashlib
from concurrent.futures import ProcessPoolExecutor
from typing import List, Tuple

from sigma.core.psi import PsiKernel
from sigma.strategies.base import SigmaStrategy
from sigma.interfaces.i_stream import IDataStream
from sigma.adapters.streams import FileStream

# ==============================================================================
# WORKER KERNEL (Must be at the top-level to be serializable by pickle)
# ==============================================================================

def _worker_process_blake2b(args: Tuple[str, bytes, int, int]) -> bytes:
    """
    Function that runs on an independent CPU core.
    Hashes ONLY its assigned mathematical chunk using Zero-Copy memoryviews.
    """
    filepath, context_person, offset, length = args

    # Optimized BLAKE2b configuration (digest_size=64 -> 512 bits)
    hasher = hashlib.blake2b(digest_size=64, person=context_person)

    if length == 0:
        return hasher.digest()

    # Efficient read with mmap (Zero-Copy in kernel space)
    with open(filepath, "rb") as f:
        # Map the entire file into virtual memory (lazy loading via OS page faults)
        with mmap.mmap(f.fileno(), 0, access=mmap.ACCESS_READ) as mm:
            # [CRITICAL OPTIMIZATION]
            # memoryview creates a C-level pointer to the exact byte range.
            # It does NOT copy the data into RAM, preserving O(1) memory overhead.
            view = memoryview(mm)[offset : offset + length]
            
            # BLAKE2b internally releases the GIL when processing large buffers
            hasher.update(view)
            
            # Release the view to free the C-level pointer
            view.release()

    return hasher.digest()

# ==============================================================================
# SIMULTANEOUS STRATEGY
# ==============================================================================

class SimultaneousStrategy(SigmaStrategy):
    """
    Family 2: Extreme Speed (Parallel SIMD Logic).
    Mathematically partitions the payload into N chunks to saturate the memory bus.
    Utilizes a Truncated Merkle Reduction to bridge N arbitrary threads back to the 
    strict 4-vector geometry required by the Psi core.
    """

    # The Psi Core mathematically requires exactly 4 vectors at the end
    PSI_REQUIRED_VECTORS = 4
    
    # Domain separation prefixes for the Fan-In reduction (prevents collisions)
    PREFIX_LEAF = b"\x00"
    PREFIX_NODE = b"\x01"

    def __init__(self, rounds: int = 5, max_threads: int = None):
        # We map 'rounds' semantics to internal logic, but allow explicit thread caps
        super().__init__(rounds=rounds, recursion_alg="blake2b")
        
        # Determine maximum concurrency. If not specified, use all available cores.
        # We enforce a minimum of 4 threads to satisfy Psi natively when possible,
        # but gracefully handle environments with fewer cores.
        sys_cores = os.cpu_count() or 1
        self.concurrency = max_threads if max_threads else max(self.PSI_REQUIRED_VECTORS, sys_cores)

    def _truncate_merkle_reduction(self, hashes: List[bytes]) -> Tuple[bytes, bytes, bytes, bytes]:
        """
        Reduces an arbitrary list of N hashes down to exactly 4 hashes using a 
        Merkle tree structure. If N < 4, pads deterministically.
        """
        current_layer = [
            hashlib.blake2b(self.PREFIX_LEAF + h, digest_size=64).digest()
            for h in hashes
        ]

        # Reduce the tree layer by layer until we have 4 or fewer nodes
        while len(current_layer) > self.PSI_REQUIRED_VECTORS:
            next_layer = []
            
            # Pair nodes and hash them together
            for i in range(0, len(current_layer), 2):
                left = current_layer[i]
                # If odd number of nodes, duplicate the last one (standard Merkle)
                right = current_layer[i + 1] if i + 1 < len(current_layer) else left
                
                # Hash node: H(0x01 || Left || Right)
                parent = hashlib.blake2b(self.PREFIX_NODE + left + right, digest_size=64).digest()
                next_layer.append(parent)
                
            current_layer = next_layer

        # If we ended up with exactly 4 nodes, great.
        if len(current_layer) == self.PSI_REQUIRED_VECTORS:
            return tuple(current_layer) # type: ignore
            
        # If we have less than 4 (e.g., ran on a 2-core machine with concurrency=2),
        # we must deterministically pad the remaining vectors to satisfy Psi.
        padded = list(current_layer)
        while len(padded) < self.PSI_REQUIRED_VECTORS:
            # Pad by hashing the last available node with a node prefix to mutate it
            last_node = padded[-1]
            new_padding = hashlib.blake2b(self.PREFIX_NODE + last_node, digest_size=64).digest()
            padded.append(new_padding)
            
        return tuple(padded) # type: ignore

    def calculate_anchor(self, stream: IDataStream) -> bytes:
        """
        Computes the macroscopic anchor by spawning N parallel processes,
        and reducing the results via a Truncated Merkle Tree.
        """

        # 1. Stream type verification
        if not isinstance(stream, FileStream):
            return self._calculate_anchor_serial(stream)

        filepath = stream._f.name
        file_size = stream.get_size()

        # 2. Mathematical Partitioning (Fan-Out)
        # Divide the file into exactly self.concurrency chunks
        tasks = []
        chunk_size = file_size // self.concurrency

        for i in range(self.concurrency):
            offset = i * chunk_size
            # The last chunk absorbs any remaining byte division remainders
            length = chunk_size if i < (self.concurrency - 1) else (file_size - offset)
            
            # Context person is truncated/padded to 16 bytes for BLAKE2b
            context = f"Sigma-Simul-{i}".encode('utf-8')[:16].ljust(16, b'\x00')
            tasks.append((filepath, context, offset, length))

        # 3. Parallel Execution
        # We cap ProcessPoolExecutor to avoid spawning more processes than chunks
        max_workers = min(self.concurrency, os.cpu_count() or 1)
        
        with ProcessPoolExecutor(max_workers=max_workers) as executor:
            results = executor.map(_worker_process_blake2b, tasks)
            raw_digests = list(results)

        # 4. Truncated Merkle Reduction (Fan-In)
        # Reduce N arbitrary digests down to exactly 4 for the Psi Core
        h1, h2, h3, h4 = self._truncate_merkle_reduction(raw_digests)

        # 5. Final Psi Absorption
        anchor = PsiKernel.compute_anchor(h1, h2, h3, h4)

        return anchor

    def _calculate_anchor_serial(self, stream: IDataStream) -> bytes:
        """Fallback for non-file streams (e.g., memory, sockets)."""
        
        # Create a hasher for each virtual thread
        hashers = []
        for i in range(self.concurrency):
            context = f"Sigma-Simul-{i}".encode('utf-8')[:16].ljust(16, b'\x00')
            hashers.append(hashlib.blake2b(digest_size=64, person=context))

        stream.reset()
        # Read in 64KB chunks to preserve RAM, updating all hashers sequentially
        while chunk := stream.read(1024 * 64):
            for h in hashers:
                h.update(chunk)

        raw_digests = [h.digest() for h in hashers]
        
        # Reduce and absorb
        h1, h2, h3, h4 = self._truncate_merkle_reduction(raw_digests)
        return PsiKernel.compute_anchor(h1, h2, h3, h4)
