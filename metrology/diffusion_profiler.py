# sigma/metrology/diffusion_profiler.py
import os
import json
import random
import statistics
from typing import Dict, Any, List
from sigma.factory import SigmaFactory


class DiffusionPropagationProfiler:
    """
    Round-by-Round Diffusion Propagation Profiler (Deep 3D Matrix).
    Evaluates the velocity at which Sigma's ARX matrix reaches Shannon's
    saturation point (50% flipped bits) across multiple topological strategies,
    scaling payload sizes, and specific parameterized round sequences.
    """

    def __init__(self):
        pass

    def _flip_random_bit(self, data: bytes) -> bytes:
        """Inverts exactly one uniformly chosen random bit in the byte array."""
        mutable_data = bytearray(data)
        byte_idx = random.randint(0, len(mutable_data) - 1)
        bit_idx = random.randint(0, 7)
        mutable_data[byte_idx] ^= 1 << bit_idx
        return bytes(mutable_data)

    def _hamming_distance(self, hex1: str, hex2: str) -> int:
        """Calculates the bitwise Hamming distance between two hex strings."""
        b1 = bytes.fromhex(hex1)
        b2 = bytes.fromhex(hex2)
        return sum(bin(x ^ y).count("1") for x, y in zip(b1, b2))

    def _print_progress(
        self, iteration: int, total: int, prefix: str = "", length: int = 40
    ):
        """Native terminal HUD to prevent console blindness during deep sweeps."""
        percent = f"{100 * (iteration / float(total)):.1f}"
        filled_length = int(length * iteration // total)
        bar = "█" * filled_length + "-" * (length - filled_length)
        print(f"\r    {prefix} | [{bar}] {percent}%", end="\r")
        if iteration == total:
            print()

    def run_exhaustive_profiling(
        self,
        strategies: List[str],
        payload_sizes: List[int],
        target_rounds: List[int],
        samples: int = 5000,
    ) -> Dict[str, Any]:

        print(f"[+] Starting Deep ARX Diffusion Profiling (3D Parameter Sweep)")
        print(f"    Samples/Round: {samples}")
        print(f"    Strategies: {strategies}")
        print(f"    Payloads: {payload_sizes} Bytes")
        print(f"    Target Rounds: {target_rounds}\n")

        global_results = {}
        # Ensure rounds are evaluated in ascending order
        sorted_rounds = sorted(target_rounds)

        for strategy in strategies:
            global_results[strategy] = {}
            # Contextualize target bit-space based on the underlying core configuration
            target_bits = 256 if strategy in ["lightweight", "realtime"] else 512
            ideal_hamming = target_bits / 2.0

            for p_size in payload_sizes:
                print(
                    f"[*] Analyzing Strategy: [{strategy.upper()}] | Payload: {p_size} Bytes"
                )
                matrix_results = {}

                for r in sorted_rounds:
                    distances = []
                    for i in range(samples):
                        # Update HUD smoothly without bottlenecking the I/O bus
                        if i % (samples // 10) == 0 or i == samples - 1:
                            self._print_progress(
                                i + 1, samples, prefix=f"Round {r:02d}"
                            )

                        msg = os.urandom(p_size)
                        msg_mutated = self._flip_random_bit(msg)

                        # Generate genuine vs mutated hashes
                        h1 = SigmaFactory.hash_bytes(msg, mode=strategy, rounds=r)
                        h2 = SigmaFactory.hash_bytes(
                            msg_mutated, mode=strategy, rounds=r
                        )

                        distances.append(self._hamming_distance(h1, h2))

                    # Statistical Moments
                    mean_dist = statistics.mean(distances)
                    stdev_dist = statistics.stdev(distances)
                    diffusion_percent = (mean_dist / target_bits) * 100.0

                    # Strict Saturation Definition: 49.5% to 50.5% boundary
                    is_saturated = 49.5 <= diffusion_percent <= 50.5

                    matrix_results[f"round_{r}"] = {
                        "mean_hamming_distance": round(mean_dist, 4),
                        "stdev_hamming_distance": round(stdev_dist, 4),
                        "diffusion_percentage": round(diffusion_percent, 4),
                        "is_saturated": is_saturated,
                    }

                # Identify the exact phase transition where the algorithm becomes secure
                saturation_round = next(
                    (str(r) for r, d in matrix_results.items() if d["is_saturated"]),
                    "UNREACHED",
                )
                print(
                    f"    -> [VERDICT] Cryptographic Shannon Saturation at: {saturation_round}\n"
                )

                global_results[strategy][f"payload_{p_size}B"] = {
                    "target_bits": target_bits,
                    "ideal_hamming": ideal_hamming,
                    "saturation_round": saturation_round,
                    "round_data": matrix_results,
                }

        return global_results


if __name__ == "__main__":
    profiler = DiffusionPropagationProfiler()

    # EXHAUSTIVE 3D SWEEP PARAMS

    # Dimension 1: Strategies
    test_strategies = ["paranoid", "simultaneous", "lightweight", "realtime"]

    # Dimension 2: Payloads (Scaling from Micro-IoT to Macroscopic chunks)
    test_payloads = [64, 256, 1024, 4096, 16384]

    # Dimension 3: Rounds (Parameterized Sequence)
    # Testing initial rapid diffusion (1-5) and asymptotic limits (8-32)
    test_rounds = [
        1,
        2,
        3,
        4,
        5,
        8,
        10,
        12,
        16,
        20,
        24,
        32,
        64,
        96,
        128,
        196,
        256,
        512,
        1024,
    ]

    report = profiler.run_exhaustive_profiling(
        strategies=test_strategies,
        payload_sizes=test_payloads,
        target_rounds=test_rounds,
        samples=5000,
    )

    with open("sigma_diffusion_metrics.json", "w") as f:
        json.dump(report, f, indent=4)
    print("[OK] Deep Metrology Dataset secured to sigma_diffusion_metrics.json.")
