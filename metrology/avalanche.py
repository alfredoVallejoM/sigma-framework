# sigma/metrology/avalanche.py
import os
import random
import statistics
import math
import json
from typing import Dict, List, Tuple
from sigma.factory import SigmaFactory


class StochasticMetrologyEngine:
    """
    Stochastic validation engine.
    Evaluates the Strict Avalanche Criterion (SAC) and Shannon Entropy
    to demonstrate resistance against differential cryptanalysis.
    """

    def __init__(self, output_bits: int = 512):
        self.output_bits = output_bits
        # Theoretical bounds for an Ideal Random Oracle (Binomial Distribution)
        self.ideal_mean = self.output_bits / 2.0
        self.ideal_variance = self.output_bits * 0.5 * 0.5
        self.ideal_stdev = math.sqrt(self.ideal_variance)

    def _flip_random_bit(self, data: bytes) -> bytes:
        """Inverts exactly 1 uniformly chosen random bit from the byte array."""
        mutable_data = bytearray(data)
        byte_idx = random.randint(0, len(mutable_data) - 1)
        bit_idx = random.randint(0, 7)
        mutable_data[byte_idx] ^= 1 << bit_idx
        return bytes(mutable_data)

    def _hamming_distance(self, hex1: str, hex2: str) -> int:
        """
        Calculates the Hamming distance between two hexadecimal outputs.
        Utilizes C-optimized int.bit_count() (Python 3.10+).
        """
        val1 = int(hex1, 16)
        val2 = int(hex2, 16)
        return (val1 ^ val2).bit_count()

    def _shannon_entropy(self, hex_string: str) -> float:
        """Calculates the Shannon entropy (bits/byte) of the hexadecimal output."""
        data = bytes.fromhex(hex_string)
        if not data:
            return 0.0
        entropy = 0.0
        length = len(data)
        freq = {b: data.count(b) for b in set(data)}
        for count in freq.values():
            p_x = count / length
            entropy += -p_x * math.log2(p_x)
        return entropy

    def run_monte_carlo_avalanche(
        self, mode: str, payload_size_bytes: int = 1024, iterations: int = 1000
    ) -> Dict[str, float]:
        print(
            f"\n[+] Analyzing Strict Avalanche Criterion (SAC) - Mode: {mode.upper()}"
        )
        print(
            f"    Payload: {payload_size_bytes} B | Monte Carlo Iterations: {iterations}"
        )

        hamming_distances = []
        aggregate_stream = bytearray()
        base_message = os.urandom(payload_size_bytes)

        # --- Internal Progress Bar Function ---
        def print_progress(iteration, total, length=40):
            percent = f"{100 * (iteration / float(total)):.1f}"
            filled_length = int(length * iteration // total)
            bar = "█" * filled_length + "-" * (length - filled_length)
            # Prints with carriage return (\r) to overwrite the line
            print(f"\r    [{bar}] {percent}% ({iteration}/{total})", end="\r")
            if iteration == total:
                print()  # Line break upon completion

        # -----------------------------------------------

        for i in range(iterations):
            msg_A = os.urandom(payload_size_bytes)
            hash_A = SigmaFactory.hash_bytes(msg_A, mode=mode, rounds=1)

            msg_B = self._flip_random_bit(msg_A)
            hash_B = SigmaFactory.hash_bytes(msg_B, mode=mode, rounds=1)

            dh = self._hamming_distance(hash_A, hash_B)
            hamming_distances.append(dh)

            aggregate_stream.extend(bytes.fromhex(hash_A))

            # Update the bar every 50 iterations to prevent terminal I/O bus bottlenecks
            if i % 50 == 0 or i == iterations - 1:
                print_progress(i + 1, iterations)

        # Statistical Moments
        emp_mean = statistics.mean(hamming_distances)
        emp_stdev = statistics.stdev(hamming_distances) if iterations > 1 else 0.0

        stream_entropy = 0.0
        if aggregate_stream:
            length = len(aggregate_stream)
            freq = {b: aggregate_stream.count(b) for b in set(aggregate_stream)}
            for count in freq.values():
                p_x = count / length
                stream_entropy += -p_x * math.log2(p_x)

        error_mean = abs(emp_mean - self.ideal_mean) / self.ideal_mean
        error_stdev = abs(emp_stdev - self.ideal_stdev) / self.ideal_stdev

        print(
            f"    -> Mean Hamming Distance   : {emp_mean:.4f} (Ideal: {self.ideal_mean}) | Deviation: {error_mean*100:.3f}%"
        )
        print(
            f"    -> Empirical Standard Dev  : {emp_stdev:.4f} (Ideal: {self.ideal_stdev:.4f}) | Deviation: {error_stdev*100:.3f}%"
        )
        print(
            f"    -> Stream Entropy          : {stream_entropy:.6f} bits/byte (Max: 8.000000)"
        )

        return {
            "mode": mode,
            "iterations": iterations,
            "mean_hamming": round(emp_mean, 4),
            "stdev_hamming": round(emp_stdev, 4),
            "stream_shannon_entropy": round(stream_entropy, 6),
            "error_mean_percent": round(error_mean * 100, 4),
            "error_stdev_percent": round(error_stdev * 100, 4),
        }


if __name__ == "__main__":
    stochastic_engine = StochasticMetrologyEngine(output_bits=512)
    strategies = ["paranoid", "simultaneous", "lightweight", "realtime"]
    report = {}

    # EXHAUSTIVE SWEEP: 50,000 iterations for bulletproof SAC demonstration
    ITERATIONS = 50000
    PAYLOAD_SIZE = 1024 * 1024  # 1 MB payloads to ensure deep entropy mixing

    try:
        for strat in strategies:
            bits = 256 if strat in ["lightweight", "realtime"] else 512
            stochastic_engine.output_bits = bits
            stochastic_engine.ideal_mean = bits / 2.0
            stochastic_engine.ideal_variance = bits * 0.25
            stochastic_engine.ideal_stdev = math.sqrt(stochastic_engine.ideal_variance)

            res = stochastic_engine.run_monte_carlo_avalanche(
                mode=strat, payload_size_bytes=PAYLOAD_SIZE, iterations=ITERATIONS
            )
            report[strat] = res

        with open("sigma_stochastic_metrics.json", "w") as f:
            json.dump(report, f, indent=4)
        print("\n[SUCCESS] Stochastic Analysis completed. Dataset saved.")

    except KeyboardInterrupt:
        print("\n[STOP] Execution halted by user.")
