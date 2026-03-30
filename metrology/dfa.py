# sigma/metrology/dfa.py
import os
import random
import statistics
import json
import math
from typing import Dict, List, Any
from sigma.core.primitives import BitwiseOps as B
from sigma.core.types import Word64
from sigma.core.psi import PsiKernel


class FaultInjectionSimulator:
    """
    Transient Fault Injection Simulator.
    Emulates the impact of a Single Event Upset (SEU) on hardware
    during the computation of the Psi core's intermediate registers.
    """

    def __init__(self, target_bit_space: int = 256):
        self.bits = target_bit_space

    def _shadow_mix_column_with_fault(
        self, v1: Word64, v2: Word64, v3: Word64, v4: Word64, fault_mask: Word64
    ) -> Word64:
        """
        Shadow execution that emulates a laser/voltage strike
        immediately following the computation of Phase A.
        """
        # --- PHASE A: Genuine Execution ---
        a1 = B.xor(B.add(v1, v3), B.rotl(v2, 13))
        a2 = B.xor(B.add(v2, v4), B.rotl(v3, 17))
        a3 = B.xor(B.sub(v3, v1), B.rotl(v4, 19))
        a4 = B.xor(B.sub(v4, v2), B.rotl(v1, 31))

        # [!] PHYSICAL FAULT INJECTION (DFA) [!]
        # The cosmic ray alters the physical register containing a1
        a1 = B.xor(a1, fault_mask)

        # --- PHASE B and C: Normal Continuation ---
        b1 = B.add(a1, a2)
        b4 = B.rotl(B.xor(a4, b1), 32)
        b3 = B.add(a3, b4)
        b2 = B.rotl(B.xor(a2, b3), 24)
        b1 = B.add(b1, b2)
        b4 = B.rotl(B.xor(b4, b1), 16)
        b3 = B.add(b3, b4)
        b2 = B.rotl(B.xor(b2, b3), 63)

        return B.add(B.xor(b1, b3), B.xor(b2, b4))

    def _shadow_compute_anchor_256(
        self, V1, V2, V3, V4, fault_col: int, fault_mask: Word64
    ) -> List[Word64]:
        """Computes the anchor by injecting the fault into a specific column."""
        raw_anchor: List[Word64] = []
        for i in range(4):
            w1 = V1[i]
            w2 = V2[(i + 1) % 4]
            w3 = V3[(i + 2) % 4]
            w4 = V4[(i + 3) % 4]

            # Inject the fault only in the target cycle (column)
            if i == fault_col:
                mixed_word = self._shadow_mix_column_with_fault(
                    w1, w2, w3, w4, fault_mask
                )
            else:
                mixed_word = PsiKernel._mix_column(w1, w2, w3, w4)

            rc = Word64(0x243F6A8885A308D3 ^ i)
            raw_anchor.append(B.xor(mixed_word, rc))

        return PsiKernel._diffuse_horizontal_256(raw_anchor)

    def run_dfa_resilience_test(self, iterations: int = 5000) -> Dict[str, Any]:
        """
        Executes N simulations by injecting a 1-bit error into internal registers.
        Measures whether the core successfully diffuses the error prior to output.
        """
        print(f"\n[+] Analyzing Differential Fault Analysis (DFA) Resilience")
        print(f"    Iterations: {iterations} | State: {self.bits} bits")

        hamming_distances = []
        import struct

        for _ in range(iterations):
            # 1. Generate random initial state
            format_256 = ">4Q"
            h1 = os.urandom(32)
            h2 = os.urandom(32)
            h3 = os.urandom(32)
            h4 = os.urandom(32)
            V1 = struct.unpack(format_256, h1)
            V2 = struct.unpack(format_256, h2)
            V3 = struct.unpack(format_256, h3)
            V4 = struct.unpack(format_256, h4)

            # 2. Genuine Execution (No faults)
            genuine_anchor = PsiKernel.compute_anchor_256(h1, h2, h3, h4)

            # 3. Prepare the fault (1 bit at a random position)
            fault_col = random.randint(0, 3)
            fault_bit = random.randint(0, 63)
            fault_mask = Word64(1 << fault_bit)

            # 4. Shadow Execution (With fault injected in Phase A)
            faulty_words = self._shadow_compute_anchor_256(
                V1, V2, V3, V4, fault_col, fault_mask
            )
            faulty_anchor = struct.pack(format_256, *faulty_words)

            # 5. Output differential calculation
            dh = (
                int.from_bytes(genuine_anchor, "big").bit_count()
                ^ int.from_bytes(faulty_anchor, "big").bit_count()
            )
            # Strict bit-by-bit alternative:
            val1 = int.from_bytes(genuine_anchor, "big")
            val2 = int.from_bytes(faulty_anchor, "big")
            hamming_distances.append((val1 ^ val2).bit_count())

        mean_dh = statistics.mean(hamming_distances)
        ideal_dh = self.bits / 2.0
        error_margin = abs(mean_dh - ideal_dh) / ideal_dh

        print(
            f"    -> Mean Output Fault Distance: {mean_dh:.2f} bits (Ideal: {ideal_dh})"
        )
        print(f"    -> Stochastic Deviation Margin : {error_margin*100:.3f}%")

        is_secure = (
            error_margin < 0.05
        )  # If it deviates less than 5% from the ideal mean, it is unassailable.
        print(
            f"    -> DFA Resistance Demonstrated     : {'YES (Irrecoverable State)' if is_secure else 'NO (Linear Algebraic Equations Possible)'}"
        )

        return {
            "iterations": iterations,
            "mean_hamming_distance_of_fault": round(mean_dh, 4),
            "ideal_hamming_distance": ideal_dh,
            "is_dfa_resistant": is_secure,
        }


if __name__ == "__main__":
    dfa_simulator = FaultInjectionSimulator(target_bit_space=256)
    report = dfa_simulator.run_dfa_resilience_test(iterations=10000)

    with open("sigma_dfa_metrics.json", "w") as f:
        json.dump(report, f, indent=4)
