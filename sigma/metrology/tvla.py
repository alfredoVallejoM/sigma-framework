# sigma/metrology/tvla.py
import os
import time
import math
import random
import statistics
import gc
from typing import Dict, Tuple
from sigma.core.psi import PsiKernel


class TVLAEngine:
    """
    Software-Level Test Vector Leakage Assessment (TVLA).
    Applies the Welch's t-test to empirically demonstrate the Constant-Time
    execution of the Psi mathematical core.
    """

    def __init__(self):
        # Generate the 4 quadrants (32 bytes each) expected by compute_anchor_256
        # This will be our Q_fixed set
        self.fixed_inputs = (
            os.urandom(32),
            os.urandom(32),
            os.urandom(32),
            os.urandom(32),
        )

    def _measure_psi_execution(
        self, is_fixed: bool, iterations_per_sample: int = 10
    ) -> int:
        """
        Measures the execution time of the pure core in nanoseconds.
        Group executions to amortize the overhead of the Python function call.
        """
        if is_fixed:
            h1, h2, h3, h4 = self.fixed_inputs
        else:
            h1, h2, h3, h4 = (
                os.urandom(32),
                os.urandom(32),
                os.urandom(32),
                os.urandom(32),
            )

        # Isolate the measurement using the highest resolution monotonic clock
        t0 = time.perf_counter_ns()
        for _ in range(iterations_per_sample):
            PsiKernel.compute_anchor_256(h1, h2, h3, h4)
        t1 = time.perf_counter_ns()

        return t1 - t0

    def compute_welch_t_statistic(
        self, fixed_times: list, random_times: list
    ) -> Tuple[float, float, float]:
        """Applies the Welch's Statistical Equation."""
        n_f, n_r = len(fixed_times), len(random_times)
        mu_f = statistics.mean(fixed_times)
        mu_r = statistics.mean(random_times)

        var_f = statistics.variance(fixed_times)
        var_r = statistics.variance(random_times)

        # Denominator calculation (Standard error of the difference)
        se_diff = math.sqrt((var_f / n_f) + (var_r / n_r))

        # t-statistic
        t_stat = (mu_f - mu_r) / se_diff if se_diff > 0 else 0

        return t_stat, mu_f, mu_r

    def run_leakage_assessment(self, total_samples: int = 100000) -> Dict[str, float]:
        print(f"\n[+] Starting Test Vector Leakage Assessment (TVLA)")
        print(f"    Total samples: {total_samples} | Security target: |t| < 4.5")

        fixed_times = []
        random_times = []

        def print_progress(iteration, total, length=40):
            percent = f"{100 * (iteration / float(total)):.1f}"
            filled_length = int(length * iteration // total)
            bar = "█" * filled_length + "-" * (length - filled_length)
            print(f"\r    [{bar}] {percent}% ({iteration}/{total})", end="\r")
            if iteration == total:
                print()

        gc.disable()
        try:
            for i in range(total_samples):
                # Update the progress bar
                if i % 1000 == 0 or i == total_samples - 1:
                    print_progress(i + 1, total_samples)

                if random.random() > 0.5:
                    fixed_times.append(self._measure_psi_execution(is_fixed=True))
                else:
                    random_times.append(self._measure_psi_execution(is_fixed=False))
        finally:
            gc.enable()

        t_stat, mu_f, mu_r = self.compute_welch_t_statistic(fixed_times, random_times)

        print(f"\n=== TVLA Results (Constant-Time Verification) ===")
        print(f" -> Fixed Samples (Q0) : {len(fixed_times)} | Mean: {mu_f:.2f} ns")
        print(f" -> Random Samples (Q1): {len(random_times)} | Mean: {mu_r:.2f} ns")
        print(f" -> Welch's t-statistic: {t_stat:.5f}")

        if abs(t_stat) > 4.5:
            print(
                "[ALERT] |t| > 4.5. Potential side-channel information leakage detected."
            )
        else:
            print(
                "[SUCCESS] |t| <= 4.5. No data-dependent information leakage detected."
            )

        return {
            "t_statistic": round(t_stat, 5),
            "mean_ns_fixed": round(mu_f, 2),
            "mean_ns_random": round(mu_r, 2),
            "samples_fixed": len(fixed_times),
            "samples_random": len(random_times),
            "leakage_detected": abs(t_stat) > 4.5,
        }


if __name__ == "__main__":
    engine = TVLAEngine()
    # EXHAUSTIVE SWEEP: 500,000 samples for deep cryptographic side-channel resistance
    results = engine.run_leakage_assessment(total_samples=500000)

    import json

    with open("sigma_tvla_metrics.json", "w") as f:
        json.dump(results, f, indent=4)
