# sigma/metrology/microarch.py
import os
import subprocess
import tempfile
import json
import re
import sys
from typing import Dict, Any


class PMUInstrumenter:
    """
    Hardware Performance Monitoring Units (PMU) interface via Linux `perf`.
    Designed to isolate the thermodynamics of the Psi core and the Sigma loop.
    """

    def __init__(self):
        # Verify access to hardware perf counters
        self.perf_available = self._check_perf_access()
        if not self.perf_available:
            print(
                "[WARNING] Hardware PMU (perf) inaccessible. Requires Linux and appropriate permissions (sysctl kernel.perf_event_paranoid < 2)."
            )

    def _check_perf_access(self) -> bool:
        if sys.platform != "linux":
            return False
        try:
            res = subprocess.run(["perf", "--version"], capture_output=True)
            return res.returncode == 0
        except FileNotFoundError:
            return False

    def _run_perf_workload(self, command: list) -> Dict[str, float]:
        """Executes a command under the thermodynamic microscope of perf stat."""
        if not self.perf_available:
            return {}

        # Events to measure: Cycles, Instructions, and L1 Data Cache Misses
        perf_events = "cycles,instructions,L1-dcache-loads,L1-dcache-load-misses"

        perf_cmd = ["perf", "stat", "-e", perf_events, "-x", ";"] + command

        res = subprocess.run(perf_cmd, capture_output=True, text=True)
        metrics = {}

        # Parsing tabular output (semicolon separated) from perf
        for line in res.stderr.split("\n"):
            if not line or line.startswith("#"):
                continue
            parts = line.split(";")
            if len(parts) >= 3:
                value = parts[0]
                event_name = parts[2]
                try:
                    metrics[event_name] = float(value.replace(",", ""))
                except ValueError:
                    pass

        return metrics

    def profile_pow_l1_confinement(self, file_size_mb: float = 1.0) -> Dict[str, Any]:
        """
        Empirical validation of the L1 Cache Confinement Theorem.
        Measures the impact of increasing R on L1 Misses.
        """
        print(f"\n[+] Evaluating L1 Confinement Theorem ({file_size_mb} MB)")
        results = {}
        rounds_to_test = [10, 100, 1000, 5000]

        # Create a temporary script in pure Python to isolate the execution,
        # ensuring perf measures only the net workload and not our metrology overhead.
        with tempfile.TemporaryDirectory() as tmpdir:
            test_file = os.path.join(tmpdir, "entropy.bin")
            with open(test_file, "wb") as f:
                f.write(os.urandom(int(file_size_mb * 1024 * 1024)))

            for r in rounds_to_test:
                runner_script = os.path.join(tmpdir, f"runner_r{r}.py")
                with open(runner_script, "w") as f:
                    f.write(
                        f"""
import sys
sys.path.insert(0, '{os.path.abspath(os.path.join(os.path.dirname(__file__), '../..'))}')
from sigma.factory import SigmaFactory
SigmaFactory.hash_file('{test_file}', mode='paranoid', rounds={r})
"""
                    )
                print(f"  -> PMU Profiling for R={r}...")
                metrics = self._run_perf_workload([sys.executable, runner_script])

                if metrics:
                    ipc = metrics.get("instructions", 0) / metrics.get("cycles", 1)
                    l1_miss_ratio = (
                        metrics.get("L1-dcache-load-misses", 0)
                        / metrics.get("L1-dcache-loads", 1)
                    ) * 100

                    results[str(r)] = {
                        "cycles": metrics.get("cycles"),
                        "instructions": metrics.get("instructions"),
                        "ipc": round(ipc, 2),
                        "l1_load_misses": metrics.get("L1-dcache-load-misses"),
                        "l1_miss_ratio_percent": round(l1_miss_ratio, 4),
                    }
                    print(
                        f"     * Cycles: {metrics.get('cycles'):.2e} | IPC: {ipc:.2f} | L1 Miss Ratio: {l1_miss_ratio:.4f}%"
                    )

        return results

    def profile_crossover_phase(self) -> Dict[str, Any]:
        """
        Identifies the thermodynamic intersection between Lightweight and RealTime
        by sweeping from 2^6 (64B) up to 2^20 (1MB).
        """
        import time
        from sigma.factory import SigmaFactory

        print(f"\n[+] Analyzing Phase Transition (Lightweight vs RealTime)")
        sizes_bytes = [2**i for i in range(6, 21)]  # From 64B to 1MB
        results = {}

        for size in sizes_bytes:
            data = os.urandom(size)

            # Lightweight
            start = time.perf_counter()
            SigmaFactory.hash_bytes(data, mode="lightweight")
            t_l = time.perf_counter() - start

            # RealTime
            start = time.perf_counter()
            SigmaFactory.hash_bytes(data, mode="realtime")
            t_r = time.perf_counter() - start

            winner = "RealTime" if t_r < t_l else "Lightweight"

            results[str(size)] = {
                "lightweight_s": t_l,
                "realtime_s": t_r,
                "winner": winner,
            }

            if (
                size <= 1024 or size == sizes_bytes[-1]
            ):  # Print only a subset to avoid saturating stdout
                print(
                    f"  -> Size: {size} B | L-Weight: {t_l*1e6:.2f} μs | R-Time: {t_r*1e6:.2f} μs | Faster: {winner}"
                )

        return results


if __name__ == "__main__":
    instrumenter = PMUInstrumenter()

    # 1. Phase Transition Test (Cross-platform)
    crossover_data = instrumenter.profile_crossover_phase()

    # 2. PMU L1 Confinement Test (Requires Linux + perf)
    pmu_data = instrumenter.profile_pow_l1_confinement(file_size_mb=2.0)

    # Export data for LaTeX plotting
    report = {"crossover_phase": crossover_data, "l1_confinement": pmu_data}

    with open("sigma_microarch_metrics.json", "w") as f:
        json.dump(report, f, indent=4)
    print("\n[OK] Microarchitectural data dumped to sigma_microarch_metrics.json")
