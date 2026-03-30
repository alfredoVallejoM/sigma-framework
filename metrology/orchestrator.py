# sigma/metrology/orchestrator.py
import os
import sys
import time
import subprocess
import json
import platform
from datetime import datetime
from typing import List, Dict


class SigmaMetrologyOrchestrator:
    """
    Master Orchestrator for the Sigma Validation Suite.
    Executes all test dimensions in isolated processes to guarantee
    thermodynamic and cache hygiene in the results.
    """

    def __init__(self):
        self.start_time = time.time()
        self.base_dir = os.path.abspath(
            os.path.join(os.path.dirname(__file__), "../..")
        )

        # Canonical validation sequence
        self.pipeline = [
            {
                "id": "ASIC_ESTIMATOR",
                "module": "sigma.metrology.asic_estimator",
                "output": "sigma_asic_metrics.json",
                "description": "Area Synthesis (GE) and Unrolling Feasibility.",
            },
            {
                "id": "DFA_RESILIENCE",
                "module": "sigma.metrology.dfa",
                "output": "sigma_dfa_metrics.json",
                "description": "Transient Fault Injection (Single Event Upsets).",
            },
            {
                "id": "STOCHASTIC_SAC",
                "module": "sigma.metrology.avalanche",
                "output": "sigma_stochastic_metrics.json",
                "description": "Strict Avalanche Criterion (Monte Carlo).",
            },
            {
                "id": "DIFFUSION_PROFILING",
                "module": "sigma.metrology.diffusion_profiler",
                "output": "sigma_diffusion_metrics.json",
                "description": "Round-by-Round Avalanche Propagation Analysis.",
            },
            {
                "id": "TVLA_CONSTANT_TIME",
                "module": "sigma.metrology.tvla",
                "output": "sigma_tvla_metrics.json",
                "description": "Welch's t-test for side-channel leakage.",
            },
            {
                "id": "TVLA_BASELINE_CONTROL",
                "module": "sigma.metrology.tvla_baseline",
                "output": "sigma_tvla_baseline_metrics.json",
                "description": "Control Test: Isolation of Python Interpreter noise.",
            },
            {
                "id": "GENERAL_BENCHMARK",
                "module": "sigma.benchmark",
                "output": "sigma_metrics.json",
                "description": "Asymptotic Throughput and PoW Linearity.",
            },
            {
                "id": "MICROARCH_PMU",
                "module": "sigma.metrology.microarch",
                "output": "sigma_microarch_metrics.json",
                "description": "L1 Cache Misses and IPC (Requires Linux perf).",
            },
        ]

    def _print_banner(self):
        print("=" * 70)
        print(f"  SIGMA FRAMEWORK - ACADEMIC METROLOGY SUITE ORCHESTRATOR")
        print(
            f"  Host: {platform.node()} | OS: {platform.system()} {platform.release()}"
        )
        print(f"  CPU Cores: {os.cpu_count()} | Python: {platform.python_version()}")
        print(f"  Started at: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        print("=" * 70 + "\n")

    def run_pipeline(self):
        self._print_banner()
        results_manifest = {}

        for task in self.pipeline:
            print(f"\n[{task['id']}] Starting: {task['description']}")
            print(f" -> Module: {task['module']}")

            # Check if JSON already exists to allow resumption upon failure
            if os.path.exists(task["output"]):
                print(f" -> [SKIP] File {task['output']} already exists. Skipping...")
                results_manifest[task["id"]] = "SKIPPED (Already exists)"
                continue

            t0 = time.time()

            # Isolated Process Execution
            # Ensure PYTHONPATH points to the project root
            env = os.environ.copy()
            env["PYTHONPATH"] = self.base_dir

            try:
                # Use sys.executable to maintain the same virtual environment
                process = subprocess.run(
                    [sys.executable, "-m", task["module"]],
                    cwd=self.base_dir,
                    env=env,
                    check=True,  # Raises exception if the script fails
                    text=True,
                )

                duration = time.time() - t0
                print(f"\n -> [DONE] Completed in {duration:.2f} seconds.")

                # Verify that the module actually generated the expected file
                if os.path.exists(os.path.join(self.base_dir, task["output"])):
                    results_manifest[task["id"]] = f"SUCCESS ({duration:.2f}s)"
                else:
                    results_manifest[task["id"]] = (
                        "WARNING: Exit 0 but output file missing."
                    )
                    print(f" -> [WARNING] Output file {task['output']} not found.")

            except subprocess.CalledProcessError as e:
                print(
                    f"\n -> [ERROR] Module {task['module']} failed with code {e.returncode}."
                )
                results_manifest[task["id"]] = f"FAILED (Exit Code {e.returncode})"
                # Fault tolerance decision: Continue with the next test
                continue
            except KeyboardInterrupt:
                print(f"\n -> [HALT] Orchestrator interrupted by user.")
                sys.exit(1)

        self._finalize(results_manifest)

    def _finalize(self, manifest: Dict[str, str]):
        total_time = time.time() - self.start_time
        print("\n" + "=" * 70)
        print(f"  PIPELINE COMPLETED - Total Time: {total_time / 60:.2f} Minutes")
        print("=" * 70)

        for task_id, status in manifest.items():
            print(f"  * {task_id.ljust(20)} : {status}")

        # Generate a master consolidation manifest
        with open("sigma_metrology_manifest.json", "w") as f:
            json.dump(
                {
                    "timestamp": datetime.now().isoformat(),
                    "total_duration_seconds": total_time,
                    "system_info": platform.uname()._asdict(),
                    "tasks": manifest,
                },
                f,
                indent=4,
            )
        print("\n[INFO] Manifest saved to sigma_metrology_manifest.json")


if __name__ == "__main__":
    orchestrator = SigmaMetrologyOrchestrator()
    orchestrator.run_pipeline()
