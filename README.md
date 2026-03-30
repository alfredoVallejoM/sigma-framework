# Sigma Framework: Hardware-Adaptive Non-Markovian Cryptography

[![License: AGPL v3](https://img.shields.io/badge/License-AGPL_v3-blue.svg)](https://www.gnu.org/licenses/agpl-3.0)
[![Python 3.8+](https://img.shields.io/badge/python-3.8+-green.svg)](https://www.python.org/downloads/)
[![Code style: black](https://img.shields.io/badge/code%20style-black-000000.svg)](https://github.com/psf/black)
[![DOI](https://zenodo.org/badge/DOI/10.5281/zenodo.19341187.svg)](https://doi.org/10.5281/zenodo.19341187)

The **Sigma Framework** is a formalization and practical implementation of a hardware-adaptive, non-Markovian cryptographic architecture. Designed to mitigate the entropic degradation (state-space collapse) inherent in traditional iterative hashing algorithms, Sigma dynamically injects a strictly monotonic **Temporal Tensor** into a Constant-Time ARX core (Ψ).

By decoupling the mathematical permutation from the macroscopic data routing, Sigma provides a polymorphic library of execution topologies designed to seamlessly adapt to the host's thermodynamic and microarchitectural constraints—from embedded IoT sensors to massively parallelized enterprise servers.

## Table of Contents
- [Dual License Model](#dual-license-model)
- [Theoretical Foundation](#theoretical-foundation)
- [Polymorphic Topologies](#polymorphic-topologies)
- [Installation](#installation)
- [Usage (CLI & API)](#usage-cli--api)
- [Academic Metrology Suite](#academic-metrology-suite)
- [Citation](#citation)

---

## Dual License Model

The Sigma Framework is distributed under a **Dual Licensing Model** to support Open Science while preventing unilateral commercial exploitation.

### 1. Open Source & Academic Use (AGPLv3)
For researchers, students, open-source developers, and non-profit organizations, this software is released under the **GNU Affero General Public License v3.0 (AGPLv3)**.
Under this license, you are free to use, modify, and distribute the framework. However, if you modify the software or integrate it into a service accessed over a network, you **must** make your complete source code publicly available under the same AGPLv3 license.

### 2. Commercial License
If you are a corporation, enterprise, or proprietary software developer intending to embed or integrate the Sigma Framework into closed-source commercial products, SaaS platforms, or proprietary hardware (ASIC/FPGA) without being subjected to the copyleft requirements of the AGPLv3, **you must obtain a Commercial License**.

For commercial licensing inquiries, consulting, or hardware synthesis rights, please contact the author directly.

---

## Theoretical Foundation

Traditional hash functions operate as strict Markov chains (Sᵢ₊₁ = f(Sᵢ)). When repurposed for continuous iteration—such as in Key Derivation Functions (KDFs) or Proof-of-Work (PoW)—this static recursion inevitably leads to short cyclic loops bounded by the Birthday Paradox.

Sigma breaks this paradigm via **Non-Markovian Evolution**. The transition function relies on a Temporal Tensor 𝓣(i) directly injected into the internal arithmetic matrix:

    Sᵢ₊₁ = Ψ(Sᵢ ⊕ M, 𝓣(i))

The underlying permutation, the **Ψ (Psi) Mixing Core**, is a Generalized Substitution-Permutation Network (G-SPN) built entirely on constant-time ARX algebra (Addition, Rotation, XOR) over ℤ/2⁶⁴ℤ. This natively neutralizes Cache-Timing Side-Channel attacks (TVLA) while maintaining an ultra-lightweight silicon synthesis footprint (under 25,000 Gate Equivalents).

---

## Polymorphic Topologies

Sigma exposes four distinct execution modes tailored to specific hardware and security environments:

1. **paranoid (Orthogonal Algorithm Stacking):** Engineered for cold storage and KDFs. It concurrently processes the payload through four heterogeneous cryptographic algorithms, maximizing thermodynamic cost and degrading the economic viability of ASIC acceleration.
2. **simultaneous (SMP Bus Saturation):** Designed for high-end workstations. It parallelizes the payload into chunks, utilizing Symmetric Multiprocessing to saturate the PCIe/NVMe bus limits (scaling linearly with available CPU cores).
3. **lightweight (O(1) Memory Footprint):** A strict sequential Merkle-Damgård-inspired windowing topology. Optimized for resource-constrained microcontrollers where dynamic memory allocation (RAM) is the primary bottleneck.
4. **realtime (Twisted Ring Accumulator):** Built for network packet inspection and high-frequency telemetry. It continuously absorbs unpadded bitstreams into a pre-warmed state matrix, yielding execution latencies in the microsecond domain.

---
## Installation

### Prerequisites
- Python 3.8 or higher.
- A Linux environment is recommended for deep Hardware PMU profiling, though the core algorithms and CLI are fully cross-platform (Windows/macOS/Linux).

### Standard Installation
Execute the following commands one by one in your terminal:

Step 1. Clone the repository:
    git clone [https://github.com/alfredoVallejoM/sigma-framework.git](https://github.com/alfredoVallejoM/sigma-framework.git)

Step 2. Navigate into the directory:
    cd sigma-framework

Step 3. Install it in editable mode:
    pip install -e .

*Note: The "-e" flag allows you to modify the source code without reinstalling the package.*

---

## Usage (CLI & API)

The Sigma Framework is designed for frictionless integration. It exposes a UNIX-like Command Line Interface for shell scripting and system administration, alongside a fully typed Python API for deep software integration.

### 1. Command Line Interface (CLI): "sigmahash"

Upon installation, the `sigmahash` command is registered globally in your environment. It supports standard POSIX flags and outputs deterministic hex digests.

**Basic File Hashing (Default Lightweight Mode)**
For standard file integrity verification where memory efficiency is paramount:

    sigmahash target_file.bin

**Orthogonal Algorithm Stacking (Paranoid Mode)**
For cold-storage wallets or high-value targets, force the framework to execute the payload through four heterogeneous algorithms simultaneously:

    sigmahash -m paranoid wallet_backup.dat

**Symmetric Multiprocessing (Simultaneous Mode)**
When processing massive datasets (e.g., ISO images or SQL dumps), utilize all available CPU cores to saturate the storage bus:

    sigmahash -m simultaneous ubuntu-server.iso

**Proof-of-Work (PoW) and KDF Depth**
By default, the $\Psi$ core executes 12 cryptographic rounds. You can scale the thermodynamic cost linearly by increasing the round depth (R) via the `-r` flag. This is essential for Key Derivation:

    sigmahash -m paranoid -r 50000 user_password_dump.txt

**Raw Text String Hashing**
You can hash short strings directly from the terminal without creating temporary files by using the `-t` or `--text` flag:

    sigmahash -t "Sigma Non-Markovian Architecture" -m realtime

**Benchmarking and Profiling**
To measure the exact execution latency and macroscopic throughput (MB/s) on your specific hardware, append the `--benchmark` flag:

    sigmahash -m simultaneous --benchmark large_database.sql

### 2. Python Developer API (SigmaFactory)

For developers building applications, consensus nodes, or forensic tools, the `SigmaFactory` class acts as the universal entry point. It abstracts the complex macroscopic routing and provides a clean, thread-safe interface.

Below is a comprehensive, copy-pasteable Python script demonstrating the API's full capabilities. Save this as `sigma_example.py` and execute it:

    import os
    from sigma.factory import SigmaFactory

    def demonstrate_sigma_api():
        print("--- Sigma Framework API Demonstration ---")

        # 1. Hashing In-Memory Bytes (RealTime Mode)
        # Ideal for micro-payloads, network packets, or raw telemetry.
        # Yields execution latencies in the microsecond domain.
        raw_telemetry = b"\x00\x01\x02\x03\x04\x05\x06\x07"
        stream_digest = SigmaFactory.hash_bytes(
            data=raw_telemetry, 
            mode="realtime", 
            rounds=12
        )
        print(f"[RealTime] Telemetry Digest: {stream_digest}")

        # 2. Hashing Strings for KDFs (Paranoid Mode)
        # Ideal for password hashing. We scale the rounds to 25,000 
        # to maximize the thermodynamic cost against brute-force attacks.
        user_password = "correct-horse-battery-staple"
        kdf_digest = SigmaFactory.hash_string(
            text=user_password, 
            mode="paranoid", 
            rounds=25000
        )
        print(f"[Paranoid] KDF Password Digest: {kdf_digest}")

        # 3. Hashing Files (Lightweight Mode)
        # Create a dummy file for demonstration
        filename = "temp_sensor_data.csv"
        with open(filename, "w") as f:
            f.write("timestamp,temperature,humidity\n1625097600,22.5,45.2")

        # The hash_file method automatically chunks the file to maintain 
        # a strict O(1) memory footprint (RAM) during execution.
        file_digest = SigmaFactory.hash_file(
            filepath=filename, 
            mode="lightweight"
        )
        print(f"[Lightweight] Sensor File Digest: {file_digest}")
        
        # Cleanup
        os.remove(filename)

    if __name__ == "__main__":
        demonstrate_sigma_api()

**Return Types:**
All high-level methods in the `SigmaFactory` return the final 256-bit state matrix serialized as a standard, lowercase 64-character hexadecimal string, ensuring immediate compatibility with standard database schemas and JSON REST APIs.

---

## Academic Metrology Suite

The framework includes an exhaustive empirical metrology suite designed for cryptographic transparency. It validates the Strict Avalanche Criterion (SAC), Test Vector Leakage Assessment (TVLA), Differential Fault Analysis (DFA) resilience, and hardware execution latencies.

**1. Run the Metrology Orchestrator:**
Execute the full benchmark pipeline (this will generate high-precision JSON datasets):

    python -m sigma.metrology.orchestrator

**2. Generate Tier-1 Publication Plots:**
Once the datasets are generated, use the plotter to render Vectorial PDFs and PNGs using anti-occlusion academic visualization techniques:

    python -m sigma.metrology.plotter

*Outputs will be saved in the "plots/" directory.*

---

## Citation

If you use the Sigma Framework or its underlying non-Markovian architecture in your research, please cite the foundational paper:

    @article{vallejo2026sigma,
      title={Sigma: A Hardware-Adaptive Non-Markovian Cryptographic Framework for Stochastic Integrity and Proof-of-Work},
      author={Vallejo Mart{\'i}n, Alfredo},
      journal={TBD (Preprint/Repository)},
      year={2026},
      url={[https://github.com/alfredoVallejoM/sigma-framework](https://github.com/alfredoVallejoM/sigma-framework)}
    }
