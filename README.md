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
- A Linux environment is recommended for deep Hardware PMU profiling (via the "perf" tool), though the core algorithms and CLI are fully cross-platform (Windows/macOS/Linux).

### Standard Installation
Clone the repository and install it in editable mode (indentation denotes commands):

    git clone [https://github.com/alfredoVallejoM/sigma-framework.git](https://github.com/alfredoVallejoM/sigma-framework.git)
    cd sigma-framework
    pip install -e .

*Note: The "-e" flag allows you to modify the source code without reinstalling the package.*

---

## Usage (CLI & API)

Once installed, the framework registers a global command-line interface ("sigmahash") and exposes the "SigmaFactory" for Python integrations.

### Command Line Interface (CLI)

Hash a file using the paranoid topology:

    sigmahash -m paranoid target_file.bin

Enable benchmarking to measure throughput:

    sigmahash -m simultaneous --benchmark large_database.sql

Set computational depth for Proof-of-Work (PoW):

    sigmahash -m paranoid -r 500 password_dump.txt

### Python API
You can effortlessly integrate Sigma into your Python applications via the SigmaFactory.

    from sigma.factory import SigmaFactory

    # Hash a file using the Lightweight topology
    file_digest = SigmaFactory.hash_file("data.csv", mode="lightweight")
    print(f"File Digest: {file_digest}")

    # Hash in-memory bytes using the RealTime ring accumulator
    raw_telemetry = b"\x00\x01\x02\x03\x04"
    stream_digest = SigmaFactory.hash_bytes(raw_telemetry, mode="realtime")
    print(f"Stream Digest: {stream_digest}")

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
