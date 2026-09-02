"""Legacy v1 exploratory measurements, retained only for reproducibility.

These Python timing, fault-diffusion and analytical hardware scripts are not
evidence of constant-time behavior, DFA resistance, or synthesized hardware.
Use the versioned experiment harness for v2 evidence.
"""

from .orchestrator import SigmaMetrologyOrchestrator
from .plotter import SigmaAcademicPlotter

__all__ = ["SigmaAcademicPlotter", "SigmaMetrologyOrchestrator"]
