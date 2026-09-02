"""
Polymorphic execution topologies for the Sigma Framework.
Includes hardware-adaptive strategies for diverse physical constraints.
"""

from .base import SigmaStrategy
from .lightweight import LightweightStrategy
from .paranoid import ParanoidStrategy
from .realtime import RealTimeStrategy
from .simultaneous import SimultaneousStrategy

__all__ = [
    "LightweightStrategy",
    "ParanoidStrategy",
    "RealTimeStrategy",
    "SigmaStrategy",
    "SimultaneousStrategy",
]
