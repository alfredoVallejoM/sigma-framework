"""
Polymorphic execution topologies for the Sigma Framework.
Includes hardware-adaptive strategies for diverse physical constraints.
"""

from .base import SigmaStrategy
from .paranoid import ParanoidStrategy
from .simultaneous import SimultaneousStrategy
from .lightweight import LightweightStrategy
from .realtime import RealTimeStrategy

__all__ = [
    "SigmaStrategy",
    "ParanoidStrategy",
    "SimultaneousStrategy",
    "LightweightStrategy",
    "RealTimeStrategy",
]
