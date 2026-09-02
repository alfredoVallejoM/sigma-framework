"""Sigma Framework.

The root ``SigmaFactory`` API is the experimental legacy v1 implementation.
Versioned v2 data types are exposed separately and must not be confused with a
claim that the v2 cryptographic construction is already production-ready.
"""

from .factory import LegacyV1Factory, SigmaFactory
from .outputs import SigmaDigestV2
from .spec import SigmaContextV2

__version__ = "2.0.0a1"
__author__ = "Alfredo Vallejo Martín"

__all__ = ["LegacyV1Factory", "SigmaContextV2", "SigmaDigestV2", "SigmaFactory"]
