"""Sigma v2.2 research framework; not a production security primitive."""

from .outputs import SigmaDigestV2
from .spec import SigmaContextV2
from .version import PACKAGE_VERSION

__version__ = PACKAGE_VERSION
__author__ = "Alfredo Vallejo Martín"

__all__ = ["SigmaContextV2", "SigmaDigestV2"]
