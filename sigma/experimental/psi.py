"""Legacy Psi mixer.

Psi is retained for reproducibility and cryptanalysis only. No registered v2
suite uses it, and it must not be treated as a permutation or root of trust.
"""

from sigma.core.psi import PsiKernel

__all__ = ["PsiKernel"]
