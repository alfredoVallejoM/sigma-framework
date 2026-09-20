"""Public facade for the incompatible Sigma v3 line through R9."""

from sigma.outputs.digest_v3 import (
    ExplicitAuditEvidenceV3,
    SigmaDigestV3,
    StructureVerificationV3,
    digest_from_evaluation_v3,
    verify_explicit_full_v3,
    verify_full_v3,
    verify_prepared_v3,
    verify_structure_v3,
)
from sigma.rounds.backends_v3 import (
    SERIAL_DEEP_BRANCH_BACKEND_V3,
    DeepBranchBackendV3,
    DeepBranchExecutionError,
    ProcessDeepBranchBackendV3,
    ThreadDeepBranchBackendV3,
)
from sigma.rounds.deep_v3 import (
    DeepEvaluationV3,
    DeepVectorEvaluationV3,
    evaluate_deep_bytes_v3,
    evaluate_deep_v3,
    evaluate_deep_vector_bytes_v3,
    evaluate_deep_vector_v3,
    next_deep_state_v3,
    next_deep_vector_state_v3,
)
from sigma.rounds.wide_once_v3 import (
    WideOnceEvaluationV3,
    evaluate_wide_once_bytes_v3,
    evaluate_wide_once_v3,
)
from sigma.spec.context_v3 import SigmaContextV3

__all__ = [
    "SERIAL_DEEP_BRANCH_BACKEND_V3",
    "DeepBranchBackendV3",
    "DeepBranchExecutionError",
    "DeepEvaluationV3",
    "DeepVectorEvaluationV3",
    "ExplicitAuditEvidenceV3",
    "ProcessDeepBranchBackendV3",
    "SigmaContextV3",
    "SigmaDigestV3",
    "StructureVerificationV3",
    "ThreadDeepBranchBackendV3",
    "WideOnceEvaluationV3",
    "digest_from_evaluation_v3",
    "evaluate_deep_bytes_v3",
    "evaluate_deep_v3",
    "evaluate_deep_vector_bytes_v3",
    "evaluate_deep_vector_v3",
    "evaluate_wide_once_bytes_v3",
    "evaluate_wide_once_v3",
    "next_deep_state_v3",
    "next_deep_vector_state_v3",
    "verify_explicit_full_v3",
    "verify_full_v3",
    "verify_prepared_v3",
    "verify_structure_v3",
]
