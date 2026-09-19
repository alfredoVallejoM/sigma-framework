"""Numeric identifiers reserved for the incompatible Sigma v3 family."""

from enum import IntEnum


class SuiteIdV3(IntEnum):
    REFERENCE_IAP_V3 = 0x0301
    EXPLICIT_AUDIT_V3 = 0x0302


class InputProfileIdV3(IntEnum):
    CANONICAL_BYTES = 0x0301


class AnchorProfileIdV3(IntEnum):
    STREAM_WIDE = 0x0301


class RoundProfileIdV3(IntEnum):
    WIDE_ONCE = 0x0301


class OutputProfileIdV3(IntEnum):
    IMPLICIT_J = 0x0301
    EXPLICIT_BINDING = 0x0302


class CardinalityProfileIdV3(IntEnum):
    BYTE_LENGTH = 0x0301


class JointProfileIdV3(IntEnum):
    VECTOR = 0x0301


class LayoutProfileIdV3(IntEnum):
    SHAKE256_REJECTION = 0x0301


class TrajectoryProfileIdV3(IntEnum):
    BINDING_DERIVED = 0x0301


class BindingFieldIdV3(IntEnum):
    ANCHOR = 0x0301
    CARDINALITY = 0x0302
    LENGTH_SIGNATURE = 0x0303
    JOINT_SIGNATURE = 0x0304


class LayoutKindV3(IntEnum):
    INIT = 0x0301
    ROUND = 0x0302


class DomainIdV3(IntEnum):
    ANCHOR_BRANCH = 0x0301
    ANCHOR_END = 0x0302
    LENGTH_SIGNATURE = 0x0303
    JOINT_SIGNATURE = 0x0304
    PARAMETER_DERIVATION = 0x0305
    LAYOUT_INIT = 0x0306
    LAYOUT_ROUND = 0x0307
    INIT_FRAME = 0x0308
    ROUND_FRAME = 0x0309
    BINDING_FIELD = 0x030A
    PUBLIC_HEADER = 0x030B
    EVIDENCE = 0x030C
    DEEP_BRANCH_FRAME = 0x030D
    VECTOR_ROUND_FRAME = 0x030E
    EXPLICIT_EVIDENCE = 0x030F


ALGORITHM_OUTPUT_SIZE_V3 = 64
