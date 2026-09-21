"""Closed suite descriptors for the Sigma v3 R1 type system."""

from dataclasses import dataclass
from types import MappingProxyType

from sigma.spec.ids import AlgorithmId
from sigma.spec.ids_v3 import (
    AnchorProfileIdV3,
    CardinalityProfileIdV3,
    DomainIdV3,
    InputProfileIdV3,
    JointProfileIdV3,
    LayoutProfileIdV3,
    OutputProfileIdV3,
    RoundProfileIdV3,
    SuiteIdV3,
    TrajectoryProfileIdV3,
)


@dataclass(frozen=True)
class SuiteDescriptorV3:
    suite_id: SuiteIdV3
    input_profile: InputProfileIdV3
    anchor_profile: AnchorProfileIdV3
    round_profile: RoundProfileIdV3
    output_profile: OutputProfileIdV3
    cardinality_profile: CardinalityProfileIdV3
    joint_profile: JointProfileIdV3
    layout_profile: LayoutProfileIdV3
    trajectory_profile: TrajectoryProfileIdV3
    anchor_algorithms: tuple[AlgorithmId, ...]
    joint_algorithms: tuple[AlgorithmId, ...]
    length_algorithm: AlgorithmId
    state_algorithm: AlgorithmId
    chunk_size: int
    state_size: int
    t_min: int
    t_max: int
    k_min: int
    k_max: int

    def __post_init__(self) -> None:
        enum_fields = (
            ("suite_id", self.suite_id, SuiteIdV3),
            ("input_profile", self.input_profile, InputProfileIdV3),
            ("anchor_profile", self.anchor_profile, AnchorProfileIdV3),
            ("round_profile", self.round_profile, RoundProfileIdV3),
            ("output_profile", self.output_profile, OutputProfileIdV3),
            ("cardinality_profile", self.cardinality_profile, CardinalityProfileIdV3),
            ("joint_profile", self.joint_profile, JointProfileIdV3),
            ("layout_profile", self.layout_profile, LayoutProfileIdV3),
            ("trajectory_profile", self.trajectory_profile, TrajectoryProfileIdV3),
            ("length_algorithm", self.length_algorithm, AlgorithmId),
            ("state_algorithm", self.state_algorithm, AlgorithmId),
        )
        for name, value, expected_type in enum_fields:
            if not isinstance(value, expected_type):
                raise TypeError(f"{name} must be {expected_type.__name__}")
        for name, algorithms in (
            ("anchor_algorithms", self.anchor_algorithms),
            ("joint_algorithms", self.joint_algorithms),
        ):
            if not isinstance(algorithms, tuple) or not algorithms:
                raise ValueError(f"{name} must be a non-empty tuple")
            if any(not isinstance(algorithm, AlgorithmId) for algorithm in algorithms):
                raise TypeError(f"{name} must contain AlgorithmId values")
            if len(algorithms) != len(set(algorithms)):
                raise ValueError(f"{name} must contain unique values")
        for name, number, minimum, maximum in (
            ("chunk_size", self.chunk_size, 1, 1 << 30),
            ("state_size", self.state_size, 1, 4096),
            ("t_min", self.t_min, 0, 1_000_000),
            ("t_max", self.t_max, 0, 1_000_000),
            ("k_min", self.k_min, 1, 64),
            ("k_max", self.k_max, 1, 64),
        ):
            if isinstance(number, bool) or not isinstance(number, int):
                raise TypeError(f"{name} must be int")
            if not minimum <= number <= maximum:
                raise ValueError(f"{name} is out of range")
        if self.t_min > self.t_max:
            raise ValueError("target round range is invalid")
        if self.k_min > self.k_max:
            raise ValueError("state count range is invalid")


REFERENCE_ALGORITHMS_V3 = (
    AlgorithmId.SHA512,
    AlgorithmId.SHA3_512,
    AlgorithmId.BLAKE2B_512,
    AlgorithmId.SHAKE256_512,
)

REFERENCE_IAP_V3 = SuiteDescriptorV3(
    suite_id=SuiteIdV3.REFERENCE_IAP_V3,
    input_profile=InputProfileIdV3.CANONICAL_BYTES,
    anchor_profile=AnchorProfileIdV3.STREAM_WIDE,
    round_profile=RoundProfileIdV3.WIDE_ONCE,
    output_profile=OutputProfileIdV3.IMPLICIT_J,
    cardinality_profile=CardinalityProfileIdV3.BYTE_LENGTH,
    joint_profile=JointProfileIdV3.VECTOR,
    layout_profile=LayoutProfileIdV3.SHAKE256_REJECTION,
    trajectory_profile=TrajectoryProfileIdV3.BINDING_DERIVED,
    anchor_algorithms=REFERENCE_ALGORITHMS_V3,
    joint_algorithms=REFERENCE_ALGORITHMS_V3,
    length_algorithm=AlgorithmId.SHA3_512,
    state_algorithm=AlgorithmId.SHA512,
    chunk_size=1 << 20,
    state_size=64,
    t_min=2,
    t_max=32,
    k_min=2,
    k_max=4,
)

DEEP_V3 = SuiteDescriptorV3(
    suite_id=SuiteIdV3.DEEP_V3,
    input_profile=InputProfileIdV3.CANONICAL_BYTES,
    anchor_profile=AnchorProfileIdV3.STREAM_WIDE,
    round_profile=RoundProfileIdV3.DEEP,
    output_profile=OutputProfileIdV3.IMPLICIT_J,
    cardinality_profile=CardinalityProfileIdV3.BYTE_LENGTH,
    joint_profile=JointProfileIdV3.VECTOR,
    layout_profile=LayoutProfileIdV3.SHAKE256_REJECTION,
    trajectory_profile=TrajectoryProfileIdV3.BINDING_DERIVED,
    anchor_algorithms=REFERENCE_ALGORITHMS_V3,
    joint_algorithms=REFERENCE_ALGORITHMS_V3,
    length_algorithm=AlgorithmId.SHA3_512,
    state_algorithm=AlgorithmId.SHA512,
    chunk_size=1 << 20,
    state_size=64,
    t_min=2,
    t_max=32,
    k_min=2,
    k_max=4,
)

DEEP_VECTOR_V3 = SuiteDescriptorV3(
    suite_id=SuiteIdV3.DEEP_VECTOR_V3,
    input_profile=InputProfileIdV3.CANONICAL_BYTES,
    anchor_profile=AnchorProfileIdV3.STREAM_WIDE,
    round_profile=RoundProfileIdV3.DEEP_VECTOR,
    output_profile=OutputProfileIdV3.IMPLICIT_J,
    cardinality_profile=CardinalityProfileIdV3.BYTE_LENGTH,
    joint_profile=JointProfileIdV3.VECTOR,
    layout_profile=LayoutProfileIdV3.SHAKE256_REJECTION,
    trajectory_profile=TrajectoryProfileIdV3.BINDING_DERIVED,
    anchor_algorithms=REFERENCE_ALGORITHMS_V3,
    joint_algorithms=REFERENCE_ALGORITHMS_V3,
    length_algorithm=AlgorithmId.SHA3_512,
    state_algorithm=AlgorithmId.SHA512,
    chunk_size=1 << 20,
    state_size=len(REFERENCE_ALGORITHMS_V3) * 64,
    t_min=2,
    t_max=32,
    k_min=2,
    k_max=4,
)


REFERENCE_IAP_HISTORY_V3 = SuiteDescriptorV3(
    suite_id=SuiteIdV3.REFERENCE_IAP_HISTORY_V3,
    input_profile=InputProfileIdV3.CANONICAL_BYTES,
    anchor_profile=AnchorProfileIdV3.STREAM_WIDE,
    round_profile=RoundProfileIdV3.WIDE_ONCE,
    output_profile=OutputProfileIdV3.IMPLICIT_J,
    cardinality_profile=CardinalityProfileIdV3.BYTE_LENGTH,
    joint_profile=JointProfileIdV3.VECTOR,
    layout_profile=LayoutProfileIdV3.SHAKE256_HISTORY_REJECTION,
    trajectory_profile=TrajectoryProfileIdV3.HISTORY_FEEDBACK,
    anchor_algorithms=REFERENCE_ALGORITHMS_V3,
    joint_algorithms=REFERENCE_ALGORITHMS_V3,
    length_algorithm=AlgorithmId.SHA3_512,
    state_algorithm=AlgorithmId.SHA512,
    chunk_size=1 << 20,
    state_size=64,
    t_min=2,
    t_max=32,
    k_min=2,
    k_max=4,
)

DEEP_HISTORY_V3 = SuiteDescriptorV3(
    suite_id=SuiteIdV3.DEEP_HISTORY_V3,
    input_profile=InputProfileIdV3.CANONICAL_BYTES,
    anchor_profile=AnchorProfileIdV3.STREAM_WIDE,
    round_profile=RoundProfileIdV3.DEEP,
    output_profile=OutputProfileIdV3.IMPLICIT_J,
    cardinality_profile=CardinalityProfileIdV3.BYTE_LENGTH,
    joint_profile=JointProfileIdV3.VECTOR,
    layout_profile=LayoutProfileIdV3.SHAKE256_HISTORY_REJECTION,
    trajectory_profile=TrajectoryProfileIdV3.HISTORY_FEEDBACK,
    anchor_algorithms=REFERENCE_ALGORITHMS_V3,
    joint_algorithms=REFERENCE_ALGORITHMS_V3,
    length_algorithm=AlgorithmId.SHA3_512,
    state_algorithm=AlgorithmId.SHA512,
    chunk_size=1 << 20,
    state_size=64,
    t_min=2,
    t_max=32,
    k_min=2,
    k_max=4,
)

DEEP_VECTOR_HISTORY_V3 = SuiteDescriptorV3(
    suite_id=SuiteIdV3.DEEP_VECTOR_HISTORY_V3,
    input_profile=InputProfileIdV3.CANONICAL_BYTES,
    anchor_profile=AnchorProfileIdV3.STREAM_WIDE,
    round_profile=RoundProfileIdV3.DEEP_VECTOR,
    output_profile=OutputProfileIdV3.IMPLICIT_J,
    cardinality_profile=CardinalityProfileIdV3.BYTE_LENGTH,
    joint_profile=JointProfileIdV3.VECTOR,
    layout_profile=LayoutProfileIdV3.SHAKE256_HISTORY_REJECTION,
    trajectory_profile=TrajectoryProfileIdV3.HISTORY_FEEDBACK,
    anchor_algorithms=REFERENCE_ALGORITHMS_V3,
    joint_algorithms=REFERENCE_ALGORITHMS_V3,
    length_algorithm=AlgorithmId.SHA3_512,
    state_algorithm=AlgorithmId.SHA512,
    chunk_size=1 << 20,
    state_size=len(REFERENCE_ALGORITHMS_V3) * 64,
    t_min=2,
    t_max=32,
    k_min=2,
    k_max=4,
)

_SUITES_V3 = MappingProxyType(
    {
        REFERENCE_IAP_V3.suite_id: REFERENCE_IAP_V3,
        DEEP_V3.suite_id: DEEP_V3,
        DEEP_VECTOR_V3.suite_id: DEEP_VECTOR_V3,
        REFERENCE_IAP_HISTORY_V3.suite_id: REFERENCE_IAP_HISTORY_V3,
        DEEP_HISTORY_V3.suite_id: DEEP_HISTORY_V3,
        DEEP_VECTOR_HISTORY_V3.suite_id: DEEP_VECTOR_HISTORY_V3,
    }
)


@dataclass(frozen=True)
class EvidenceEnvelopeDescriptorV3:
    suite_id: SuiteIdV3
    output_profile: OutputProfileIdV3
    domain: DomainIdV3
    inner_output_profile: OutputProfileIdV3

    def __post_init__(self) -> None:
        if not isinstance(self.suite_id, SuiteIdV3):
            raise TypeError("suite_id must be SuiteIdV3")
        if not isinstance(self.output_profile, OutputProfileIdV3):
            raise TypeError("output_profile must be OutputProfileIdV3")
        if not isinstance(self.domain, DomainIdV3):
            raise TypeError("domain must be DomainIdV3")
        if not isinstance(self.inner_output_profile, OutputProfileIdV3):
            raise TypeError("inner_output_profile must be OutputProfileIdV3")


EXPLICIT_AUDIT_ENVELOPE_V3 = EvidenceEnvelopeDescriptorV3(
    suite_id=SuiteIdV3.EXPLICIT_AUDIT_V3,
    output_profile=OutputProfileIdV3.EXPLICIT_BINDING,
    domain=DomainIdV3.EXPLICIT_EVIDENCE,
    inner_output_profile=OutputProfileIdV3.IMPLICIT_J,
)

_EVIDENCE_ENVELOPES_V3 = MappingProxyType(
    {
        EXPLICIT_AUDIT_ENVELOPE_V3.suite_id: EXPLICIT_AUDIT_ENVELOPE_V3,
    }
)


def get_suite_v3(suite_id: SuiteIdV3) -> SuiteDescriptorV3:
    try:
        return _SUITES_V3[suite_id]
    except KeyError as exc:
        raise ValueError("unregistered Sigma v3 suite") from exc


def get_evidence_envelope_v3(
    suite_id: SuiteIdV3,
) -> EvidenceEnvelopeDescriptorV3:
    try:
        return _EVIDENCE_ENVELOPES_V3[suite_id]
    except KeyError as exc:
        raise ValueError("unregistered Sigma v3 evidence envelope") from exc
