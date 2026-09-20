"""Independent byte-exact Sigma v3 reference (stdlib only; never imports sigma)."""

from __future__ import annotations

import hashlib
from dataclasses import dataclass

VERSION = 3
SUITE = 0x0301
ALG_SHA512 = 1
ALG_SHA3_512 = 2
ALG_BLAKE2B_512 = 3
ALG_SHAKE256_512 = 4
ALGORITHMS = (ALG_SHA512, ALG_SHA3_512, ALG_BLAKE2B_512, ALG_SHAKE256_512)
DOMAIN_ANCHOR = 0x0301
DOMAIN_LENGTH = 0x0303
DOMAIN_JOINT = 0x0304
DOMAIN_PARAMETERS = 0x0305
DOMAIN_LAYOUT_INIT = 0x0306
DOMAIN_LAYOUT_ROUND = 0x0307
DOMAIN_INIT = 0x0308
DOMAIN_ROUND = 0x0309
DOMAIN_BINDING_FIELD = 0x030A
DOMAIN_EVIDENCE = 0x030C
DOMAIN_DEEP_BRANCH = 0x030D
DOMAIN_VECTOR_ROUND = 0x030E
DOMAIN_DEEP_FOLD = 0x0310
KIND_INIT = 0x0301
KIND_ROUND = 0x0302
BINDING_FIELDS = (0x0301, 0x0302, 0x0303, 0x0304)


def _u(value: int, width: int) -> bytes:
    return value.to_bytes(width, "big")


def _tlv(fields: tuple[tuple[int, bytes], ...], length_width: int = 4) -> bytes:
    return b"".join(_u(tag, 2) + _u(len(value), length_width) + value for tag, value in fields)


def _record(magic: bytes, fields: tuple[tuple[int, bytes], ...]) -> bytes:
    body = _tlv(fields)
    return magic + _u(VERSION, 2) + _u(len(body), 4) + body


def _transcript(domain: int, fields: tuple[tuple[int, bytes], ...]) -> bytes:
    return b"SIGMA3TR" + _u(VERSION, 2) + _u(domain, 2) + _tlv(fields, 8)


def _domain(domain: int) -> bytes:
    return b"SIGMA3DS" + _u(domain, 2)


def _hash(algorithm: int, domain: int, data: bytes) -> bytes:
    payload = _domain(domain) + data
    if algorithm == ALG_SHA512:
        return hashlib.sha512(payload).digest()
    if algorithm == ALG_SHA3_512:
        return hashlib.sha3_512(payload).digest()
    if algorithm == ALG_BLAKE2B_512:
        return hashlib.blake2b(payload, digest_size=64).digest()
    if algorithm == ALG_SHAKE256_512:
        return hashlib.shake_256(payload).digest(64)
    raise ValueError("unknown algorithm")


def _u16_sequence(values: tuple[int, ...]) -> bytes:
    return _u(len(values), 2) + b"".join(_u(value, 2) for value in values)


def _bytes_sequence(values: tuple[bytes, ...]) -> bytes:
    return _u(len(values), 2) + b"".join(_u(len(value), 4) + value for value in values)


@dataclass(frozen=True)
class Context:
    salt: bytes
    challenge: bytes
    application_context: bytes
    suite_id: int = SUITE
    round_profile: int = 0x0301
    state_size: int = 64

    def encode(self) -> bytes:
        return _record(
            b"SIGMACT3",
            (
                (1, _u(self.suite_id, 2)),
                (2, _u(0x0301, 2)),
                (3, _u(0x0301, 2)),
                (4, _u(self.round_profile, 2)),
                (5, _u(0x0301, 2)),
                (6, _u(0x0301, 2)),
                (7, _u(0x0301, 2)),
                (8, _u(0x0301, 2)),
                (9, _u(0x0301, 2)),
                (10, _u16_sequence(ALGORITHMS)),
                (11, _u16_sequence(ALGORITHMS)),
                (12, _u(ALG_SHA512, 2)),
                (13, _u(4, 2)),
                (14, _u(1 << 20, 4)),
                (15, _u(self.state_size, 2)),
                (16, _u(2, 4)),
                (17, _u(32, 4)),
                (18, _u(2, 2)),
                (19, _u(4, 2)),
                (20, self.salt),
                (21, self.challenge),
                (22, self.application_context),
                (23, _u(ALG_SHA3_512, 2)),
            ),
        )


def _cardinality(length: int) -> bytes:
    return _record(b"SIGMA3CD", ((1, _u(length, 8)),))


def _anchor(
    context: bytes,
    cardinality: bytes,
    message: bytes,
    suite_id: int = SUITE,
) -> tuple[bytes, tuple[bytes, ...]]:
    transcript = _transcript(DOMAIN_ANCHOR, ((1, context), (2, cardinality), (3, message)))
    components = tuple(_hash(algorithm, DOMAIN_ANCHOR, transcript) for algorithm in ALGORITHMS)
    encoded = _record(
        b"SIGMA3AN",
        (
            (1, _u(suite_id, 2)),
            (2, _u(len(message), 8)),
            (3, _u16_sequence(ALGORITHMS)),
            (4, _bytes_sequence(components)),
        ),
    )
    return encoded, components


def _length_signature(context: bytes, cardinality: bytes) -> bytes:
    transcript = _transcript(DOMAIN_LENGTH, ((1, context), (2, cardinality)))
    digest = _hash(ALG_SHA3_512, DOMAIN_LENGTH, transcript)
    return _record(b"SIGMA3LS", ((1, cardinality), (2, digest)))


def _joint(
    context: bytes,
    cardinality: bytes,
    message: bytes,
    anchor: bytes,
    length_signature: bytes,
) -> tuple[bytes, tuple[bytes, ...]]:
    transcript = _transcript(
        DOMAIN_JOINT,
        (
            (1, context),
            (2, cardinality),
            (3, message),
            (4, anchor),
            (5, length_signature),
        ),
    )
    components = tuple(_hash(algorithm, DOMAIN_JOINT, transcript) for algorithm in ALGORITHMS)
    encoded = _record(
        b"SIGMA3JS",
        ((1, _u16_sequence(ALGORITHMS)), (2, _bytes_sequence(components))),
    )
    return encoded, components


def _binding(anchor: bytes, cardinality: bytes, length_signature: bytes, joint: bytes) -> bytes:
    return _record(
        b"SIGMA3BI",
        ((1, anchor), (2, cardinality), (3, length_signature), (4, joint)),
    )


class _Reader:
    def __init__(self, domain: int, seed: bytes) -> None:
        self._shake = hashlib.shake_256(_domain(domain) + seed)
        self._offset = 0

    def read(self, length: int) -> bytes:
        end = self._offset + length
        result = self._shake.digest(end)[self._offset : end]
        self._offset = end
        return result


def _uniform(reader: _Reader, minimum: int, maximum: int) -> int:
    width = maximum - minimum + 1
    count = max(1, ((width - 1).bit_length() + 7) // 8)
    space = 1 << (8 * count)
    limit = space - space % width
    while True:
        candidate = int.from_bytes(reader.read(count), "big")
        if candidate < limit:
            return minimum + candidate % width


def _parameters(context: bytes, binding: bytes) -> tuple[int, int, bytes]:
    seed = _transcript(DOMAIN_PARAMETERS, ((1, context), (2, binding)))
    reader = _Reader(DOMAIN_PARAMETERS, seed)
    target = _uniform(reader, 2, 32)
    count = _uniform(reader, 2, 4)
    encoded = _record(b"SIGMA3TP", ((1, _u(target, 8)), (2, _u(count, 8))))
    return target, count, encoded


def _placement(field: int, slot: int) -> bytes:
    return _record(b"SIGMA3LP", ((1, _u(field, 2)), (2, _u(slot, 8))))


def _layout(
    context: bytes,
    length_signature: bytes,
    kind: int,
    index: int,
    base_length: int,
) -> tuple[bytes, tuple[tuple[int, int], ...]]:
    domain = DOMAIN_LAYOUT_INIT if kind == KIND_INIT else DOMAIN_LAYOUT_ROUND
    seed = _transcript(
        domain,
        (
            (1, context),
            (2, length_signature),
            (3, _u(kind, 2)),
            (4, _u(index, 8)),
            (5, _u(base_length, 8)),
        ),
    )
    reader = _Reader(domain, seed)
    placements = tuple(
        sorted(
            ((field, _uniform(reader, 0, base_length)) for field in BINDING_FIELDS),
            key=lambda item: (item[1], item[0]),
        )
    )
    encoded_placements = _tlv(
        tuple(
            (position + 1, _placement(field, slot))
            for position, (field, slot) in enumerate(placements)
        )
    )
    encoded = _record(
        b"SIGMA3PL",
        (
            (1, _u(index, 8)),
            (2, _u(base_length, 8)),
            (3, encoded_placements),
            (4, _u(kind, 2)),
        ),
    )
    return encoded, placements


def _placed(
    base: bytes,
    plan: bytes,
    placements: tuple[tuple[int, int], ...],
    values: dict[int, bytes],
) -> bytes:
    records = {
        field: b"SIGMA3BF"
        + _domain(DOMAIN_BINDING_FIELD)
        + _u(field, 2)
        + _u(len(value), 8)
        + value
        for field, value in values.items()
    }
    body = bytearray()
    previous = 0
    for field, slot in placements:
        if slot > previous:
            body.extend(base[previous:slot])
            previous = slot
        body.extend(records[field])
    body.extend(base[previous:])
    return b"SIGMA3PS" + _u(VERSION, 2) + _u(len(plan), 4) + plan + _u(len(body), 8) + bytes(body)


def _header(cardinality: bytes, anchor: bytes, length_signature: bytes, parameters: bytes) -> bytes:
    return _record(
        b"SIGMA3PH",
        ((1, cardinality), (2, anchor), (3, length_signature), (4, parameters)),
    )


def _window(parameters: bytes, states: tuple[bytes, ...]) -> bytes:
    return _record(b"SIGMA3TW", ((1, parameters), (2, _bytes_sequence(states))))


def evaluate(
    message: bytes, *, salt: bytes, challenge: bytes, application_context: bytes
) -> dict[str, object]:
    """Return every normative R7 intermediate as bytes or tuples of bytes."""

    context = Context(salt, challenge, application_context).encode()
    cardinality = _cardinality(len(message))
    anchor, anchor_components = _anchor(context, cardinality, message)
    length_signature = _length_signature(context, cardinality)
    joint, joint_components = _joint(context, cardinality, message, anchor, length_signature)
    binding = _binding(anchor, cardinality, length_signature, joint)
    target, count, parameters = _parameters(context, binding)
    values = {
        0x0301: anchor,
        0x0302: cardinality,
        0x0303: length_signature,
        0x0304: joint,
    }
    init_layout, init_placements = _layout(context, length_signature, KIND_INIT, 0, len(message))
    init_placed = _placed(message, init_layout, init_placements, values)
    init_frame = _transcript(DOMAIN_INIT, ((1, context), (2, init_layout), (3, init_placed)))
    state = _hash(ALG_SHA512, DOMAIN_INIT, init_frame)
    states = [state]
    layouts: list[bytes] = []
    frames: list[bytes] = []
    for index in range(target + count - 1):
        layout, placements = _layout(context, length_signature, KIND_ROUND, index, len(state))
        placed = _placed(state, layout, placements, values)
        frame = _transcript(
            DOMAIN_ROUND,
            ((1, context), (2, _u(index, 8)), (3, layout), (4, placed)),
        )
        state = _hash(ALG_SHA512, DOMAIN_ROUND, frame)
        layouts.append(layout)
        frames.append(frame)
        states.append(state)
    window_states = tuple(states[target : target + count])
    return {
        "message": message,
        "context": context,
        "cardinality": cardinality,
        "anchor": anchor,
        "anchor_components": anchor_components,
        "length_signature": length_signature,
        "joint": joint,
        "joint_components": joint_components,
        "binding": binding,
        "target_round": target,
        "state_count": count,
        "parameters": parameters,
        "init_layout": init_layout,
        "round_layouts": tuple(layouts),
        "init_frame": init_frame,
        "round_frames": tuple(frames),
        "states": tuple(states),
        "header": _header(cardinality, anchor, length_signature, parameters),
        "window": _window(parameters, window_states),
    }


def _suite_parameters(suite_id: int) -> tuple[int, int]:
    """Return ``(round_profile, state_size)`` for executable v3 suites."""
    try:
        return {
            0x0301: (0x0301, 64),
            0x0303: (0x0302, 64),
            0x0304: (0x0303, 256),
        }[suite_id]
    except KeyError as exc:
        raise ValueError("unknown executable Sigma v3 suite") from exc


def _digest(context: bytes, header: bytes, window: bytes) -> bytes:
    return _record(
        b"SIGMA3DG",
        (
            (1, _u(0x0301, 2)),
            (2, _domain(DOMAIN_EVIDENCE)),
            (3, context),
            (4, header),
            (5, window),
        ),
    )


def evaluate_suite(
    message: bytes,
    *,
    suite_id: int,
    salt: bytes,
    challenge: bytes,
    application_context: bytes,
) -> dict[str, object]:
    """Evaluate any executable v3 suite without importing :mod:`sigma`.

    The result intentionally exposes every R12 corpus intermediate. Placements
    are ``(binding_field_id, original_base_slot)`` pairs.
    """
    round_profile, state_size = _suite_parameters(suite_id)
    context = Context(
        salt,
        challenge,
        application_context,
        suite_id,
        round_profile,
        state_size,
    ).encode()
    cardinality = _cardinality(len(message))
    anchor, anchor_components = _anchor(context, cardinality, message, suite_id)
    length_signature = _length_signature(context, cardinality)
    joint, joint_components = _joint(
        context,
        cardinality,
        message,
        anchor,
        length_signature,
    )
    binding = _binding(anchor, cardinality, length_signature, joint)
    target, count, parameters = _parameters(context, binding)
    values = {
        0x0301: anchor,
        0x0302: cardinality,
        0x0303: length_signature,
        0x0304: joint,
    }

    init_layout, init_placements = _layout(
        context,
        length_signature,
        KIND_INIT,
        0,
        len(message),
    )
    init_placed = _placed(message, init_layout, init_placements, values)
    init_frame = _transcript(
        DOMAIN_INIT,
        ((1, context), (2, init_layout), (3, init_placed)),
    )
    if round_profile == 0x0303:
        state = b"".join(_hash(algorithm, DOMAIN_INIT, init_frame) for algorithm in ALGORITHMS)
    else:
        state = _hash(ALG_SHA512, DOMAIN_INIT, init_frame)

    states = [state]
    round_layouts: list[bytes] = []
    round_placements: list[tuple[tuple[int, int], ...]] = []
    round_frames: list[bytes] = []
    branch_frames: list[tuple[bytes, ...]] = []
    branch_outputs: list[tuple[bytes, ...]] = []
    fold_frames: list[bytes] = []

    for index in range(target + count - 1):
        layout, placements = _layout(
            context,
            length_signature,
            KIND_ROUND,
            index,
            len(state),
        )
        placed = _placed(state, layout, placements, values)
        state_frame_domain = DOMAIN_VECTOR_ROUND if round_profile == 0x0303 else DOMAIN_ROUND
        state_frame = _transcript(
            state_frame_domain,
            (
                (1, context),
                (2, _u(index, 8)),
                (3, layout),
                (4, placed),
            ),
        )
        if round_profile == 0x0301:
            state = _hash(ALG_SHA512, DOMAIN_ROUND, state_frame)
            current_branch_frames: tuple[bytes, ...] = ()
            branches: tuple[bytes, ...] = ()
        else:
            current_branch_frames = tuple(
                _transcript(
                    DOMAIN_DEEP_BRANCH,
                    (
                        (1, context),
                        (2, _u(index, 8)),
                        (3, _u(position, 2)),
                        (4, _u(algorithm, 2)),
                        (5, state_frame),
                    ),
                )
                for position, algorithm in enumerate(ALGORITHMS)
            )
            branches = tuple(
                _hash(algorithm, DOMAIN_DEEP_BRANCH, frame)
                for algorithm, frame in zip(ALGORITHMS, current_branch_frames, strict=True)
            )
            if round_profile == 0x0302:
                fold_frame = _transcript(
                    DOMAIN_DEEP_FOLD,
                    ((1, context), (2, _u(index, 8)), (3, _bytes_sequence(branches))),
                )
                fold_frames.append(fold_frame)
                state = _hash(ALG_SHA512, DOMAIN_DEEP_FOLD, fold_frame)
            else:
                state = b"".join(branches)

        round_layouts.append(layout)
        round_placements.append(placements)
        round_frames.append(state_frame)
        branch_frames.append(current_branch_frames)
        branch_outputs.append(branches)
        states.append(state)

    window_states = tuple(states[target : target + count])
    header = _header(cardinality, anchor, length_signature, parameters)
    window = _window(parameters, window_states)
    digest = _digest(context, header, window)
    return {
        "suite_id": suite_id,
        "message": message,
        "context": context,
        "cardinality": cardinality,
        "anchor": anchor,
        "anchor_components": anchor_components,
        "length_signature": length_signature,
        "joint": joint,
        "joint_components": joint_components,
        "binding": binding,
        "target_round": target,
        "state_count": count,
        "parameters": parameters,
        "init_layout": init_layout,
        "init_placements": init_placements,
        "round_layouts": tuple(round_layouts),
        "round_placements": tuple(round_placements),
        "init_frame": init_frame,
        "round_frames": tuple(round_frames),
        "branch_frames": tuple(branch_frames),
        "branch_outputs": tuple(branch_outputs),
        "fold_frames": tuple(fold_frames),
        "states": tuple(states),
        "header": header,
        "window": window,
        "digest": digest,
    }
