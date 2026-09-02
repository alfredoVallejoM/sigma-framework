"""Canonical multi-state digest container for Sigma v2."""

import json
import re
from dataclasses import dataclass
from typing import Any, Dict, List, Optional, Tuple

from sigma.spec.context import SigmaContextV2
from sigma.spec.encoding import DecodeError, decode_uint, encode_uint
from sigma.spec.ids import DIGEST_MAGIC
from sigma.suites.registry import get_suite

MAX_STATE_BYTES = 1024


@dataclass(frozen=True)
class SigmaDigestV2:
    """A self-describing digest, not a digital signature."""

    context: SigmaContextV2
    states: Tuple[bytes, ...]

    def __post_init__(self) -> None:
        if not isinstance(self.context, SigmaContextV2):
            raise TypeError("context must be SigmaContextV2")
        if len(self.states) != self.context.state_count:
            raise ValueError("number of states must equal context.state_count")
        if not self.states:
            raise ValueError("at least one state is required")
        if not all(isinstance(state, bytes) for state in self.states):
            raise TypeError("states must contain bytes")
        state_size = len(self.states[0])
        if not 1 <= state_size <= MAX_STATE_BYTES:
            raise ValueError(f"state size must be in [1, {MAX_STATE_BYTES}]")
        if any(len(state) != state_size for state in self.states):
            raise ValueError("all states must have the same size")

    def to_bytes(self) -> bytes:
        context_bytes = self.context.to_bytes()
        encoded_states = b"".join(encode_uint(len(state), 2) + state for state in self.states)
        return (
            DIGEST_MAGIC
            + encode_uint(len(context_bytes), 4)
            + context_bytes
            + encode_uint(len(self.states), 2)
            + encoded_states
        )

    def hex(self) -> str:
        return self.to_bytes().hex()

    def to_json(self, *, indent: Optional[int] = None) -> str:
        """Encode a presentation wrapper around the canonical binary digest."""

        return json.dumps(
            {"binary": self.hex(), "format": "sigma-v2"},
            sort_keys=True,
            separators=(",", ":") if indent is None else None,
            indent=indent,
        )

    def metadata(self) -> Dict[str, Any]:
        return {
            "anchor_profile": self.context.anchor_profile.name,
            "application_context_hex": self.context.application_context.hex(),
            "branches": [branch.name for branch in self.context.branches],
            "challenge_hex": self.context.challenge.hex(),
            "chunk_size": self.context.chunk_size,
            "format": "sigma-v2",
            "round_profile": self.context.round_profile.name,
            "salt_hex": self.context.salt.hex(),
            "state_count": self.context.state_count,
            "state_size": len(self.states[0]),
            "states_hex": [state.hex() for state in self.states],
            "suite_id": int(self.context.suite_id),
            "suite_name": get_suite(self.context.suite_id).name,
            "target_round": self.context.target_round,
        }

    @classmethod
    def from_json(cls, encoded: str) -> "SigmaDigestV2":
        if not isinstance(encoded, str):
            raise TypeError("JSON digest must be text")

        def unique_object(pairs):
            result = {}
            for key, value in pairs:
                if key in result:
                    raise DecodeError(f"duplicate JSON key: {key}")
                result[key] = value
            return result

        try:
            value = json.loads(encoded, object_pairs_hook=unique_object)
        except (json.JSONDecodeError, UnicodeError) as exc:
            raise DecodeError(f"invalid digest JSON: {exc}") from exc
        if not isinstance(value, dict) or set(value) != {"binary", "format"}:
            raise DecodeError("digest JSON must contain only binary and format")
        if value["format"] != "sigma-v2":
            raise DecodeError("unsupported JSON digest format")
        binary = value["binary"]
        if not isinstance(binary, str) or re.fullmatch(r"[0-9a-f]+", binary) is None:
            raise DecodeError("binary digest must be non-empty lowercase hexadecimal")
        if len(binary) % 2:
            raise DecodeError("binary digest hexadecimal length must be even")
        return cls.from_bytes(bytes.fromhex(binary))

    @classmethod
    def from_bytes(cls, data: bytes) -> "SigmaDigestV2":
        if not isinstance(data, bytes):
            raise TypeError("digest encoding must be bytes")
        header_size = len(DIGEST_MAGIC) + 4
        if len(data) < header_size or not data.startswith(DIGEST_MAGIC):
            raise DecodeError("invalid or truncated digest magic")
        context_length = decode_uint(data[len(DIGEST_MAGIC) : header_size], 4)
        context_end = header_size + context_length
        if context_end + 2 > len(data):
            raise DecodeError("truncated digest context")
        context = SigmaContextV2.from_bytes(data[header_size:context_end])
        try:
            get_suite(context.suite_id).validate_context(context)
        except ValueError as exc:
            raise DecodeError(f"context does not match its suite: {exc}") from exc
        count = decode_uint(data[context_end : context_end + 2], 2)
        if count != context.state_count:
            raise DecodeError("digest state count differs from context")
        offset = context_end + 2
        states: List[bytes] = []
        expected_size: Optional[int] = None
        for _ in range(count):
            if offset + 2 > len(data):
                raise DecodeError("truncated state length")
            state_size = decode_uint(data[offset : offset + 2], 2)
            offset += 2
            if not 1 <= state_size <= MAX_STATE_BYTES:
                raise DecodeError("invalid state size")
            if expected_size is not None and state_size != expected_size:
                raise DecodeError("states have inconsistent sizes")
            expected_size = state_size
            end = offset + state_size
            if end > len(data):
                raise DecodeError("truncated state")
            states.append(data[offset:end])
            offset = end
        if offset != len(data):
            raise DecodeError("trailing bytes after digest")
        try:
            return cls(context=context, states=tuple(states))
        except (TypeError, ValueError) as exc:
            raise DecodeError(f"invalid digest: {exc}") from exc
