"""Optional bearer-token authentication for OCI registries.

Authentication is operational state only.  Tokens and credentials never enter
OCI descriptors, Sigma ArtifactId, receipts, or persisted IX0 metadata.
"""

from __future__ import annotations

import base64
import json
import urllib.parse
from dataclasses import dataclass, field
from typing import Mapping, Protocol, runtime_checkable

from sigma.artifact.remote_http import HttpResponseV1

DEFAULT_OCI_AUTH_MAX_RESPONSE_BYTES = 64 * 1024
DEFAULT_OCI_AUTH_MAX_TOKEN_BYTES = 16 * 1024


class OciBearerAuthError(RuntimeError):
    """Bearer challenge/token exchange failed."""


@dataclass(frozen=True)
class OciBearerChallengeV1:
    realm: str
    service: str | None = None
    scope: str | None = None

    def __post_init__(self) -> None:
        parsed = urllib.parse.urlsplit(self.realm)
        if parsed.scheme not in ("http", "https") or not parsed.netloc:
            raise OciBearerAuthError(
                "bearer auth realm must be absolute http/https URL"
            )
        if parsed.fragment:
            raise OciBearerAuthError(
                "bearer auth realm must not contain fragment"
            )
        for name, value in (
            ("service", self.service),
            ("scope", self.scope),
        ):
            if value is not None and not isinstance(value, str):
                raise OciBearerAuthError(
                    f"bearer auth {name} must be str or None"
                )


@dataclass(frozen=True)
class OciBearerAuthV1:
    """Credentials/configuration for challenge-based bearer token exchange."""

    username: str | None = None
    password: str | None = field(default=None, repr=False)
    allow_insecure_realm: bool = False
    max_response_bytes: int = DEFAULT_OCI_AUTH_MAX_RESPONSE_BYTES
    max_token_bytes: int = DEFAULT_OCI_AUTH_MAX_TOKEN_BYTES

    def __post_init__(self) -> None:
        if (self.username is None) != (self.password is None):
            raise ValueError(
                "bearer auth username and password must be provided together"
            )
        if self.username is not None and not isinstance(self.username, str):
            raise TypeError("bearer auth username must be str")
        if self.password is not None and not isinstance(self.password, str):
            raise TypeError("bearer auth password must be str")
        if not isinstance(self.allow_insecure_realm, bool):
            raise TypeError("allow_insecure_realm must be bool")
        for name, value in (
            ("max_response_bytes", self.max_response_bytes),
            ("max_token_bytes", self.max_token_bytes),
        ):
            if (
                isinstance(value, bool)
                or not isinstance(value, int)
                or value < 1
            ):
                raise ValueError(f"{name} must be a positive int")


@runtime_checkable
class OciAuthTransportV1(Protocol):
    def request(
        self,
        method: str,
        url: str,
        *,
        headers: Mapping[str, str] | None = None,
        body: bytes | None = None,
        timeout: float = 30.0,
    ) -> HttpResponseV1:
        ...


def _split_auth_params(value: str) -> tuple[str, ...]:
    parts: list[str] = []
    start = 0
    quoted = False
    escaped = False
    for index, char in enumerate(value):
        if escaped:
            escaped = False
            continue
        if quoted and char == "\\":
            escaped = True
            continue
        if char == '"':
            quoted = not quoted
            continue
        if char == "," and not quoted:
            parts.append(value[start:index].strip())
            start = index + 1
    if quoted or escaped:
        raise OciBearerAuthError(
            "malformed quoted bearer challenge"
        )
    parts.append(value[start:].strip())
    return tuple(part for part in parts if part)


def _unquote_auth_value(value: str) -> str:
    candidate = value.strip()
    if not candidate:
        return ""
    if not candidate.startswith('"'):
        return candidate
    if len(candidate) < 2 or not candidate.endswith('"'):
        raise OciBearerAuthError(
            "malformed quoted bearer challenge value"
        )
    body = candidate[1:-1]
    out: list[str] = []
    escaped = False
    for char in body:
        if escaped:
            out.append(char)
            escaped = False
        elif char == "\\":
            escaped = True
        else:
            out.append(char)
    if escaped:
        raise OciBearerAuthError(
            "malformed bearer challenge escape"
        )
    return "".join(out)


def parse_bearer_challenge_v1(
    header: str | None,
) -> OciBearerChallengeV1 | None:
    """Parse a single Bearer WWW-Authenticate challenge.

    Non-Bearer challenges return None so callers can leave other auth schemes to
    explicit user configuration.
    """

    if header is None:
        return None
    if not isinstance(header, str):
        raise TypeError("WWW-Authenticate header must be str or None")
    scheme, separator, tail = header.strip().partition(" ")
    if not separator or scheme.lower() != "bearer":
        return None
    params: dict[str, str] = {}
    for item in _split_auth_params(tail):
        key, equals, raw_value = item.partition("=")
        if not equals or not key.strip():
            raise OciBearerAuthError(
                "malformed bearer challenge parameter"
            )
        normalized = key.strip().lower()
        if normalized in params:
            raise OciBearerAuthError(
                "duplicate bearer challenge parameter"
            )
        params[normalized] = _unquote_auth_value(raw_value)
    realm = params.get("realm")
    if not realm:
        raise OciBearerAuthError(
            "bearer challenge omitted realm"
        )
    return OciBearerChallengeV1(
        realm=realm,
        service=params.get("service"),
        scope=params.get("scope"),
    )


def _strict_json_object(
    pairs: list[tuple[str, object]],
) -> dict[str, object]:
    out: dict[str, object] = {}
    for key, value in pairs:
        if key in out:
            raise OciBearerAuthError(
                "duplicate token response JSON key"
            )
        out[key] = value
    return out


def _token_url(challenge: OciBearerChallengeV1) -> str:
    parsed = urllib.parse.urlsplit(challenge.realm)
    query = urllib.parse.parse_qsl(
        parsed.query,
        keep_blank_values=True,
    )
    existing: dict[str, list[str]] = {}
    for key, value in query:
        existing.setdefault(key, []).append(value)

    for key, challenge_value in (
        ("service", challenge.service),
        ("scope", challenge.scope),
    ):
        if challenge_value is None:
            continue
        prior = existing.get(key, [])
        if prior:
            if any(value != challenge_value for value in prior):
                raise OciBearerAuthError(
                    f"bearer realm contains conflicting {key} query"
                )
        else:
            query.append((key, challenge_value))

    return urllib.parse.urlunsplit(
        (
            parsed.scheme,
            parsed.netloc,
            parsed.path,
            urllib.parse.urlencode(query),
            "",
        )
    )


def exchange_bearer_challenge_v1(
    challenge: OciBearerChallengeV1,
    *,
    auth: OciBearerAuthV1,
    transport: OciAuthTransportV1,
    timeout: float,
) -> str:
    """Exchange a parsed challenge and return an Authorization header value."""

    if not isinstance(challenge, OciBearerChallengeV1):
        raise TypeError("challenge must be OciBearerChallengeV1")
    if not isinstance(auth, OciBearerAuthV1):
        raise TypeError("auth must be OciBearerAuthV1")
    if not isinstance(transport, OciAuthTransportV1):
        raise TypeError("transport must implement OciAuthTransportV1")

    parsed = urllib.parse.urlsplit(challenge.realm)
    if parsed.scheme == "http" and not auth.allow_insecure_realm:
        raise OciBearerAuthError(
            "refusing bearer credential exchange over insecure HTTP realm"
        )

    headers = {"Accept": "application/json"}
    if auth.username is not None and auth.password is not None:
        credential = (
            f"{auth.username}:{auth.password}"
        ).encode("utf-8")
        encoded = base64.b64encode(credential).decode("ascii")
        headers["Authorization"] = "Basic " + encoded

    response = transport.request(
        "GET",
        _token_url(challenge),
        headers=headers,
        timeout=timeout,
    )
    if response.status != 200:
        raise OciBearerAuthError(
            f"bearer token service returned HTTP {response.status}"
        )
    if len(response.body) > auth.max_response_bytes:
        raise OciBearerAuthError(
            "bearer token response exceeds configured limit"
        )
    try:
        payload = json.loads(
            response.body.decode("utf-8"),
            object_pairs_hook=_strict_json_object,
        )
    except OciBearerAuthError:
        raise
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise OciBearerAuthError(
            "bearer token response is invalid JSON"
        ) from exc
    if not isinstance(payload, dict):
        raise OciBearerAuthError(
            "bearer token response must be an object"
        )

    token = payload.get("token")
    access_token = payload.get("access_token")
    if token is not None and access_token is not None and token != access_token:
        raise OciBearerAuthError(
            "token and access_token fields disagree"
        )
    selected = token if token is not None else access_token
    if not isinstance(selected, str) or not selected:
        raise OciBearerAuthError(
            "bearer token response omitted token"
        )
    if len(selected.encode("utf-8")) > auth.max_token_bytes:
        raise OciBearerAuthError(
            "bearer token exceeds configured limit"
        )
    if "\r" in selected or "\n" in selected:
        raise OciBearerAuthError(
            "bearer token contains newline"
        )
    return "Bearer " + selected


__all__ = [
    "DEFAULT_OCI_AUTH_MAX_RESPONSE_BYTES",
    "DEFAULT_OCI_AUTH_MAX_TOKEN_BYTES",
    "OciAuthTransportV1",
    "OciBearerAuthError",
    "OciBearerAuthV1",
    "OciBearerChallengeV1",
    "exchange_bearer_challenge_v1",
    "parse_bearer_challenge_v1",
]
