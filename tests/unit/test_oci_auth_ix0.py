from __future__ import annotations

import base64

import pytest

from scripts.product_closure.ix0_fixtures import (
    GateOciRegistryTransport,
    make_subject_descriptor,
)
from sigma.artifact import ArtifactProfileV1, create_artifact_v1
from sigma.interop import (
    OciBearerAuthError,
    OciBearerAuthV1,
    OciRegistryClientV1,
    exchange_bearer_challenge_v1,
    parse_bearer_challenge_v1,
)
from sigma.tree import build_tree


def _artifact(payload: bytes = b"ix0-auth"):
    return create_artifact_v1(
        ArtifactProfileV1.TREE,
        tree_root=build_tree(payload),
    )


def test_ix0_bearer_challenge_parser_accepts_standard_registry_shape():
    challenge = parse_bearer_challenge_v1(
        'Bearer realm="https://auth.example/token",'
        'service="registry.example",'
        'scope="repository:team/sigma:pull,push"'
    )
    assert challenge is not None
    assert challenge.realm == "https://auth.example/token"
    assert challenge.service == "registry.example"
    assert challenge.scope == "repository:team/sigma:pull,push"


def test_ix0_bearer_parser_ignores_other_schemes_and_rejects_duplicates():
    assert parse_bearer_challenge_v1(
        'Basic realm="registry"'
    ) is None

    with pytest.raises(
        OciBearerAuthError,
        match="duplicate",
    ):
        parse_bearer_challenge_v1(
            'Bearer realm="https://auth.example/token",'
            'realm="https://other.example/token"'
        )


def test_ix0_bearer_parser_handles_quoted_commas_and_escapes():
    challenge = parse_bearer_challenge_v1(
        'Bearer realm="https://auth.example/token",'
        'service="registry,primary",'
        'scope="repository:team/\\\"sigma\\\":pull"'
    )
    assert challenge is not None
    assert challenge.service == "registry,primary"
    assert challenge.scope == 'repository:team/"sigma":pull'


def test_ix0_private_registry_anonymous_bearer_flow_is_reused():
    transport = GateOciRegistryTransport(
        native_referrers=True,
        bearer_required=True,
    )
    client = OciRegistryClientV1(
        "https://registry.example/",
        "team/sigma",
        transport=transport,
        auth_transport=transport,
        bearer_auth=OciBearerAuthV1(),
    )

    assert client.ping() is True
    result = client.attach_artifact(
        _artifact(b"private-anonymous"),
        subject=make_subject_descriptor(b"private-subject"),
    )
    assert result.discovered_after_push is True
    assert len(transport.token_requests) == 1

    registry_requests = [
        request
        for request in transport.requests
        if "registry.example" in request[1]
    ]
    assert any(
        request[2].get("Authorization")
        == "Bearer " + transport.bearer_token
        for request in registry_requests
    )


def test_ix0_private_registry_basic_credentials_only_go_to_token_realm():
    transport = GateOciRegistryTransport(
        native_referrers=True,
        bearer_required=True,
        bearer_username="alice",
        bearer_password="correct horse battery staple",
    )
    client = OciRegistryClientV1(
        "https://registry.example/",
        "team/sigma",
        transport=transport,
        auth_transport=transport,
        bearer_auth=OciBearerAuthV1(
            username="alice",
            password="correct horse battery staple",
        ),
    )

    assert client.ping() is True
    assert len(transport.token_requests) == 1
    token_headers = transport.token_requests[0][1]
    expected = "Basic " + base64.b64encode(
        b"alice:correct horse battery staple"
    ).decode("ascii")
    assert token_headers["Authorization"] == expected

    registry_headers = [
        request[2]
        for request in transport.requests
        if "registry.example" in request[1]
    ]
    assert all(
        header.get("Authorization") != expected
        for header in registry_headers
    )
    assert any(
        header.get("Authorization")
        == "Bearer " + transport.bearer_token
        for header in registry_headers
    )


def test_ix0_explicit_authorization_header_takes_precedence_over_auto_auth():
    transport = GateOciRegistryTransport(
        native_referrers=True,
        bearer_required=True,
    )
    client = OciRegistryClientV1(
        "https://registry.example/",
        "team/sigma",
        transport=transport,
        auth_transport=transport,
        headers={"Authorization": "Bearer explicitly-wrong"},
        bearer_auth=OciBearerAuthV1(),
    )

    assert client.ping() is False
    assert transport.token_requests == []


def test_ix0_bearer_realm_requires_https_unless_explicitly_allowed():
    transport = GateOciRegistryTransport(
        native_referrers=True,
        bearer_required=True,
        bearer_realm="http://auth.example/token",
    )
    strict = OciRegistryClientV1(
        "https://registry.example/",
        "team/sigma",
        transport=transport,
        auth_transport=transport,
        bearer_auth=OciBearerAuthV1(),
    )
    with pytest.raises(
        OciBearerAuthError,
        match="insecure HTTP realm",
    ):
        strict.ping()

    allowed = OciRegistryClientV1(
        "https://registry.example/",
        "team/sigma",
        transport=transport,
        auth_transport=transport,
        bearer_auth=OciBearerAuthV1(
            allow_insecure_realm=True,
        ),
    )
    assert allowed.ping() is True


def test_ix0_direct_bearer_exchange_rejects_bad_token_service_status():
    challenge = parse_bearer_challenge_v1(
        'Bearer realm="https://auth.example/token"'
    )
    assert challenge is not None

    class DeniedTransport:
        def request(
            self,
            method,
            url,
            *,
            headers=None,
            body=None,
            timeout=30.0,
        ):
            del method, headers, body, timeout
            from sigma.artifact.remote_http import HttpResponseV1

            return HttpResponseV1(
                403,
                (),
                b"",
                url,
            )

    with pytest.raises(
        OciBearerAuthError,
        match="HTTP 403",
    ):
        exchange_bearer_challenge_v1(
            challenge,
            auth=OciBearerAuthV1(),
            transport=DeniedTransport(),
            timeout=1.0,
        )


def test_ix0_bearer_auth_repr_does_not_expose_password():
    auth = OciBearerAuthV1(
        username="alice",
        password="super-secret-password",
    )
    assert "super-secret-password" not in repr(auth)
