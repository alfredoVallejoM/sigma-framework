# PX4 — HTTP and Binary Request Protocol V1

Status: **FROZEN / GATE PENDING**  
Date: 2026-09-24

## 1. General

Transport:

    HTTP/1.1

POST requests require:

    Content-Length
    endpoint-specific Content-Type

V1 rejects:

    Transfer-Encoding
    duplicate Content-Length
    query strings
    URI fragments
    unknown media types

Responses include:

    Content-Length
    Content-Type
    Cache-Control: no-store
    Connection: close

## 2. Why binary request framing

Large source bytes must not be:
- base64-expanded;
- JSON buffered;
- copied into receipts;
- hashed before policy preflight.

Therefore source-bearing POST bodies use fixed big-endian binary framing.

Metadata comes first; source comes last.

## 3. Version

Every binary body starts with an 8-byte magic and u16 protocol version.

Current:

    version = 1

Unknown magic/version rejects.

## 4. Capabilities wire

VerificationCapabilitiesV1 is encoded as canonical ASCII JSON because it is
small fixed metadata.

Exact fields:

    artifact_metadata_profile
    contains_symlink
    estimated_working_memory_bytes
    has_provenance
    has_signature
    has_tree_evidence
    tree_proof_bytes

Canonical JSON requirements:
- keys sorted;
- compact separators;
- ASCII;
- newline terminator;
- no unknown/missing keys;
- decode + reencode byte equality.

Empty capabilities bytes are accepted as VerificationCapabilitiesV1 defaults for
low-level decoder compatibility. The public encoder always emits explicit
canonical capabilities JSON.

## 5. Artifact verification body

Media type:

    application/vnd.sigma.gateway.artifact-verify.v1

Magic:

    SIGGWAV1

Header, big endian:

    magic            8 bytes
    version          u16
    flags            u16
    artifact_id      32 bytes
    artifact_length  u32
    policy_length    u32
    capabilities_len u32
    source_length    u64

Payload:

    optional canonical SigmaArtifactV1
    canonical VerificationPolicyV1
    canonical capabilities JSON
    optional exact source bytes

Flag:

    bit 0 = source present

Unknown flag bits reject.

If artifact_length = 0:
- artifact is loaded from PX1 by artifact_id.

If artifact_length > 0:
- embedded artifact is parsed;
- canonical byte equality required;
- its ArtifactId must equal header ArtifactId.

## 6. Policy evaluation body

Media type:

    application/vnd.sigma.gateway.policy-evaluate.v1

Magic:

    SIGGWPE1

Header:

    magic              8 bytes
    version            u16
    flags              u16
    artifact_identity_len u16
    evidence_length    u32
    policy_length      u32
    capabilities_len   u32
    source_length      u64

Payload:

    receipt artifact_identity bytes
    canonical evidence wire
    canonical VerificationPolicyV1
    canonical capabilities JSON
    optional source

artifact_identity is 1..255 bytes, matching SV3 receipt constraints.

## 7. Batch verification body

Media type:

    application/vnd.sigma.gateway.batch-verify.v1

Magic:

    SIGGWBV1

Batch header:

    magic       8 bytes
    version     u16
    item_count  u16

Each item header:

    flags              u16
    artifact_identity_len u16
    evidence_length    u32
    policy_length      u32
    capabilities_len   u32
    source_length      u64

followed immediately by:

    identity
    evidence
    policy
    capabilities
    source segment

Then the next item begins.

No offset table is required.

The gateway processes items in stream order.

## 8. Inclusion-proof verification body

Media type:

    application/vnd.sigma.gateway.inclusion-verify.v1

Magic:

    SIGGWPI1

Header:

    magic        8 bytes
    version      u16
    proof_length u32
    leaf_length  u32

Payload:

    InclusionProofV1 wire
    exact leaf bytes

Inclusion proof wire is parsed before leaf bytes are consumed.

If proof parsing fails:
- leaf bytes are not read.

If header leaf_length differs from canonical proof.leaf_byte_length:
- response is verified=false;
- leaf bytes are not read;
- connection closes after the response.

Response:

    {
      "schema": "sigma-gateway-proof-verification-v1",
      "verified": true|false
    }

canonical JSON.

## 9. Range-proof verification body

Media type:

    application/vnd.sigma.gateway.range-verify.v1

Magic:

    SIGGWPR1

Header:

    magic        8 bytes
    version      u16
    proof_length u32
    value_length u64

Payload:

    RangeProofV1 wire
    exact disclosed range bytes

RangeProofV1 is parsed before disclosed range bytes are consumed.

If value_length differs from proof.length:
- response is verified=false;
- range bytes are not read.

value_length is bounded by max_proof_value_bytes before value allocation.

## 10. Artifact verification response

Content-Type:

    application/json

Schema:

    sigma-gateway-artifact-verification-v1

Fields project ArtifactVerificationResultV1 exactly:
- accepted;
- artifact_id;
- profile;
- dual_conjunction;
- failure_sides;
- tree result;
- trajectory result;
- policy result.

Expected/actual local evidence wires are hex or null.

No timestamp is introduced.

## 11. Policy evaluation response

Content-Type:

    application/json

Schema:

    sigma-gateway-policy-evaluation-v1

Contains:
- full VerificationDecisionV1 projection;
- receipt_id hex;
- canonical VerificationReceiptV1 wire as hex.

The receipt remains the canonical SV3 binary object.

JSON is only the HTTP presentation.

## 12. Batch response

Content-Type:

    application/vnd.sigma.batch-result.v1

Body:

    exact BatchVerificationResultV1 wire

No HTTP wrapper changes batch_id.

## 13. GET artifact

Path:

    /v1/artifacts/<64 lowercase-or-uppercase hex chars>

The parser accepts hex syntax and normalizes internally to bytes.

Response:
- exact canonical PX1 SigmaArtifactV1 wire.

Unknown/missing artifact:
- 404 canonical error JSON.

## 14. GET parents

Path:

    /v1/artifacts/<id>/parents

Response schema:

    sigma-gateway-artifact-parents-v1

Fields:

    schema
    artifact_id
    parents

parents are hex strings in canonical ArtifactIdentity order.

## 15. Health

GET /health

Response:

    {
      "schema":"sigma-gateway-health-v1",
      "status":"ok"
    }

Health V1 only means:
- process is serving;
- request dispatcher is operational.

It is not a remote-store health check.

## 16. Version

GET /version

Response includes:

    sigma-gateway-version-v1
    gateway_protocol_version
    package_version

No git branch, filesystem path or credential-bearing build environment is exposed.

## 16A. Outer HTTP parser errors

Malformed HTTP syntax handled by BaseHTTPRequestHandler is projected through the
same canonical sigma-gateway-error-v1 JSON schema by overriding send_error.

Transport admission failures also emit the fixed safe audit schema.

## 17. Error JSON

Schema:

    sigma-gateway-error-v1

Canonical fields:

    code
    message
    retryable
    schema

Messages are fixed/sanitized.

Raw exception strings are not exposed.

## 18. Source geometry rule

For artifact and policy requests the source is the final body field.

After reading header+metadata:

    reader.remaining == source_length

must hold.

Thus early response does not mean malformed framing is accepted.

## 19. Body preflight

Before body reader creation:

    Content-Length <= max_request_bytes

Before source spool:

    source_length <= max_source_bytes

Before metadata read:

    metadata lengths <= max_metadata_bytes

Before proof value read:

    value <= max_proof_value_bytes

Before batch processing:

    item_count <= max_batch_items

During batch:

    sum(source_length) <= max_batch_total_source_bytes

## 20. Early response behavior

If source bytes are syntactically present but verification policy can decide
without them, the service may respond after metadata preflight without reading
the source.

The HTTP adapter always closes the connection.

This is protocol-defined V1 behavior.

Clients must not depend on persistent connection reuse.

## 21. Expect: 100-continue

The handler applies:
- header-size admission;
- Content-Length parsing;
- max_request_bytes;

before sending 100 Continue.

An oversize request can therefore receive a final error without sending body.

## 22. Chunked HTTP

Socket blocking reads use request_timeout_seconds. A body-read timeout maps to
the deterministic gateway timeout error.

Transfer-Encoding is intentionally unsupported in V1.

Reason:
the fixed Content-Length outer bound is part of the cheap admission contract.

Streaming refers to incremental consumption/spooling inside that known envelope,
not unknown-length HTTP chunking.

## 23. Header policy

Header bytes are limited during stdlib parsing through a budgeted readline
wrapper. PX4 does not wait for an arbitrarily large parsed mapping before
applying max_header_bytes.

Aggregate parsed header bytes are also rechecked after parse.

The gateway does not log arbitrary headers.

No header participates in:
- VerificationPolicy;
- ArtifactId;
- receipt;
- proof verification;
- batch identity.

## 24. Query policy

Queries/fragments reject.

This avoids:
- ambiguous duplicate parameter semantics;
- accidental credential logging;
- policy values outside canonical request bodies.

Future API extensions should use a new route/media version rather than silent
query additions.

## 25. Compatibility

PX4 V1 request magic/media types are independent axes from:
- Artifact V1;
- Tree V1;
- VerificationPolicy V1;
- Receipt V1;
- package version.

A future gateway V2 can coexist without changing any underlying Sigma identity.
