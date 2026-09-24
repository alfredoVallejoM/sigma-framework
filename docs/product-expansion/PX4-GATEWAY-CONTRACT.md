# PX4 — Verification Gateway Contract

Status: **FROZEN IMPLEMENTATION CONTRACT / EXECUTED GATE PENDING**  
Date: 2026-09-24

## 1. Purpose

PX4 exposes already-defined Sigma verification semantics as a bounded service.

It does not define a new verifier.

Authority remains:

    Tree proofs            -> sigma.tree verify_inclusion / verify_range
    Artifact verification  -> SA1 verify_artifact_v1
    Policy evaluation      -> SV2 verify_with_policy_v1
    Receipts               -> SV3 receipt_from_decision_v1
    Batch                  -> SV3 verify_batch_item_v1 / BatchVerificationResultV1
    Artifact bytes         -> PX1 LocalArtifactStoreV1
    Parent IDs             -> canonical SigmaArtifactV1 identity

The gateway is transport + admission + resource isolation + deterministic
serialization.

## 2. In-process API

Primary runtime:

    GatewayServiceV1.handle(
      method,
      path,
      content_type,
      body_stream,
      content_length,
      token=None
    )

The HTTP daemon is intentionally thin.

This lets tests compare:

    local library result
      ==
    in-process gateway result
      ==
    HTTP gateway result

without giving HTTP code its own semantic implementation.

## 3. HTTP endpoints

V1 routes:

    POST /v1/artifacts/verify
    POST /v1/proofs/inclusion/verify
    POST /v1/proofs/range/verify
    POST /v1/policies/evaluate
    POST /v1/batch/verify

    GET  /v1/artifacts/{ArtifactId}
    GET  /v1/artifacts/{ArtifactId}/parents
    GET  /health
    GET  /version

No query strings are accepted in V1.

No path aliases are accepted.

## 4. Artifact verification delegation

Artifact endpoint parses:
- requested ArtifactId;
- optional embedded canonical SigmaArtifactV1;
- VerificationPolicyV1;
- VerificationCapabilitiesV1;
- optional source length;
- source bytes only when local verification requires them.

If artifact bytes are omitted, PX4 loads through PX1.

If embedded, PX4 requires:

    parsed artifact ArtifactId == requested ArtifactId
    parsed.to_bytes() == supplied artifact wire

Then:

    verify_artifact_v1(...)

is the decision authority.

PX4 serializes the returned ArtifactVerificationResultV1.

It does not reinterpret:
- tree side;
- trajectory side;
- policy decision;
- failure_sides;
- expected/actual wires.

## 5. Policy and receipt delegation

Policy endpoint delegates to:

    verify_with_policy_v1

and creates the receipt through:

    receipt_from_decision_v1

with:

    verifier_package = sigma-framework
    verifier_version = PACKAGE_VERSION
    verifier_build   = configured immutable bytes
    claimed_unix_time = None

Leaving claimed time absent makes the gateway/local differential deterministic
and avoids claiming trusted time without a timestamp authority.

Authorization/Cookie/HTTP metadata are never passed to receipt construction.

Thus changing request credentials cannot change receipt bytes.

## 6. Batch delegation

PX4 consumes batch items sequentially from the request stream.

Each item is evaluated with:

    verify_batch_item_v1(index=original_index)

using the same verifier package/version/build as local SV3.

The final binary response is:

    BatchVerificationResultV1.to_bytes()

exactly.

This preserves:
- item order;
- error projection;
- receipt wires;
- batch_id semantics.

PX4 deliberately does not invent a JSON batch receipt format.

## 7. Proof delegation

Inclusion:

    InclusionProofV1.from_bytes
    verify_inclusion

Range:

    RangeProofV1.from_bytes
    verify_range

The gateway returns only the Boolean verification result in a stable JSON
envelope.

Malformed proof and valid-but-false proof remain distinct:
- malformed -> gateway error;
- structurally valid but non-verifying -> HTTP 200, verified=false.

## 8. Canonical artifact reads

GET artifact returns:

    LocalArtifactStoreV1.get_artifact_bytes(id)

with media type:

    application/vnd.sigma.artifact.v1

PX1 reparses/rechecks canonical storage before returning bytes.

## 9. Parent reads

GET parents intentionally does not call the mutable SQLite parent index directly.

It loads:

    store.get_artifact(id)

then returns:

    artifact.parent_artifact_ids

Therefore the HTTP parent endpoint preserves the PX2 authority rule:

    canonical ArtifactIdentity parents are truth
    SQL index is only acceleration metadata.

## 10. Cheap preflight law

The fundamental PX4 admission sequence for source-bearing requests is:

    Content-Length admission
      -> fixed framing header
      -> bounded metadata
      -> local verifier with source=None
      -> only if SOURCE_REQUIRED:
           spool source
           run full local verifier

This means existing SA1/SV2 policy logic decides whether expensive source work is
needed.

Examples that can return before source read:
- committed input already exceeds VerificationPolicy;
- suite disallowed;
- Tree-only artifact not permitted;
- missing signature/provenance capability;
- rounds exceed policy;
- malformed evidence decisions that do not require source.

PX4 does not duplicate these policy rules.

## 11. Gateway operational limits

Gateway limits are admission limits, not VerificationPolicy.

Defaults:

    max_request_bytes             = 1 GiB + 16 MiB
    max_metadata_bytes            = 4 MiB
    max_source_bytes              = 1 GiB
    max_memory_spool_bytes        = 1 MiB
    max_proof_value_bytes         = 64 MiB
    max_batch_items               = 256
    max_batch_total_source_bytes  = 1 GiB
    max_concurrent_requests       = 16
    max_http_connections          = 32
    request_timeout_seconds       = 120
    read_chunk_bytes              = 1 MiB
    max_response_bytes            = 32 MiB
    max_header_bytes              = 64 KiB
    max_trajectory_rounds         = 1,000,064

Operational rejection is reported as a gateway error rather than falsifying the
underlying local VerificationDecision.

## 12. Streaming body model

PX4 does not require source bytes to be base64/JSON materialized.

Binary V1 framing declares:
- metadata lengths;
- source-present flag;
- source length.

Metadata is read first.

When source replay is needed, source bytes enter IncrementalSpoolSource:
- first max_memory_spool_bytes in memory;
- spill to temporary storage afterwards;
- total bounded by source limit;
- replayable for Tree and Trajectory verification.

## 13. Exact source geometry

For single-source requests:

    declared source_length
      ==
    remaining Content-Length bytes after metadata

is required before source read.

A request cannot exploit early policy rejection to hide:
- truncated body;
- trailing body;
- contradictory source length.

Batch items require source length to fit within the remaining batch stream and
consume/discard their exact segment before the next item.

## 14. Early response and connection lifetime

Some policy decisions intentionally leave source bytes unread.

HTTP V1 therefore always sends:

    Connection: close

and marks the handler connection closed after every response.

No subsequent request is parsed from unread bytes on the same TCP connection.

This is a deliberate V1 simplification.

## 15. Cancellation

GatewayCancellationTokenV1 is request-local.

It supports:
- explicit cancel();
- absolute monotonic deadline derived from timeout.

The token is checked:
- before/after bounded body reads;
- while source is spooled;
- before each CanonicalSource replay chunk;
- around proof kernels;
- between batch items.

Client body disconnects are translated to cancellation.

The underlying existing verifiers remain unchanged.

## 16. Timeout semantics

Timeout is cooperative.

For source-based verification, CancellableSourceV1 checks on every source replay
chunk.

For bounded in-memory proof kernels, PX4 checks immediately before and after the
local verifier call.

If a proof kernel itself consumes the remaining deadline, its result is discarded
and the response becomes timeout.

Blocking socket reads inherit request_timeout_seconds, so a stalled client
cannot bypass the deadline merely by blocking inside rfile.read().

PX4 V1 does not kill Python threads asynchronously.

This avoids unsafe interruption of shared library state.

## 17. Concurrency isolation

PX4 uses two distinct admission bounds.

### HTTP connection/thread bound

GatewayThreadingHTTPServerV1 has a pre-thread connection semaphore.

Default:

    32 HTTP connections

If exhausted, the server writes canonical HTTP 503 / code=busy directly from
process_request and closes the socket without creating another handler thread.

This bounds clients stalled before GatewayServiceV1.handle, including partial
request-line/header senders.

### Verification-request bound

GatewayServiceV1 has its own BoundedSemaphore.

Default:

    16 concurrent verification requests

No request waiting queue is created by the service.

If all verification slots are occupied:

    HTTP 503
    code = busy

before body read.

A cancelled/timed-out request cannot mutate verification state because PX4
verification endpoints are read-only with respect to the PX1 store.

The semaphore slot is released before audit sink I/O.

Thus a slow audit sink cannot consume verification concurrency capacity.

## 18. Batch resource isolation

Batch is not implemented as unconstrained verify_batch_v1(max_workers=N).

PX4 parses and verifies pointwise, preserving indices.

Benefits:
- only one item source spool must remain alive at a time;
- total declared batch source bytes are bounded;
- cancellation checks occur between items;
- no hidden N-way CPU fan-out.

The resulting BatchVerificationResultV1 remains byte-equivalent to local
max_workers=1 semantics.

## 19. Response budget

PX4 has max_response_bytes.

Batch admission additionally uses a conservative fixed result budget per item
before item verification starts.

This prevents a batch from completing expensive work only to discover that the
serialized result cannot be returned under gateway policy.

## 20. Error model

Gateway errors have one canonical JSON schema:

    sigma-gateway-error-v1

Fields:

    schema
    code
    message
    retryable

No exception traceback, source bytes, credential headers or raw exception string
is included.

Representative status/code mapping:

    400 bad-request
    404 not-found
    408 timeout
    409 cancelled / artifact-id-mismatch
    411 length-required
    413 request/source/metadata/policy limit
    415 unsupported-media-type
    431 header-too-large
    503 busy
    500 internal

Valid verification rejection remains HTTP 200 because the request executed
successfully and the local verifier rejected the evidence.

## 21. Structured audit schema

Audit records contain only:

    sequence
    method
    normalized endpoint label
    status
    stable error code
    ArtifactId hex when known
    PolicyId hex when known
    decision enum/summary
    bytes_in
    bytes_out
    elapsed milliseconds
    timeout flag
    cancelled flag

They do not contain:
- Authorization;
- Cookie;
- Proxy-Authorization;
- arbitrary headers;
- source bytes;
- artifact bytes;
- evidence bytes;
- receipt bytes;
- raw query string;
- raw unknown path;
- exception message.

Known dynamic artifact paths normalize to:

    /v1/artifacts/{id}
    /v1/artifacts/{id}/parents

Unknown paths log:

    <unmatched>

## 22. Audit sink failure

Audit is observability, not verification authority.

Sink failure:
- does not change response decision;
- does not alter receipts;
- does not corrupt store state;
- is swallowed by the gateway layer.

A managed deployment can add external alerting for sink failures without changing
verification semantics.

## 23. HTTP admission

PX4 HTTP V1 requires Content-Length for POST.

It rejects:
- Transfer-Encoding;
- duplicate Content-Length;
- invalid/negative Content-Length;
- headers above configured aggregate limit;
- body length above max_request_bytes.

This makes body-resource admission deterministic before request payload parsing.

## 24. Standard HTTP logging

BaseHTTPRequestHandler.log_message is disabled.

Reason:
the standard handler logs the raw request line, which may contain query-string
secrets.

PX4 emits only its own fixed audit schema.

## 24A. Packaged daemon entrypoint

Installed console entrypoint:

    sigma-gateway

Authority:

    sigma.gateway.cli:main

Default bind:

    127.0.0.1:8080

A non-loopback bind requires:

    --allow-nonlocal-bind

This flag acknowledges exposure; it is not authentication.

The CLI exposes resource limits but deliberately accepts no bearer tokens,
passwords, private keys or TLS secrets.

The compatibility development runner delegates to the same implementation:

    scripts/product_closure/px4_daemon.py

## 25. Authentication / TLS boundary

PX4 V1 does not implement application authentication or TLS key management.

Recommended deployments put PX4 behind:
- local Unix/network boundary;
- TLS reverse proxy;
- Kubernetes ingress/admission service;
- service mesh;
- CI worker boundary.

Those layers may authenticate the caller.

Credentials must not be translated into:
- ArtifactId;
- PolicyId;
- ReceiptId;
- verifier_build;
- audit decision fields.

## 26. No PX3 coupling requirement

PX4 can run over one PX1 local store without PX3.

A deployment may use PX3 to populate PX1 before verification, but remote
transport is not implicitly invoked by verification endpoints.

This preserves failure attribution:
- remote retrieval is PX3;
- verification is PX4.

## 27. No PX5 coupling requirement

PX4 consumes canonical VerificationPolicyV1.

It does not parse human YAML/JSON policy DSL.

PX5 will compile user-facing policy documents into canonical VerificationPolicyV1
before they reach PX4.

## 28. No new cryptographic claim

PX4 adds:
- no hash;
- no signature scheme;
- no aggregate security width;
- no new proof semantics.

Its core closure obligation is equivalence with the local library.
