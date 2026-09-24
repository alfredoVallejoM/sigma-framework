# PX4 — Verification Gateway / Daemon Implementation Evidence

Status: **ACTIVE — IMPLEMENTED, EXECUTED CLOSURE GATE PENDING**  
Date: 2026-09-24  
Branch: campaign/sigma-dual-integrity-product-closure

## 1. Scope

Runtime:

    sigma/gateway/runtime.py
    sigma/gateway/protocol.py
    sigma/gateway/service.py
    sigma/gateway/http.py
    sigma/gateway/__init__.py

Local runner:

    scripts/product_closure/px4_daemon.py

Validation:

    tests/unit/test_gateway_px4.py
    scripts/product_closure/px4_gate.py
    scripts/product_closure/px4_benchmark.py

Contracts:

    PX4-GATEWAY-CONTRACT.md
    PX4-HTTP-PROTOCOL.md
    PX4-COMPLEXITY-AUDIT.md

No GitHub Actions workflow was added or enabled.

## 2. Implemented endpoints

    POST /v1/artifacts/verify
    POST /v1/proofs/inclusion/verify
    POST /v1/proofs/range/verify
    POST /v1/policies/evaluate
    POST /v1/batch/verify
    GET  /v1/artifacts/{id}
    GET  /v1/artifacts/{id}/parents
    GET  /health
    GET  /version

## 3. No verifier fork

Artifact:
- delegates SA1 verify_artifact_v1.

Policy:
- delegates SV2 verify_with_policy_v1.

Receipt:
- delegates SV3 receipt_from_decision_v1.

Batch:
- delegates SV3 verify_batch_item_v1 and canonical result records.

Proofs:
- delegate Tree V1 parser/verifiers.

This is the central PX4 design choice.

## 4. Binary source-bearing protocol

Implemented endpoint-specific V1 magic/media types.

Source bytes are the final field.

Artifact/policy metadata is available before source.

The service can therefore perform actual local preflight with source=None before
source buffering/hashing.

## 5. Cheap artifact preflight

Flow:

    parse request header
    read bounded artifact/policy/capabilities
    verify_artifact_v1(None,...)

If result policy code is not SOURCE_REQUIRED:
- serialize that exact result;
- do not spool/read source;
- HTTP closes connection.

Unit and gate campaigns inspect audit bytes_in and require it to remain below the
full request size for policy-short-circuit cases.

## 6. Cheap policy preflight

Equivalent flow:

    verify_with_policy_v1(..., source=None)

Source is only spooled when decision code is SOURCE_REQUIRED.

Malformed/unsupported/terminal policy decisions therefore do not automatically
trigger expensive message evaluation.

## 7. Length-only policy rejection

When declared source length exceeds VerificationPolicy max_input_bytes, PX4 can
pass a preflight-only CanonicalSource exposing only byte_length.

The existing local verifier produces the canonical INPUT_TOO_LARGE result without
source iteration.

The preflight source raises if code accidentally attempts byte iteration.

This preserves decision parity while avoiding discarded-body hashing.

## 8. Framing correction from adversarial review

Initial source framing allowed an early terminal policy result before proving the
declared source segment matched Content-Length.

Finding:
a request could claim source_length inconsistent with actual remaining request
bytes and still get a terminal verification response.

Resolution:
single-source metadata parsers now require:

    source_length == reader.remaining

before verifier preflight result can be returned.

Batch items require source segment length <= remaining stream and consume/discard
the exact segment before parsing the next item.

## 9. Request body bounds

GatewayBodyReaderV1 checks Content-Length against max_request_bytes before any
stream.read.

The unit/gate BombStream raises if read; oversize requests must produce 413
without invoking it.

Metadata, proof values, source and batch totals have separate limits.

## 10. Spool

IncrementalSpoolSource is reused rather than creating a new buffering system.

CancellableSourceV1 decorates the finalized replayable spool.

This gives:
- bounded memory threshold;
- disk rollover;
- exact replay;
- cancellation checks during existing verifier source iteration.

## 11. Cancellation

Implemented:
- explicit GatewayCancellationTokenV1.cancel;
- client body read disconnect -> cancellation;
- source chunk checks;
- batch item checks;
- proof pre/post checks.

Cancellation returns stable gateway code:

    cancelled

and cannot modify PX1 artifacts.

Concurrent unit/gate cases pair a cancelled request with a valid request and
require the valid request to remain accepted.

## 12. Timeouts

Monotonic deadline is stored in the cancellation token.

Timeout code:

    timeout

Gate/unit use deterministic fake clocks to force timeout without sleeping.

The timeout is request-local.

## 13. Concurrency

GatewayServiceV1 uses non-blocking BoundedSemaphore.

Overflow:

    503 busy

before body read.

Busy rejection itself is audited.

Semaphore release occurs before audit sink I/O after a completed request.

This remediation came from adversarial review: a slow audit sink must not consume
verification admission capacity.

## 14. Structured audit

Implemented sinks:
- NullGatewayAuditSinkV1;
- MemoryGatewayAuditSinkV1;
- JsonLinesGatewayAuditSinkV1.

Fixed record contains only safe structural fields.

No raw headers/body/query/exception messages.

## 15. Audit path redaction remediation

Initial review found:
- query-bearing rejected requests could bypass normal audit;
- raw path could contain a query secret.

Resolution:
- query rejection occurs inside audited dispatch;
- endpoint is normalized independently of request text;
- known artifact paths become placeholders;
- unknown path becomes <unmatched>.

HTTP tests send explicit query, Authorization and Cookie secrets and require none
to appear in serialized audit.

## 16. Credential-independent receipts

HTTP tests send the exact same policy request under different:
- Authorization;
- Cookie.

Required:

    HTTP response body A
      ==
    HTTP response body B
      ==
    local decision + local receipt serialization.

Thus transport credentials demonstrably cannot enter receipt bytes.

## 17. HTTP logger disabled

BaseHTTPRequestHandler default log_message is overridden to no-op.

PX4 therefore avoids the standard raw request-line access log.

Only GatewayAuditRecordV1 is emitted.

## 18. Request-smuggling hardening

HTTP V1 rejects:
- any Transfer-Encoding;
- duplicate Content-Length;
- invalid Content-Length;
- negative Content-Length.

A raw-socket unit test sends two Content-Length headers and requires HTTP 400.

## 19. Expect: 100-continue

The handler evaluates:
- header aggregate;
- Content-Length syntax;
- max_request_bytes

before sending 100 Continue.

This prevents an admitted oversize body from being requested from a cooperative
client.

## 20. Header bound

Aggregate parsed HTTP headers:

    <= max_header_bytes

Default:

    64 KiB

Header values are inspected only for transport admission and Content-Type.

They are not copied to audit/receipt.

## 21. Response connection policy

Every response sends:

    Connection: close

This is essential because cheap preflight may intentionally leave declared source
body unread.

V1 chooses simple correct framing over keep-alive complexity.

## 22. Canonical GET parents

Adversarial concern:
using PX1 artifact_parents directly would expose mutable acceleration metadata as
a public lineage authority.

Resolution:
GET parents loads canonical artifact through PX1 and returns identity-bound parent
tuple.

## 23. Error schema

All PX4-controlled errors use:

    sigma-gateway-error-v1

No traceback or raw exception body.

Repeated malformed gate inputs require identical status/body.

## 24. Batch memory refinement

PX4 does not parse all item source bodies before verification.

Items are handled sequentially.

Terminal preflight item:
- source is discarded in bounded reads;
- no spool/hash.

SOURCE_REQUIRED item:
- one spool;
- verify;
- close.

This prevents sum of all batch sources from becoming simultaneous memory/disk
working set.

## 25. Batch response prebudget remediation

Review found:
max_response_bytes checked only after full batch verification could allow compute
amplification followed by a response-limit error.

Resolution:
batch count must also satisfy conservative 16 KiB/item response budget before
verification begins.

Actual final result is checked again.

## 26. Proof memory boundary

RangeProof local verifier accepts bytes, not CanonicalSource.

PX4 therefore does not pretend this endpoint is fully streaming.

It enforces max_proof_value_bytes before reading the disclosed range bytes.

A future streaming Tree proof verifier can be adopted additively.

## 27. Daemon runner

Prepared:

    python scripts/product_closure/px4_daemon.py --store <path>

Options expose only operational non-secret parameters:
- host;
- port;
- source/request limits;
- concurrency;
- timeout;
- optional audit JSONL path.

No password/token flags are provided.

## 28. Authentication/TLS

Not implemented inside PX4 V1.

Reason:
putting credentials into this layer creates pressure to log or bind them to
receipts.

Deployment auth/TLS belongs to outer infrastructure.

PX4 tests nevertheless prove incoming HTTP credentials are ignored by verifier,
receipt and audit schemas.

## 29. Benchmark harness

Prepared:

    scripts/product_closure/px4_benchmark.py

Compares:
- direct local library;
- in-process GatewayServiceV1;
- localhost HTTP.

No values have been executed/frozen.

## 30. Gate campaign

Prepared minimums:

    artifact/local parity       300
    policy+receipt parity       300
    batch wire parity           100
    proof cases                 300
    cheap reject cases          200
    concurrency cancel/timeout  100
    deterministic error cases   100
    localhost HTTP cases         40

Additional HTTP credential receipt test is structural and exact.

## 31. Obligation mapping

### PX4-O01 — gateway decisions/receipts equal local API

Implemented:
- artifact JSON exact projection;
- policy decision + receipt exact differential;
- batch binary exact differential;
- proof bool differential;
- HTTP vs in-process/local differential.

Status: IMPLEMENTED / GATE PENDING.

### PX4-O02 — limits reject before expensive hashing/buffering

Implemented:
- outer Content-Length gate;
- metadata/source/proof/batch limits;
- local source=None preflight;
- BombStream tests;
- audit bytes_in evidence.

Status: IMPLEMENTED / GATE PENDING.

### PX4-O03 — cancellation/timeouts isolate requests

Implemented:
- request-local token;
- source decorator;
- bounded semaphore;
- concurrent cancelled + healthy differential;
- fake-clock timeout;
- no mutable verification state.

Status: IMPLEMENTED / GATE PENDING.

### PX4-O04 — no secrets/raw credentials in receipts/logs

Implemented:
- no raw headers in service API;
- normalized audit route;
- disabled stdlib access log;
- fixed error strings;
- different HTTP credentials -> identical receipt bytes;
- query/header secret negative tests.

Status: IMPLEMENTED / GATE PENDING.

## 32. Adversarial findings resolved

### AR-PX4-01 — source JSON/base64 would force full buffering

Resolution:
binary metadata-first request framing.

### AR-PX4-02 — policy logic duplicated at gateway

Resolution:
call local verifier with source=None for preflight.

### AR-PX4-03 — early policy result could accept inconsistent source framing

Resolution:
source_length exact remainder rule.

### AR-PX4-04 — raw query/path could leak through audit

Resolution:
fixed normalized endpoint labels.

### AR-PX4-05 — default http.server logging leaks raw request line

Resolution:
log_message disabled.

### AR-PX4-06 — duplicate Content-Length / chunked ambiguity

Resolution:
both rejected in HTTP V1.

### AR-PX4-07 — slow audit sink held concurrency slot

Resolution:
release semaphore before sink emit.

### AR-PX4-08 — cancellation swallowed by SV3 batch error projection

Resolution:
token.check immediately after verify_batch_item_v1; a cancelled/deadline token
re-raises at request level.

### AR-PX4-09 — batch retained all source spools

Resolution:
pointwise sequential parse/verify/close.

### AR-PX4-10 — response size discovered only after batch compute

Resolution:
prebudget by item count + final exact response check.

### AR-PX4-11 — mutable parent SQL index exposed publicly

Resolution:
GET parents uses canonical artifact bytes.

### AR-PX4-12 — transport credentials could contaminate receipts

Resolution:
headers never passed to service semantics; byte-exact two-credential receipt test.

### AR-PX4-13 — header limit applied only after stdlib parse

Finding:
a post-parse aggregate limit did not itself bound header materialization.

Resolution:
GatewayHTTPRequestHandlerV1 wraps rfile during parse_request with a bounded
readline reader and rejects at max_header_bytes while parsing.

Status: RESOLVED IN IMPLEMENTATION.

### AR-PX4-14 — blocking body read could outlive cooperative deadline

Finding:
a stalled socket read can block between cancellation-token checks.

Resolution:
the HTTP socket timeout is set from request_timeout_seconds and read TimeoutError
maps to GatewayTimeoutError.

Status: RESOLVED IN IMPLEMENTATION.

### AR-PX4-15 — outer transport rejection was outside structured audit

Finding:
header/length/method/parser errors can occur before GatewayServiceV1.handle.

Resolution:
audit_transport_rejection emits the same safe GatewayAuditRecordV1 schema for
those failures; stdlib send_error is overridden to canonical JSON.

Status: RESOLVED IN IMPLEMENTATION.

### AR-PX4-16 — daemon existed only as an internal script

Finding:
PX4 was usable as library/runner but not as an installed product entrypoint.

Resolution:
sigma.gateway.cli provides the packaged sigma-gateway command. Default bind is
loopback; non-loopback requires --allow-nonlocal-bind.

Status: RESOLVED IN IMPLEMENTATION.

### AR-PX4-17 — ThreadingHTTPServer could spawn unbounded pre-service threads

Finding:
the verification semaphore is acquired inside GatewayServiceV1, after the HTTP
server has already created a handler thread. Clients stalled during request
parsing could therefore consume threads outside max_concurrent_requests.

Resolution:
GatewayThreadingHTTPServerV1 now owns a second BoundedSemaphore controlled by
max_http_connections. Exhaustion returns canonical 503 before thread creation.
The gate/unit suite reserves the only slot and requires a new connection to be
rejected without a handler thread.

Status: RESOLVED IN IMPLEMENTATION.

### AR-PX4-18 — proof value buffered before proof validation

Finding:
proof endpoints initially read the complete disclosed leaf/range value before
parsing the proof.

Resolution:
staged proof-head readers parse canonical proof metadata first. Malformed proofs
and valid proofs with incompatible declared value length return before disclosed
value read. Unit and gate use a prefix-only stream that raises if value bytes are
requested.

Status: RESOLVED IN IMPLEMENTATION.

### AR-PX4-19 — arbitrary HTTP method token could enter audit

Finding:
the method field was copied from the request and therefore remained one
user-controlled string in an otherwise fixed audit schema.

Resolution:
audit methods are normalized to GET/POST/HEAD/PUT/DELETE/PATCH/OPTIONS or
<other>. A secret-like custom method is required not to appear in serialized
audit.

Status: RESOLVED IN IMPLEMENTATION.

### AR-PX4-20 — per-request spool bounds allowed large aggregate disk reservation

Finding:
max_source_bytes and max_concurrent_requests bounded each request but could still
reserve their product in temporary storage.

Resolution:
GatewayServiceV1 now has a global max_total_spool_bytes budget (4 GiB default).
Declared source length is reserved before source read; exhaustion returns
503/busy. Reservation release is protected by nested finally. CLI exposes both
the global budget and --spool-temp-dir.

Status: RESOLVED IN IMPLEMENTATION.

## 33. Current disposition

Implementation for planned PX4 V1: COMPLETE.

Adversarial design review: PASS after remediation.

Unit tests: implemented, not executed here.

Closure gate: implemented, not executed here.

Benchmark: implemented, not executed here.

Stage:

    PX4 ACTIVE

PX4-O01..O04 remain PLANNED pending real local gate/quality execution.
