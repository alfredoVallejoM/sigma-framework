# PX4 — Resource Complexity Audit

Status: **IMPLEMENTATION CONTRACT FROZEN; EMPIRICAL LEDGER PENDING**  
Date: 2026-09-24

## 1. Parameters

    B    source body bytes for one verification
    M    request metadata bytes
    A_w  Artifact V1 wire bytes
    E_w  policy/evidence bytes
    P_w  proof wire bytes
    V    disclosed proof value bytes
    I    batch item count
    B_i  source bytes of item i
    B_T  sum_i B_i
    Q    concurrent admitted verification requests
    Q_h  concurrent HTTP connection/handler slots
    R_o  response bytes
    C    streaming read chunk bytes
    S_m  memory spool threshold
    T    configured timeout
    H    parsed HTTP header bytes

## 2. Outer HTTP admission

Header scan:

    O(H)

with:

    H <= max_header_bytes

Content-Length comparison:

    O(1)

No body is read when:

    Content-Length > max_request_bytes

This is the cheapest gateway rejection path.

## 3. Request framing

Fixed header parsing:

    O(1)

Metadata read:

    O(M)

with:

    M <= max_metadata_bytes

No base64 inflation is introduced for source bytes.

## 4. Policy preflight

Artifact verification runs:

    verify_artifact_v1(None,...)

before source spool.

Policy evaluation runs:

    verify_with_policy_v1(..., source=None)

before source spool.

These operations parse/check already-bounded metadata and policy.

If they return a terminal decision other than SOURCE_REQUIRED:

    body hashing cost = 0
    source spool cost = 0

HTTP may leave source bytes unread and closes the connection.

## 5. Source spool

When needed:

    network/body read O(B)
    temporary storage O(B)
    in-memory spool <= S_m
    incremental write buffer O(C)

Defaults:

    S_m = 1 MiB
    C   = 1 MiB

Larger sources roll to temporary storage.

## 6. Full verification

PX4 does not change local verifier complexity.

TREE:

    O(B)

Trajectory:

    O(cost existing evaluate_v3(B, rounds))

DUAL:

    O(Tree(B) + SigmaV3(B))

because SA1 intentionally verifies both independent sides.

A replayable spooled source can therefore be read more than once.

Gateway auxiliary memory remains bounded independently of those existing
algorithmic internals.

## 7. Policy/evidence endpoint

Metadata/evidence parse:

    O(E_w)

Source path if required:

    O(B) spool
    + existing SV2 verifier cost

Receipt construction:

    O(receipt size)

Receipt size is small and independently bounded by SV3 fields/evidence hashes.

## 8. Inclusion proof endpoint

Request memory:

    O(P_w + leaf bytes)

Leaf is bounded by proof geometry and gateway proof-value bound.

Verification:

    existing verify_inclusion complexity
    typically O(log N) witness composition.

PX4 adds O(P_w) parsing only.

## 9. Range proof endpoint

Current local verify_range consumes disclosed value bytes as bytes.

Thus gateway V1 bounds:

    V <= max_proof_value_bytes

Memory:

    O(P_w + V)

Verification complexity remains existing Tree proof complexity.

PX4 does not claim streaming range verification where the underlying API does not
currently expose it.

## 10. Batch streaming

PX4 does not materialize all source bodies before verification.

For each item:
- metadata parsed;
- preflight performed;
- source either discarded, spooled and verified, or absent;
- source closed;
- result retained.

Peak source spool:

    O(max_i min(B_i, S_m) memory)
    + O(max_i B_i temporary storage)

not:

    O(B_T) simultaneous spool memory.

Result metadata retained:

    O(I * receipt/result size)

with:

    I <= max_batch_items
    B_T <= max_batch_total_source_bytes

## 11. Batch CPU

Sequential V1 gateway batch:

    sum_i verification_cost(item_i)

No hidden ThreadPoolExecutor fan-out is introduced by PX4.

This is a deliberate resource-predictability choice.

SV3 local batch can still use max_workers separately outside the gateway.

## 12. Batch response budget

Before item verification:

    I * 16 KiB <= max_response_bytes

is required by the conservative gateway budget.

Actual BatchVerificationResultV1 is checked again against max_response_bytes.

This avoids compute-amplification into an unreturnable result.

## 13. Concurrency

HTTP connection threads are bounded before handler-thread creation:

    Q_h <= max_http_connections

Default:

    Q_h <= 32

Verification requests are separately bounded:

    Q <= max_concurrent_requests

Default:

    Q <= 16

Neither layer creates an unbounded waiting queue.

HTTP-connection overflow receives canonical 503 before a new handler thread is
created.

Verification overflow receives 503 before body read.

Worst gateway-owned simultaneous spool memory:

    O(Q * S_m)

Default upper envelope:

    ~16 MiB

excluding existing verifier state and Python/runtime overhead.

Temporary disk upper envelope is bounded by admitted request source policies.

## 14. Cancellation

Cancellation state:

    O(1) per request

Source checks:

    O(number of replay chunks)

with one monotonic/event check per chunk.

There is no growing cancellation history.

## 15. Timeouts

Deadline comparison:

    O(1)

per check.

PX4 does not spawn a watchdog thread per request.

The HTTP worker thread itself executes the request.

This keeps thread cardinality tied to actual HTTP concurrency.

## 16. Audit

One fixed audit record per handled request.

Record size:

    O(1)

with bounded strings/hex IDs.

No source/evidence/header copies are stored.

JsonLines sink performs one append per record.

The verification semaphore is released before audit sink I/O.

Therefore slow audit storage does not reduce admission slots, although the
individual worker thread can still spend time writing its record.

## 17. Error response

Canonical error JSON:

    O(1)

No traceback formatting or raw exception serialization.

## 18. HTTP headers

PX4 wraps the header reader while stdlib parsing is in progress.

Raw header bytes consumed by parse_headers are bounded by:

    H <= 64 KiB default

plus at most one detection byte.

Therefore max_header_bytes is enforced during parse rather than only after a
complete parsed header mapping already exists.

The stdlib request-line limit remains an outer transport bound.

## 18A. Blocking socket read deadline

The HTTP connection socket timeout is set to request_timeout_seconds before
request parsing/body consumption.

A stalled blocking body read therefore cannot hold a request thread indefinitely.

GatewayBodyReaderV1 maps read TimeoutError to GatewayTimeoutError.

This complements cooperative cancellation checks; PX4 still does not terminate
Python threads asynchronously.

## 18B. Transport-rejection audit

Header/length/method errors can occur before GatewayServiceV1.handle.

Those failures emit the same fixed safe GatewayAuditRecordV1 schema through
audit_transport_rejection.

Audit remains O(1) bounded metadata per rejected request.

## 19. Stored artifact GET

PX1:

    metadata lookup
    + Artifact wire read/parse O(A_w)

Gateway:

    response write O(A_w)

Artifact codec already limits Artifact record size.

## 20. Parent GET

PX4 intentionally reparses canonical artifact bytes instead of using only SQL
edge metadata.

Cost:

    O(A_w + d_p)

where d_p is parent count.

This spends a small extra parse to preserve PX2 authority.

## 21. Local HTTP overhead benchmark

Prepared harness:

    scripts/product_closure/px4_benchmark.py

Measures independently:
- direct local verify_artifact_v1;
- GatewayServiceV1 in-process;
- localhost HTTP daemon.

Prepared sizes:

    0
    1 KiB
    64 KiB
    1 MiB

No performance numbers are frozen until execution.

## 22. Resource-complexity verdict

PX4 adds no combinatorial enumeration.

Dominant costs are:
- linear body movement/spool;
- the existing verifier;
- bounded per-request metadata;
- bounded concurrency;
- sequential batch aggregation.

The service specifically avoids:
- all-body JSON/base64 copies;
- unbounded batch parallelism;
- unbounded connection queues inside GatewayServiceV1;
- transitive lineage computation;
- remote bucket/registry scans;
- receipt histories;
- all-request body logging.

## 23. Empirical evidence required later

Freeze only after local benchmark/gate execution:
- local vs in-process overhead;
- localhost HTTP overhead;
- spool rollover at 1 MiB;
- 1/4/16 concurrent requests;
- accepted vs policy-short-circuit requests;
- cancellation latency;
- timeout latency;
- JSONL sink on/off;
- batch sizes 1/16/64/256;
- proof value near max_proof_value_bytes;
- peak RSS;
- temporary disk use.

Those are empirical product characteristics, not correctness claims.
