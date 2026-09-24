# IX0 — OCI / ORAS Adapter — Resource Complexity Audit

Status: SOURCE AUDIT / EXECUTION PENDING  
Branch: `campaign/ix0-oci-oras-adapter`  
Date: 2026-09-24

## 1. Parameters

Use the following resource parameters throughout IX0:

    B = canonical SigmaArtifactV1 payload bytes
    M = single OCI manifest bytes
    Q = one referrers response/index page bytes
    R = unique referrer descriptors accumulated
    P = number of referrers pages traversed
    A = annotations normalized in one descriptor/manifest
    T = retry attempts after the first request

Network byte cost is counted separately from CPU complexity.

## 2. Default hard limits

`OciRegistryLimitsV1` defaults:

    max_blob_bytes       = 64 MiB
    max_manifest_bytes   = 1 MiB
    max_referrers_bytes  = 4 MiB per page
    max_referrers        = 10,000 unique descriptors
    max_pages            = 32
    max_retries          = 4
    retry_backoff        = 50 ms * attempt

OCI annotation limits inherited from IX0-A:

    max annotations      = 128
    max key bytes        = 256
    max value bytes      = 4096

These are implementation ceilings, not OCI protocol maxima.

## 3. Transport memory bound

The default network transport is `BoundedUrllibOciTransportV1`.

It reads at most:

    max(
      max_blob_bytes,
      max_manifest_bytes,
      max_referrers_bytes
    ) + 1

bytes from any individual HTTP response before rejecting.

Therefore default single-response buffering is bounded by approximately 64 MiB
plus protocol/object overhead.

A caller-supplied custom transport is outside this enforcement mechanism and is
required by contract to provide an equivalent or stricter response bound.

## 4. Referrer construction

For a canonical Sigma artifact:

    build_sigma_artifact_referrer_v1

Cost:

    time   O(B + A log A)
    memory O(B + M + A)

The current Python artifact codec already materializes the complete canonical
wire, so IX0 does not claim a zero-copy or streaming build.

## 5. Blob publication

`put_blob(data)` performs:

1. SHA-256 over B;
2. HEAD by digest;
3. if absent, POST upload-session creation;
4. PUT exact bytes with digest completion;
5. HEAD verification.

CPU:

    O(B)

Network:
- reused object: O(1) body bytes, two metadata operations at most;
- new object: O(B) upload plus metadata requests.

Memory:

    O(B)

The data argument is already materialized. The method rejects B above the configured
limit before starting an upload session.

## 6. Manifest publication

`put_manifest` hashes and sends the exact manifest bytes.

CPU:

    O(M)

Network:

    O(M)

Memory:

    O(M)

The size limit is checked before the PUT.

## 7. Native referrers discovery

For P pages and R unique descriptors:

    time   O(sum(Q_p) + R * A)
    memory O(R * descriptor_size + max(Q_p))

Admission is fail-closed when:

    P > max_pages
    R > max_referrers
    Q_p > max_referrers_bytes

Descriptors are deduplicated by OCI digest. If the same digest is returned with
different descriptor metadata, IX0 rejects the response as contradictory rather
than selecting one interpretation.

## 8. Referrers-tag fallback

The fallback index is loaded as one bounded OCI image index.

Read:

    time   O(Q + R * A)
    memory O(Q + R * descriptor_size)

Update:

    time   O(Q + R log R)
    memory O(Q + R * descriptor_size)

The new descriptor list is canonically sorted before local serialization.

If an existing fallback index supplies an ETag, IX0 uses `If-Match` on update.
A 412 response is classified as a concurrency conflict.

Without an ETag the OCI protocol does not provide a universal atomic compare-and-
swap primitive for this tag. IX0 therefore does not claim race-free fallback
updates on such registries; native referrers API registries are preferred for
concurrent writers.

## 9. Attach

Ignoring bounded retries:

    artifact wire build/hash        O(B)
    payload upload/reuse            O(B)
    manifest build/push             O(M)
    discovery                       O(sum(Q_p) + R*A)

Overall:

    time   O(B + M + sum(Q_p) + R*A)
    memory O(B + M + R*descriptor_size + max(Q_p))

The empty OCI config is constant-size.

Repeated attachment of the same canonical artifact can reuse both config and
payload blobs because they are addressed by content digest.

## 10. Pull by referrer digest

The referrer manifest is fetched and its requested digest is recomputed before
the payload descriptor is trusted.

Then:

1. descriptor size admission;
2. payload GET;
3. payload digest and exact size verification;
4. canonical SigmaArtifactV1 parse;
5. ArtifactId recomputation;
6. optional expected subject / ArtifactId comparison.

Cost:

    time   O(M + B)
    memory O(M + B)

No registry metadata substitutes for the final Sigma verification.

## 11. Pull by ArtifactId

ArtifactId-driven discovery first scans bounded referrers metadata:

    O(sum(Q_p) + R*A)

It selects only descriptors whose Sigma ArtifactId annotation matches.

Zero matches:
    NotFound

More than one distinct referrer digest claiming the same ArtifactId:
    Conflict

Exactly one:
    normal pull-by-digest cost O(M+B)

IX0 deliberately fails closed on ambiguity.

## 12. Retry amplification

For a request with T allowed retries, worst-case request count is:

    T + 1

With default T = 4:

    <= 5 attempts/request

All retry loops are finite. Retryable statuses are:

    408
    425
    429
    5xx

Transport-level retryable errors follow the same budget.

This does not make every remote operation transactionally idempotent. IX0 relies
on content-addressed blob and manifest publication so repeated successful writes
converge on the same content identity.

## 13. Credential/redirect resource and security boundary

Cross-origin upload locations and redirects never receive:
- Authorization;
- Proxy-Authorization.

The stripping is case-insensitive.

This prevents upload redirection from turning bounded retry logic into credential
exfiltration.

## 14. Complexity regressions to gate

The IX0 gate must fail if future work introduces any of:

1. unbounded referrers pagination;
2. unbounded descriptor accumulation;
3. response reads without a hard body ceiling in the default transport;
4. artifact/blob body acceptance before configured size admission;
5. retry loops without a finite attempt budget;
6. O(R^2) referrer deduplication or query logic;
7. loading arbitrary external registry metadata into ArtifactId;
8. repeated full payload hashing more than a small constant number of times per
   attach/pull path without explicit justification.

## 15. Non-claims

IX0 currently does not claim:

- zero-copy streaming upload;
- zero-copy streaming verification;
- bounded memory below B for Sigma payload verification;
- race-free referrers-tag updates on registries without conditional-write support;
- HA/distributed registry semantics;
- registry authentication challenge/token negotiation beyond caller-supplied
  headers/ORAS-managed credentials;
- performance superiority over ORAS.

Those can be added only with separate contracts and gates.
