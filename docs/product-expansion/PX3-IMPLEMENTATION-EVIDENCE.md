# PX3 — Remote Storage Backends Implementation Evidence

Status: **ACTIVE — IMPLEMENTED, EXECUTED CLOSURE GATE PENDING**  
Date: 2026-09-24  
Branch: campaign/sigma-dual-integrity-product-closure

## 1. Scope implemented

Core:

    sigma/artifact/remote.py

HTTP / OCI:

    sigma/artifact/remote_http.py

S3-compatible:

    sigma/artifact/remote_s3.py

Public exports:

    sigma.artifact

Tests:

    tests/unit/test_remote_store_px3.py

Closure infrastructure:

    scripts/product_closure/px3_fixtures.py
    scripts/product_closure/px3_gate.py

Detailed backend contract:

    PX3-BACKEND-CONTRACT.md

Resource audit:

    PX3-COMPLEXITY-AUDIT.md

No GitHub Actions workflow was added or enabled.

## 2. Product result

PX3 now provides one high-level interface:

    RemoteArtifactRepositoryV1

over:

    LocalArtifactStoreV1
      <- verified pull/push ->
    RemoteBlobBackendV1

Concrete backends:
- S3CompatibleBackendV1;
- OciRegistryBackendV1;
- HttpReadOnlyMirrorBackendV1.

## 3. Canonical ArtifactId mapping

Remote key:

    artifacts/v1/<ArtifactId hex>.sigart

The remote value must equal the exact canonical no-audit Artifact V1 wire stored
by PX1.

Remote key metadata never participates in ArtifactId.

## 4. Push

push_artifact:
1. fetches bytes from PX1;
2. validates canonical base Artifact envelope;
3. checks max_object_bytes;
4. computes transport wire SHA-256;
5. HEADs deterministic remote key;
6. if present, downloads/verifies exact bytes and returns idempotent reuse;
7. otherwise starts/resumes upload;
8. checkpoints each accepted offset when configured;
9. completes provider upload;
10. post-verifies full remote bytes by default;
11. removes checkpoint only after success.

A remote key containing different bytes never gets silently overwritten by the
high-level repository.

## 5. Pull

pull_artifact:
1. uses a valid existing PX1 object immediately;
2. optionally tries the verified cache;
3. HEADs remote key;
4. rejects oversize object before read_range;
5. reconciles download checkpoint/partial state;
6. performs bounded ranged reads;
7. reconstructs complete local partial file;
8. checks provider digest hint if available;
9. parses canonical Artifact V1;
10. requires requested ArtifactId;
11. publishes through PX1 only after complete validation;
12. optionally populates verified cache.

## 6. Retry

RemoteRetryableError only.

Default maximum:

    4 retries per remote operation

Exponential backoff exists as an explicit policy parameter.

Default backoff is zero in the library contract so test/gate execution is
deterministic and callers can choose operational delay.

## 7. Upload resume

RemoteUploadSessionV1 binds:
- backend fingerprint;
- key;
- total size;
- expected wire SHA-256;
- provider token;
- accepted offset;
- provider-effective chunk size;
- bounded opaque state.

Provider token repr is suppressed.

RemoteUploadCheckpointV1 serializes this state canonically.

## 8. Session expiry

RemoteSessionExpiredError is not treated as an ordinary transient retry.

When a checkpoint references a dead provider session:
- checkpoint is discarded;
- a new upload session is created;
- upload restarts from offset zero.

This avoids repeatedly querying a permanently dead upload ID.

## 9. Provider-ahead resume

Gate/unit failure injection covers:

    chunk accepted remotely
    process dies before checkpoint update

On next invocation:
- local checkpoint may say offset b;
- provider may report b+C;
- backend reconciles operational offset;
- upload continues from provider-confirmed position;
- final remote wire is still fully verified.

## 10. Download resume

Download checkpoint + partial file must agree exactly.

The checkpoint binds remote revision/digest only as mutation hints.

If hints change:
- partial is discarded;
- download restarts.

If a resumed server refuses Range:
- partial state is discarded;
- a full offset-zero download is attempted.

## 11. HTTP mirror

Implemented:
- deterministic path mapping;
- HEAD size/revision;
- Range GET;
- Content-Range validation;
- full-body fallback only at offset zero;
- read-only failures for all upload operations;
- credential-independent backend fingerprint.

Adversarial refinement:
the initial design considered GET range 0-0 as fallback metadata probe if HEAD
was unavailable.

Rejected because a server can ignore Range and return a full body before size
policy is applied.

Current V1 requires HEAD.

## 12. Safe redirects

UrllibHttpTransportV1 strips Authorization and Proxy-Authorization when an HTTP
redirect crosses origin.

No credential is copied into ArtifactId, cache key or backend fingerprint.

## 13. S3-compatible

Implemented:
- S3ClientV1 abstraction;
- S3CompatibleBackendV1;
- Boto3S3ClientAdapterV1 without mandatory boto3 dependency;
- multipart initiation;
- part SHA-256 checksums;
- ListParts resume;
- contiguous part validation;
- repeated part-number idempotency;
- completion;
- abort;
- ranged GET;
- custom metadata for transport wire SHA-256.

Adversarial refinement:
resume originally validated a short part as non-final only when another part
already followed it in the ListParts result.

That is insufficient for an incomplete upload.

Current implementation evaluates cumulative offset: any part that does not end
the complete object must equal the session chunk size.

## 14. S3 checksum claim boundary

PX3 does not equate:
- ETag;
- multipart ChecksumSHA256;
- ArtifactId;
- full wire SHA-256.

SHA-256 multipart checksums are used per part.

Default post-upload read validates complete canonical wire.

## 15. OCI Distribution

Implemented:
- resumable POST/PATCH/PUT blob uploads;
- GET session offset;
- 416 retry reconciliation;
- digest-bound blob completion;
- byte-range blob pulls;
- Docker-Content-Digest consistency check;
- portable OCI image manifest storage locator;
- empty OCI config blob;
- deterministic key-derived tag;
- credential-independent backend fingerprint.

The locator manifest is not IX0.

IX0 can later add:
- OCI subjects;
- referrers;
- semantic media-type integrations;
- ORAS workflows.

PX3 only solves reliable byte storage/retrieval.

## 16. Cache

VerifiedRemoteArtifactCacheV1:
- keyed by ArtifactId;
- validates every read;
- corrupt cache becomes miss;
- atomic write;
- explicit evict.

Unit/gate semantics require:

    with cache
      ==
    after cache eviction + remote refetch

for accepted canonical bytes.

## 17. Resource gate

RemoteTransferPolicyV1 includes:
- chunk_size;
- max_object_bytes;
- max_retries;
- retry_backoff_seconds;
- fsync_each_chunk;
- verify_after_upload.

Unit negative coverage verifies that an oversize HEAD fails before the backend
body read is invoked.

## 18. Canonical checkpoints

Both upload and download checkpoint parsers require exact canonical semantic
round-trip.

This catches:
- uppercase hex alternatives;
- reordering inside opaque session state;
- non-canonical representation variants.

## 19. Independent Artifact wire differential

PX3 gate does not use production Artifact encoding as its sole oracle.

Each generated TREE artifact is independently reconstructed with:

    reference/artifact_v1.py

The local runtime wire must equal the independent reference wire before the
remote differential case is admitted.

Then:

    local PX1 wire
      ==
    remote backend wire
      ==
    destination PX1 wire
      ==
    independent reference Artifact V1 wire

## 20. Closure gate

Minimum configured campaigns:

    remote/local roundtrips       300
    retry/resume cases            200
    remote corruption cases       200
    verified-cache cases          100
    HTTP backend cases             80
    S3 backend cases               80
    OCI backend cases              80

The retry/resume family rotates:
- retryable accepted-response-loss;
- fatal interruption with server ahead of checkpoint;
- expired session restart;
- interrupted download + resume.

Corruption cases mutate remote artifact wire and require rejection before PX1
publication.

Concrete backend cases require byte-identical destination PX1 objects.

## 21. Obligation mapping

### PX3-O01 — local/remote canonical byte identity

Implemented by:
- deterministic ArtifactId key;
- independent Artifact V1 oracle;
- full remote/local byte differential;
- concrete S3/HTTP/OCI fixtures.

Status: IMPLEMENTED / GATE PENDING.

### PX3-O02 — retry/duplicate writes idempotent

Implemented by:
- bounded retry controller;
- duplicate remote key full verification/reuse;
- S3 repeated part number;
- OCI 416 offset reconciliation;
- accepted-response-loss fault model.

Status: IMPLEMENTED / GATE PENDING.

### PX3-O03 — resumed transfers verify before publication

Implemented by:
- upload wire digest/session binding;
- provider completion integrity;
- default full post-upload verification;
- complete canonical validation before PX1 pull publication;
- partial-file checkpoint protocol.

Status: IMPLEMENTED / GATE PENDING.

### PX3-O04 — credentials/cache/metadata do not alter ArtifactId

Implemented by:
- backend fingerprints exclude credential material;
- provider metadata never enters Artifact construction;
- cache is validated/disposable;
- identity tests with alternate HTTP/OCI credentials and alternate S3 clients.

Status: IMPLEMENTED / GATE PENDING.

## 22. Adversarial findings resolved

### AR-PX3-01 — expired sessions classified as generic retry

Resolution:
session expiry restarts upload instead of retrying dead token.

### AR-PX3-02 — provider token exposed in dataclass repr

Resolution:
upload token is repr=False.

### AR-PX3-03 — non-canonical checkpoint semantic variants accepted

Resolution:
parse must reserialize byte-exactly.

### AR-PX3-04 — HTTP metadata GET can bypass preflight

Resolution:
HTTP mirror requires HEAD.

### AR-PX3-05 — ranged server can return beyond requested end

Resolution:
HTTP/OCI 206 end must be <= requested end.

### AR-PX3-06 — S3 range adapter could infer total length from partial ContentLength

Resolution:
ranged GetObject requires ContentRange total.

### AR-PX3-07 — S3 resume accepted short last-listed part even when upload incomplete

Resolution:
cumulative offset determines whether a part is genuinely final.

### AR-PX3-08 — multipart ETag mistaken for integrity identity

Resolution:
ETag is revision only; full canonical remote wire is post-verified.

### AR-PX3-09 — credential material contaminates resume identity

Resolution:
fingerprint includes only public endpoint/bucket/repository/prefix scope.

### AR-PX3-10 — unbounded provider metadata before payload policy

Finding:
OCI locator manifests and S3 ListParts are control-plane inputs and therefore
could consume resources independently of artifact body size.

Resolution:
- OCI locator manifests are capped at 1 MiB before JSON parsing;
- boto3 ListParts accumulation is capped at 10,000 parts.

Status: RESOLVED IN IMPLEMENTATION.

## 23. Security / trust boundary

PX3 assumes providers implement their documented HTTP/S3/OCI protocol semantics
well enough to transfer bytes.

It does not trust them to establish Sigma identity.

A malicious remote can:
- delete;
- replay;
- corrupt;
- truncate;
- change metadata;
- lie about ETag/revision.

PX3 acceptance still requires canonical ArtifactId validation.

PX3 does not itself solve:
- freshness;
- rollback;
- transparency;
- signatures;
- provider authorization policy;
- multi-region consensus.

Those belong to later interop/security layers.

## 24. Current disposition

Implementation: complete for planned PX3 V1 scope.

Adversarial design review: PASS after remediation.

Independent Artifact wire oracle: integrated.

Concrete S3/HTTP/OCI provider models: implemented.

Unit coverage: implemented, execution pending.

Closure gate: implemented, execution pending.

Stage:

    PX3 ACTIVE

PX3-O01..O04 remain PLANNED until the real gate/quality run is executed.
