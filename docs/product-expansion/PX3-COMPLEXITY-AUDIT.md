# PX3 — Resource Complexity Audit

Status: **IMPLEMENTATION CONTRACT FROZEN; EMPIRICAL LEDGER/GATE PENDING**  
Date: 2026-09-24

## 1. Parameters

    B    canonical remote object bytes
    C    transfer chunk size
    P    number of chunks/parts = ceil(B/C)
    R    retry attempts actually used
    O    remote objects transferred in a workload
    K    verified-cache objects
    B_K  total verified-cache bytes
    B_p  local partial-download bytes
    M    provider metadata bytes
    L    network RTT / provider latency

For Artifact V1 the canonical envelope itself is bounded independently by the
Artifact codec. PX3 nevertheless keeps an explicit max_object_bytes because:
- provider metadata is untrusted;
- future remote object profiles may differ;
- the transport API is generic.

## 2. Push preflight

Local PX1 read + canonical validation:

    time O(B)
    RAM  O(B)

Wire SHA-256:

    time O(B)

No remote upload is started if:

    B > max_object_bytes

## 3. Generic upload

Number of body chunks:

    P = ceil(B / effective_chunk_size)

Network payload:

    O(B)

Control operations:

    O(P + R)

Checkpoint writes:

    O(P)

small JSON files.

The checkpoint does not contain B; it stores O(1) session metadata.

## 4. Upload checkpoint write amplification

With fsynced checkpoint after each accepted chunk:

    checkpoint I/O = O(P * small_checkpoint_size)

This is intentionally conservative for crash recovery.

For Artifact V1, B is normally much smaller than large source data, so the
default correctness-first strategy is acceptable.

If future remote objects become very large, checkpoint batching can be added as
an operational policy without changing ArtifactId or the backend protocol.

## 5. Accepted-but-response-lost retry

A retry of the same chunk can transmit that chunk twice.

Worst bounded network overhead from retry policy:

    O(B + R*C)

for R retryable lost-response events under fixed chunk size.

No retry loop is unbounded:

    attempts per operation <= max_retries + 1

## 6. Resumed upload

If server accepted prefix b:

    remaining body = B - b

The checkpoint itself is O(1).

Provider status reconciliation:
- generic O(1) abstract operation;
- S3 ListParts O(P);
- OCI upload status O(1) response.

## 7. Download preflight

HEAD:

    O(1) control request

Before body allocation/download:

    advertised size <= max_object_bytes

This is a hard resource gate in the high-level repository.

HTTP mirror V1 requires HEAD specifically to preserve this property.

## 8. Ranged download

Body bytes:

    O(B)

Control requests:

    O(P + R)

Partial disk:

    O(B)

Peak in-memory range body:

    O(C)

except a server that ignores Range at offset zero, where PX3 may receive the
already-preflighted full B-byte object.

Final Artifact parser currently requires:

    O(B) RAM

because SigmaArtifactV1.from_bytes consumes the complete envelope.

## 9. Resumed download

If local partial has b validated operational bytes:

    network = O(B - b)

Final validation remains:

    O(B)

because the entire canonical wire must be parsed/recomputed before PX1
publication.

Partial data is never published as an artifact.

## 10. Post-upload verification

Default:

    verify_after_upload = true

This intentionally adds one full remote read:

    extra network O(B)
    extra hash/parse O(B)

Thus correctness-first upload has approximately:

    upload B
    + verification download B
    = O(2B)

body transfer, excluding retries.

This is deliberate.

A future provider profile may skip the full re-read only if it has an evidence
contract strong enough to preserve the exact same acceptance rule. Such an
optimization must never promote ETag or provider metadata into ArtifactId.

## 11. Verified cache

Storage:

    O(B_K)

Lookup:
- filesystem lookup O(1) expected;
- full canonical parse/hash O(B) before use.

Cache is not a trust shortcut.

Eviction:

    O(1) filesystem unlink per object

and cannot require graph recomputation or remote identity changes.

## 12. S3 multipart

Effective part count:

    P <= 10,000

Default part size floor:

    5 MiB

UploadPart body work:

    O(B)

SHA-256 part checksums:

    O(B)

ListParts resume:

    O(P)

Completion descriptor construction:

    O(P)

Memory:
- high-level Artifact wire O(B);
- per-part transient slice O(C);
- part metadata O(P).

The high-level repository currently holds the Artifact V1 wire in memory because
PX1 get_artifact_bytes returns bytes.

## 13. OCI Distribution

Blob upload:

    O(B) body

Chunk control:

    O(P)

Locator manifest:

    O(1) small JSON

Manifest GET is one extra metadata request for head/lookup.

Current read_range resolves the locator manifest before each blob range, so
ranged OCI pull control traffic is conservatively:

    O(P) manifest GET
    + O(P) blob GET

This favors mutation detection and simple semantics over minimal request count.

A future immutable-locator snapshot optimization may cache the manifest
descriptor for one transfer while preserving revision checks.

## 14. HTTP mirror

HEAD:

    O(1)

Ranged GETs:

    O(P)

If Range is ignored at offset zero:
- one full GET O(B);
- only after HEAD approved B.

If Range is ignored after a non-zero resume offset:
- partial state is discarded;
- transfer restarts from zero.

Worst-case one-time fallback body cost:

    previous partial b + full B

with b < B.

## 15. Checkpoint storage secrecy/resource profile

Upload checkpoint:
- O(1) provider token/state;
- no artifact bytes;
- no credential header.

Download checkpoint:
- O(1) identity/offset/revision metadata;
- body remains in separate partial file.

Tokens may themselves be sensitive provider capabilities.

They are hidden from object repr and written atomically through mkstemp.

## 16. Retry state

No operation stores an unbounded history of retries.

Retry controller keeps:

    O(1)

state:
- attempt counter;
- total retry count.

## 17. Backend fingerprints

Fingerprint work:

    O(endpoint/repository configuration length)

Credentials are excluded.

Fingerprints are operational scope IDs for checkpoint compatibility, not
cryptographic provider identities.

## 18. No hidden global enumeration

PX3 does not:
- list all S3 objects;
- list all OCI repositories/tags;
- enumerate remote graph lineage;
- scan a remote bucket to resolve ArtifactId;
- compute transitive closure;
- discover credentials;
- enumerate caches.

Artifact remote location is deterministic from ArtifactId.

S3:
    prefix/artifacts/v1/<ArtifactId>.sigart

HTTP:
    base/artifacts/v1/<ArtifactId>.sigart

OCI:
    deterministic tag from hash(remote key)
    -> locator manifest
    -> one payload blob

## 18A. Provider metadata hard limits

OCI locator manifest body:

    M_oci <= 1 MiB

is checked before JSON decoding.

S3 multipart metadata:

    P <= 10,000

is enforced both by part-number validation and by the boto3 ListParts accumulator.

Thus control-plane/provider metadata cannot grow without a PX3 bound merely
because B is small.

## 19. Complexity verdict

Mainstream Artifact V1 transfer:

    time/network O(B)
    memory O(B) current parser model
    partial disk O(B)
    control O(P + R)

S3 resume:

    O(P)

Cycle/graph complexity from PX2 does not appear in PX3.

No new exponential or combinatorial layer is introduced.

## 20. Empirical evidence still required

Do not freeze performance claims until local execution measures at least:
- 1 KiB / 64 KiB / 1 MiB / max Artifact wire;
- cold/warm verified cache;
- 0/1/4 retry paths;
- resumed upload at 25/50/75%;
- resumed download at 25/50/75%;
- S3-compatible local provider;
- OCI registry fixture/provider;
- HTTP mirror;
- fsync_each_chunk true/false comparison;
- provider RTT sensitivity.

These are empirical product measurements, not correctness obligations.
