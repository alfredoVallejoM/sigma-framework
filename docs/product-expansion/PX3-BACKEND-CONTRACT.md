# PX3 — Remote Storage Backend Contract

Status: **FROZEN IMPLEMENTATION CONTRACT / GATE PENDING**  
Date: 2026-09-24

## 1. Authority boundary

PX3 is a transport/storage layer.

It does not define:
- ArtifactId;
- ManifestId;
- TreeRoot;
- provenance identity;
- a remote metadata identity;
- a trust decision about provider metadata.

For Artifact V1 the only accepted remote object is the same canonical no-audit
SigmaArtifactV1 envelope accepted by PX1.

The remote key is deterministic:

    artifacts/v1/<ArtifactId hex>.sigart

This key is operational addressing. It is not hashed into ArtifactId.

## 2. Provider-neutral backend interface

RemoteBlobBackendV1 exposes:

    fingerprint
    read_only
    head(key)
    read_range(key,start,max_bytes)
    begin_upload(...)
    resume_upload(session)
    upload_chunk(session,data)
    complete_upload(session)
    abort_upload(session)

The interface deliberately models append/resume rather than provider-specific
multipart terminology.

Provider metadata is normalized to:

    RemoteObjectInfoV1(
      key,
      size,
      revision,
      wire_sha256,
      provider_locator
    )

Only key and requested ArtifactId select the logical operation.

The following remain advisory/operational:
- revision;
- ETag;
- provider locator;
- object version;
- OCI manifest digest;
- S3 multipart ETag;
- cache path;
- credentials.

## 3. Final acceptance rule

No provider metadata can cause local acceptance.

For every remote pull, PX3 requires:

    parse SigmaArtifactV1
    no TrajectoryAudit in ArtifactId-addressed object
    artifact.artifact_id == requested ArtifactId
    artifact.to_bytes() == received bytes

Only after those checks does PX3 call:

    LocalArtifactStoreV1.put_artifact_bytes(...)

Therefore the local PX1 visibility boundary remains unchanged.

## 4. Remote wire digest

PX3 computes:

    wire_sha256 = SHA256(canonical SigmaArtifactV1 bytes)

This is a transport-integrity digest, not ArtifactId.

It may be:
- sent to a provider;
- stored in provider metadata;
- stored in checkpoints;
- used to detect remote mutation.

It does not replace ArtifactId.

Provider-supplied wire_sha256 is verified against received bytes whenever it is
present.

## 5. Retry semantics

Only RemoteRetryableError participates in automatic retry.

Default:

    max_retries = 4

Backoff is explicit and bounded.

The following are not blindly retried:
- canonical-integrity failures;
- ID mismatch;
- provider conflict;
- expired upload session;
- read-only backend violation;
- malformed checkpoint.

An expired session starts a new upload instead of repeatedly retrying a dead
provider token.

## 6. Accepted-but-response-lost uploads

The difficult retry case is:

    provider accepts bytes
    network response is lost
    client still holds old offset

PX3 requires backend upload_chunk to make this safe.

S3:
- retry uses the same part number;
- S3 replacement semantics make the part operation idempotent;
- part checksum must match.

OCI:
- retry of an already accepted range can yield HTTP 416;
- backend queries upload status;
- if provider offset equals expected end, the chunk is treated as committed;
- any other offset is a conflict.

The generic closure fixture implements the same failure model.

## 7. Upload checkpoints

RemoteUploadCheckpointV1 binds:

    backend fingerprint
    remote key
    ArtifactId
    total wire size
    wire SHA-256
    provider upload session

Provider session state includes:
- token/location/upload ID;
- accepted offset;
- effective chunk size;
- small provider-specific state.

Checkpoint serialization is canonical JSON.

Parser acceptance requires:

    parse(checkpoint).to_bytes() == original checkpoint bytes

This rejects semantically equivalent but non-canonical variants.

Upload tokens are hidden from dataclass repr.

Checkpoint files are written through mkstemp + fsync + os.replace. The temporary
file mode is provided by mkstemp and therefore does not make upload tokens part
of normal logs/output.

## 8. Provider-ahead checkpoint recovery

The server may have accepted more bytes than the last fsynced local checkpoint.

On resume:

    backend.resume_upload(session)

is authoritative only for operational offset reconciliation.

The provider is still not trusted for final artifact acceptance.

The resumed offset must:
- belong to the same backend fingerprint;
- same key;
- same total size;
- same expected wire SHA-256;
- be within total size.

Final remote bytes are verified after completion by default.

## 9. Download checkpoints

RemoteDownloadCheckpointV1 binds:

    backend fingerprint
    key
    ArtifactId
    total size
    accepted local offset
    remote revision hint
    remote wire digest hint

A partial file is resumed only when:
- checkpoint identity matches;
- remote total size matches;
- revision/digest hints do not contradict current HEAD;
- partial file size equals checkpoint offset.

Otherwise PX3 discards partial state and restarts.

## 10. Download publication law

For a resumed download:

    partial bytes
      -> full assembled bytes
      -> optional provider-digest check
      -> canonical Artifact parser
      -> requested ArtifactId check
      -> PX1 atomic publication

No prefix/partial object is visible through PX1.

## 11. HTTP mirror profile

HttpReadOnlyMirrorBackendV1 is read-only.

Requirements:
- absolute http/https base URL;
- deterministic key-to-path mapping;
- HEAD support;
- byte Range support preferred;
- full-body 200 fallback allowed only from offset 0 after HEAD approved size;
- non-zero resume requires real 206 semantics.

PX3 V1 intentionally requires HEAD.

Reason:
a GET-based metadata probe could cause a server that ignores Range to return an
entire object before the client had applied max_object_bytes.

HTTP Range responses require:
- valid Content-Range for 206;
- exact requested start;
- returned end not beyond requested end;
- payload length equal declared range.

ETag is a revision hint only.

## 12. HTTP credential redirect boundary

The dependency-free UrllibHttpTransportV1 installs a custom redirect handler.

On cross-origin redirect it strips:
- Authorization;
- Proxy-Authorization.

Provider credentials are not forwarded to another host by default.

This follows the safety boundary required by modern OCI Distribution guidance.

## 13. S3-compatible profile

S3CompatibleBackendV1 depends on S3ClientV1.

The runtime has no mandatory boto3 dependency.

Boto3S3ClientAdapterV1 can wrap an externally-created boto3-compatible client.

Backend public fingerprint uses only:

    endpoint identity
    bucket
    prefix

Credentials remain inside the supplied S3 client.

### Multipart

Default minimum part size:

    5 MiB

Maximum:

    10,000 parts

Uploads use:
- CreateMultipartUpload;
- UploadPart;
- ListParts for resume;
- CompleteMultipartUpload;
- AbortMultipartUpload.

### Part integrity

Each uploaded part carries:

    Base64(SHA256(part bytes))

Part numbers must be contiguous from 1.

Resume rejects:
- missing part number;
- zero-size part;
- oversized part;
- short non-final part;
- aggregate size beyond expected object.

PX3 does not treat multipart ETag as a wire digest.

### Whole-object integrity

For SHA-256 multipart, provider checksum semantics are composite rather than a
full-object SHA-256.

Therefore:
- full expected wire SHA-256 is stored as operational metadata;
- every part is checksummed;
- completion is followed by canonical full remote re-read by default.

A future S3 specialization may additionally use provider-supported full-object
CRC checksums, but ArtifactId remains the final Sigma identity regardless.

## 14. OCI Distribution profile

OciRegistryBackendV1 uses:
- OCI blob upload sessions;
- POST/PATCH/PUT resumable blob flow;
- GET upload status;
- Range blob reads;
- OCI image manifest as a storage locator.

It deliberately does not define IX0 referrer semantics.

### Blob integrity

Canonical artifact bytes are uploaded as one OCI blob:

    sha256:<wire SHA-256>

Completion includes that digest.

The registry must reject a digest mismatch before the blob is accepted.

### Locator manifest

PX3 uses the existing OCI image manifest media type.

The manifest contains:
- artifactType identifying PX3 storage locator;
- OCI empty config descriptor;
- exactly one layer pointing at the canonical artifact blob;
- an annotation binding the deterministic PX3 remote key hash.

The OCI manifest digest/tag are remote location metadata.

They do not alter ArtifactId.

### Key/tag mapping

A deterministic OCI tag is derived from SHA-256(remote key).

This prevents arbitrary artifact names from becoming registry tags while still
giving ArtifactId-keyed lookup.

IX0 may later define richer OCI subject/referrer interoperability. PX3's locator
manifest should be treated as storage plumbing, not ecosystem semantics.

## 15. Verified cache

VerifiedRemoteArtifactCacheV1 stores only bytes that already pass:

    canonical Artifact V1 parse
    requested ArtifactId equality
    no-audit base envelope rule

Every cache read validates again.

If a cache entry is corrupt:
- it is discarded;
- the operation becomes a cache miss;
- remote retrieval is used.

Eviction changes performance only.

It cannot change the accepted artifact bytes while the remote object remains
available.

## 16. Resource preflight

Default RemoteTransferPolicyV1:

    chunk_size        = 8 MiB
    max_object_bytes  = 64 MiB
    max_retries       = 4
    fsync_each_chunk  = true
    verify_after_upload = true

Pull:

    HEAD
      -> size policy
      -> only then GET body/ranges

An oversize HEAD rejects before read_range.

Push validates local canonical bytes and max_object_bytes before creating a
remote upload session.

## 17. Read-only semantics

A read-only backend must fail begin/resume/upload/complete/abort with
RemoteReadOnlyError.

RemoteArtifactRepositoryV1 checks read_only before starting push.

HTTP mirror implements this profile.

## 18. Failure taxonomy

Retryable:
- transport timeout;
- 408;
- 425;
- 429;
- 5xx;
- equivalent provider transient errors.

Not found:
- object absent;
- expired session is classified separately.

Integrity:
- malformed ranges;
- provider digest mismatch;
- canonical artifact mismatch;
- wrong ArtifactId;
- remote object changes during one transfer.

Conflict:
- wrong server upload offset;
- invalid part geometry;
- same ArtifactId key with different canonical bytes.

## 19. Identity non-interference

Changing any of the following does not construct a new Sigma artifact and cannot
change ArtifactId:

    S3 credentials
    OCI bearer token
    HTTP Authorization header
    endpoint URL
    bucket/repository
    ETag
    OCI manifest digest
    provider version ID
    retry count
    cache state
    checkpoint token
    remote locator

PX3 can only accept or reject transport bytes already governed by SA0/PX1.
