# IX0 — OCI / ORAS Adapter — Implementation Evidence

Status: **ACTIVE — IX0-A SOURCE IMPLEMENTED / EXECUTION PENDING**  
Branch: `campaign/ix0-oci-oras-adapter`  
Started: 2026-09-24  
Base: `campaign/sigma-dual-integrity-product-closure@c3bce389d3bc5705f92e0b0dbe7a4a6003026666`

## 1. Scope of this first implementation block

IX0-A establishes the canonical interoperability boundary between Sigma Artifact V1
and OCI 1.1 artifact/referrer structures.

Implemented source surface:

- `sigma.interop.oci.OciDescriptorV1`;
- `build_sigma_artifact_referrer_v1`;
- `verify_sigma_artifact_referrer_v1`;
- `parse_sigma_referrers_index_v1`;
- explicit Sigma OCI media types;
- strict JSON duplicate-key rejection;
- bounded manifest and annotation parsing;
- offline verification of extracted Sigma artifact bytes;
- independent OCI digest and Sigma ArtifactId validation.

This stage deliberately does **not** reinterpret the PX3 OCI locator manifest as
an IX0 referrer. PX3 remains storage plumbing. IX0 is the ecosystem-semantic
adapter.

## 2. Canonical mapping

A normal OCI object remains the subject.

The Sigma artifact is represented by a referrer manifest:

    OCI image manifest
      schemaVersion = 2
      artifactType = application/vnd.sigma.artifact.referrer.v1
      subject = <ordinary OCI descriptor>
      config = canonical empty OCI config
      layers[0] = canonical SigmaArtifactV1 bytes

The Sigma payload descriptor uses:

    mediaType = application/vnd.sigma.artifact.v1
    digest    = sha256(canonical SigmaArtifactV1 wire)
    size      = len(canonical SigmaArtifactV1 wire)

The OCI descriptor additionally carries the ArtifactId as an annotation for
discovery and reconciliation, but that annotation is never an input to
ArtifactId.

## 3. Identity boundary

IX0 distinguishes three values which MUST NOT be conflated:

1. **ArtifactId**
   - Sigma identity;
   - computed by the frozen SA0 domain-separated identity construction;
   - independent of OCI serialization, tags, subjects and registry metadata.

2. **OCI payload digest**
   - SHA-256 over the exact SigmaArtifactV1 transport bytes;
   - changes if those bytes change;
   - does not replace ArtifactId.

3. **OCI referrer-manifest digest**
   - SHA-256 over the exact OCI JSON manifest bytes;
   - can change when OCI metadata or JSON serialization changes;
   - does not change ArtifactId.

This distinction is source-enforced by the API types and verifier.

## 4. Offline acceptance path

After extraction from a registry, verification requires no registry:

    manifest bytes
      -> strict bounded OCI parse
      -> subject/config/layer profile validation
      -> payload digest + size validation
      -> SigmaArtifactV1.from_bytes(payload)
      -> recomputed/stored ArtifactId validation
      -> ArtifactId annotation reconciliation
      -> optional expected subject / expected ArtifactId check

Registry trust is therefore transport/discovery trust only. The canonical Sigma
identity is re-established locally from the extracted bytes.

## 5. Referrers response handling

IX0-A parses an OCI image-index-shaped referrers response and returns only
descriptors whose `artifactType` is the Sigma IX0 artifact-referrer media type.

The parser is deliberately closed for V1:
- duplicate JSON keys reject;
- unknown top-level response fields reject;
- unknown descriptor fields reject;
- malformed digest/media type/size reject;
- metadata size is bounded before parsing.

A later compatibility stage may widen accepted OCI descriptor fields only after
an explicit semantic review; permissive parsing is not assumed by V1.

## 6. Test surface added

`tests/unit/test_oci_interop_ix0.py` covers source-level obligations for:

- offline build/verify round-trip;
- explicit OCI digest / ArtifactId namespace separation;
- registry metadata mutation with invariant ArtifactId;
- OCI manifest JSON re-encoding with invariant ArtifactId;
- payload digest tamper rejection;
- ArtifactId annotation tamper rejection;
- expected-subject fail-closed semantics;
- referrers-index filtering;
- unknown descriptor field rejection;
- duplicate JSON key rejection;
- reserved ArtifactId annotation rejection;
- explicit Sigma referrer artifactType.

These tests are committed but are **not claimed as executed** in this evidence
record.

## 7. Resource-complexity contract

Parameters:

    B = canonical SigmaArtifactV1 wire bytes
    M = OCI manifest bytes
    Q = referrers response bytes
    R = number of referrer descriptors
    P = referrers pages
    A = annotations
    T = retry attempts

Hard defaults after IX0-B:

    B <= 64 MiB
    M <= 1 MiB
    Q <= 4 MiB per page
    R <= 10,000 unique referrers
    P <= 32 pages
    T <= 4 retries after the initial attempt
    A <= 128 annotations per normalized descriptor
    annotation key <= 256 UTF-8 bytes
    annotation value <= 4096 UTF-8 bytes

The default production transport is bounded: it never reads more than the
largest configured response-body ceiling plus one byte. Custom transports are an
explicit trust/configuration boundary and must preserve the same contract.

### Build referrer

    time   O(B + A log A)
    memory O(B + M + A)

### Attach

Ignoring bounded retry multiplicity:

    time   O(B + M + discovery)
    memory O(B + M + Q)

The payload/config blobs are content-addressed and HEAD-checked before upload, so
duplicate attach reuses already-published bytes.

### Offline verify

    time   O(B + M + A)
    memory O(B + M + A)

### Referrers discovery

    time   O(sum(Q_p) + R * A)
    memory O(R * descriptor_size + max(Q_p))

Both pages and unique descriptor count are bounded. Contradictory descriptors for
the same OCI digest fail closed.

### Pull

    time   O(B + M + discovery)
    memory O(B + M + Q)

The payload descriptor size is checked before body acceptance. Digest and size are
then recomputed before Sigma parsing; the final accepted object is still the SA0
canonical artifact.

See also `IX0-COMPLEXITY-AUDIT.md`.

## 8. Obligation status

### IX0-O01 — OCI/ORAS push-pull byte round-trip

**SOURCE IMPLEMENTED / LIVE EXECUTION PENDING.**

Implemented:
- bounded OCI Distribution client;
- blob HEAD/upload/completion;
- manifest push by digest;
- OCI 1.1 referrers API discovery;
- mandatory referrers-tag fallback when the API is unavailable;
- byte-exact pull by referrer digest;
- ArtifactId-based discovery;
- deterministic in-memory native/fallback registry fixtures;
- local campaign gate;
- live ORAS 1.3 differential probe.

The obligation is not COMPLETE until the local gate and a real registry/ORAS
round-trip are executed and evidence is captured.

### IX0-O02 — OCI digest and ArtifactId remain distinct

**SOURCE IMPLEMENTED / EXECUTION PENDING.**

Enforced by:
- separate `OciDescriptorV1.digest: str`;
- separate `artifact_id: bytes`;
- explicit payload/referrer digest recomputation;
- identity-separation tests.

### IX0-O03 — Registry metadata never enters ArtifactId

**SOURCE IMPLEMENTED / EXECUTION PENDING.**

OCI subject, tags, annotations, registry URLs and manifest digest never feed
`SigmaArtifactV1.artifact_id`.

### IX0-O04 — Pulled artifact verifies offline

**SOURCE IMPLEMENTED / EXECUTION PENDING.**

`verify_sigma_artifact_referrer_v1` needs only the extracted OCI manifest and
Sigma payload bytes.

No IX0 obligation is promoted to COMPLETE solely from source implementation.
Execution evidence remains mandatory.

## 9. IX0-B implementation

IX0-B source is now implemented.

### Registry client

`OciRegistryClientV1` provides:

1. bounded registry liveness probe;
2. content-addressed blob existence and upload;
3. manifest publication by digest/reference;
4. explicit `OCI-Subject` acknowledgement handling;
5. mandatory OCI Distribution 1.1 referrers-tag fallback;
6. deterministic referrers discovery with bounded pagination;
7. referrer pull by digest;
8. ArtifactId-driven discovery;
9. final local/offline Sigma verification;
10. bounded retry for retryable transport/status failures.

### Credential boundary

Authorization and proxy-authorization headers are stripped case-insensitively
before a cross-origin upload Location is followed. The default urllib redirect
handler applies the same rule to HTTP redirects.

### CLI

The installed `sigma` command now exposes:

    sigma oci attach
    sigma oci refs
    sigma oci pull
    sigma oci verify

`verify` is fully offline. `pull` writes accepted bytes only after the registry
descriptor and Sigma identity checks succeed.

### Local source gate

`scripts/product_closure/ix0_gate.py` covers:
- native referrers API round-trips;
- referrers-tag fallback round-trips;
- OCI-metadata / ArtifactId invariance;
- corruption rejection;
- retry recovery;
- ambiguous multiple-referrer rejection;
- pagination/resource ceilings;
- exact SA0 wire parity against the independent reference implementation.

### Live ORAS differential

`scripts/product_closure/ix0_oras_diff.py` performs, against a user-selected
real registry:
- Sigma attach;
- `oras discover --artifact-type ... --format json --depth 1`;
- exact `oras manifest fetch` byte comparison;
- exact `oras blob fetch` byte comparison;
- Sigma pull and offline re-verification.

The current reference target is ORAS CLI 1.3 semantics. This is a manual/local
gate and does not enable GitHub Actions.

### Local runner

`scripts/product_closure/run_ix0_local.sh` is the canonical no-Actions runner.

It executes, in order:

1. focused IX0 pytest;
2. Ruff over IX0 production/tests/gates;
3. Mypy over the IX0 production/gate surface;
4. deterministic `ix0_gate.py`;
5. optional live `ix0_oras_diff.py` when `IX0_LIVE=1`.

Outputs default to:

    verification/ix0-local/ix0-current.log
    verification/ix0-local/ix0-gate.json
    verification/ix0-local/ix0-oras-live.json   # only in live mode

The runner is executable and introduces no GitHub workflow.

## 10. Promotion rule

IX0 remains ACTIVE until:

- IX0-O01..O04 execute successfully;
- IX0-RT-001 and IX0-ID-001 pass;
- the deterministic local IX0 gate passes;
- a live registry/ORAS differential passes;
- resource limits are exercised adversarially;
- SA0 ArtifactId vectors remain byte exact;
- no GitHub Actions are required or introduced for the gate.
