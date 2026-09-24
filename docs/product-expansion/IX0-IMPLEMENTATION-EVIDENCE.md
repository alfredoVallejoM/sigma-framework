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
    M = OCI manifest/referrers-index bytes
    R = number of descriptors in a referrers response
    A = number of annotations

Current hard bounds:

    M <= 1 MiB
    A <= 128 annotations per descriptor/manifest normalization
    annotation key <= 256 UTF-8 bytes
    annotation value <= 4096 UTF-8 bytes

Expected costs:

### Build referrer

    time   O(B + A log A)
    memory O(B + M + A)

The artifact wire must be materialized by the current Python API. IX0-A does not
claim streaming construction.

### Offline verify

    time   O(B + M + A)
    memory O(B + M + A)

The dominant cryptographic work in IX0 itself is SHA-256 over the payload and
manifest bytes; SigmaArtifact parsing/recomputation remains the SA0 authority.

### Parse referrers index

    time   O(M + R * A)
    memory O(M + R * A)

The 1 MiB metadata ceiling bounds JSON materialization in IX0-A. A later registry
client MUST add an explicit maximum descriptor count and network-body limit before
promotion of IX0-O01.

## 8. Obligation status

### IX0-O01 — OCI/ORAS push-pull byte round-trip

**PENDING IX0-B.**

Needs:
- registry client operations;
- local registry fixture;
- ORAS reference differential;
- byte-exact push/pull corpus.

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

No IX0 obligation is promoted to COMPLETE in this commit series.

## 9. IX0-B remaining implementation

Next block:

1. registry transport on OCI Distribution endpoints;
2. blob existence/upload with digest-checked completion;
3. push IX0 referrer manifest by digest/reference;
4. referrers discovery by subject digest;
5. pull payload by descriptor digest;
6. local offline verification before returning accepted Sigma object;
7. ORAS CLI/reference fixtures when available locally;
8. resumable/retry semantics by reusing provider-neutral PX3 transport principles
   without treating PX3 locator manifests as IX0 semantics;
9. bounded registry response sizes, descriptor counts, redirects and retries;
10. CLI surface:
    - `sigma oci attach`
    - `sigma oci refs`
    - `sigma oci pull`
    - `sigma oci verify`.

## 10. Promotion rule

IX0 remains ACTIVE until:

- IX0-O01..O04 execute successfully;
- IX0-RT-001 and IX0-ID-001 pass;
- registry/ORAS differential evidence is captured;
- resource limits are exercised adversarially;
- SA0 ArtifactId vectors remain byte exact;
- no GitHub Actions are required or introduced for the gate.
