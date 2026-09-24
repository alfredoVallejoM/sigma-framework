# Sigma Product Expansion Program

Estado: PLANIFICACIÓN POST-CORE / EJECUTABLE EN PARALELO  
Ramal base: `campaign/sigma-dual-integrity-product-closure`  
Fecha: 2026-09-23

## 0. Propósito

Sigma ya dispone de tres capas de producto diferenciadas:

1. **Sigma Tree** — integridad estructural local, proofs, resume, delta/append, manifest.
2. **Sigma Trajectory** — audit, checkpoint, policy, receipts y batch.
3. **Sigma Artifact** — identidad canónica TREE / TRAJECTORY / DUAL y verificación conjunta.

La siguiente fase no introduce otra construcción criptográfica central. Convierte
estas capas en infraestructura de producto interoperable:

    Artifact integrity runtime
      + content-addressed storage
      + lineage graph
      + policy/gateway
      + ecosystem adapters
      + Data/ML profiles
      + native runtime / SDKs
      + advanced proof research.

La ruta SA2 -> SA3 -> REL0..REL3 sigue siendo la ruta de cierre del primer release.
Las etapas de expansión **no bloquean REL3 por defecto**.

## 1. Principios de arquitectura

### EXP-INV-001 — No reabrir identities congeladas

Ninguna extensión cambia:
- TreeRoot V1;
- SigmaDigestV3;
- ArtifactId V1;
- PolicyId V1;
- ReceiptId V1;
- wires ST/SV/SA ya congelados.

Nuevas capacidades se expresan como:
- sidecars derivados;
- adapters;
- metadata profiles;
- external attestations;
- nuevos profile/version axes explícitos.

### EXP-INV-002 — Interoperar, no reimplementar ecosistemas enteros

Sigma no reconstruye:
- OCI Registry;
- Sigstore;
- Rekor;
- in-toto;
- SLSA;
- TUF;
- KMS/HSM.

Se implementan adapters canónicos y differential/conformance gates.

### EXP-INV-003 — Storage no cambia identidad

Cambiar:
- filesystem -> SQLite -> S3 -> OCI;
- cache layout;
- persistent Tree index;
- daemon topology

no cambia ArtifactId ni evidence wires.

### EXP-INV-004 — Metadata profiles no alteran content commitments salvo declaración explícita

Data/ML metadata se separa en:
- identity-bound metadata;
- advisory/inspection metadata.

Nunca se incorpora metadata mutable accidentalmente al ArtifactId.

### EXP-INV-005 — Native parity antes de optimización

Rust/Go/JS/WASM deben reproducir byte por byte las referencias Python/std-lib antes
de publicar speedups.

### EXP-INV-006 — Nuevos proofs tienen profile/version propios

Subchunk/private/distributed proof work no reinterpreta RangeProof V1.

### EXP-INV-007 — Resource complexity audit obligatorio

Toda etapa declara:
- B bytes;
- N chunks/items;
- F files;
- A artifacts;
- E lineage edges;
- P proofs;
- concurrency;
- index/cache/storage overhead;
- I/O/network cost.

## 2. Tracks

### PX — Platform Core

    PX0 Persistent Tree Index
    PX1 Artifact CAS / Local Store
    PX2 Artifact Lineage Graph
    PX3 Remote Storage Backends
    PX4 Verification Gateway / Daemon
    PX5 Policy DSL / Compiler

### IX — Ecosystem Interoperability

    IX0 OCI / ORAS Adapter
    IX1 Sigstore / Rekor Adapter
    IX2 in-toto / SLSA Adapter
    IX3 TUF Adapter
    IX4 KMS / HSM / Keyless Signing
    IX5 Generic Transparency Log Adapter

### ML — Data & ML Artifacts

    ML0 Data/ML Metadata Profiles
    ML1 Scientific/ML File Adapters
    ML2 Sharded Dataset/Model Artifacts
    ML3 ML Registry Integrations

### NR — Native Runtime & SDKs

    NR0 Rust Canonical Core
    NR1 Python Native Bindings
    NR2 Go SDK
    NR3 JS / WASM SDK

### AX — Advanced Proof / Distribution Research

    AX0 Subchunk Proof Profile
    AX1 Private / ZK Selective Disclosure
    AX2 Distributed Proof & Cache Protocol

## 3. Priority waves

### Wave A — v1 closure, current critical path

    SA2 -> SA3 -> REL0 -> REL1 -> REL2 -> REL3

No expansion stage is allowed to delay this path.

### Wave B — highest product leverage

Can start in parallel:

    PX0 Persistent Tree Index
    PX1 Artifact Store
    PX2 Lineage Graph
    PX4 Verification Gateway
    PX5 Policy DSL
    IX0 OCI/ORAS
    IX1 Sigstore/Rekor
    IX2 in-toto/SLSA
    ML0 Data/ML Profiles
    NR0 Rust Core
    NR1 Python Native Bindings

Goal: turn the library into an artifact-integrity platform.

### Wave C — ecosystem/enterprise expansion

    PX3 Remote Storage
    IX3 TUF
    IX4 KMS/HSM/keyless
    IX5 Transparency Logs
    ML1 File Adapters
    ML2 Sharded Artifacts
    ML3 Registry Integrations
    NR2 Go
    NR3 JS/WASM

### Wave D — advanced/research

    AX0 Subchunk Proofs
    AX1 Private/ZK Ranges
    AX2 Distributed Proof/Cache

These do not block mainstream product adoption.

# 4. PX0 — Persistent Tree Index

## Goal

Persist the derived TreeProofIndex/DeltaIndex geometry without making it part of
TreeRoot or ArtifactId.

Proposed sidecar:

    .sigma-index

Logical contents:
- index format version;
- TreeRoot wire;
- source length/chunk count;
- leaf summaries;
- canonical subtree summaries;
- frontier;
- optional source identity hints;
- integrity checksum for sidecar corruption detection.

## Required properties

- rebuilding index from source reproduces the same logical index;
- sidecar corruption is detected;
- stale sidecar never produces a valid proof for changed source;
- mmap/non-mmap readers are semantically identical;
- proof/delta/append results equal no-index/full-rebuild references;
- atomic replace/update;
- ArtifactId independent of sidecar bytes.

## Complexity targets

Build:

    O(B)

Storage:

    O(N * summary_size)

Proof generation:

    O(log N)

Delta:

    O(k log N + changed bytes)

Open/mmap:

    O(1) metadata + demand paging target.

# 5. PX1 — Artifact CAS / Local Store

## Goal

Provide a content-addressed repository:

    ArtifactId -> SigmaArtifactV1
    ManifestId -> ManifestV1
    TreeRoot/Index -> derived cache

Initial backends:
1. filesystem;
2. SQLite metadata/index.

Operations:

    put
    get
    has
    delete
    verify
    list
    parents
    children
    attach evidence
    garbage collect.

## Storage invariants

- writes atomic;
- ID recomputed before publication;
- duplicate put is idempotent;
- wrong-key/wrong-ID file rejected;
- crash cannot publish partial artifact;
- GC preserves reachable graph under declared roots;
- store backend does not alter wire identity.

## Current implementation status

PX1 is ACTIVE and implemented; executed closure remains pending.

Implemented:
- LocalArtifactStoreV1;
- filesystem canonical blobs + SQLite metadata/index;
- ArtifactId and ManifestId recomputation before publication;
- exact base-artifact put/get;
- parent/child lookup;
- evidence attachments;
- PX0 persistent-index derived cache;
- bounded GC with declared roots;
- bounded deterministic PX1 closure gate.

Critical SA0 boundary:
ArtifactId does not include TrajectoryAudit. Therefore the ArtifactId CAS accepts
only the canonical SigmaArtifactV1 base envelope with no audit. COMPACT/FULL audit
bytes use the evidence surface and never select or overwrite the ArtifactId value.

GC resource admission is checked before graph materialization:

    A <= max_artifacts
    E <= max_edges
    M + X + I <= max_auxiliary_items

An empty root set fails closed.

Evidence:
- PX1-IMPLEMENTATION-EVIDENCE.md
- PX1-COMPLEXITY-AUDIT.md

PX1 may move to COMPLETE only after the unit/quality suite and px1_gate.py are
executed successfully and PX1-O01..O04 are promoted.

# 6. PX2 — Artifact Lineage Graph

## Goal

Turn parent ArtifactIds into a first-class DAG.

API:

    parents(id)
    children(id)
    ancestors(id)
    descendants(id)
    roots()
    topological_order()
    explain_path(a,b)

Optional typed edges later:

    source-of
    built-from
    derived-from
    dataset-for
    checkpoint-of.

V1 starts with parent edges already identity-bound by SA0.

## Required properties

- no implicit cycles in an accepted lineage snapshot;
- parent existence policy explicit: strict / external / unresolved;
- graph queries deterministic;
- graph metadata cannot rewrite ArtifactId parent list;
- cycle detection O(A+E);
- transitive traversal bounded by policy.

## Current implementation status

PX2 está ACTIVE e implementado; el cierre ejecutado queda pendiente.

Autoridad:

    SigmaArtifactV1.parent_artifact_ids

SQLite artifact_parents es únicamente un índice. La construcción desde store
relee los blobs canónicos bajo una sola transacción BEGIN IMMEDIATE y exige
igualdad exacta entre el índice mutable y los padres ligados a identidad.

Políticas:

    STRICT
      todo padre debe estar almacenado;

    EXTERNAL
      cada padre ausente debe declararse explícitamente como externo;

    UNRESOLVED
      los ausentes no declarados se preservan como frontera unresolved.

Consultas implementadas:

    parents
    children
    ancestors
    descendants
    roots
    local_entrypoints
    topological_order
    explain_path
    status

Semántica de root:
- roots() significa cero parent IDs en la identidad;
- local_entrypoints() significa cero padres almacenados, aunque existan padres
  externos/no resueltos.

Ciclos:
- admisión lineal O(A+E);
- REJECT lanza witness cerrado determinista;
- REPORT devuelve snapshot rechazado con graph=None;
- nunca se materializa un ArtifactLineageGraphV1 cíclico aceptado.

Resource defaults:

    max_artifacts                 = 100,000
    max_edges                     = 1,000,000
    max_total_artifact_wire_bytes = 512 MiB
    max_traversal_nodes           = 100,000

Evidence:
- PX2-IMPLEMENTATION-EVIDENCE.md
- PX2-COMPLEXITY-AUDIT.md

PX2 sólo podrá promocionarse a COMPLETE tras ejecutar el gate y promover
PX2-O01..O04.

# 7. PX3 — Remote Storage Backends

Backends:

    S3-compatible object storage
    OCI registry blobs/manifests
    HTTP read-only mirror

Requirements:
- local/remote canonical artifact bytes identical;
- retry/idempotency;
- resumable upload/download;
- integrity verified before local publication;
- cache eviction never changes semantics;
- credentials external to ArtifactId.

## Current implementation status

PX3 está ACTIVE e implementado; cierre ejecutado pendiente.

Core:

    RemoteArtifactRepositoryV1
    RemoteBlobBackendV1
    RemoteTransferPolicyV1
    RemoteUploadCheckpointV1
    RemoteDownloadCheckpointV1
    VerifiedRemoteArtifactCacheV1

Backends:

    S3CompatibleBackendV1
      multipart + resume/ListParts + part SHA-256;
      Boto3S3ClientAdapterV1 opcional;

    OciRegistryBackendV1
      OCI Distribution POST/PATCH/PUT sessions;
      digest-bound blob completion;
      image-manifest locator, no IX0 semantics;

    HttpReadOnlyMirrorBackendV1
      HEAD preflight + Range GET;
      read-only;
      full-body fallback sólo desde offset cero.

Artifact remote key:

    artifacts/v1/<ArtifactId hex>.sigart

Acceptance:

    complete remote bytes
      -> canonical SigmaArtifactV1 parse
      -> no-audit base envelope
      -> requested ArtifactId equality
      -> only then PX1 publication

Operational metadata never enters ArtifactId:
- credentials;
- URL/bucket/repository;
- ETag/version;
- OCI digest/tag;
- cache state;
- resume token/checkpoint;
- retry count.

Default resource policy:

    chunk_size         = 8 MiB
    max_object_bytes   = 64 MiB
    max_retries        = 4
    fsync_each_chunk   = true
    verify_after_upload = true

HTTP V1 requires HEAD so max_object_bytes is enforced before body download.

Evidence:
- PX3-BACKEND-CONTRACT.md
- PX3-COMPLEXITY-AUDIT.md
- PX3-IMPLEMENTATION-EVIDENCE.md

PX3 sólo se promociona a COMPLETE tras ejecutar el gate y promover PX3-O01..O04.

# 8. PX4 — Verification Gateway / Daemon

Expose the existing verifier as a service.

Initial HTTP API:

    POST /v1/artifacts/verify
    POST /v1/proofs/inclusion/verify
    POST /v1/proofs/range/verify
    POST /v1/policies/evaluate
    POST /v1/batch/verify
    GET  /v1/artifacts/{id}
    GET  /v1/artifacts/{id}/parents
    GET  /health
    GET  /version

Deployment targets:
- local daemon;
- CI service;
- registry webhook;
- Kubernetes admission backend.

Requirements:
- same decisions as local Python API;
- deterministic JSON error schema;
- streaming request bodies;
- request/resource limits before hashing;
- no secrets in receipts/logs;
- structured audit logging;
- cancellation/timeouts.


## Current implementation status

PX4 está ACTIVE e implementado; cierre ejecutado pendiente.

Semantic authority remains local:

    artifacts -> SA1 verify_artifact_v1
    policy    -> SV2 verify_with_policy_v1
    receipts  -> SV3 receipt_from_decision_v1
    batch     -> SV3 verify_batch_item_v1 / BatchVerificationResultV1
    proofs    -> Tree V1 parsers/verifiers
    storage   -> PX1 canonical artifacts

Implemented routes:

    POST /v1/artifacts/verify
    POST /v1/proofs/inclusion/verify
    POST /v1/proofs/range/verify
    POST /v1/policies/evaluate
    POST /v1/batch/verify
    GET  /v1/artifacts/{id}
    GET  /v1/artifacts/{id}/parents
    GET  /health
    GET  /version

Source-bearing bodies use versioned binary metadata-first framing.

Admission layers:
- max_http_connections before handler-thread creation;
- header budget during stdlib parsing;
- exact Content-Length required for POST;
- no Transfer-Encoding V1;
- max_request/max_metadata/max_source/max_proof/max_batch bounds;
- global temporary spool-byte budget before source read;
- policy preflight before source spool/hash;
- proof geometry parsed before disclosed value buffering;
- socket deadline + cooperative cancellation;
- bounded concurrent requests;
- conservative batch response budget.

Structured audit contains only:
- normalized endpoint labels;
- canonical ArtifactId/PolicyId where known;
- decision/error codes;
- byte counters;
- elapsed time and timeout/cancel flags.

It never stores arbitrary headers/query strings/body or raw exception messages.

Daemon:

    sigma-gateway --store <PX1-store>

Default bind is loopback. Non-loopback requires --allow-nonlocal-bind and still
expects TLS/authentication to be provided by trusted outer infrastructure.

Evidence:
- PX4-GATEWAY-CONTRACT.md
- PX4-HTTP-PROTOCOL.md
- PX4-COMPLEXITY-AUDIT.md
- PX4-IMPLEMENTATION-EVIDENCE.md

PX4 sólo se promociona a COMPLETE tras ejecutar el gate y promover PX4-O01..O04.

# 9. PX5 — Policy DSL / Compiler

Human-facing YAML/JSON policy -> canonical VerificationPolicyV1.

Example:

    version: 1
    artifact: dual
    trajectory:
      required: true
      history: true
    tree:
      required: true
    signature:
      required: true
    provenance:
      required: true
    resources:
      max_input: 20GiB

Compiler output:

    canonical VerificationPolicyV1 wire
    PolicyId
    diagnostic explanation.

Requirements:
- deterministic compilation;
- no ambiguous units;
- unknown keys reject;
- semantic conflicts reject before compilation;
- decompiler/inspect preserves normalized meaning;
- strict-policy relation exposed to users.

# 10. IX0 — OCI / ORAS

Map Sigma objects to OCI artifacts/referrers.

Recommended model:
- source artifact remains ordinary OCI subject;
- SigmaArtifact/Receipt/Manifest/Proof become OCI referrers;
- media types versioned under Sigma namespace.

Operations:

    sigma oci attach
    sigma oci pull
    sigma oci verify
    sigma oci refs

Requirements:
- OCI digest and ArtifactId remain distinct identities;
- pull/push round-trip preserves Sigma bytes;
- no registry metadata enters ArtifactId;
- offline verification after pull;
- ORAS CLI/reference differential fixtures.

# 11. IX1 — Sigstore / Rekor

Do not replace Sigstore.

Use it to authenticate/publish Sigma identities and receipts.

Flows:
- Cosign/keyless sign ArtifactId or receipt bundle;
- attach Sigstore bundle to artifact;
- optional Rekor publication;
- verify certificate identity/issuer under policy.

Requirements:
- Sigstore signature does not change ArtifactId;
- offline bundle verification where supported;
- Rekor presence is a separate policy fact;
- Sigma receipt signature and Sigstore signature remain distinguishable;
- issuer/subject regex policies canonicalized outside core Artifact identity.

# 12. IX2 — in-toto / SLSA

Adapters:

    SigmaArtifact -> in-toto subject
    Sigma parent graph -> materials/subjects
    Sigma receipt -> attestation evidence
    SLSA provenance -> SA2 provenance claim

Requirements:
- adapters round-trip supported fields;
- unsupported semantics remain explicit;
- SLSA level is never inferred from opaque payload alone;
- external statement digest does not replace ArtifactId;
- differential fixtures against official schemas.

# 13. IX3 — TUF

Use TUF for trusted software distribution/freshness, not as Tree replacement.

Integration:
- ArtifactId / canonical artifact wire as target metadata;
- target custom metadata can reference Sigma evidence;
- verify TUF first, then Sigma content;
- rollback/freeze/freshness semantics remain TUF's authority.

# 14. IX4 — KMS / HSM / Keyless Signing

SA2 defines the signature/provenance abstraction.

Backends:
- local Ed25519;
- PKCS#11;
- cloud KMS;
- Sigstore keyless.

Requirements:
- signing backend never changes unsigned artifact identity;
- public key identity explicit;
- algorithm allowlist closed;
- key material never serialized into receipts;
- signing request bytes observable/testable;
- mock HSM/KMS conformance.

# 15. IX5 — Generic Transparency Adapter

Generic interface:

    submit(entry) -> log receipt
    verify_inclusion(entry,receipt)
    verify_checkpoint(log checkpoint)

Initial concrete backend can be Rekor.

Important:
- transparency proves log inclusion/consistency, not artifact semantic validity;
- timestamps remain log-specific claims;
- log receipt is auxiliary evidence, not ArtifactId.

# 16. ML0 — Data / ML Metadata Profiles

Define typed advisory/identity-bound metadata profiles.

Core types:

    DatasetArtifact
    ModelArtifact
    CheckpointArtifact
    ShardCollection
    EmbeddingIndexArtifact

Candidate metadata:
- framework;
- format;
- dtype;
- tensor names/shapes;
- dataset schema;
- compression;
- shard count;
- model architecture tag;
- tokenizer reference;
- training/config parent IDs.

V1 rule: large/mutable descriptive metadata is advisory unless a profile marks a
field identity-bound explicitly.

# 17. ML1 — File Format Adapters

Adapters in priority order:

    safetensors
    NumPy .npy/.npz
    Parquet
    Zarr
    HDF5
    PyTorch checkpoint inspection

Capabilities:
- canonical file/shard inventory;
- logical tensor/column range mapping;
- Tree range proofs for selected physical regions;
- schema extraction;
- no framework execution required for inspection.

Security:
- never unpickle arbitrary model files in verifier paths.

# 18. ML2 — Sharded Dataset / Model Artifacts

Represent very large logical artifacts as a manifest/graph of shard artifacts.

Requirements:
- top-level ArtifactId binds ordered shard ArtifactIds;
- missing/duplicate shard reject;
- parallel shard verification;
- partial verification policy;
- changed-shard update avoids rebuilding unaffected shard commitments;
- deterministic sharding profile or explicit external shard order.

# 19. ML3 — ML Registry Integrations

Targets:

    Hugging Face Hub
    MLflow
    generic object-store model registry

Operations:
- push SigmaArtifact sidecars;
- verify on pull;
- lineage display;
- receipt/provenance attach;
- local cache.

Do not require external registry metadata to become part of ArtifactId.

# 20. NR0 — Rust Canonical Core

First native scope:
- Tree codec/model/build;
- proof verify/generate;
- Artifact codec/ArtifactId;
- Policy codec;
- receipt codec.

Do **not** port experimental Sigma v3 first.

Closure rule:
- every frozen KAT exact;
- randomized differential Python<->Rust;
- malformed parser corpus exact accept/reject class;
- no unsafe unless separately justified/reviewed.

# 21. NR1 — Python Native Bindings

Python facade keeps the public semantic API.

Backend selection:

    pure-python
    rust-native

Requirements:
- bytes and exceptions semantically equivalent;
- native backend optional;
- wheel fallback documented;
- no silent change of profile/limits;
- benchmark only after conformance.

# 22. NR2 — Go SDK

Scope:
- parse/serialize Artifact/Tree/Policy/Receipt;
- verify Tree/proofs/artifacts;
- client for verification gateway.

No need to implement Sigma v3 evaluation initially; unsupported trajectory full
replay remains explicit until implemented.

# 23. NR3 — JS / WASM SDK

Primary target:
- browser/node inspection;
- ArtifactId/PolicyId/Receipt validation;
- Tree proof verification;
- gateway client.

Large-file streaming and WASM memory ceilings must be tested explicitly.

# 24. AX0 — Subchunk Proof Profile

Problem:

RangeProof V1 may reveal up to two complete edge-chunk complements.

New profile must be separately versioned.

Candidate geometry:
- two-level Tree: 64KiB chunks + subchunk Merkle tree;
- configurable fixed subchunk size under a registered profile.

Requirements:
- old RangeProof V1 unchanged;
- disclosure bound derived exactly;
- proof-size/verify tradeoff ledger;
- no privacy/ZK claim.

# 25. AX1 — Private / ZK Selective Disclosure

Research-only until a standard proof system and threat model are selected.

Possible targets:
- prove committed range/property without revealing edge complements;
- membership predicates over structured data.

Requirements before implementation:
- explicit statement language;
- trusted-setup assumptions;
- verifier complexity;
- transcript/versioning;
- no custom ZK primitive.

# 26. AX2 — Distributed Proof / Cache Protocol

Goal:

Let remote peers/cache servers provide:
- Tree proofs;
- ranges;
- derived indexes;
- artifacts;

while trust remains anchored in canonical IDs.

Requirements:
- cache untrusted by default;
- proofs verify locally;
- cache poisoning cannot alter accepted result;
- content-addressed cache keys;
- TTL/freshness only operational unless separately signed;
- protocol cancellation/backpressure;
- no consensus/blockchain dependency.

# 27. Product packaging model

Recommended public surfaces:

### Sigma Integrity SDK

    sigma.tree
    sigma.artifact
    sigma.trajectory
    sigma.policy

### Sigma Artifact Store

    local CAS
    lineage graph
    remote backends

### Sigma Verify

    CLI
    daemon
    policy DSL
    receipts
    batch

### Sigma Interop

    OCI
    Sigstore
    in-toto/SLSA
    TUF

### Sigma Data/ML

    profiles
    file adapters
    registries

### Sigma Native

    Rust core
    Python/Go/JS SDKs

Experimental v2/v3 applications remain outside the primary product narrative.

# 28. Commercial / licensing boundary

Current AGPL + commercial-license model fits a split:

Open:
- canonical specs/wires;
- reference verifiers;
- core CLI/library.

Commercial candidates:
- managed verification gateway;
- hosted Artifact Store;
- enterprise KMS/HSM adapters;
- policy management/UI;
- registry/admission integrations;
- support/compliance packs;
- private deployment/HA/observability.

Interoperability specs and canonical test vectors should stay public to preserve
trust and adoption.

# 29. Recommended execution order

Parallel immediately after current SA1 state:

    current critical path:
      SA2 -> SA3 -> REL0 -> REL1 -> REL2 -> REL3

    expansion lane A:
      PX0 -> PX1 -> PX2
             |
             +-> PX3
             +-> PX4 -> PX5

    expansion lane B:
      SA2 -> IX1
      SA2 -> IX2
      SA2 -> IX4
      SA0 -> IX0
      IX1 -> IX5
      SA2 + SA3 -> IX3

    expansion lane C:
      SA0 -> ML0 -> ML1 -> ML2 -> ML3

    expansion lane D:
      ST5 + SA0 -> NR0 -> NR1
                           +-> NR2
                           +-> NR3

    research lane:
      ST2 -> AX0 -> AX1
      PX0 + PX3 -> AX2

# 30. Exit doctrine

An expansion stage is COMPLETE only if:
1. canonical semantics are frozen;
2. unsupported cases are explicit;
3. reference or external standard oracle exists;
4. differential/adversarial tests pass;
5. complexity/resource contract is recorded;
6. existing Artifact/Tree/Trajectory IDs remain byte exact;
7. release claims state exactly what the stage does and does not prove.

