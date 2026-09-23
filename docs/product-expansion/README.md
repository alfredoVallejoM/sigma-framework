# Sigma Product Expansion — Índice

Este directorio contiene la planificación posterior al núcleo Dual Integrity.

Autoridad principal:

- [SIGMA-PRODUCT-EXPANSION-ROADMAP.md](SIGMA-PRODUCT-EXPANSION-ROADMAP.md)

El programa está registrado además en las autoridades ejecutables existentes:

- `docs/product-closure/SIGMA-DUAL-INTEGRITY-STAGE-REGISTRY.tsv`
- `docs/product-closure/SIGMA-DUAL-INTEGRITY-OBLIGATIONS.tsv`
- `docs/product-closure/SIGMA-DUAL-INTEGRITY-TEST-MATRIX.tsv`

## Tracks

- **PX** — Platform Core: persistent index, Artifact Store, lineage, remote storage, gateway, Policy DSL.
- **IX** — Interoperability: OCI/ORAS, Sigstore/Rekor, in-toto/SLSA, TUF, KMS/HSM/keyless, transparency logs.
- **ML** — Data/ML: metadata profiles, safe file adapters, sharded artifacts, registry integrations.
- **NR** — Native/SDK: Rust core, Python native backend, Go, JS/WASM.
- **AX** — Advanced research: subchunk proofs, private/ZK selective disclosure, distributed proof/cache protocol.

## Release boundary

La ruta de release actual sigue siendo:

    SA2 -> SA3 -> REL0 -> REL1 -> REL2 -> REL3

Ninguna etapa PX/IX/ML/NR/AX bloquea REL3 por defecto.

## Product-version intent

### v1

- Dual Integrity core;
- provenance/signature;
- product API/CLI;
- release hardening.

### v1.x

- persistent Tree index;
- local Artifact Store;
- lineage graph;
- verification gateway;
- Policy DSL;
- OCI/ORAS adapters;
- initial Data/ML profiles.

### v2 candidate

- remote store;
- Sigstore/in-toto/TUF enterprise interop;
- native Rust backend;
- Go/JS SDKs;
- richer ML registry integrations.

### Research profiles

- subchunk proof geometry;
- private/ZK selective disclosure;
- distributed proof/cache protocols.

Esta clasificación es de roadmap/producto, no un compromiso de versionado semántico
hasta que cada etapa congele su propio wire/profile.


## Estado PX

PX0 — Persistent Tree Index — está **COMPLETE**.

Cierre PX0:
- run `35799646274`;
- 110 focused/regression tests PASS;
- 500 sidecar/reference cases;
- 500 proof cases;
- 300 delta + 300 append cases;
- 5,000 checksum corruptions rejected;
- 200 structural corruptions rejected;
- 200 stale sources rejected;
- ArtifactId/TreeRoot invariance confirmed;
- mmap/normal parity;
- atomic publication PASS.

Formato:

    SIGTIDX1
    PERSISTENT_TREE_INDEX_FORMAT_VERSION = 1

Evidence:
- `PX0-GATE-REPORT.json`;
- `PX0-PERFORMANCE-LEDGER.json`;
- `PX0-IMPLEMENTATION-EVIDENCE.md`.

PX1 — Artifact CAS / Local Store — está **ACTIVE / IMPLEMENTED, GATE PENDING**.

Implementación PX1:
- filesystem CAS + SQLite metadata/index;
- canonical ArtifactId recomputation before publication;
- idempotent duplicate put and concurrent same-ID serialization;
- crash-safe metadata visibility with recoverable orphan blobs;
- ManifestId CAS;
- PX0 Tree index derived cache with source hints stripped;
- parent/child index;
- auxiliary evidence surface;
- bounded reachability-preserving GC.

Identity boundary:
- ArtifactId-addressed CAS stores only the canonical no-audit SigmaArtifactV1 envelope;
- TrajectoryAudit remains auxiliary evidence because SA0 deliberately excludes it from ArtifactId.

Evidence:
- PX1-IMPLEMENTATION-EVIDENCE.md;
- PX1-COMPLEXITY-AUDIT.md.

PX1 is not COMPLETE until the repository-native pytest/Ruff/Mypy checks and
scripts/product_closure/px1_gate.py execute successfully.
