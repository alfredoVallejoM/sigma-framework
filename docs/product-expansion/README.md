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
