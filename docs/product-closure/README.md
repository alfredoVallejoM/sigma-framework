# Sigma Dual Integrity — Índice de campaña

Este directorio contiene la planificación normativa de la capa de producto Dual Integrity.

Autoridad funcional:
- SIGMA-DUAL-INTEGRITY-FUNCTIONAL-SPEC.md

Autoridad de ejecución:
- SIGMA-DUAL-INTEGRITY-CAMPAIGN.md

Libro mayor de obligaciones:
- SIGMA-DUAL-INTEGRITY-OBLIGATIONS.tsv

Matriz de pruebas:
- SIGMA-DUAL-INTEGRITY-TEST-MATRIX.tsv

Registro de etapas:
- SIGMA-DUAL-INTEGRITY-STAGE-REGISTRY.tsv

## Regla de trabajo

Una etapa pasa por:

PLANNED -> ACTIVE -> IMPLEMENTED -> CANDIDATE -> COMPLETE

COMPLETE exige revisión posterior de las obligaciones; compilar o pasar tests por sí solo no cierra una etapa.

## Frontera científica

La campaña no modifica la construcción Sigma v3/IAP ni la evidencia confirmatoria R14/R15. Sigma v2.2 permanece congelado como baseline histórico.

La capa de producto se divide en:

- Sigma Tree: estructura local.
- Sigma Trajectory: historia global.
- Sigma Artifact: composición TREE / TRAJECTORY / DUAL.

## Estado ST0

ST0 — Sigma Tree core extraction — está **COMPLETE** tras revisión adversaria.

El cierre demuestra que:
1. ninguna KAT histórica cambia;
2. TreeCore tiene una única semántica;
3. legacy_v22 está aislado;
4. reference y production coinciden en root y frontier;
5. el contrato de complejidad está instrumentado;
6. el gate de cierre ejecuta >=100k mutaciones de codecs y mutaciones TLV estructurales explícitas.

ST1 — Canonical Manifest — está **COMPLETE**.

Implementado:
- canonical paths NFC/UTF-8 y ordering por bytes;
- FILE / DIRECTORY / SYMLINK(TEXT) con TreeRoot V1;
- metadata base host-independent;
- optional SigmaDigestV3 byte binding;
- scanner sin follow implícito y apertura O_NOFOLLOW cuando está disponible;
- oracle independiente;
- gate local reproducible + peer-report cross-platform;
- ledger de complejidad;
- CLI provisional `sigma manifest`.

Evidencia local:
- 50,000 path cases;
- 1,000 traversal permutations;
- 1,000 differential manifests contra referencia;
- 50,000 codec bit mutations;
- 20 structural TLV mutations;
- root relocation / touch / chmod / content / symlink tests PASS;
- fixture Linux SHA-256:
  `abc5d712225b89532320ee3ff9e7ac6ffe9aad5663fa61357adc2e729613ef83`.



ST2 — Inclusion and Range Proofs — está **COMPLETE** tras revisión adversaria.

Cierre ST2:
- 100,000 inclusion proofs generadas;
- 100,000 range proofs generadas;
- 45,760 canonical-cover cases exhaustivos;
- 500 differential cases contra verifier independiente;
- 20,000 proof-wire mutations sin una mutación alterada todavía válida;
- InclusionProof wire O(m log N), pendiente exacta 378 bytes/nivel en V1;
- RangeProof verifica sólo con range bytes + proof;
- invalid ranges se rechazan antes de construir/hash el Tree;
- KAT ST2 SHA-256:
  `dea26a2bfdfe4906acf176ab8b57c1963b895c567aab7d9b614a485c5b17d674`;
- range edge disclosure documentado explícitamente: V1 no es zero-knowledge.

Evidencia normativa de cierre:
- ST2-IMPLEMENTATION-EVIDENCE.md

ST3 — Portable Tree Resume — está **COMPLETE** tras revisión adversaria.

Cierre ST3:
- 100,000 split/resume cases PASS;
- 13 directed chunk-boundary cases PASS;
- 500 independent differential cases PASS;
- 1,000 repeated checkpoint cycles PASS;
- 20,000 checkpoint-wire mutations: 8,503 rejected, 11,497 accepted-but-invalid, 0 still-valid;
- transactional write failure preserves previous checkpoint;
- restore serializa sólo frontier + tail, nunca estado interno de hashlib;
- checkpoint wire crece 350 bytes por frontier node en el sweep estructural;
- KAT ST3 SHA-256:
  `c46ad683e2c295aa251873c3de6b08eff8b78055f7bf3e5d80a4b308b9499e62`.

SourceHint permanece explícitamente heurístico y no forma parte de la seguridad semántica.

Evidencia normativa:
- ST3-IMPLEMENTATION-EVIDENCE.md

ST4 — Delta / Append — está **COMPLETE** tras revisión adversaria.

Cierre ST4:
- 5,000 cumulative delta cases PASS;
- 1,000 cumulative append cases PASS;
- 500 fresh independent differential cases PASS;
- exact affected-leaf/ancestor closure;
- compatible overlap normalization order-independent;
- conflicting overlaps rejected;
- RebuildRequired for insertion/deletion/length shifts;
- rollback before and during commit publication;
- append reuses prior canonical frontier/subtrees;
- 1,000-leaf performance sweep:
  - 0.1% ~369x vs rebuild;
  - 1% ~49x;
  - 10% ~6x;
  - 100% ~0.71x, retained as negative result;
- KAT ST4 SHA-256:
  `ed94e768dd52c71039b938eec9eafdd8330465a974b4636c3a2a975129178999`.

ST5 closes the in-memory index layout and resource policy; a persistent sidecar wire remains deferred to SA3/future storage work.

Evidencia normativa:
- ST4-IMPLEMENTATION-EVIDENCE.md

ST5 — Tree Performance and Scale Closure — está **COMPLETE** tras revisión adversaria.

Cierre ST5:
- 1,000 optimized/reference Tree builds: 0 divergences;
- 500 FULL/STREAMING proof corpora: 0 divergences;
- optimized leaf framing preserves exact ST0 bytes without four payload-sized frames;
- ProofIndex 16 MiB audit: ~0.39 MiB extra allocation, no second B-sized payload copy;
- streaming Tree 32 MiB audit: ~24 KiB auxiliary peak;
- near-full 16 MiB range proof generation: ~23 KiB auxiliary peak;
- near-full 16 MiB range verification: ~138 KiB auxiliary peak;
- explicit FULL / STREAMING / REJECT resource plans;
- DeltaIndex B-sized mutable copy is explicit and budgeted;
- over-budget delta rejects before index construction;
- Manifest reads are bounded to 65,536 bytes per request;
- frozen local ledger:
  `ST5-PERFORMANCE-LEDGER.json`.

Evidence:
- ST5-IMPLEMENTATION-EVIDENCE.md

No persistent index wire was introduced in ST5; only its logical layout/resource contract was closed.


SV0 — Trajectory Audit — está **COMPLETE** tras gate runtime + revisión adversaria.

Implementado:
- TrajectoryAuditV3 COMPACT/FULL;
- projection exacta a SigmaDigestV3;
- replay estructural sin source;
- full source verification por reevaluación v3;
- history causality H_i -> H_(i+1);
- exact layout/frame/branch/fold wires en FULL;
- Deep vs DeepVector fidelity;
- independent stdlib audit encoder;
- frozen R12.5 corpus replay;
- gate 600 differential / >=2,000 mutations / >=60 source replays;
- complexity/size ledger runner.

No se ha modificado binding/layout/rounds/digest/suite/domain v3 ni ningún corpus congelado.

SV0 closure ejecutado:
- GitHub Actions run `35783099798`;
- 600 differential cases;
- 4,000 directed mutations;
- 60 source replays;
- 3 frozen R12.5 cases;
- `closure_eligible=true`.

Report:
- `SV0-GATE-REPORT.json`

Evidencia:
- SV0-IMPLEMENTATION-EVIDENCE.md

SV1 — Trajectory Checkpoint — está **COMPLETE**.

Implementado:
- internal TrajectoryCheckpointV1 separado de SigmaCheckpointV3;
- all-index checkpointing con window_prefix mínimo;
- continuation/finalization sin source replay;
- exact final SigmaDigestV3;
- independent stdlib checkpoint encoder;
- all-index differential tests;
- source rebind correcto/incorrecto;
- canonical codec/adversarial tests;
- semantic gate preparado.

Cierre ejecutado:
- GitHub Actions run `35783661720`;
- 60 evaluations;
- 1,214 all-index cases;
- 1,946 directed mutations;
- 30 source rebinds;
- `closure_eligible=true`.

Report:
- `SV1-GATE-REPORT.json`

SV2 — Verification Policy — está **COMPLETE**.

Implementado:
- canonical SIGPOLY1 wire/version 1;
- stable PolicyId;
- Accepted / Rejected / Inconclusive / Unsupported;
- cheap-check-before-replay ordering;
- suite/history/resource/capability constraints;
- explicit v2.2 opt-in;
- normalized strict<=weak relation;
- Artifact-facing capabilities bridge;
- frozen policy KATs;
- deterministic/adversarial/property tests;
- semantic gate preparado.

Cierre ejecutado:
- GitHub Actions run `35783661720`;
- 400 decision cases;
- 100 monotonic cases;
- 100 cheap-reject cases;
- four-way coverage completa;
- legacy default reject / explicit opt-in accept;
- `closure_eligible=true`.

Report:
- `SV2-GATE-REPORT.json`

Por decisión de campaña, benchmarks/timings empíricos de SV1/SV2 se difieren a una fase posterior.

SV3 — Verification Receipts & Batch — está **COMPLETE**.

Implementado:
- canonical `SIGRCPT1` VerificationReceiptV1;
- artifact/policy/verifier/evidence/result binding;
- exact VerificationDecisionV1 projection;
- explicit UNSIGNED receipts;
- optional Ed25519 receipt signing;
- claimed timestamp/provenance claim boundary;
- canonical `SIGBCRI1` per-item batch results;
- canonical `SIGBCHT1` batch results;
- pointwise batch semantics;
- isolated item failures;
- deterministic input-order results;
- serial/threaded byte equivalence;
- stdlib-only independent receipt/batch encoder.

Cierre ejecutado:
- GitHub Actions run `35786646804`;
- compile/Ruff/Mypy PASS;
- pytest: 14 passed;
- 200 receipt cases;
- 1,000 signed-field mutations;
- 100 batch cases;
- 100 injected item failures;
- pointwise/threaded equivalence true;
- `closure_eligible=true`.

Frozen streams:
- receipt: `c8f889fc9a20c5c141ca9628cb5abec4b63478744f68e335100a3eddd978c261`;
- signed receipt: `8d0f725e940b28a7ea9014cfa1f68bff03bbf12779149049d21513b31767d7e4`;
- batch: `d06d75b39e2b5fed2b264a89b3092b66a6870ea93c1d43219f019fef8deca75b`.

Reports/evidence:
- `SV3-GATE-REPORT.json`;
- `SV3-IMPLEMENTATION-EVIDENCE.md`.

SV0–SV3 están ya cerrados semánticamente. Los benchmarks empíricos finos de SV1–SV3 siguen deliberadamente diferidos.


ST1 — Canonical Manifest — está **COMPLETE** tras gate cross-platform real.

Cierre final ST1:
- GitHub Actions run `35789236301`;
- macOS local gate PASS;
- Linux gate + Darwin peer PASS;
- 50,000 path cases;
- 1,000 permutation cases;
- 1,000 independent differential cases;
- 50,000 codec mutations;
- 20 structural TLV mutations;
- symlink checks PASS;
- Linux/Darwin fixture SHA-256 idéntico:
  `abc5d712225b89532320ee3ff9e7ac6ffe9aad5663fa61357adc2e729613ef83`;
- `cross_platform_complete=true`;
- `closure_eligible=true`.

Reports/evidence:
- `ST1-CROSS-PLATFORM-GATE-REPORT.json`;
- `ST1-IMPLEMENTATION-EVIDENCE.md`.

SA0 — Canonical Sigma Artifact — está **COMPLETE**.

Implementado:
- independent `ARTIFACT_WIRE_VERSION=1`;
- `SIGADSC1` descriptor;
- `SIGAIDN1` canonical identity;
- `SIGARTF1` artifact envelope;
- exact TREE / TRAJECTORY / DUAL primary-evidence profiles;
- non-circular ArtifactId;
- ManifestId binding;
- parent ArtifactId binding;
- optional COMPACT/FULL TrajectoryAudit without ArtifactId drift;
- stdlib-only independent artifact oracle;
- six-case frozen KAT corpus.

Cierre ejecutado:
- GitHub Actions run `35789466377`;
- compile/Ruff/Mypy PASS;
- pytest: 36 passed, including ST4 delta regression;
- frozen-vector `--check` PASS;
- 600 differential artifact cases;
- 1,800 identity mutations;
- 200 audit-stability cases;
- 600 corrupted stored ArtifactIds rejected;
- profile coverage: 200 TREE / 200 TRAJECTORY / 200 DUAL;
- `closure_eligible=true`.

Frozen corpus SHA-256:
- `60a0405516dd55b5ce52f14a442c12f836128357ac7b838a28f8d7b5eb748631`.

Reports/evidence:
- `SA0-GATE-REPORT.json`;
- `SA0-IMPLEMENTATION-EVIDENCE.md`.

SA0 does not yet define the DUAL verification conjunction; that remains SA1.


SA1 — Dual Verification — está **COMPLETE**.

Implementado:
- independent Tree and Trajectory side verification;
- exact DUAL conjunction;
- side-specific status/code/expected/actual wires;
- preserved failure attribution;
- VerificationPolicyV1 artifact-level preflight;
- explicit TREE / TRAJECTORY / DUAL requirements;
- attached TrajectoryAudit replay;
- TREE_ONLY / DECLARED / REQUIRE_ALL_FILES manifest modes;
- stdlib-only independent side verifier.

Cierre ejecutado:
- GitHub Actions run `35792567055`;
- compile/Ruff/Mypy PASS;
- pytest: 36 passed;
- 300 valid DUAL cases;
- 300 Tree-only failures;
- 300 Trajectory-only failures;
- 300 both-fail cases;
- 200 policy cases;
- 100 mixed manifest cases;
- `closure_eligible=true`.

Frozen streams:
- Tree: `e5154d09e09d6bd9f773f62412fe4d3e7113c964e4d096898340acc50a6123c1`;
- Trajectory: `af0ea2e9b2b87f6feffc7bedb8d6793138adebf3b77309f8681c6889446154f7`;
- composition: `82fa259392e63533a63ef513f775dc7167c62c01c9c8dd7196f5d43487bc8774`.

Evidence:
- `SA1-GATE-REPORT.json`;
- `SA1-IMPLEMENTATION-EVIDENCE.md`.

SA1 establishes conjunction, not additive security bits.

## Programa de expansión

Además de la ruta SA2/SA3/REL, existe ya una planificación ejecutable de expansión:

- [Sigma Product Expansion Roadmap](../product-expansion/SIGMA-PRODUCT-EXPANSION-ROADMAP.md)
- [Expansion index](../product-expansion/README.md)

Tracks registrados:

    PX0..PX5  Platform Core
    IX0..IX5  Interoperability
    ML0..ML3  Data/ML
    NR0..NR3  Native/SDK
    AX0..AX2  Advanced research

Estas etapas no bloquean el release v1 por defecto y pueden desarrollarse en
paralelo una vez satisfechas sus dependencias.
