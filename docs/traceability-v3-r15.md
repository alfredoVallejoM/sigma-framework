# Sigma v3 R15 — traceability

Fecha: 2026-09-21.  
Estado: **R15 PLAN ACTIVO; confirmatory acquisition BLOCKED**.

R15 queda dividido en ejecución secuencial. Antes de cualquier dato
confirmatorio debe cerrarse R14.1 porque el candidato R14 técnico original no
congeló todavía toda la implementación de endpoints ni la escala de publicación.

| Etapa | Objetivo | Estado |
|---|---|---|
| R15-0A | execution closure | **PASS** — 21/21 executors |
| R15-0B | publication-scale volume/interval freeze | **PASS** — 406 cells / 153,536 run units |
| R15-0C | streaming/storage/provenance freeze | **PASS** |
| R14.1 | regenerate/refreeze/re-audit | **TECHNICAL PASS** — CI/bundle green |
| TAG-01 | exact final freeze tag | **PENDING external action** |
| R15-A | confirmatory unlock/preflight | **STATIC PASS; full unlock blocked by tag + real host/tool manifests** |
| R15-B | harness validation | **PASS** — 7 tests / 11 adversarial checks |
| R15-C | structural acquisition | **REAL ACQUISITION BLOCKED; 33-cell shadow battery launched** |
| R15-D | reduced cryptanalysis | **REAL ACQUISITION BLOCKED; 32-cell shadow battery launched** |
| R15-E | KDF/PoW/mitigation | blocked |
| R15-F | external STAT | blocked |
| R15-G | locked analysis | blocked |
| R15-H | adversarial data audit | blocked |
| R15 closure | dataset + review + handoff R16 | blocked |

## Publication-scale doctrine

Primary curves target 6–8 estimable points, usually 2-bit spacing, plus stress
points where useful. Cheap reduced campaigns use hundreds to ~1,000 replicates
per point; physical paired campaigns use hundreds per host; rare events use
large conditional-exposure counts.

Primary results require 95% confidence intervals. Rare/zero-event security
boundaries additionally report 99% one-sided upper bounds. Power target is 95%
where meaningful.

## Data doctrine

Processed bytes are not retained bytes. Large STAT streams are deterministic,
hashed and consumed incrementally. Git stores code/config/manifests/results, not
large generated streams.

Scratch targets:

- default <=10 GiB;
- preferred STAT <=2 GiB.

Final retained scientific dataset target: approximately 1–5 GiB or less.

## No confirmatory execution

Until R14.1 PASS + exact TAG-01:

- no `sigma-v3-r15` seed may be consumed for measurement;
- no result may be labelled confirmatory;
- no publication-scale config may be altered based on observed R15 outcomes.

Governing plan: `docs/r15-confirmatory-campaign-plan.md`.


## Estado técnico observado antes de R15-B

Último baseline verde antes de la batería R15-B:

- HEAD `00c2e172b81fb9c45df4cd9ab70fe72f3606a39b`;
- CI run `35548277304`: PASS;
- 1033 tests passed, 1 skipped;
- R14.1 protocol: 21 attacks, 406 cells, 153,536 run units;
- regions: 240 estimable, 92 exhaustive, 32 stress, 18 paired, 24 descriptive;
- R15-0A execution closure: PASS;
- R15-0C data closure: PASS;
- R14.1 source/runtime freeze bundle: PASS;
- R15-A static preflight: PASS;
- confirmatory_unlocked=false.

R15-B usa exclusivamente el namespace `sigma-v3-r15-harness-v1` y valida
crash/resume, timeout, duplicate RunKey, wrong seed, record/checkpoint tampering,
budget overflow, execution-manifest mismatch y retry policy. No consume el
namespace `sigma-v3-r15`.


## Shadow acquisition doctrine

R15-C/D shadow rehearsals are pre-data integration tests, not scientific
observations. They use dedicated namespaces:

- `sigma-v3-r15-shadow-c-v1`;
- `sigma-v3-r15-shadow-d-v1`.

They consume real R14.1 cell factors but clamp work to CI-safe limits, write
canonical records/receipts, build deterministic ledgers and assert mode/fault/
strategy coverage. They never call `derive_confirmatory_seed_r141` and cannot
enter R15 figures/tables.
