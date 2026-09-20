# Sigma v3 R15 — traceability

Fecha: 2026-09-21.  
Estado: **R15 PLAN ACTIVO; confirmatory acquisition BLOCKED**.

R15 queda dividido en ejecución secuencial. Antes de cualquier dato
confirmatorio debe cerrarse R14.1 porque el candidato R14 técnico original no
congeló todavía toda la implementación de endpoints ni la escala de publicación.

| Etapa | Objetivo | Estado |
|---|---|---|
| R15-0A | execution closure | **NEXT** |
| R15-0B | publication-scale volume/interval freeze | planned |
| R15-0C | streaming/storage/provenance freeze | planned |
| R14.1 | regenerate/refreeze/re-audit | blocked by R15-0A/B/C |
| TAG-01 | exact final freeze tag | blocked by R14.1 |
| R15-A | confirmatory unlock/preflight | blocked |
| R15-B | harness validation | blocked |
| R15-C | structural acquisition | blocked |
| R15-D | reduced cryptanalysis | blocked |
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
