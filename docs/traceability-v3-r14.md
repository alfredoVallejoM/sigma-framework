# Sigma v3 R14 — traceability

Fecha: 2026-09-20.  
Estado: **R14 technical PASS — cierre formal bloqueado sólo por TAG-01**.  
Candidato técnico auditado: `b6ebc780cc0b201fd27562c85c64c90df37c1075`.  
Workflow autoritativo: `35529570894`.  
Informe adversarial: `docs/adversarial-reviews/R14.md`.

Baselines:

- R12.5 PASS: `5ac306bb23acae0e0a4ef03eb56b3062343c2127`;
- R13 PASS: `8a71de3d350ea8215c481e16c9eadbeed54066ef`.

R14 no cambia la construcción. Su salida es un protocolo experimental
congelado y preregistrado que desbloquea R15.

| Bloque | Artefacto esperado | Estado |
|---|---|---|
| R14-A baseline lock | `scripts/check_r14_baselines.py` | PASS |
| R14-B campaign inventory | C01–C20 + 30 R13 attacks disposed | PASS |
| R14-C pilot budgeting | `r14-budget-decision-record.json` | PASS |
| R14-D protocol lock | `experiments/r14_protocol.py` | PASS |
| config schema | `experiments/r14_schema.py` | PASS |
| result schema | `ConfirmatoryRecordV3` | PASS |
| discovery separation | separate namespace + no reuse | PASS |
| confirmatory configs | 21 frozen R15 configs | PASS |
| analysis | synthetic-only analysis gate | PASS |
| figures | 15 figures + 9 tables predeclared | PASS |
| artifact freeze | wheel/sdist/SBOM/SHA256SUMS | PASS |
| preregistration | `experiments/preregistration-v3.md` | FROZEN |
| freeze manifest | 44 Git-blob-bound files | PASS |
| R14 gate | `scripts/check_r14_freeze.py` | PASS |
| adversarial review | `docs/adversarial-reviews/R14.md` | VERSIONED |
| exact Git tag | `sigma-v3-r14-freeze-v1` | **TAG-01 PENDING** |

Documento rector:
`docs/r14-experimental-freeze-plan.md`.

## Invariante principal

Ningún resultado confirmatorio puede existir antes del PASS R14. Pilotos y
discovery deben estar marcados explícitamente y utilizar namespaces de seed,
directorios y manifests distintos del confirmatorio.

## Criterio de salida

R14 cierra cuando cualquier investigador puede tomar el tag/artifact congelado
y saber de antemano, sin consultar resultados:

- todas las celdas que se ejecutarán;
- todos los budgets y sample sizes;
- todas las seeds;
- todos los stopping/censoring rules;
- todos los análisis;
- todas las figuras/tablas;
- todos los hashes de configuración/preregistro/artifact.

R15 no puede modificar esos elementos.


## Evidencia de cierre técnico

Run autoritativo: `35529570894`.

- 1006 tests passed, 1 skipped;
- Ruff/mypy/compileall PASS;
- R12/R12.5 corpora PASS;
- R13 design gate PASS;
- R14 freeze gate PASS;
- 21 confirmatory attacks / 21 configs;
- 44 protocol-freeze files;
- 15 synthetic figures / 9 tables;
- confirmatory_executed = false;
- Linux 3.10–3.13, macOS 3.13 y Windows 3.13 PASS.

Artifacts:

- `r14-authoritative-gate`: id `10610822307`,
  sha256 `1aa5f0b21117a32a8d1a5e417284f99dfee98d20b3f19fdbcf5ea67219d7706b`;
- `r14-freeze-bundle`: id `10609774757`,
  sha256 `089ed944e70654124d9489f9f50fa51e2128fae4fa3e668ca21b86e770914152`.

## TAG-01

El único requisito de cierre formal no satisfecho es crear el tag exacto:

`sigma-v3-r14-freeze-v1 -> b6ebc780cc0b201fd27562c85c64c90df37c1075`.

R15 permanece bloqueado hasta que ese tag exista. No se debe apuntar el tag a
los commits documentales posteriores.
