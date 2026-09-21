# Sigma v3 R14 — traceability

Fecha: 2026-09-20.  
Estado: **R14 abierto — planificación de freeze creada**.

Baselines:

- R12.5 PASS: `5ac306bb23acae0e0a4ef03eb56b3062343c2127`;
- R13 PASS: `8a71de3d350ea8215c481e16c9eadbeed54066ef`.

R14 no cambia la construcción. Su salida es un protocolo experimental
congelado y preregistrado que desbloquea R15.

| Bloque | Artefacto esperado | Estado |
|---|---|---|
| R14-A baseline lock | baseline guard R12.5/R13 | pendiente |
| R14-B campaign inventory | claim/attack disposition | pendiente |
| R14-C pilot budgeting | pilot decision record v3 | pendiente |
| R14-D protocol lock | statistical protocol | pendiente |
| config schema | v3 confirmatory config schema | pendiente |
| result schema | confirmatory raw-record schema | pendiente |
| discovery configs | frozen discovery set | pendiente |
| confirmatory configs | frozen R15 config set | pendiente |
| analysis | scripts + synthetic fixtures | pendiente |
| figures | predeclared figure/table builders | pendiente |
| artifact freeze | wheel/sdist/SBOM/checksums | pendiente |
| preregistration | `experiments/preregistration-v3.md` | pendiente |
| freeze manifest | canonical hash manifest | pendiente |
| R14 gate | `scripts/check_r14_freeze.py` | pendiente |
| adversarial review | `docs/adversarial-reviews/R14.md` | pendiente |

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
