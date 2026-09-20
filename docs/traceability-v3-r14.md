# Sigma v3 R14 — trazabilidad del freeze experimental

Fecha: 2026-09-20.  
Estado: **R14 planificado; implementación no iniciada**.

Baselines:

- R12.5 construction PASS: `5ac306bb23acae0e0a4ef03eb56b3062343c2127`;
- R13 design PASS: `8a71de3d350ea8215c481e16c9eadbeed54066ef`.

R14 no puede cambiar suites, domains, wire, KAT, history semantics ni attacker
meaning. Si aparece una necesidad de modificar la función, R12.5/R13 deben
reabrirse con un nuevo candidato.

## Etapas

| Etapa | Objetivo | Estado |
|---|---|---|
| R14.0 | freeze boundary e inventario | pendiente |
| R14.1 | schemas experimentales v3 | pendiente |
| R14.2 | pilotos de dimensionamiento | pendiente |
| R14.3 | sample sizes/power/precision | pendiente |
| R14.4 | discovery/holdout | pendiente |
| R14.5 | preregistration v3 | pendiente |
| R14.6 | configs confirmatorias | pendiente |
| R14.7 | artifact freeze | pendiente |
| R14.8 | adversarial freeze review | pendiente |

## Artefactos obligatorios

- `docs/r14-experimental-freeze-plan.md`;
- `experiments/preregistration-v3.md`;
- `experiments/pilot-decision-record-v3-r14.json`;
- `experiments/configs/confirmatory-v3-r14/`;
- `experiments/freeze-v3-r14.json`;
- `scripts/check_r14_freeze.py`;
- `tests/unit/test_r14_freeze.py`;
- `docs/adversarial-reviews/R14.md`.

## Gate

R14 PASS requiere que R15 pueda ejecutarse desde un tag limpio y un wheel
instalado fuera del checkout sin tomar ninguna decisión nueva sobre hipótesis,
presupuestos, seeds, endpoints, análisis o figuras.
