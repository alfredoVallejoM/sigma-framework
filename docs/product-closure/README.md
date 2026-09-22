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

## Primer bloque autorizado

El primer bloque implementable es ST0 — Sigma Tree core extraction.

Antes de escribir ST1-ST4 se debe cerrar ST0 y demostrar que:
1. ninguna KAT histórica cambia;
2. TreeCore tiene una única semántica;
3. legacy_v22 está aislado;
4. reference y production coinciden;
5. el contrato de complejidad está instrumentado.
