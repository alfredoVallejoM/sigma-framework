# Sigma v3 R13 — trazabilidad de seguridad y criptoanálisis

Fecha: 2026-09-20.  
Estado: **R13 abierto; formalización base implementada**.

Baseline inmutable de construcción:
`5ac306bb23acae0e0a4ef03eb56b3062343c2127` (R12.5 PASS).

## Entregables

| Bloque | Artefacto | Estado |
|---|---|---|
| FORM-01..13 | `specification/security-analysis-v3-r13.md` | base formal creada |
| claim registry | `docs/claims-evidence-v3-r13.md` | creada |
| history reduced model | `experiments/history_reduced.py` | pendiente en este gate |
| reduced tests | `tests/unit/test_history_reduced.py` | pendiente en este gate |
| HIST-01..06 pilot attackers | experiment harness | abierto |
| PARAM-01..06 | parameter/grinding harness | abierto |
| TMTO | attacker registry | abierto |
| Deep/DeepVector failure controls | branch harness | abierto |

R13 no modifica suites, domains, frames, KAT o corpus R12.5. Cualquier necesidad
de cambiar la construcción vuelve a abrir R12.5 con nuevos IDs/candidato.

## Criterio R13

R13 cerrará cuando cada claim publicable tenga:

1. juego;
2. recursos;
3. hipótesis;
4. teorema/reducción o etiqueta open;
5. atacante falsador;
6. baseline;
7. esquema de datos;
8. criterio de éxito/censura;
9. limitación explícita.

No se necesitan resultados confirmatorios para cerrar R13; éstos pertenecen a
R15.
