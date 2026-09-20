# Sigma v3 R13 — trazabilidad de seguridad y criptoanálisis

Fecha: 2026-09-20.  
Estado: **candidato de implementación R13; gate/adversarial review pendiente**.

Baseline inmutable de construcción:
`5ac306bb23acae0e0a4ef03eb56b3062343c2127` (R12.5 PASS).

R13 no cambia suites, domains, frames, KAT ni corpus R12.5. Sólo añade
formalización, atacantes reducidos, schemas y gates de diseño. Cualquier cambio
necesario en la función vuelve a abrir la construcción con nuevos IDs/candidato.

## Entregables

| Bloque | Artefacto | Estado |
|---|---|---|
| FORM-01..13 | `specification/security-analysis-v3-r13.md` | implementado; G-TRAJ-2PRE descompuesto |
| claim registry humano | `docs/claims-evidence-v3-r13.md` | implementado |
| attacker registry ejecutable | `experiments/r13_attack_registry.py` | implementado |
| history reduced model | `experiments/history_reduced.py` | implementado |
| HIST attackers | `experiments/history_attackers_v3.py` | implementado |
| reduced collision/preimage family | `experiments/trajectory_attacks_v3.py` | implementado |
| PARAM-01..06 | `experiments/parameter_grinding_v3.py` | implementado |
| TMTO | `experiments/tmto_v3.py` | implementado |
| Deep/DeepVector failure controls | `experiments/branch_failures_v3.py` | implementado |
| deterministic design pilots | `experiments/r13_pilots.py` | implementado; no confirmatory |
| history reduced tests | `tests/unit/test_history_reduced.py` | implementado |
| attacker tests | `tests/unit/test_r13_attackers.py` | implementado |
| authoritative design check | `scripts/check_r13_design.py` | integrado en CI/gate |

## Familias ejecutables

### HIST

- HIST-01: state crossing con mismo persistent binding y distinto history;
- HIST-02: full-state collision `(H_i,S_i)`;
- HIST-03: collision enumeration de HistoryStep reducido;
- HIST-04: skip/replay/reorder como control de conformidad;
- HIST-05: truncation ablation del history;
- HIST-06: fixed-layout vs history-adaptive layout.

### REDUCED

- RED-02: collision scaling de ventanas;
- RED-03: preimage de target window externo;
- RED-04: second-preimage con policy same/any persistent;
- RED-05: multi-target window attack.

### PARAM

- PARAM-01: distribución `(t,k)`;
- PARAM-02: correlaciones candidate/persistent ↔ `t,k`;
- PARAM-03: cheapest-stratum search;
- PARAM-04: KDF early rejection;
- PARAM-05: PoW nonce-cost grinding;
- PARAM-06: derived-cost vs fixed-cost mitigation.

### TMTO

Direct tables, distinguished points, rho, Hellman y rainbow, con recursos
offline/online/history/memory/depth separados y R12/R12.5 como baselines.

### BRANCH

Deep y DeepVector bajo constant/correlated/truncated/omitted/permuted branches,
constant fold y truncated fold cuando aplica.

## Gate de diseño

`scripts/check_r13_design.py`:

1. ejecuta pilotos deterministas con seed pública fija;
2. valida schemas contra `ATTACK_REGISTRY_V3`;
3. exige un piloto para todo attacker confirmatory-eligible;
4. exige `confirmatory=false` para todos los registros R13;
5. falla si desaparece un falsador, baseline o campo obligatorio.

El gate forma parte tanto de `scripts.validate_project` como de
`.github/workflows/ci.yml`.

## Criterio de cierre R13

Cada claim publicable debe tener:

1. juego/property;
2. recursos;
3. hipótesis;
4. teorema/reducción o etiqueta open/boundary;
5. atacante falsador;
6. baseline;
7. schema;
8. éxito/censura;
9. limitación explícita.

No se requieren resultados confirmatorios para cerrar R13. R14 congelará
presupuestos, sample sizes, discovery/holdout, configs y prerregistro. R15
producirá la evidencia cuantitativa. R16 mantiene la reproducción y revisión
criptográfica externa.
