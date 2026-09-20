# Sigma v3 R13 — matriz de claims y evidencia

Estado: **R13 design candidate; resultados confirmatorios pendientes de R15**  
Baseline de construcción: R12.5 `5ac306bb23acae0e0a4ef03eb56b3062343c2127`.

La columna "nivel" describe evidencia ya disponible. Los pilotos de diseño R13
validan interfaces y presupuestos, pero **no** elevan un claim a E2/E3.

| ID | Claim permitido | Nivel actual | Supuesto/límite | Falsador ejecutable | Evidencia actual | Siguiente evidencia |
|---|---|---|---|---|---|---|
| C01 | codecs aceptados son canónicos/injectivos por tipo | E1+E3 | contrato parser/spec | fuzz/negative corpus | R12.5 parser/fuzz PASS | mutation/grammar fuzz R15 |
| C02 | `H_i` compromete pasado estricto, no `S_i` | E1+E3 | semántica causal R12.5 | HIST-04 + causal tests | proof + unit/adversarial tests | reproducción R16 |
| C03 | mismo `S_i`, distinto `H_i` produce frame distinto | E1+E3 | encoding injectivo | HIST-01 | proof + KAT/property | reduced confirmatory R15 |
| C04 | igualdad de `S_i` no implica coalescencia | E1; E2 pendiente | C03 + transición modelada | HIST-01, HIST-02 | proof de separación + attacker ejecutable | crossing scaling R15 |
| C05 | igualdad de `Z_i=(H_i,S_i)` basta para coalescer | E1; E2 pendiente | determinismo | HIST-02 | proof | exhaustive reduced R15 |
| C06 | ventana de `k` estados exige coincidencias repetidas bajo `Sep_W/Fresh_W` | ideal-model | RO + queries separadas/fresh | HIST-01/02, RED-02/03/04/05, TMTO-01 | bound condicional + G-TRAJ-2PRE decomposition | scaling/2pre/multi-target R15 |
| C07 | backend/I/O no cambia la función | E3 | conformance | schedule/I/O adversary | R12.5 multiplatform PASS | reproducción externa R16 |
| C08 | layout ROUND es history-adaptive | E1+E3 | schedule R12.5 | HIST-06 | spec + corpus/KAT | distribución R15 |
| C09 | layout collision no elimina separación histórica | E1; E2 pendiente | history serializado como field | HIST-06 | encoding proof | forced-layout controls R15 |
| C10 | Deep está limitado por fold/composición | open/conditional | propiedad del fold | BRANCH-01 | attacker/control implementado | broken-fold confirmatory R15 |
| C11 | DeepVector consume el vector previo completo | E1+E3 | frame spec | BRANCH-01 | differential/product tests | branch controls R15 |
| C12 | ramas múltiples no suman bits automáticamente | boundary | no independencia automática | BRANCH-01 | claim boundary | correlated-branch R15 |
| C13 | rejection sampling es uniforme para seed fija | E1; E2 pendiente | ideal XOF stream | PARAM-01 | algorithmic proof + design harness | exhaustive/statistical R15 |
| C14 | uniformidad no impide grinding de estratos | E1; E2 pendiente | selección entre bindings | PARAM-02/03/06 | probability identity + attackers | grinding/mitigation R15 |
| C15 | Sigma no añade entropía ni memory-hardness a passwords | boundary | atribución a Argon2id | PARAM-04 / APP-KDF | explicit boundary | equal-budget KDF R15 |
| C16 | coste Sigma por guess puede sufrir early rejection | open | target `t,k` públicos | PARAM-04/06 | attacker implementado | KDF measurement R15 |
| C17 | PoW puede sufrir selección de nonces por coste | open | nonce controla `P,t,k` | PARAM-05/06 | attacker implementado | nonce-grinding R15 |
| C18 | firma autentica digest; mensaje requiere full verify | E1+E3 | Ed25519 EUF-CMA + codec | APP-SIG/replay | composition proof + tests | external review R16 |
| C19 | Python no tiene claim constant-time | boundary | — | SIDE (condicionado) | no claim | núcleo nativo si existe |
| C20 | no claim ASIC/GPU/VDF/PoSW | boundary | — | HW/parallel (condicionado) | no claim | artefacto hardware si existe |

## Registro ejecutable

La fuente autoritativa de attackers es `experiments/r13_registry.py`. Cada
entrada fija:

- claims afectados;
- baselines;
- recursos;
- condición de éxito;
- regla de censura;
- campos mínimos de salida;
- elegibilidad para futuro confirmatorio.

`scripts/check_r13_design.py` exige que todo attacker
`confirmatory_eligible=True` tenga un piloto ejecutable y un schema válido.
`HIST-04` es deliberadamente un control de conformidad y no un experimento
confirmatorio.

## Reglas de uso

- Un piloto R13 nunca aparece como resultado científico del paper.
- Un resultado E2/E3 no se reescribe como E1.
- NIST STS/PractRand/TestU01 son controles descriptivos, no pruebas de seguridad.
- `state_size + history_size` nunca se publica como seguridad aditiva.
- Un PASS de ingeniería no se denomina auditoría criptográfica.
- Un ataque que no encuentra éxito sólo excluye éxitos dentro de su presupuesto,
  estrategia y modelo.
