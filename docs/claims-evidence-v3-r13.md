# Sigma v3 R13 — matriz de claims y evidencia

Estado: **working claim registry**  
Candidato de construcción: R12.5 `5ac306bb23acae0e0a4ef03eb56b3062343c2127`.

| ID | Claim permitido | Nivel actual | Supuesto principal | Falsador/ataque | Evidencia requerida |
|---|---|---|---|---|---|
| C01 | los codecs aceptados son canónicos/injectivos por tipo | E1+E3 | parsers cumplen spec | parser differential/fuzz | negative corpus + fuzz |
| C02 | `H_i` compromete el pasado estricto, no `S_i` | E1 | spec causal | skip/reorder/replay | causal property tests |
| C03 | mismo `S_i`, distinto `H_i` produce frame distinto | E1 | encoding injectivo | state-cross mutation | KAT + property + HIST-01 |
| C04 | igualdad de `S_i` no implica coalescencia | E1/E2 | C03 + modelo de transición | HIST-01 | reduced crossing experiment |
| C05 | igualdad de `Z_i=(H_i,S_i)` es suficiente para coalescer | E1 | determinismo | full-state mutation | proof + reduced exhaustive |
| C06 | ventana de k estados exige coincidencias repetidas mientras history difiera | ideal-model | RO/freshness | HIST-01/02 | reduced scaling; no concrete-bit claim |
| C07 | R12.5 no es más débil por cambiar backend/I/O | E3 | conformance | schedule/I/O adversary | R12.5 gate + cross-platform |
| C08 | layout es history-adaptive | E1+E3 | SHAKE schedule spec | LAYOUT-04 | vectors + distribution pilot |
| C09 | layout collision no elimina separación histórica | E1 | history serialized in placed stream | force same plan | encoding proof + reduced control |
| C10 | Deep está limitado por fold y composición | open/conditional | fold assumptions | broken-fold controls | BRANCH-05/07 |
| C11 | DeepVector preserva dependencia del vector completo | E1+E3 | frame spec | single-component mutation | differential + BRANCH-06 |
| C12 | ramas múltiples no suman bits automáticamente | boundary | no independence assumption | correlated/broken branch | BRANCH-04/06 |
| C13 | rejection sampling es uniforme para seed fija | E1/E2 | ideal XOF bytes | exhaustive small ranges | PARAM-01 |
| C14 | uniformidad no impide grinding de estratos | E1 | adversary samples candidates | cheapest-stratum search | PARAM-03 |
| C15 | Sigma no añade entropía ni memory-hardness a passwords | boundary | Argon2 attribution | offline guessing | APP-KDF |
| C16 | coste Sigma por guess puede sufrir early rejection | open | public target t,k | PARAM-04 | KDF attack measurement |
| C17 | PoW puede sufrir selección de nonces por coste | open | nonce controls P/t/k | PARAM-05 | nonce-grinding measurement |
| C18 | firma autentica digest, no demuestra mensaje sin full verify | E1 | Ed25519 EUF-CMA | replay/substitution | APP-SIG |
| C19 | Python no tiene claim constant-time | boundary | — | timing | no security claim |
| C20 | no existe claim ASIC/GPU/VDF/PoSW | boundary | — | hardware/parallel attack | explicitly out of scope |

## Reglas de uso

- Un resultado E2/E3 no se reescribe como E1.
- NIST STS/PractRand/TestU01 sólo pueden apoyar controles descriptivos.
- `state_size + history_size` nunca se publica como seguridad aditiva.
- Un PASS de ingeniería no se denomina auditoría criptográfica.
- Un resultado negativo del ataque se publica con su presupuesto, no como
  prueba de inexistencia de ataques mejores.
