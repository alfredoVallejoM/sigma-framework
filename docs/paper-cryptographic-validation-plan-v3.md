# Sigma v3 — plan científico, criptográfico y de seguridad para el paper

Estado: **plan maestro de evidencia post-R12.5**  
Fecha: 2026-09-20

## 1. Doctrina de evidencia

Ninguna batería estadística sustituye al criptoanálisis. Toda afirmación se
clasifica como: proved, reduced, ideal-model, exhaustive-reduced, empirical,
engineering-conformance u open.

Niveles:

| Nivel | Evidencia | Uso |
|---|---|---|
| E0 | especificación | define la función |
| E1 | teorema/reducción | propiedad bajo hipótesis explícitas |
| E2 | enumeración/modelo reducido | mecanismo y scaling exhaustible |
| E3 | medición de implementación | rendimiento, memoria, difusión, robustez |
| E4 | reproducción externa | independencia de host/autor |
| E5 | revisión criptográfica externa | seguridad revisada por terceros |

Cada claim debe tener definición, adversario, recursos, supuesto, teorema o
hipótesis, código, test de conformidad, experimento refutador, baseline, raw
data, análisis, figura/tabla, resultado negativo, reproducción y estado de
revisión.

## 2. FORM — formalización y reducciones

FORM-01 Canonicalidad: inyectividad de records, transcripts, placed streams,
frames, headers, windows y aplicaciones. Atacar duplicados, orden, longitudes,
trailing bytes, aliases, downgrade y concatenación ambigua.

FORM-02 Historia causal:

\[
H_0=Seed(C,P_X), \qquad H_{i+1}=Step(C,i,H_i,S_i).
\]

Probar ausencia de circularidad y qué prefijo causal compromete cada H_i.

FORM-03 Separación histórica: H_i distinto o S_i distinto debe producir input
de ronda distinto salvo fallo del encoding/domain separation.

FORM-04 No coalescencia: juego en el que dos trayectorias distintas reciben una
colisión observable S_i=S_i'. Determinar qué evento adicional permite mantener
S_{i+1}=S_{i+1}'.

FORM-05 Coalescencia completa: caracterizar qué igualdad del estado dinámico
Z_i=(H_i,S_i) basta para producir sucesores iguales.

FORM-06 Juegos separados: G-COLL, G-PRE, G-2PRE, G-SEG-COLL, G-TRAJ-2PRE y
G-MULTI. Nunca derivar preimage de collision resistance.

FORM-07 Ventana multiestado: bounds sólo bajo freshness y separación histórica;
explicitar cuellos de botella del anchor, history y fuente.

FORM-08 Deep: separar seguridad del estado escalar, ramas, fold y correlaciones.

FORM-09 DeepVector: reducción conservadora a componentes sin asumir suma
aditiva de seguridades.

FORM-10 Parámetros derivados: distribución de (t,k), rechazo sin sesgo y
adversarios que seleccionan estratos baratos.

FORM-11 Layout: slots, ties, dependencia de length/context/history, equivalencia
de planes y carácter content-adaptive o no.

FORM-12 Aplicaciones: juegos distintos para firma, message binding, KDF offline
guessing, PoW nonce search y downgrade/cross-protocol.

FORM-13 Recursos: toda afirmación publica
(W,Q_A,Q_H,Q_R,d,p,mu,u): trabajo, queries de anchor/history/round, profundidad
adaptativa, procesadores, memoria y objetivos.

## 3. CONFORM — conformidad byte-exacta

CONFORM-01 Triple oracle: comparar implementación productiva, referencia
independiente y corpus congelado en todos los intermedios.

CONFORM-02 Backends/I-O: serial, threads, process, mmap, file, bytes, spool e
incremental. Cero divergencias.

CONFORM-03 Plataformas: Python 3.10–3.13; Linux x86-64; macOS ARM64; Windows
x86-64; segundo host Linux independiente.

CONFORM-04 Metamorphic: rechunking, copia de fichero, backend y scheduling no
cambian digest; mutar un campo cambia su transcript; checkpoint de prefijo
coincide con evaluación directa.

CONFORM-05 Negative corpus: corpus versionado de entradas inválidas para todos
los parsers, frames y aplicaciones.

## 4. HIST — ataques al feedback histórico

HIST-01 State crossing: encontrar en modelos reducidos S_i^X=S_i^Y con
H_i^X != H_i^Y y comprobar que no hay coalescencia automática. Medir nueva
coincidencia, queries, longitud de racha y tiempo hasta reseparación.

HIST-02 Full-state collision: buscar (H_i,S_i)=(H_i',S_i') y comparar scaling
con colisión sólo de S_i.

HIST-03 History collision: collision, second-preimage, multicollision,
fixed-point, cycle y chosen-prefix contra HistoryStep reducido.

HIST-04 Skip/replay/reorder: history antiguo, history de otra ronda, ronda
omitida/duplicada, estado reordenado e índice equivocado. Silent acceptance
bloquea el gate.

HIST-05 Truncation ablation: variar anchura reducida de history para identificar
el cuello de botella real.

HIST-06 History-aware layout: si el layout incorpora H_i, comparar history sólo
en valores frente a history también en la seed del placement.

## 5. REDUCED — criptoanálisis exacto/reducido

RED-01 Enumeración exhaustiva: imagen, preimages por output, collisions,
second-preimages, ciclos, componentes funcionales y longitudes tail/cycle.

RED-02 Collision scaling: anchuras geométricas, múltiples seeds y ajuste de
log2 Q50 frente a bits efectivos con intervalos.

RED-03 Preimage scaling: separado de collision; objetivos uniformes y objetivos
de mensajes reales.

RED-04 Second-preimage: fijar el mensaje objetivo antes de la seed del atacante.

RED-05 Multi-target: variar u y comprobar el factor de unión.

RED-06 Chosen-prefix/related-input: prefijos controlados, longitudes
iguales/diferentes y contextos relacionados.

RED-07 Multicollision: estudiar reutilización entre niveles con y sin history.

RED-08 Herding/Nostradamus: comprometer destino y conectar después prefijos.

RED-09 Expandable messages/long-message 2PRE: ejecutar sólo cuando la semántica
de cardinalidad lo haga metodológicamente comparable.

## 6. TMTO — precomputación y tradeoffs tiempo-memoria

Atacantes: Pollard rho, distinguished points, Hellman, rainbow, tablas por
estrato (t,k), precomputación por layout y multi-target shared tables.

Métricas: trabajo offline/online, memoria, Q_A, Q_H, Q_R, reutilización,
profundidad adaptativa y speedup amortizado.

Figura obligatoria: frontera tiempo-memoria por construcción y baseline.

## 7. PARAM — grinding y estratificación

PARAM-01 Uniformidad del rejection sampling por enumeración reducida y
simulación grande.

PARAM-02 Correlaciones de (t,k) con length, anchor, J, history genesis, digest y
layout.

PARAM-03 Cheapest-stratum search: coste de generar candidatos hasta obtener una
trayectoria barata y ahorro neto.

PARAM-04 KDF early rejection: medir si un guess incorrecto puede descartarse
después de derivar (t,k) y antes de pagar la trayectoria completa.

PARAM-05 PoW nonce grinding: costes por nonce, selección de trayectorias baratas
y efecto en intentos/s.

PARAM-06 Mitigaciones: comparar parámetros derivados del input, fijados por
contexto, buckets de coste y perfiles especiales de KDF/PoW.

## 8. LAYOUT — placement

LAYOUT-01 distribución de slots.
LAYOUT-02 frecuencia y efecto de ties.
LAYOUT-03 equivalencia entre mensajes de igual longitud.
LAYOUT-04 sensibilidad al history si entra en la seed.
LAYOUT-05 fronteras: 0,1, chunks, potencias de dos y máximos.
LAYOUT-06 shift/splice: inserción, borrado, desplazamiento y splicing intentando
preservar placed stream.

## 9. DIFF — diferencial, avalanche y dependencia

Estas pruebas son controles, no pruebas de seguridad.

DIFF-01 SAC por capa y ronda, perturbando mensaje, contexto, anchor, J, history,
estado e índice.

DIFF-02 BIC con intervalos y corrección por múltiples comparaciones.

DIFF-03 Hamming distance completa: media, varianza, quantiles y peor sesgo.

DIFF-04 Mutual information entre input/output, ramas, rounds consecutivos,
history/state y componentes DeepVector.

DIFF-05 Differential trails reduced: búsqueda de diferencias de baja activación.

DIFF-06 Broken-branch controls: rama constante, identidad, copia y truncada para
comprobar qué claims sobreviven.

## 10. ALG — análisis algebraico/estructural reducido

- grado algebraico por ronda;
- crecimiento de monomios;
- ANF en tamaños exhaustibles;
- invariantes lineales/afines;
- fixed points y cycles;
- simetrías de permutación;
- relaciones rotational/slide-like cuando el modelo lo permita;
- SAT/SMT para collisions/preimages reducidas;
- MILP para trails cuando exista codificación válida.

Guardar instancia, solver, versión, timeout, modelo/certificado y seed.

## 11. STAT — baterías estadísticas externas

Streams separados por suite, estado, domain y corpus. Nunca mezclar bytes de
framing con bytes presentados como pseudoaleatorios.

Baterías:
- NIST STS / SP 800-22 como control descriptivo;
- PractRand;
- TestU01 SmallCrush;
- TestU01 Crush;
- BigCrush sólo si adaptador y presupuesto son válidos.

Controles: SHA-512, SHA3-512, BLAKE2b-512, SHAKE256-512 y fuente
deliberadamente defectuosa.

Registrar versión, comando, endianness, adaptación bit/byte, tamaño de stream,
tests no aplicables y logs completos. Pasar estas baterías nunca se interpreta
como certificación criptográfica.

## 12. BRANCH — Deep y DeepVector

BRANCH-01 omisión de rama.
BRANCH-02 reorder posición/algoritmo.
BRANCH-03 duplicación de rama.
BRANCH-04 primitivas correlacionadas.
BRANCH-05 fold truncado/constante/reducido en Deep.
BRANCH-06 cambio de cualquier componente de DeepVector debe afectar a todas las
ramas siguientes.
BRANCH-07 fold vs vector scaling a coste normalizado comparable.

## 13. FAULT — fault injection

Bit flips en mensaje/history/state; branch skip; round skip; ronda duplicada;
stale history; wrong index; layout/fold corruptos; partial write; process
failure; cancelación en cada frontera canónica.

Métricas: detección, latencia de propagación, primera capa divergente y silent
acceptance. No llamarlo DFA sin modelo específico.

## 14. APP-SIG — firma

- sustitución de digest/suite/key id;
- cross-wire y downgrade;
- replay;
- attestation frente a full verification;
- reuse experiments en anchuras reducidas.

Claim permitido: Sigma no fortalece Ed25519; separa autenticación del digest de
binding completo al mensaje.

## 15. APP-KDF — contraseñas

Baselines: Argon2id; Argon2id+WideOnce; +Deep; +DeepVector.

Métricas: latencia, RSS, guesses/s, preparación, rondas, early rejection por
(t,k), variabilidad entre passwords y efecto salt/context.

Seguridad: record sin secreto, key no serializable, parámetros baratos antes de
Argon2, malformed records, downgrade y resource DoS. No atribuir entropía ni
memory-hardness adicional a Sigma.

## 16. APP-POW — PoW experimental

Distribución geométrica, intentos por dificultad, nonce throughput, full verify,
preparation/round cost, grinding de (t,k), paralelismo, challenge separation,
replay, downgrade y resource DoS.

No reclamar VDF, PoSW, consenso, ASIC resistance ni verificación barata.

## 17. PARSE — parsers y API hostil

Fuzzing mutacional determinista, Atheris coverage-guided, grammar-aware,
differential parser fuzzing y corpus minimization.

Targets: context, binding, history, layout, frames, digest, explicit evidence,
firma, KDF y PoW.

Property-based: límites exactos, bool/int confusion, enteros enormes, secuencias
vacías/máximas, truncación en cada byte, tags desconocidos/duplicados.

Mutation testing sobre codecs, validaciones, history update, domains, índices,
length checks y application policy. Todo mutante conductual superviviente se
clasifica.

## 18. DOS — recursos

Atacar records límite/+1, secuencias máximas, spool limits, declared lengths,
t/k fuera de política, worker explosion, file mutation, disk-full, permisos,
cancelación y process crash.

Métricas: tiempo hasta rechazo, memoria pico, bytes leídos, temporales y
procesos/hilos residuales. Validaciones baratas antes de hashing/spool/Argon2.

## 19. CONC — concurrencia

Schedules aleatorios, workers 1..N, process start methods, delays, reorder de
completion, exceptions, cancellation races, concurrent file mutation y repeated
finalization. Cero divergencias matemáticas y cero publicación parcial.

## 20. PERF — rendimiento y complejidad

Medir por separado canonical source, anchor, J, parameter derivation, layout,
history update, round frame, branch work, fold, digest encoding y full verify.

Métricas: ns/op, ciclos cuando sean fiables, ops/s, bytes/s sólo para tareas que
procesan bytes, RSS, allocations, I/O, speedup y eficiencia paralela.

Sweeps: tamaño de mensaje, t, k, workers, branch count, state width y history
width. Ajustar exponentes empíricos y compararlos con costes derivados del
código.

## 21. SIDE — side channels condicionada

Python no recibe claim constant-time.

Sólo con núcleo nativo revisable: dudect/TVLA fixed-vs-random, timing,
cache/perf counters, branch counters, ensamblado archivado, compilador/flags y
ctgrind/instrumentación apropiada cuando aplique.

Sin núcleo nativo: no evaluado / no claimed.

## 22. HW — hardware condicionada

Sin RTL o implementación hardware, testbench, síntesis reproducible,
tecnología/corner, área, frecuencia, potencia, memoria y baseline comparable no
existe claim ASIC/GPU/FPGA.

## 23. SUPPLY — release y supply chain

Wheel/sdist reproducibles; SHA-256; CycloneDX SBOM; provenance/attestation;
CI actions fijadas/revisadas; dependency audit; instalación aislada; spec,
reference y corpus incluidos; tag limpio; hash de dataset y scripts.

## 24. Diseño científico

Pilotos: sólo dimensionan coste, varianza, effect size y timeouts.

Prerregistro antes del confirmatorio: hipótesis, endpoints, factores, sample
sizes, seeds, exclusiones, stopping rules, censura, análisis, corrección
múltiple, figuras y presupuesto.

Discovery/holdout para atacantes heurísticos: el atacante se ajusta sólo en
discovery y se evalúa en holdout inmutable.

Repetición: múltiples seeds y hosts, orden aleatorio de tratamientos, warm-up
cuando proceda, intervalos, effect sizes y publicación de resultados negativos.

### Publication-scale rule

Las curvas principales de R15 deben tener al menos 6 puntos estimables,
preferiblemente 7–8, con pasos de 2 bits cuando se estudien anchuras y con
puntos adicionales de stress/censoring cuando sean informativos.

Los primary endpoints reportan 95% CI. Rare/zero-event boundaries reportan
además 99% one-sided upper bounds. El target de power es 95% cuando el power
calculation sea aplicable; 90% es el mínimo excepcional.

El tamaño exacto por familia se gobierna por
`experiments/r15-publication-scale-plan.json` y se materializa durante
R14.1 antes de cualquier dato R15.

### Streaming/data rule

Volumen procesado no equivale a volumen retenido. Los streams estadísticos
grandes son deterministically regenerable ephemeral computation:

[
seed+generator+length+hash Rightarrow stream.
]

Git no almacena grandes streams. PractRand/TestU01/NIST deben consumir pipes,
callbacks o un único fichero temporal por vez. El límite objetivo de scratch es
10 GiB general y 2 GiB preferido para STAT. El archive científico retenido se
mantiene en el orden de 1–5 GiB o menos.

La política exacta está en `experiments/r15-data-policy.json`.

## 25. Baselines obligatorios

- SHA-512;
- SHA3-512;
- BLAKE2b-512;
- SHAKE256-512;
- hash chain ordinaria;
- R12 anchor-reinjection sin history;
- R12.5 history feedback;
- Deep;
- DeepVector;
- construcción deliberadamente defectuosa.

R12 es un baseline de ablación: mide exactamente qué aporta H_i sin
reinterpretar su PASS histórico.

## 26. Figuras principales del paper

F1 arquitectura P_X -> (H_i,S_i).  
F2 cruce de S_i sin coalescencia histórica.  
F3 collision scaling: S_i frente a (H_i,S_i).  
F4 rachas multiestado y scaling con k.  
F5 second-preimage reducida.  
F6 frontera tiempo-memoria.  
F7 distribución y grinding de (t,k).  
F8 layout/history ablation.  
F9 Deep vs DeepVector.  
F10 coste descompuesto.  
F11 memoria/workers.  
F12 KDF early rejection.  
F13 PoW nonce-cost grinding.  
F14 diffusion/BIC controls.  
F15 conformance multiplataforma.

Tablas mínimas: IDs/domains/suites; claims/evidencia; teoremas/supuestos;
corpus/KAT; mejor ataque; resultados negativos; rendimiento; reproducción por
host; hallazgos adversariales; limitaciones.

## 27. Artefactos mínimos del paper

Especificación byte-exacta post-R12.5; reference independiente; corpus/KAT;
matriz de claims; security analysis; preregistration; raw confirmatory dataset;
manifests; scripts de análisis; figuras generadas; logs de baterías externas;
wheel/sdist; SBOM/checksums; adversarial review; reproducción externa; dataset
archivado con identificador persistente.

## 28. Gates revisados

R12.5 — History Feedback Restoration: recurrencia histórica y nueva revisión
adversarial.

R13 — Formal Security & Cryptanalysis Design: FORM-01..13, modelos de amenaza,
attackers y matriz claim/evidence. Sin resultados confirmatorios.

R14 — Experimental Freeze: implementación/IDs/wire/corpus/attackers/schemas,
pilotos y prerregistro congelados; gates remoto y local verdes sobre tag limpio.

R15 — Confirmatory Scientific Campaign: ejecutar exclusivamente el conjunto
confirmatorio finalmente congelado en R14.1, a escala de publicación y con
política streaming/storage reproducible. Conservar fallos, censura y resultados
negativos. DIFF/FAULT/PARSE/DOS/CONC/PERF no se incorporan retroactivamente como
nuevas campañas confirmatorias si no figuran en el freeze final.

R16 — External Reproduction & Publication: segundo host/persona, reproducción,
archivo persistente y revisión criptográfica externa.

## 29. Criterio de terminado

Por cada resultado principal:

1. juego/property;
2. construcción exacta;
3. hipótesis;
4. baseline;
5. atacante;
6. condición de falsación;
7. raw data;
8. análisis;
9. incertidumbre;
10. resultado negativo que limita interpretación;
11. reproducción externa;
12. nivel E0–E5.

Si falta uno, se etiqueta como hipótesis, observación preliminar o trabajo
futuro.
