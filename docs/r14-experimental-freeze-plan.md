# Sigma v3 R14 — freeze experimental y prerregistro científico

Estado: **plan rector R14; ejecución no iniciada**  
Fecha: 2026-09-20  
Baseline criptográfico/constructivo inmutable: R12.5 `5ac306bb23acae0e0a4ef03eb56b3062343c2127`  
Baseline de diseño de seguridad: R13 `8a71de3d350ea8215c481e16c9eadbeed54066ef`

## 1. Objetivo de R14

R14 no añade una nueva construcción criptográfica ni nuevos claims. Su función
es convertir la línea R12.5+R13 en un **objeto experimental congelado** que
pueda producir en R15 un dataset confirmatorio científicamente defendible.

R14 termina cuando quedan fijados, antes de observar datos confirmatorios:

- commit y tag candidato;
- wheel/sdist exactos;
- corpus y referencia;
- attacker registry;
- schemas;
- configs;
- seeds y política de derivación de seeds;
- tamaños muestrales y presupuestos;
- discovery/holdout;
- stopping rules;
- censura/timeouts;
- endpoints;
- análisis estadístico;
- corrección por comparaciones múltiples;
- figuras/tablas predefinidas;
- reglas de exclusión;
- definición de resultados negativos;
- política de host/multiplataforma;
- manifiesto de freeze;
- prerregistro completo.

R14 **no** ejecuta la campaña confirmatoria principal. Los pilotos R14 son
desechables y sólo dimensionan presupuesto, varianza, precisión y factibilidad.

## 2. Principio de no-retroajuste

Después del freeze R14:

1. no se cambia ningún byte normativo de R12.5;
2. no se cambia ningún attacker confirmatory-eligible;
3. no se cambian endpoints primarios/secundarios;
4. no se cambian sample sizes salvo regla adaptativa prerregistrada;
5. no se cambian stopping/censoring rules;
6. no se cambian análisis/plots principales;
7. no se descartan resultados por dirección del efecto;
8. cualquier desviación crea un nuevo freeze id y debe declararse.

Una corrección de bug que cambie resultados matemáticos invalida el freeze.
Una corrección puramente documental puede preservarlo sólo si no altera ninguna
decisión experimental.

## 3. Etapas R14

### R14.0 — Inventario y freeze boundary

Objetivo: definir exactamente qué entra y qué queda fuera del artefacto.

Entregables:

- `docs/traceability-v3-r14.md`;
- lista de ficheros normativos;
- lista de ficheros experimentales congelables;
- hashes R12.5/R13;
- mapa claim -> attacker -> experiment family -> endpoint;
- declaración explícita de elementos fuera de scope.

Gate R14.0:

- R12.5 PASS intacto;
- R13 PASS intacto;
- ningún diff en suites/domains/frames/KAT/corpus;
- atacante confirmatorio sin claim asociado => error;
- claim publicable sin falsador => error.

### R14.1 — Schemas experimentales v3

Cada familia debe tener schema cerrado, versionado y validado antes de crear
outputs.

Familias mínimas:

- HIST;
- REDUCED;
- PARAM;
- TMTO;
- BRANCH;
- LAYOUT;
- DIFF;
- ALG;
- STAT;
- FAULT;
- APP-SIG;
- APP-KDF;
- APP-POW;
- PARSE;
- DOS;
- CONC;
- PERF.

Campos globales obligatorios:

- `schema_version`;
- `campaign`;
- `experiment_family`;
- `attack_id` cuando aplica;
- `construction`;
- `baseline`;
- `master_seed`;
- `execution.tasks`;
- `budget`;
- `endpoints`;
- `censoring`;
- `analysis_plan_id`;
- `artifact_path`;
- `freeze_manifest`.

Gate R14.1:

- unknown field rejection;
- invalid ranges rejected before output creation;
- canonical JSON;
- schema round-trip;
- every config validates against exactly one experiment family.

### R14.2 — Pilotos de dimensionamiento

Los pilotos son descartables y no pueden alimentar tablas/figuras finales.

Objetivos:

- estimar tiempo por unidad;
- memoria pico;
- varianza;
- tasa de censura;
- probabilidad de encontrar eventos raros;
- estabilidad entre hosts;
- coste de atacantes;
- sensibilidad de endpoints;
- tamaño viable de streams estadísticos.

Para cada familia se genera un `pilot-decision-record-v3-r14.json` que guarda
sólo decisiones de dimensionamiento, nunca raw results como evidencia del paper.

Gate R14.2:

- ningún piloto marcado `confirmatory=true`;
- decisión de sample size trazable a una regla;
- presupuesto total estimado;
- no reutilización de seeds confirmatorias;
- pilotos y confirmatorio usan namespaces de seed distintos.

### R14.3 — Sample sizes y power/precision contracts

No se permite escoger N por conveniencia.

#### Bernoulli/eventos raros

Para tasas de éxito/collision/event persistence:

- intervalos exactos o Wilson según preregistro;
- si se observan 0 eventos, informar upper bound compatible con N;
- N se fija por precisión objetivo o probabilidad mínima detectable.

#### Scaling

Para modelos `log2 Q = a n + b`:

- anchuras fijadas antes del confirmatorio;
- número de repeticiones por anchura fijado por varianza piloto;
- ajuste primario y modelo alternativo definidos antes de datos.

#### Rendimiento

- número de warmups;
- repeticiones;
- orden aleatorizado de tratamientos;
- bloque por host;
- mediana/quantiles e intervalo;
- ninguna comparación de timing mezcla hosts sin modelar host.

#### Estadística externa

- tamaño de stream;
- transformación byte/bit;
- batería/versión;
- tests no aplicables;
- regla para p-values;
- no se usa "pass all" como claim criptográfico.

Gate R14.3:

- sample-size table congelada por endpoint;
- precisión/power target documentado;
- stopping rule explícita;
- ninguna regla depende del signo observado en piloto.

### R14.4 — Discovery/holdout para atacantes adaptativos

Aplica a:

- SAT/SMT;
- TMTO heurístico;
- chosen-prefix search;
- differential trail search;
- parameter grinding heuristics;
- branch/fold adversaries.

Se separan:

- `discovery_seed_namespace`;
- `holdout_seed_namespace`.

El atacante se diseña y ajusta sólo en discovery. El holdout es inmutable.

Gate R14.4:

- hashes del código atacante congelados;
- holdout inaccessible por el workflow de tuning;
- cualquier cambio del attacker después de ver holdout invalida el freeze.

### R14.5 — Prerregistro v3

Crear `experiments/preregistration-v3.md`.

Debe contener:

1. preguntas primarias;
2. hypotheses directionales/no direccionales;
3. claims que cada experimento puede y no puede soportar;
4. variables;
5. baselines;
6. budgets;
7. seeds;
8. sample sizes;
9. endpoints primarios/secundarios;
10. stopping rules;
11. censoring;
12. exclusions;
13. multiple-comparison correction;
14. statistical models;
15. figures/tables;
16. negative-result interpretation;
17. host/platform matrix;
18. external battery protocol;
19. artifact retention;
20. deviation policy.

Gate R14.5:

- preregistration hash estable;
- revisión humana explícita;
- ninguna sección "TBD" para un endpoint confirmatorio.

### R14.6 — Configs confirmatorias congeladas

Crear `experiments/configs/confirmatory-v3-r14/`.

Toda config debe:

- seleccionar un attack/experiment registrado;
- bindear preregistration SHA-256;
- bindear wheel SHA-256;
- bindear freeze manifest;
- declarar host requirements;
- declarar timeout;
- declarar tareas;
- declarar expected schema, no expected result.

El sistema de runner debe rechazar:

- config fuera del freeze;
- wheel distinto;
- commit/tag distinto;
- dirty tree;
- preregistration distinta;
- config alterada;
- seed namespace incorrecto.

### R14.7 — Artifact freeze

Construir desde checkout limpio:

- wheel;
- sdist;
- checksums;
- SBOM;
- corpus R12;
- corpus R12.5;
- independent reference;
- R13 registry/attackers;
- confirmatory configs;
- preregistration;
- analysis scripts;
- figure specifications;
- environment constraints.

Crear `freeze-v3-r14.json` con hashes de todo.

Requisitos:

- exact tag;
- clean tree;
- reproducible manifest;
- artifact path no apuntando al checkout editable;
- wheel smoke v2.2 + R12.5;
- baseline guard;
- independent consumer checks.

### R14.8 — Adversarial freeze review

Crear `docs/adversarial-reviews/R14.md`.

La revisión debe intentar romper:

- config tampering;
- manifest substitution;
- seed reuse;
- discovery/holdout leakage;
- preregistration mismatch;
- attacker drift;
- wheel/source mismatch;
- dirty-tag execution;
- schema downgrade;
- silent censoring;
- overwrite/resume;
- missing negative outcomes;
- host metadata omissions.

Gate final R14:

- authoritative local gate PASS;
- CI matrix PASS;
- freeze checker PASS;
- preregistration checker PASS;
- all configs frozen;
- wheel/sdist hashes frozen;
- artifact manifest frozen;
- R14 adversarial PASS versionado.

## 4. Matriz de familias experimentales

| Familia | Pregunta primaria | Baseline mínimo | Resultado principal |
|---|---|---|---|
| HIST | ¿history impide coalescencia por cruce visible? | R12 vs R12.5 | crossing/full-state rates y scaling |
| REDUCED | ¿cómo escalan collision/preimage/2pre? | random oracle controls | exponentes y censura |
| PARAM | ¿t,k generan grinding explotable? | fixed-cost profile | selección/coste ahorrado |
| TMTO | ¿se reutiliza trabajo entre contextos? | R12 vs R12.5 | frontera W-M-reuse |
| BRANCH | ¿qué degrada Deep/DeepVector? | normal | image collapse/collision growth |
| LAYOUT | ¿qué aporta history-adaptive placement? | fixed-layout ablation | reuse/ties/sensitivity |
| DIFF | ¿difusión y dependencia muestran anomalías? | SHA family | SAC/BIC/MI |
| ALG | ¿hay invariantes/trails reducidos? | reduced RO | solver complexity/trails |
| STAT | ¿streams muestran anomalías descriptivas? | SHA family + broken control | battery outputs |
| FAULT | ¿fallos operativos se detectan? | no-fault | silent acceptance/latency |
| APP-SIG | ¿auth digest vs binding se separan? | Ed25519 digest auth | substitutions/replay |
| APP-KDF | ¿hay early rejection/coste real por guess? | Argon2id | guesses/s + saved work |
| APP-POW | ¿nonce grinding reduce coste? | unfiltered nonce | cost distribution/filter gain |
| PARSE | ¿wire hostil se rechaza canónicamente? | valid corpus | crashes/noncanonical accepts |
| DOS | ¿rechazo ocurre antes de coste caro? | valid inputs | time/memory/read-before-reject |
| CONC | ¿scheduling cambia matemática? | serial | divergence/race incidence |
| PERF | ¿cuál es el coste de cada etapa? | SHA/R12 | stage timings/RSS/scaling |

## 5. Endpoints primarios propuestos

R14 debe declarar por familia qué es primario. Propuesta:

- HIST: slope/exponent of crossing/full-state search + probability of next-state
  equality conditioned on visible crossing;
- REDUCED: median query complexity by width and fitted scaling exponent;
- PARAM: cheapest-stratum attempts and net saved round work;
- TMTO: reuse_rate under equal offline/online budgets;
- BRANCH: image size/collision-pair degradation normalized by work;
- KDF: full-trajectory fraction after public parameter screening;
- PoW: effective transition cost distribution after nonce selection;
- PERF: decomposed wall time + RSS per stage.

El resto debe ser secondary/exploratory para limitar researcher degrees of freedom.

## 6. Reglas de análisis

### Multiple testing

Las familias con múltiples hipótesis deben declarar una sola estrategia:

- Holm para familias pequeñas de tests;
- FDR sólo donde el objetivo sea discovery;
- no corrección cruzada artificialmente entre preguntas científicas distintas.

### Effect sizes

Todo p-value debe acompañarse de tamaño de efecto e intervalo.

### Censura

Timeout/candidate-budget exhaustion es dato censurado, no error.

### Resultados negativos

Un ataque que no encuentra éxito informa sólo:

- presupuesto;
- upper/lower bound compatible;
- dominio explorado;
- limitación.

Nunca "security proven".

### Comparaciones R12/R12.5

Deben normalizar:

- número de oracle queries;
- trabajo;
- memory;
- adaptive depth.

No comparar sólo wall time.

## 7. Freeze de figuras y tablas

Antes de R15 se congelan scripts/specs de:

- F2 state crossing;
- F3 collision/full-state scaling;
- F4 multi-state scaling;
- F5 structured 2PRE;
- F6 TMTO frontier;
- F7 parameter grinding;
- F8 layout/history ablation;
- F9 Deep vs DeepVector;
- F10 stage cost;
- F11 memory/workers;
- F12 KDF early rejection;
- F13 PoW grinding;
- F14 diffusion controls;
- F15 multiplatform conformance.

Las figuras pueden recibir datos R15, pero no cambiar pregunta/ejes primarios
después de observarlos.

## 8. Freeze de claims

R14 copia `docs/claims-evidence-v3-r13.md` a una matriz de publicación
versionada y bloquea cambios de nivel de evidencia sin nuevo resultado.

Cada claim debe declarar:

- wording permitido;
- wording prohibido;
- evidencia mínima;
- figure/table;
- known limitations.

## 9. Infraestructura a reutilizar

R14 reutiliza la infraestructura v2.2 que ya existe:

- `experiments.freeze`;
- `scripts.prepare_confirmatory`;
- transactional runner;
- canonical config hashing;
- task attempt archival;
- resume integrity;
- host manifest;
- artifact hashing;
- exact-tag requirement.

Debe extenderse a v3, no duplicarse.

## 10. Nuevos artefactos previstos

- `docs/traceability-v3-r14.md`;
- `docs/r14-experimental-freeze-plan.md`;
- `experiments/preregistration-v3.md`;
- `experiments/configs/confirmatory-v3-r14/*.json`;
- `experiments/pilot-decision-record-v3-r14.json`;
- `experiments/freeze-v3-r14.json`;
- `scripts/check_r14_freeze.py`;
- `tests/unit/test_r14_freeze.py`;
- `docs/adversarial-reviews/R14.md`.

## 11. Obligaciones R14

### FREEZE-01..05

1. exact commit/tag;
2. wheel/sdist;
3. corpus/reference;
4. attacker registry;
5. environment constraints.

### PRE-01..10

1. hypotheses;
2. endpoints;
3. sample sizes;
4. seeds;
5. stopping;
6. censoring;
7. exclusions;
8. corrections;
9. analyses;
10. figures/tables.

### CFG-01..06

1. schema;
2. config validation;
3. config hashing;
4. artifact binding;
5. freeze-manifest binding;
6. dirty-tree/tag rejection.

### SCI-01..06

1. pilot/confirmatory separation;
2. discovery/holdout separation;
3. effect sizes;
4. negative-result semantics;
5. resource accounting;
6. host/multiplatform design.

### AUDIT-01..05

1. tamper tests;
2. downgrade tests;
3. resume/overwrite tests;
4. artifact provenance;
5. adversarial PASS.

## 12. Criterio de terminado R14

R14 está cerrado sólo cuando:

1. R12.5 y R13 permanecen inmutables;
2. todos los schemas v3 están congelados;
3. todos los attackers confirmatorios están congelados;
4. todos los pilots necesarios han terminado y sólo alimentan decisiones;
5. sample sizes/budgets están fijados;
6. preregistration no contiene TBDs;
7. discovery/holdout está separado;
8. configs confirmatorias están generadas y hasheadas;
9. wheel/sdist/reference/corpus están hasheados;
10. freeze manifest une todos los artefactos;
11. runner rechaza cualquier drift;
12. gate local y CI remoto pasan;
13. existe review R14 versionada;
14. R15 puede ejecutarse sin tomar una sola decisión científica nueva.

R14 no se considera PASS porque "el código funciona", sino cuando la libertad de
cambiar el experimento después de ver los datos confirmatorios queda
operacionalmente eliminada.
