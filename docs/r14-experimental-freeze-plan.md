# Sigma v3 R14 — Experimental Freeze & Preregistration

Estado: **implementación/gate R14 PASS; cierre formal pendiente TAG-01**  
Fecha: 2026-09-20

Baselines inmutables:

- R12.5 construcción: `5ac306bb23acae0e0a4ef03eb56b3062343c2127`;
- R13 diseño formal/criptoanalítico: `8a71de3d350ea8215c481e16c9eadbeed54066ef`.

R14 no modifica suites, domains, frames, KAT, corpus ni semántica R12.5. Si
durante R14 aparece una razón para cambiar la función, R14 se detiene y la
construcción se reabre con nuevos IDs/candidato. R14 tampoco produce resultados
confirmatorios: congela de forma auditable todo lo necesario para que R15 los
produzca sin decisiones retrospectivas.

## 1. Objetivo

R14 transforma el diseño de R13 en un protocolo científico congelado.

Al terminar R14 deben estar fijados, antes de observar resultados confirmatorios:

1. claims primarios y secundarios;
2. ataques/falsadores que entran en R15;
3. baselines y ablaciones;
4. factores y celdas experimentales;
5. presupuestos de recursos;
6. widths, tamaños y workloads;
7. sample sizes y número de réplicas;
8. seeds y su derivación;
9. separación discovery/holdout;
10. stopping rules;
11. censura, timeout y tratamiento de errores;
12. métricas primarias/secundarias;
13. análisis estadístico;
14. corrección por comparaciones múltiples;
15. schemas de raw data;
16. scripts de análisis;
17. figuras/tablas y su fuente de datos;
18. artefacto ejecutable exacto;
19. hosts/plataformas requeridos;
20. freeze manifest y preregistration hash.

R15 sólo podrá consumir configuraciones que pertenezcan al freeze manifest R14.

## 2. Fronteras epistemológicas

R14 distingue cuatro clases de material:

- **baseline normativo**: R12.5/R13, inmutable;
- **piloto de diseño**: se usa para estimar coste/varianza/sample size y se
  descarta como evidencia;
- **discovery**: permite ajustar atacantes heurísticos sólo antes del freeze;
- **holdout confirmatorio**: no se inspecciona ni ajusta hasta R15.

Ninguna observación de pilotos R13 puede aparecer como resultado del paper.
Ningún resultado R15 puede cambiar una configuración, un atacante o un análisis
sin invalidar el freeze y abrir una nueva campaña.

## 3. Decisiones R14

| ID | Decisión a congelar | Bloquea |
|---|---|---|
| R14-001 | conjunto final de claims primarios/secundarios | todo R15 |
| R14-002 | ataques R13 que pasan a confirmatorio | configs |
| R14-003 | ataques conditional/out-of-scope y razón | claims |
| R14-004 | baselines por ataque | análisis |
| R14-005 | factores/celdas por familia | sample size |
| R14-006 | resource budgets por celda | configs |
| R14-007 | seeds y derivación determinista | reproducción |
| R14-008 | discovery/holdout split | attackers heurísticos |
| R14-009 | stopping/censoring/timeout | inferencia |
| R14-010 | sample-size rule y mínimo por celda | freeze |
| R14-011 | análisis estadístico y multiplicidad | paper |
| R14-012 | raw-data schema | runner |
| R14-013 | figure/table schema | manuscript |
| R14-014 | host/platform matrix | reproducibilidad |
| R14-015 | artifact identity y dependency lock | ejecución |
| R14-016 | external battery adapters/formatos | STAT |
| R14-017 | KDF/PoW cost model exacto | APP/PARAM |
| R14-018 | performance protocol y warm-up | PERF |
| R14-019 | dataset/folder naming and integrity | archive |
| R14-020 | human approval + immutable freeze manifest | desbloquea R15 |

## 4. Inventario de campañas que debe resolver R14

### 4.1 HIST

**HIST-01 — state crossing.**
Congelar widths de estado/history, round indices, candidate budgets, número de
crossings por celda y endpoint primario:
`P(S_(i+1)=S'_(i+1) | S_i=S'_i,H_i!=H'_i)`.
Registrar además full-state equality y longitud de racha visible.

**HIST-02 — full-state collision.**
Congelar widths geométricos, candidate budget, estrategia de first-hit y
censura. Endpoint: queries/candidates hasta primera colisión de `(H_i,S_i)`.

**HIST-03 — HistoryStep.**
Separar collision, second-preimage, fixed-point y cycle. No combinar sus
presupuestos ni inferencias.

**HIST-04 — replay/skip/reorder.**
Producto real, no modelo reducido. Endpoint primario:
`silent_acceptance == 0`. Cada mutación debe identificar la primera capa de
rechazo.

**HIST-05 — truncation ablation.**
Congelar una rejilla de history widths y comparar visible/full-state collision
scaling a coste normalizado.

**HIST-06/LAYOUT-04 — layout ablation.**
Comparar:
- fixed layout;
- history en values solamente;
- history en seed + values.
El baseline R12.5 real es el tercero.

### 4.2 REDUCED

**RED-01.** Exhaustive map sólo en widths para las que el espacio completo sea
enumerable dentro del budget congelado.

**RED-02.** Collision scaling en widths geométricos. Endpoint principal:
pendiente `log2(Q50)` vs bits; censura mediante supervivencia, no eliminación
de runs censurados.

**RED-03.** Preimage: target fijado antes de la randomness del atacante.

**RED-04.** Second-preimage: challenge message fijado antes de seed; registrar
same-P/any-P, same-header y first divergence.

**RED-05.** Multi-target: congelar `u` y comparar con single-target.

**RED-06/07/08.** Chosen-prefix, multicollision y herding sólo pasan a R15 si
R14 dispone de un atacante implementado, testado y con design pilot separado.
Si no, quedan `open/future work`; no se improvisan durante R15.

**RED-09.** Expandable-message/long-message 2PRE permanece conditional salvo
que R14 demuestre comparabilidad exacta de cardinalidad/semántica.

### 4.3 PARAM

**PARAM-01.**
Distribución conjunta de los 93 pares `(t,k)`. R14 fija un mínimo de
observaciones por celda esperada y la prueba GOF. El número final se obtiene de
pilotos, pero nunca puede quedar por debajo del umbral que haga inválida la
aproximación elegida; si es necesario se usa Monte Carlo exacto.

**PARAM-02.**
Correlaciones con candidate/persistent/header/history/layout. Mutual
information se estima con permutation control y holdout.

**PARAM-03.**
Cheapest-stratum grinding. Medir:
`preparation work + selection work + selected trajectory work`.
El speedup se define frente a no-selection con el mismo budget total.

**PARAM-04.**
KDF early rejection. Diseño emparejado:
mismos passwords/salts/Argon2 params para fixed-cost y derived-cost Sigma.
Endpoint primario: work/guess y fracción de guesses que evitan full trajectory.

**PARAM-05.**
PoW nonce grinding. Diseño emparejado por challenge/payload. Endpoint:
throughput y distribución de coste con/sin selección.

**PARAM-06.**
Mitigaciones: context-fixed, cost-bucketed y derived. R14 debe fijar cuál entra
como mitigación principal; R15 no puede inventar una cuarta variante.

### 4.4 TMTO

Congelar para direct/distinguished/rho/Hellman/rainbow:

- state/history widths;
- table entries;
- chain lengths;
- distinguished bits;
- targets `u`;
- offline/online split;
- memory accounting;
- parallel depth.

La figura primaria será una frontera Pareto
`(offline work, online work, memory)`; no un ranking único.

### 4.5 BRANCH

**BRANCH-05.**
Deep: normal, constant/truncated fold y branch faults predefinidos.
Endpoints: image size, collision pairs, effective conservative width.

**BRANCH-06.**
DeepVector: perturbación de un componente y dependencia sobre todas las ramas
siguientes. Registrar first divergence y affected branches.

Los faults no pueden añadirse después de ver resultados.

### 4.6 FAULT / PARSE / DOS / CONC

R14 debe congelar un corpus de fallos y schedules adversariales:

- stale/replayed history;
- wrong index;
- branch/round skip;
- branch reorder/duplicate;
- truncated frames;
- malformed parsers;
- spool/disk/resource limits;
- process/thread failure;
- cancellation races;
- concurrent file mutation.

El endpoint de seguridad de ingeniería es silent acceptance, resource leak o
divergencia matemática.

### 4.7 APP-SIG / APP-KDF / APP-POW

Cada aplicación recibe un modelo de amenaza separado, configs separadas y
claims separados. Un resultado de KDF no se reutiliza como evidencia PoW ni
viceversa.

### 4.8 DIFF / STAT / ALG

- DIFF: SAC/BIC/Hamming/MI son controles descriptivos;
- STAT: NIST STS/PractRand/TestU01 son secundarios y nunca prueban seguridad;
- ALG: ANF/SAT/SMT/MILP sólo para reduced instances con instancia, solver,
  versión y timeout archivados.

## 5. Política de sample size

R14 no fija sample sizes por conveniencia. Para cada endpoint se guarda una
ficha:

`effect_of_interest, variance_pilot, alpha_family, power_target,
minimum_cell_size, censoring_model, derived_N, frozen_N`.

Reglas:

1. los pilotos sólo estiman coste/varianza/effect-size plausible;
2. `frozen_N` se calcula antes de R15;
3. si no existe power calculation útil, se usa un budget fijo justificado por
   resolución del endpoint y se etiqueta como tal;
4. una vez congelado, no se aumenta N porque el resultado sea no significativo;
5. una extensión posterior es una campaña distinta.

Para rare events se priorizan intervalos exactos/binomiales y bounds por cero
éxitos; para collision/preimage censurados se usan métodos de supervivencia y
first-hit, no medias de sólo runs exitosos.

## 6. Seeds

No se seleccionan seeds a mano.

Cada seed confirmatoria se deriva determinísticamente:

`SHA256("sigma-v3-r15" || freeze_id || attack_id || cell_id || replicate_id)`.

Discovery usa namespace `sigma-v3-r14-discovery`; holdout/confirmatory usa
`sigma-v3-r15`. Los namespaces no comparten seeds.

El freeze manifest fija:
- algoritmo de derivación;
- encoding de labels;
- lista de cell IDs;
- replicate count.

## 7. Discovery / holdout

Para atacantes que contienen tuning heurístico:

- discovery: máximo 30% del budget de desarrollo;
- holdout: mínimo 70% reservado y nunca inspeccionado durante tuning;
- parámetros del atacante se congelan después de discovery;
- el holdout sólo se ejecuta en R15.

Para atacantes puramente exhaustivos/deterministas no se fuerza un split
artificial; se congela el espacio exhaustivo.

## 8. Stopping, censoring y errores

Estados terminales canónicos:

- `success`;
- `no-success`;
- `censored`;
- `timeout`;
- `error`.

Reglas:

- éxito first-hit puede terminar esa réplica porque el endpoint es el tiempo al
  primer evento;
- ausencia de éxito sólo cuenta como no-success al agotar el budget fijado;
- timeout no se convierte en no-success;
- error no se excluye silenciosamente;
- resource-safety stop produce censura con razón;
- no existe optional stopping basado en p-value o tendencia de efecto.

## 9. Análisis estadístico congelado

### Primary families

Cada familia de claims define de antemano sus hipótesis primarias.

- Binomial/rare-event: intervalos Clopper-Pearson o exactos predeclarados.
- First-hit/censored: Kaplan-Meier u otro estimator predeclarado + intervalos.
- Scaling: regresión `log2(work)` frente a width con bootstrap de slope.
- Uniformidad: chi-square sólo si sus condiciones están satisfechas; en otro
  caso Monte Carlo exacto.
- Paired cost: ratios/differences pareados con bootstrap CI.
- TMTO: Pareto frontier y dominancia, no score agregado.
- Performance: median/quantiles + bootstrap CI; p-values no son el resultado
  principal.

### Multiplicity

- Holm family-wise correction para hipótesis primarias de una misma familia;
- BH/FDR sólo para análisis exploratorios claramente marcados;
- no se promueven endpoints secundarios después de ver resultados.

## 10. Performance methodology

R14 congela:

- hosts requeridos;
- CPU governor/power mode;
- Python version;
- process start method;
- worker counts;
- warm-up;
- randomized execution order;
- repetitions;
- message sizes;
- cache policy;
- RSS/allocator/I/O instrumentation;
- definition exacta de throughput y speedup.

La descomposición mínima es:

[
T =
T_{source}+T_A+T_J+T_{param}+T_{layout}+T_H+
T_{frame}+T_{branch}+T_{fold}+T_{digest}.
]

R12 y R12.5 se comparan a workloads idénticos.

## 11. Schemas y raw data

Todo record confirmatorio debe contener como mínimo:

- schema/version;
- campaign_id;
- freeze_id;
- attack_id;
- claim_ids;
- construction/suite;
- cell_id;
- replicate_id;
- seed label;
- discovery/holdout/confirmatory flag;
- declared ResourceBudget;
- observed ResourceBudget;
- status;
- metrics;
- censor/error reason;
- code commit;
- artifact SHA-256;
- config SHA-256;
- preregistration SHA-256;
- host/interpreter/dependencies;
- timestamps;
- integrity hash.

Los raw records son append-only. Las correcciones se versionan; nunca se
reescribe un resultado.

## 12. Figures y tablas congeladas antes de R15

R14 debe crear scripts que puedan producir las figuras usando **synthetic data**
con el mismo schema. Así se congela la transformación antes de ver resultados.

Figuras previstas:

1. arquitectura `P_X -> (H_i,S_i)`;
2. state crossing;
3. visible/full-state collision scaling;
4. multi-state scaling con `k`;
5. second-preimage reduced;
6. TMTO Pareto frontier;
7. `(t,k)` distribution/grinding;
8. layout/history ablation;
9. Deep vs DeepVector;
10. coste descompuesto;
11. memoria/workers;
12. KDF early rejection;
13. PoW nonce grinding;
14. diffusion controls;
15. multiplatform conformance.

Tablas mínimas:

- suites/domains;
- claims/evidence;
- theorem/assumption status;
- attacker budgets;
- KAT/corpus;
- negative results;
- performance;
- host reproduction;
- limitations.

## 13. Artefactos R14

R14 debe producir y congelar:

- `experiments/preregistration-v3.md`;
- `experiments/configs/v3-confirmatory-frozen/*.json`;
- `experiments/configs/v3-confirmatory-frozen/freeze.json`;
- `experiments/configs/v3-discovery-frozen/*.json` cuando aplique;
- `scripts/check_r14_freeze.py`;
- `scripts/prepare_v3_confirmatory.py` o extensión explícita del preparador
  existente;
- schema v3 de resultados;
- analysis scripts;
- synthetic fixture dataset;
- figure/table schema tests;
- wheel/sdist/checksums/SBOM;
- dependency lock;
- R12.5 corpus + independent reference;
- R13 registry/schema;
- manifest de hashes de todos los anteriores.

No debe existir raw confirmatory data dentro del freeze R14.

## 14. Subgates R14

### R14-A — Baseline lock

- comprobar hashes R12.5/R13;
- prohibir cambios semánticos;
- corpus/KAT/reference verdes.

### R14-B — Campaign inventory

- cada claim C01–C20 tiene estado:
  `confirmatory / reduced-only / conditional / boundary / out-of-scope`;
- cada ataque del registry entra o queda excluido con razón versionada.

### R14-C — Pilot budgeting

- ejecutar sólo pilotos R14-discovery;
- estimar coste, varianza, event rate y feasibility;
- ningún output se incorpora al manuscrito como evidencia.

### R14-D — Protocol lock

Congelar sample sizes, budgets, seeds, factors, stopping/censoring, análisis,
multiplicity, hosts y figure schemas.

### R14-E — Config freeze

Generar todos los configs canónicos y validarlos contra schemas cerrados.

### R14-F — Artifact freeze

Construir wheel/sdist desde checkout limpio; checksums/SBOM; instalar fuera del
árbol; fijar artifact hash en configs.

### R14-G — Preregistration freeze

Prerregistro completo firmado/revisado por el owner, hash incluido en cada
config y freeze manifest.

### R14-H — Adversarial freeze audit

Intentar:
- alterar config;
- alterar prereg;
- ejecutar config no manifestado;
- cambiar seed;
- cambiar N;
- cambiar attacker;
- cambiar analysis script;
- mezclar pilot/confirmatory;
- ejecutar desde dirty tree/no tag;
- reutilizar artifact distinto.

Cualquier aceptación silenciosa bloquea R14.

## 15. Gate autoritativo R14

El gate debe verificar:

1. R12.5 PASS baseline intacto;
2. R13 PASS baseline intacto;
3. tests/lint/type/fuzz/build verdes;
4. registry/schema únicos;
5. 100% de configs validados;
6. 100% de configs incluidos en freeze manifest;
7. hashes de prereg/configs/analysis/artifact coinciden;
8. synthetic analysis reproduce todas las figuras/tablas previstas;
9. ningún record/config está marcado confirmatory ejecutado;
10. checkout limpio y tag exacto;
11. wheel instalado fuera del checkout;
12. informe adversarial versionado.

## 16. Criterio de cierre

R14 queda PASS sólo si existe un único conjunto congelado capaz de responder,
sin decisiones posteriores, a:

- qué se va a medir;
- por qué;
- contra qué baseline;
- con qué attacker;
- con qué recursos;
- con cuántas réplicas;
- con qué seeds;
- cuándo se detiene;
- cómo se censura;
- qué análisis se aplica;
- qué figura/tabla se genera;
- qué artefacto ejecuta el experimento.

Al cerrar R14, R15 queda autorizado a **ejecutar**, no a rediseñar.

## 17. Orden de implementación recomendado

1. R14-A baseline lock.
2. R14-B claim/attack disposition table.
3. R14-C pilot budgeting.
4. R14-D statistical/protocol lock.
5. implementar schema v3 + config validators.
6. crear synthetic dataset + analysis/figure scripts.
7. generar configs confirmatorios.
8. freeze artifact.
9. congelar preregistration.
10. ejecutar adversarial freeze audit.
11. registrar PASS R14.
12. sólo entonces abrir R15.


## 18. Estado de implementación

El candidato técnico
`b6ebc780cc0b201fd27562c85c64c90df37c1075` pasó el run
`35529570894` con todos los subgates R14, matriz multiplataforma, build y
freeze bundle en verde.

El informe adversarial está versionado en
`docs/adversarial-reviews/R14.md`.

El único requisito restante del propio plan es TAG-01: crear
`sigma-v3-r14-freeze-v1` sobre el candidato exacto. Hasta entonces R15 sigue
bloqueado.
