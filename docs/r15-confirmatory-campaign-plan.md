# Sigma v3 R15 — Confirmatory Scientific Campaign

Estado: **PLAN ACTIVO; adquisición confirmatoria bloqueada hasta R14.1 + TAG-01**  
Fecha: 2026-09-21

## 1. Principio rector

R15 no modifica Sigma, no diseña nuevos ataques después de ver resultados y no
optimiza parámetros en respuesta a outcomes. R15 ejecuta un protocolo
previamente congelado, registra toda la evidencia y produce un dataset
reproducible.

La secuencia normativa pasa a ser:

[
R14 technical candidate
	o
R14.1/R15	ext{-}0 execution+publication closure
	o
new R14 gate
	o
TAG	ext{-}01
	o
R15 acquisition
	o
R15 analysis
	o
R15 PASS
	o
R16.
]

No se ejecuta ninguna seed del namespace `sigma-v3-r15` antes del nuevo
freeze/tag.

## 2. Modificación normativa A — publication-scale volume

El tamaño experimental no se fija por conveniencia computacional. Cada barrido
debe justificar:

- resolución del eje;
- número de puntos por curva;
- número de réplicas por punto;
- precisión de intervalos;
- potencia cuando exista un modelo de power válido;
- resolución de rare events;
- región estimable;
- región de stress/censoring.

### 2.1. Reglas globales

Para curvas principales:

- mínimo 6 puntos estimables;
- preferiblemente 7–8;
- anchuras criptográficas con paso de 2 bits cuando sea viable;
- además 1–2 puntos de stress cuando aporten lower bounds útiles.

Réplicas:

- reduced/first-hit barato: 512–1024 por punto;
- exhaustive-map por seed: 128–256;
- paired physical measurements: 256–512 por host;
- rare-event conditional exposures: (10^5)–(10^6) trials por punto;
- external statistics: decenas de streams independientes por celda.

No se incrementa N después de observar un resultado no significativo.

### 2.2. Intervalos

Primarios:

[
95% CI
]

para todos los effect sizes/endpoints.

Rare events y zero-event claims:

[
99% one	ext{-}sided upper bound
]

además del 95%.

Curvas:

- 95% pointwise intervals;
- 95% simultaneous band para la curva completa cuando aplique.

Bootstrap principal:

[
B=10,000
]

resamples deterministas. Figuras finales baratas pueden usar (B=50,000)
si queda congelado antes de datos.

Power:

- target primario: 95%;
- mínimo excepcional: 90%;
- nunca usar 80% como objetivo por defecto en R15.

### 2.3. Regla de región estimable

Para survival/first-hit:

- puntos con 70–80% o más eventos bajo el modelo de diseño pueden entrar en
  estimación principal de medianas/slopes;
- >50% censoring se etiqueta como stress/lower-bound y no se mezcla
  automáticamente en la regresión principal.

## 3. Publication-scale target por campaña

Los números siguientes son objetivos de R14.1 y sustituyen los tamaños
preliminares R14 una vez se materialicen en configs congelados.

### HIST-01A — natural crossings

- (n=hin{6,8,10,12,14,16});
- round index (iin{1,2,4});
- 18 celdas;
- 512 réplicas/celda;
- 9,216 run records;
- crossing_target explícito, propuesto: 32 por réplica.

### HIST-01B — conditional crossing mechanism

Experimento reducido separado para estimar

[
P(S_{i+1}=S'_{i+1}mid S_i=S'_i,H_i
e H'_i).
]

- mismas 18 celdas;
- 256 batches/celda;
- 1,024 conditional trials/batch;
- 262,144 conditional trials/celda;
- 4,718,592 transitions totales.

Esto permite upper bounds útiles hasta (n=16).

### HIST-02 — full-state collision

- bits: 4,6,8,10,12,14,16;
- 7 puntos;
- 512 réplicas/punto;
- 3,584 runs.

### HIST-03 — HistoryStep games

- games: collision, second-preimage, fixed-point, cycle;
- widths: 4,6,8,10,12,14,16;
- 28 celdas;
- 256 seeds/celda;
- 7,168 runs.

### HIST-05 — truncation ablation

- (hin{4,6,8,10,12,14,16,18});
- 128 exhaustive/random-map seeds por width;
- 1,024 runs.

### HIST-06 / LAYOUT-04

- (hin{6,8,10,12,14,16,18});
- slots (in{17,33,65,129});
- variants: fixed, values-only, adaptive;
- 28 celdas por attack id;
- 256 réplicas/celda;
- 7,168 runs por attack id.

### RED-02 — collision/window scaling

Grid adaptado a (m=kn):

- k=1: n=6,8,10,12,14,16,18,20;
- k=2: n=4,6,8,10,12,14,16;
- k=3: n=4,6,8,10,12;
- k=4: n=4,6,8,10.

24 celdas/construction, dos constructions, 48 celdas.

- 512 réplicas/celda;
- 24,576 runs.

Budget de diseño:

[
Q_{max}approx 4cdot2^{kn/2}
]

hasta un cap computacional congelado. Puntos cap-limited se etiquetan stress.

### RED-03 — preimage

- n=4,6,8,10,12,14,16;
- k=2;
- n=4..10: región estimable;
- n=12..16: stress;
- 512 réplicas/punto estimable;
- 256 réplicas/punto stress;
- dos constructions.

### RED-04 — second preimage

Misma malla que RED-03 con:

- same-persistent;
- any-persistent.

### RED-05 — multi-target

- u=1,2,4,8,16,32,64;
- n=6,8,10,12;
- two constructions;
- 56 celdas;
- 512 réplicas/celda;
- 28,672 runs.

### TMTO-01/02

- bits=8,10,12,14,16,18;
- strategies: direct, distinguished, rho, Hellman, rainbow;
- two constructions;
- 60 celdas;
- 256 réplicas/celda;
- 15,360 runs.

### PARAM-01

- 186,000 samples/replicate;
- 64 replicates;
- 11,904,000 parameter derivations;
- expected count = 2,000 por cada uno de los 93 pares.

### PARAM-02

- 32,768 observations/replicate;
- 128 replicates;
- 5,000 deterministic permutations;
- 4,194,304 cryptographic observations.

### PARAM-03

Candidate budgets:

93,186,465,930,1860,4650,9300.

- 7 niveles;
- 512 réplicas/nivel;
- 3,584 runs.

### PARAM-04 — KDF

Publication target:

- 3 physical hosts;
- 256 paired replicates/host;
- 4,096 guesses/replicate;
- 1,048,576 guesses/host;
- 3,145,728 guesses total.

### PARAM-05 — PoW

- 3 physical hosts;
- nonce budgets 4,096 and 16,384;
- 512 paired replicates/host/budget;
- 3,072 run records;
- 31,457,280 nonce evaluations.

### PARAM-06 — mitigation

- 3 physical hosts;
- 3 frozen modes;
- 512 replicates/host/mode;
- 4,608 run records.

### BRANCH-05

- 8 faults;
- 1,024 replicates/fault;
- 8,192 runs.

### BRANCH-06

- 6 faults;
- 1,024 replicates/fault;
- 6,144 runs.

### STAT-01

R15 no archiva los streams grandes.

Publication target inicial:

- 24 construction/corpus cells;
- 64 deterministic streams/cell;
- 1,536 stream identities;
- streaming batteries;
- volumen procesado escalonado, no retenido.

El tamaño exacto por battery se congela en R14.1 después de validar adapters y
scratch limits. No se permite que el volumen requiera cientos de GiB
persistentes.

## 4. Modificación normativa B — R15-DATA

Regla fundamental:

[
processed volume 
e retained volume.
]

Los streams estadísticos grandes son cálculo efímero reproducible, no raw data
canónico.

### DATA-01

Ningún stream grande se versiona en Git ni se convierte en artefacto canónico.

### DATA-02

Todo stream debe ser reconstruible exactamente a partir de:

- freeze id;
- construction;
- corpus;
- stream id;
- seed;
- generator version/hash;
- byte count.

### DATA-03

Todo stream tiene SHA-256 completo. Para streams grandes se guardan además
hashes por chunks y, opcionalmente, Merkle root.

### DATA-04

PractRand/TestU01/NIST deben usar streaming/pipe/callback cuando la herramienta
lo permita.

### DATA-05

Si una herramienta exige fichero, se materializa sólo un fichero temporal,
se verifica, consume y elimina antes de pasar al siguiente.

### DATA-06

Raw numeric records sí son append-only y se conservan.

### DATA-07

Se conservan permanentemente:

- stream manifest;
- hashes;
- tool/version manifest;
- commands;
- stdout/stderr;
- parsed battery results;
- failure/not-applicable status.

### DATA-08 — resource ceiling

Objetivo de scratch por defecto:

[
Disk_{scratch}le 10 GiB.
]

Objetivo preferido STAT:

[
Disk_{scratch}le 2 GiB.
]

Buffers deben ser O(1) respecto al stream total, típicamente 1–16 MiB.

### DATA-09 — repository boundary

Git contiene:

- code;
- configs;
- schemas;
- manifests;
- small fixtures;
- summary tables;
- analysis scripts;
- checksums.

Git no contiene:

- large generated streams;
- temporary battery files;
- raw scratch directories;
- multi-GiB external outputs.

### DATA-10 — archival target

El dataset científico final R15/R16 debe contener preferentemente:

- canonical JSONL compressed;
- Parquet analysis tables;
- stream manifest;
- external battery results;
- logs/manifests;
- checksums;
- figures/tables.

Target orientativo del archivo retenido:

[
1	ext{–}5 GiB
]

y preferiblemente menor, sin reducir el volumen procesado.

## 5. Arquitectura R15

### R15-0A — execution closure

Antes de datos:

- implementar HIST-03 completo;
- implementar layout values-only;
- implementar PARAM-02 MI/permutation;
- implementar PARAM-04 real;
- implementar PARAM-05 real;
- implementar PARAM-06 real;
- implementar BRANCH-06 affected-branches;
- implementar STAT adapters;
- congelar retry/checkpoint semantics.

### R15-0B — publication-scale freeze

Materializar en machine-readable configs:

- grids;
- replication counts;
- conditional trial counts;
- host counts;
- budgets;
- expected event region;
- stress region;
- 95/99% intervals;
- power target;
- bootstrap B;
- simultaneous-band method.

### R15-0C — data/storage freeze

Implementar y congelar:

- stream generator protocol;
- chunk hashing;
- scratch quota;
- append-only raw ledger;
- external tool manifest;
- canonical archive format.

### R14.1 — refreeze

Después de R15-0A/B/C:

1. regenerar configs;
2. actualizar preregistration;
3. actualizar protocol-freeze;
4. rebuild wheel/sdist/SBOM;
5. synthetic analysis gate;
6. adversarial R14.1 review;
7. nuevo candidato;
8. crear TAG-01 sobre ese candidato exacto.

Sólo entonces se habilita `sigma-v3-r15`.

## 6. Ejecución secuencial R15

### R15-A — unlock/preflight

Verificar tag, artifact, configs, preregistration, analysis, hosts y data policy.

### R15-B — harness validation

Sólo namespace sintético/no-confirmatorio. Probar crash, resume, duplicate key,
wrong seed, wrong hash, budget violation, timeout y atomic writes.

### R15-C — structural/reduced acquisition

Ejecutar HIST/LAYOUT/BRANCH/PARAM-01..03.

### R15-D — cryptanalytic acquisition

Ejecutar RED-02..05 y TMTO-01/02.

### R15-E — application economics

Ejecutar PARAM-04/05/06 en hosts físicos.

### R15-F — external statistical controls

Generar streams deterministas online y ejecutar STAT-01.

### R15-G — locked analysis

Raw -> validated raw -> derived tables -> figures.

### R15-H — adversarial data audit

Mutar records, seeds, hashes, configs, statuses, external logs y manifests;
cualquier aceptación silenciosa bloquea R15.

## 7. Inferencia congelada

- exact/Clopper-Pearson para proportions/rare events;
- 99% one-sided upper bounds para zero-event security boundaries;
- Kaplan-Meier para first-hit/right-censored;
- RMST con horizonte predeclarado;
- log2 scaling regression sólo sobre región estimable predeclarada;
- paired ratios/differences para KDF/PoW/mitigations;
- deterministic permutation MI;
- Pareto dominance para TMTO;
- Holm primary families;
- BH/FDR sólo exploratory.

No se interpretan p-values aislados como magnitud científica.

## 8. Criterio de cierre

R15 PASS significa integridad/completitud de la campaña, no resultado favorable
para Sigma.

Debe cumplirse:

[
ExpectedRunKeys = ObservedRunKeys.
]

Además:

- missing=0;
- duplicate canonical RunKeys=0;
- invalid seeds=0;
- invalid hashes=0;
- unclassified errors=0;
- budget violations=0;
- analysis reproducible;
- 15/15 figure surfaces reproducibles;
- external logs completos;
- negative/censored results publicados;
- adversarial review versionada.

R16 recibe el dataset cerrado; R16 no rediseña R15.
