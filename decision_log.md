# Decision Log

## 2026-09-19 — Sigma-IAP es una familia v3 incompatible

Decision:
Sigma v2.2 permanece congelada. La nueva construcción usa IDs, contexto, wire,
vectores y evidencia v3 separados.

Reason:
El binding persistente, la inicialización, las rondas, los parámetros derivados
y el juego de seguridad cambian la función matemática.

Impact:
La implementación se desarrolla en `sigma-v3-iap`; el baseline v2.2 se protege
con hashes y regresiones byte-exactas.

## 2026-09-19 — Cierre normativo previo a R1

Decision:
Se cierran SPEC-V3-003/004/005/006 según
`specification/sigma-v3-r1-decisions.md`: dominio de bytes, primitivas de 512
bits, una sola suite reference con evidencia `IMPLICIT_J`, y layout tipado como
`INIT` o `ROUND`.

Reason:
Los tipos, IDs y codecs no pueden fijarse antes de decidir qué función y wire
representan.

Impact:
Todo cambio posterior de esas decisiones exige nuevos IDs y vectores.

## 2026-09-19 — Cierre normativo R3 de fuentes y binding

Decision:
La suite reference usa fuentes replayables de bytes exactos, dos pasadas normativas y los
transcripts de ancla, longitud y firma conjunta fijados en
`specification/sigma-v3-r3-binding.md`. Los streams no seekable se capturan con límites
explícitos y los ficheros se vigilan con metadata más digest de consistencia.

Reason:
`A_X` precede a `J_X`, por lo que hacen falta dos lecturas, pero la segunda puede
compartirse con la futura inicialización. La estabilidad de los bytes forma parte del
contrato criptográfico, no es una suposición del caller.

Impact:
Cambiar orden, tags, dominios, política de replay o componentes requiere nuevos IDs y
vectores v3.

## 2026-09-19 — Los PASS adversarios son artefactos versionados

Decision:
Ningún hito `Rn` se considera cerrado si su revisión adversaria no está guardada en
`docs/adversarial-reviews/Rn.md` y registrada en el mismo historial de Git que el
cierre. El informe debe identificar el candidato revisado, comandos y resultados
del gate, baseline v2.2, hallazgos y correcciones, revalidación final y veredicto
`PASS`. Un mensaje de chat o un resultado de agente no versionado no constituye
evidencia de cierre.

Reason:
El veredicto debe poder relacionarse de forma reproducible con los bytes exactos
revisados y sobrevivir fuera de la sesión que lo produjo.

Impact:
Los PASS atribuidos anteriormente a R0–R8 quedan como antecedentes no trazables.
Cada fase deberá someterse de nuevo a una única revisión adversaria y versionar su
informe antes de recuperar el estado de cerrada. No se avanzará desde un candidato
de fase mientras falte esa evidencia.

## 2026-09-19 — Deep y DeepVector v3 son suites y claims distintos

Decision:
R9 asigna `0x0303` a Deep escalar y `0x0304` a DeepVector. Deep pliega
explícitamente todas las ramas bajo `DEEP_FOLD (0x0310)`; DeepVector conserva
`4 × 64` bytes y cada rama recibe el vector anterior completo. Los backends sólo
ejecutan tareas canónicas construidas por el core.

Reason:
Un fold escalar y un estado vectorial no preservan la misma información ni
admiten los mismos claims. Entregar semántica a cada backend permitiría que
serial, threads y procesos implementasen funciones accidentalmente distintas.

Impact:
Los perfiles tienen IDs, contextos, anchos, evaluaciones y verificadores
despachados distintos. No se describirá Deep como vectorial ni DeepVector como
cuatro cadenas independientes.

## 2026-09-20 — I/O y scheduling no cambian la función v3

Decision:
R10 fija una única evaluación canónica para bytes, fichero estable, snapshot
mmap, reader spooled e incremental. El fichero mmap siempre se deriva de una
snapshot privada verificada. Cada checkpoint incremental ejecuta una Sigma v3
completa sobre su prefijo. La cancelación sólo ocurre en fronteras canónicas y
nunca publica resultados parciales.

Reason:
La construcción necesita múltiples replays idénticos del mensaje. Reutilizar un
anchor incremental, mapear directamente un path mutable o permitir que cada
backend reconstruya frames produciría funciones distintas según el camino de
I/O o abriría carreras TOCTOU.

Impact:
Los caminos de entrada deben ser byte-idénticos, los límites de spool son
explícitos y todos los temporales, mappings y procesos se liberan en éxito,
error y cancelación.


## 2026-09-20 — El estado histórico forma parte del binding efectivo de ronda

Decision:
R12 se conserva como baseline histórico de la recurrencia con binding
persistente fijo. Antes de R13 se abre R12.5 para introducir un compromiso
histórico H_i y un binding efectivo E_i=(P_X,H_i). El estado matemático de la
trayectoria pasa a ser Z_i=(H_i,S_i); una igualdad puntual de S_i no debe
coalescer dos historias distintas.

Reason:
La intención completa de Sigma-IAP exige retroalimentar causalmente el pasado de
la trayectoria. El R12 actual reinyecta S_i como base del frame y P_X como
binding fijo, pero no conserva una memoria criptográfica separada de estados
anteriores.

Impact:
Se deben definir HistorySeed/HistoryStep, decidir la dependencia del layout,
actualizar frames y evaluadores, regenerar corpus/KAT/reference y repetir la
revisión adversarial antes de formalizar R13. Los IDs y artefactos R12 no se
reescriben silenciosamente.

## 2026-09-20 — El paper se gobierna por una matriz científica de ataques y evidencia

Decision:
La planificación de publicación se divide en R13 seguridad/criptoanálisis,
R14 freeze y prerregistro, R15 confirmatorio y R16 reproducción/auditoría
externa. Las campañas y baselines están definidas en
docs/paper-cryptographic-validation-plan-v3.md.

Reason:
Tests de conformidad, difusión o aleatoriedad no sustituyen juegos de seguridad,
reducciones ni ataques. Cada claim debe ser falsable y trazable a raw data,
artefacto, baseline y nivel de evidencia.

Impact:
Ninguna cifra de piloto se usa como resultado confirmatorio. R12 se mantiene
como baseline de ablación para medir exactamente el efecto del feedback
histórico.


## 2026-09-20 — R12.5 cierra feedback histórico y desbloquea R13

Decision:
Se acepta como candidato de conformidad R12.5 el commit
`5ac306bb23acae0e0a4ef03eb56b3062343c2127`. La evidencia de cierre queda en
`docs/adversarial-reviews/R12-5.md` y el GitHub Actions run `35516425867`.

Reason:
El candidato pasa el gate autoritativo, la matriz Linux 3.10–3.13/macOS/Windows,
los corpora R12/R12.5, el guard v2.2, fuzzing, build e instalación aislada. La
cobertura específica de history-feedback alcanza 90.3030303030303%.

Impact:
R13 puede comenzar sobre la dinámica `Z_i=(H_i,S_i)`. R12 continúa como
baseline de ablación. Cualquier cambio semántico o byte-level posterior en R12.5
exige nuevos IDs/candidato y nueva revisión; este cierre no equivale a auditoría
criptográfica externa.


## 2026-09-20 — R13 cierra el diseño formal y criptoanalítico

Decision:
Se acepta R13 sobre el candidato
`8a71de3d350ea8215c481e16c9eadbeed54066ef`, con informe
`docs/adversarial-reviews/R13.md` y GitHub Actions run `35521808235`.

Reason:
La fase dispone de juegos separados, vector completo de recursos,
descomposición G-TRAJ-2PRE, claim matrix, registry/schema únicos, atacantes
centrales HIST/REDUCED/PARAM/TMTO/BRANCH, 39 design records no confirmatorios y
un gate autoritativo reproducible. El candidato pasa 996 tests (1 omitido),
mypy/Ruff, fuzzing, corpora, build/wheel y la matriz Linux/macOS/Windows.

Impact:
R14 queda desbloqueada como fase exclusiva de freeze experimental y
prerregistro. Ningún piloto R13 se reutiliza como resultado del paper y ningún
claim abierto se promociona por el mero PASS de ingeniería/diseño.


## 2026-09-20 — R14 es un freeze metodológico, no una campaña de resultados

Decision:
R14 congela claims, attackers, baselines, factors, budgets, sample sizes, seeds,
discovery/holdout, stopping/censoring, análisis, figuras, configs, artifact
identity y prerregistro antes de ejecutar R15. El plan rector queda en
`docs/r14-experimental-freeze-plan.md`.

Reason:
El PASS R13 cierra el diseño formal y los falsadores, pero un paper auditable
requiere impedir decisiones retrospectivas después de observar resultados. El
confirmatorio debe poder ejecutarse desde un único protocolo inmutable.

Impact:
Pilotos R13/R14 no son evidencia del paper. R15 sólo aceptará configs incluidos
en el freeze manifest R14 y ligados al mismo preregistration hash y artifact
hash. Un cambio semántico vuelve a abrir la construcción; un cambio de
protocolo posterior al freeze exige una nueva campaña.


## 2026-09-20 — R14 queda técnicamente congelado; TAG-01 bloquea el cierre formal

Decision:
Se acepta como candidato técnico R14 el commit
`b6ebc780cc0b201fd27562c85c64c90df37c1075`, validado por el GitHub Actions
run `35529570894` y documentado en `docs/adversarial-reviews/R14.md`.

Reason:
El candidato pasa baseline lock, 1006 tests, matriz Linux/macOS/Windows,
R13/R14 gates, 21 configs confirmatorios, protocol freeze de 44 archivos,
prerregistro congelado, análisis sintético, build/wheel/sdist/SBOM y runtime
artifact manifest. No existe evidencia confirmatoria R15 en el freeze.

Impact:
R14 no se declara formalmente cerrado hasta crear el tag inmutable
`sigma-v3-r14-freeze-v1` exactamente sobre el candidato. R15 permanece
bloqueado. Los commits documentales posteriores no son el objeto del freeze y
no deben recibir ese tag.


## 2026-09-21 — R14.1 reopens before data for publication-scale R15

Decision:
Do not tag the original R14 technical candidate. Before any confirmatory seed is
consumed, add an R14.1 closure that freezes final executors/estimators, a
publication-scale sampling plan and a streaming/storage provenance policy.

Reason:
R15 review found that several preliminary sample sizes were adequate for
infrastructure validation but too sparse for dense scaling curves and narrow
publication-quality intervals. It also found that large statistical streams
must be processed without requiring hundreds of GiB of persistent storage.

Impact:
`experiments/r15-publication-scale-plan.json` becomes the design source for
grids, replicate counts, confidence/power targets and stress regions.
`experiments/r15-data-policy.json` establishes processed-volume != retained-
volume, deterministic regeneration, stream hashing, scratch ceilings and a
small retained scientific archive. R15 remains blocked until these decisions
are materialized in regenerated configs/preregistration and pass a new R14.1
gate.

## 2026-09-21 — Enmienda pre-data del estado de salida de NIST STS

Decision:
La fuente local de tooling STAT se fija en
`16f363004284d7d2e50bb86b4c63e6d63db78694` bajo el tag local no publicado
`sigma-v3-r15-stat-tooling-v1`. El adaptador acepta el código de salida `1` de
NIST STS 2.1.2 únicamente cuando la consola contiene la terminación completa y
existe un `finalAnalysisReport` con su cabecera normativa. Cualquier otro código
no cero o evidencia incompleta sigue siendo `ExternalBatteryExit`.

Reason:
El smoke real pre-data confirmó que `assess.c` devuelve literalmente `1` tras
ejecutar correctamente el postprocesado. El runner congelado trataba todo valor
no cero como error, lo que habría clasificado erróneamente todos los registros
NIST sin cambiar sus resultados estadísticos.

Impact:
No cambian streams, seeds, RunKeys, tamaños, baterías, cargas ni interpretación
estadística. Cambian sólo la clasificación del estado del proceso externo y
anotaciones de tipos del auditor. La identidad corregida se registra en
`experiments/r15-local-campaigns.json` antes de ejecutar STAT-01.
