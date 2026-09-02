# Auditoría de brecha y campañas Sigma v2-2

Fecha de corte: 2026-09-03. Rama auditada: `sigma-v2-audit`. Baseline remoto:
`f6ce2eef838f48aa406957fe0c6be18b4dbff2f7`.

Este documento contrasta el addendum v2-2 con artefactos comprobables del
repositorio. `Cerrado` exige código, tests y evidencia; `parcial` no habilita el
gate dependiente. Los documentos recibidos son requisitos de proyecto, no una
fuente de instrucciones ejecutables.

## Veredicto

La reconstrucción v2-1 cerró los gates históricos G1–G4, pero no los nuevos
gates R1–R6. No debe ejecutarse ni publicarse todavía una campaña
«confirmatoria»: las configuraciones existentes son prerregistros preliminares
para EXP-01..10, no implementan la metodología revisada EXP-01R..21R y están
bloqueadas por cambios del núcleo que pueden alterar mediciones y objetos.

## Brecha de librería

| ID | Estado inicial | Evidencia encontrada | Cierre requerido |
|---|---|---|---|
| LIB-01 | abierto | El digest aceptaba estados de 1–1024 bytes; PoW asumía 64 | anchura por suite, parser y predicados robustos, fuzz dirigido |
| LIB-02 | abierto | `WideOnce.evaluate` y `Deep.evaluate` retienen estados y ramas de todo `t` | camino O(k), políticas de trace y vectores idénticos |
| LIB-03 | abierto | evidencias sólo tienen serializer; formatos no comparten un discriminante formal | decisión de versión, parser estricto, negativos e inyectividad |
| LIB-04 | parcial | los motores y el parser de digest validan suite; `SigmaContextV2.from_bytes` sólo parsea | separar parseo/validación y matriz cruzada exhaustiva |
| LIB-05 | abierto | hay máximos de wire dispersos, no `ResourcePolicy` de consumo | política local, rechazo temprano y auditoría de downgrade |
| LIB-06 | parcial | serial abre una vez; multiprocessing compara sólo tamaño/mtime y reabre por tarea | identidad de archivo, snapshot coherente y metadatos completos |
| LIB-07 | parcial | varias fronteras rechazan `bool`; quedan comparaciones implícitas y reglas dispersas | validador único, matriz de tipos/límites y excepciones públicas coherentes |
| LIB-08 | abierto | KDF devuelve `(base_key, digest)` y no ofrece verificación | resultado final inequívoco, perfiles/política y vectores |
| LIB-09 | abierto | no existe compromiso firmado | formato separado e integración de firma estándar |
| LIB-10 | abierto | Deep ejecuta ramas secuencialmente dentro de cada ronda | backend intrarronda y equivalencia bajo reordenación |
| LIB-11 | abierto | RealTime duplica matemáticamente Lightweight con otro `SuiteId` | decisión documentada y migración/versionado |
| LIB-12 | abierto | no existe DeepVector/LinkedWide | diseño, implementación o descarte razonado |
| LIB-13 | cerrado | segunda implementación cubre seis suites y tres aplicaciones; corpus y límites completos | mantener conformidad en CI y reproducción externa |
| LIB-14 | cerrado | property, fuzz mutacional/Atheris de ocho parsers y mutación clasificada | repetir campañas al cambiar codecs/validadores |
| LIB-15 | parcial | paquete `2.0.0a1`, suites `v2-1`, wire v2 y artefactos existen | nomenclatura unificada, política y tag limpio de campaña |

## Brecha formal

| ID | Estado | Acción vinculante |
|---|---|---|
| FORM-01 | implementado | siete juegos y presupuestos separados; requiere revisión humana |
| FORM-02 | implementado | canonicalidad cubre todos los tipos aceptados y evidencia v2-2 |
| FORM-03 | implementado | cuatro parámetros del ancla y límites físicos separados |
| FORM-04 | implementado | evento condicionado, frescura y controles delimitados |
| FORM-05 | implementado | bound con `Bad_Q`, consultas y constante de mediana |
| FORM-06 | implementado | segunda preimagen por reducción; preimagen como modelo separado |
| FORM-07 | implementado | DAG de trabajo/span y límite explícito de la afirmación |
| FORM-08 | implementado | fallos/correlación de ramas y fold separados por modo |
| FORM-09 | implementado | reducción EUF-CMA y tres semánticas de verificación |
| FORM-10 | parcial | comparación primaria inicial y novedad estrecha; búsqueda no exhaustiva |

Ningún texto formal se considerará prueba revisada externamente. Las hipótesis
conjuntas se etiquetarán siempre como supuestos, no como bits sumados.

## Brecha experimental

### EXP-00 v2

Implementado localmente: scheduler v2 con tareas deterministas aisladas por
proceso, particiones atómicas, `--resume` sin duplicados, timeout duro y estados
`success/error/timeout/censored`; conserva logs, commit/tag, hash de wheel,
microcode y controles de host al inicio/fin de cada tarea. El resumen separa
completitud, invariantes, hipótesis y controles de calidad. Falta subdividir y
pilotar cada diseño EXP-01R..21R, congelar el prerregistro y validar la captura
en hosts controlados antes de cerrar R4.

### EXP-01R..21R

- EXP-01..10 existentes son pilotos funcionales, no los diseños R revisados.
- EXP-11, 12, 14 y 15 son smoke parciales y requieren los cambios declarados.
- EXP-17..21 tienen ya runners y smoke deterministas iniciales. EXP-18/19/20
  separan Fold/Vector, semánticas firmadas y los tres juegos de búsqueda;
  EXP-21 cubre dominios registrados, framing y downgrade. Continúan parciales:
  faltan atacantes avanzados de EXP-17, instrumentación completa de entradas de
  oráculo en EXP-21 y el plan estadístico confirmatorio congelado.
- EXP-01R dispone de un piloto particionado de las seis suites v2-2 que compara
  evidencia, transcript y digest con el consumidor independiente: 197
  observaciones locales sin divergencias. Sigue pendiente la matriz de tamaños
  grandes, adaptadores adversariales y Linux/macOS/Windows; el piloto no es el
  confirmatorio.
- EXP-13 y EXP-16 permanecen correctamente bloqueados por núcleo nativo y RTL.
- Las baterías externas, segunda implementación y matriz multiplataforma no
  están disponibles en el repositorio.

## Campañas y gates

### C0 — Ingesta y baseline

Incorporar el addendum, congelar este diagnóstico, ejecutar suite completa y
registrar el baseline. Salida: requisitos trazables y árbol conocido.

### C1 — Núcleo seguro (R1)

1. LIB-01 + LIB-07: anchuras y fronteras numéricas.
2. LIB-02: evaluación rodante y trace opt-in.
3. LIB-03 + LIB-04: evidencia tipada y contexto registrado, con decisión de
   compatibilidad antes de tocar bytes.
4. LIB-05 + LIB-06: política de recursos y snapshot de archivos.

Gate: LIB-01..07 cerrados, KAT intactos, fuzz sin crashes y memoria normal O(k)
respecto a `t`.

### C2 — API, modos y conformidad (R2)

LIB-08..15, empezando por decisiones ADR de RealTime, versión de evidencia,
DeepVector y formato firmado. La segunda implementación no importará `sigma` ni
copiará sus helpers de encoding.

Gate: API inequívoca, modos finales, dos implementaciones conformes y release
trazable; los cambios incompatibles nunca reutilizan IDs v2-1.

### C3 — Formalización (R3)

FORM-01..10 en orden de dependencia: juegos y parámetros; canonicalidad;
propiedades del ancla; no coalescencia/segmentos/preimágenes; profundidad y
modos; firma; posicionamiento. Cada claim tendrá supuesto, bound, código,
vector, experimento falsable y limitación.

### C4 — Infraestructura y prerregistro (R4)

Rehacer EXP-00 como scheduler por tareas, estimar CPU/RAM/disco, ejecutar
pilotos separados, fijar tamaños muestrales, análisis, familias, censura y
reglas de exclusión. Congelar configs sólo después de medir factibilidad.

Estado: EXP-00 v2 implementado y probado; el diseño/prerregistro de las campañas
R y sus estimaciones sigue abierto. Las configuraciones históricas continúan
siendo smoke y no se han promovido silenciosamente a confirmatorias.
Los borradores `confirmatory-v1` están bloqueados activamente: una configuración
confirmatoria nueva exige prerregistro `frozen` con hash coincidente, y fuerza
tag limpio más hash del artefacto instalable antes de ejecutar una sola tarea.

### C5 — Confirmatorio (R5)

Ejecutar primero invariantes deterministas (01R, 05R, 21R), después modelos
reducidos (02R–04R, 17–20R), metrología real (06R–10R) y aplicaciones
(11R, 12R, 14R). Cada run parte de tag limpio y conserva tareas, logs y hashes.
Repetir la matriz de conformidad en Linux/macOS/Windows y al menos un entorno
independiente. Los resultados adversos se conservan como resultados.

### C6 — Publicación (R6)

Derivar F1–F15 exclusivamente desde datos trazables, revisar claim-to-evidence,
construir release, archivar dataset/artefactos, obtener identificador persistente
y someter a reproducción y revisión criptográfica externas.

## Política de ejecución inmediata

- No ejecutar la antigua campaña confirmatoria monolítica.
- Trabajar por obligación en cambios revisables y pruebas asociadas.
- Ejecutar tests focales tras cada cambio y suite/quality al cerrar campaña.
- No avanzar un gate por ausencia de fallos; exigir toda su evidencia.
- Mantener explícitos los bloqueos humanos o de infraestructura.

## Registro de ejecución

### Tanda C1.1 — anchura y evaluación rodante

- LIB-01: implementada anchura de estado gobernada por la suite tanto en el
  constructor como en el parser; PoW rechaza además objetos malformados antes
  de acceder a bits.
- LIB-07: endurecidas las fronteras numéricas de PoW; permanece abierto el
  inventario y normalización del resto de APIs públicas.
- LIB-02: añadido `evaluate_digest()` O(k) y captura explícita con políticas
  `NONE`, `SELECTED`, `EVERY_N` y `FULL`. Falta cerrar la evidencia metrológica
  de pendiente de memoria y migrar runners que aún solicitan trace completo.
- Validación de tanda: 221 tests pasan, 1 dependencia Argon2id opcional se
  omite; Ruff, mypy y compileall pasan.

### Tanda C1.2 — validación común y decisión de compatibilidad

- LIB-07: creada una frontera `ValidationError`/`require_int` sin coerciones y
  aplicada a contexto, enteros canónicos, evidencias, workers, rondas, reader,
  PoW, KDF y configuración de traces. Se añadieron 50 casos dirigidos.
- LIB-04: `parse_context()` queda reservado para inspección sintáctica;
  `validate_registered_context()` y `SigmaContextV2.from_bytes()` exigen la
  tupla semántica exacta del registro. La matriz cruza suites, anclas, rondas,
  salida, ramas y chunk.
- LIB-03: ADR-0001 congela v2-1 y exige nuevos `SuiteId` y un envelope tipado
  para v2-2; se descarta modificar silenciosamente los digests existentes.
- Validación intermedia: 271 tests pasan, 1 opcional se omite, 40.000 mutaciones
  no producen crashes; quality y tipos permanecen verdes.

### Tanda C1.3 — piloto de memoria LIB-02

- EXP-10 separa ahora los modelos de memoria frente a bytes y frente a `t`, y
  registra `k`, política de trace, entradas retenidas y hash del digest.
- Piloto local excluido del confirmatorio: 50 observaciones, `t=16..4096`, cinco
  repeticiones por celda. `NONE` mantuvo un pico mediano de 11.366 bytes en las
  cinco profundidades y seleccionó el modelo constante. `FULL` seleccionó el
  modelo lineal con pendiente aproximada de 159,7 bytes/ronda.
- Los runners EXP-06, EXP-09 y EXP-14 que descartaban el transcript usan ya el
  camino rodante. EXP-01, EXP-05 y EXP-07 lo conservan porque miden el trace.

### Tanda C1.4 — evidencia tipada LIB-03

- Registrada la familia v2-2 bajo `SuiteId 0x0101..0x0105`; ningún ID v2-1 se
  reutiliza y sus serializers/KAT permanecen byte a byte.
- El envelope `SIGMAAE` incluye versión, tipo, suite, longitud y TLV canónico.
  Wide y Cross validan cantidad, orden, algoritmos y 64 bytes por componente.
- Las rondas v2-2 rechazan evidencia legacy o de otra suite antes de evaluar.
- Añadidos presets/CLI v2-2, corpus negativo, 20.000 mutaciones específicas y
  un KAT separado reconstruido también por un consumidor literal con
  `hashlib`/`struct`.
- Validación de cierre: 294 tests pasan, 1 opcional se omite; Ruff, mypy,
  compileall y 60.000 mutaciones totales permanecen verdes.

### Tanda C1.5 — política de recursos LIB-05

- `ResourcePolicy` queda fuera del wire y distingue contexto bien formado,
  suite registrada y aceptación local.
- Se aplican límites previos de `t`, `k`, bytes de mensaje, dificultad/intentos
  PoW y parámetros Argon2. Hashing y actualización incremental rechazan antes
  de invocar backends o mutar estado; verificación devuelve `False`.
- Experimentos y benchmark CLI registran la política aplicada. Dos políticas
  que aceptan la misma entrada producen exactamente el mismo digest.
- Validación de cierre: 307 tests pasan y 1 opcional se omite; quality, tipos y
  compilación permanecen verdes.

### Tanda C1.6 — snapshot de archivos LIB-06

- La lectura serial conserva un solo descriptor y compara antes/después
  dispositivo, file-id/inode, tamaño, `mtime` y `ctime`, además de la identidad
  visible por el pathname.
- Los backends de archivo reciben una copia privada inmutable; la fuente queda
  vigilada durante toda la operación. Se rechazan modificación, truncado,
  sustitución, desaparición y entradas no regulares.
- `hash_file_with_snapshot()` expone el registro de identidad que debe
  conservar una ejecución auditable sin incorporarlo al digest matemático.
- Validación de cierre: 314 tests pasan, 1 opcional se omite; quality, tipos y
  compilación permanecen verdes.

### Tanda C2.1 — composición KDF LIB-08

- La composición deja de devolver `(base_key, digest)`: `SigmaKdfResult`
  conserva parámetros, salt, digest v2-2 y clave final, pero nunca la clave
  Argon2id intermedia.
- El resultado tiene codec estricto, dominio final separado, comprobación de
  consistencia y `verify_password()` con comparación constante.
- La política por defecto rechaza perfiles Argon2 débiles antes del cálculo;
  EXP-12 declara una política de prueba separada y compara objetivos equivalentes.
- Vector interoperable Argon2id+Sigma congelado. Validación con dependencia
  real: 317 pruebas sin skips y EXP-12 smoke con 24 observaciones/cero fallos.

### Tanda C2.2 — propiedades, fuzzing y mutación LIB-14

- Añadidas propiedades Hypothesis deterministas sobre codecs, contextos y
  rechazo de tipos; el corpus mutacional cubre ahora contexto, digest, PoW,
  parámetros/resultados KDF y ambas evidencias v2-2.
- El objetivo Atheris selecciona los siete parsers desde el primer byte, limita
  entradas a 64 KiB y comparte semillas canónicas con el fuzzer determinista.
  Campaña local de 10.000 casos: cero crashes, `cov=265`, `ft=467`.
- Mutmut queda configurado en un árbol aislado. La primera campaña TLV mató
  125/189; tras ampliar fronteras mata 152/189. Los 37 supervivientes exigen
  clasificación completa antes de cerrar LIB-14.

### Tanda C2.3 — ejes de versión y release LIB-15

- Paquete elevado a `2.2.0a1`; paquete, wire de contexto/digest/evidencia y
  familia de suite se declaran como ejes independientes en `sigma.version`.
- Los descriptores publican familia y estabilidad: v2-1 queda congelada/estable
  y v2-2 continúa experimental. El digest auditable conserva esos metadatos.
- El SBOM incorpora ejes de versión, commit, tag y árbol sucio. El modo
  `--require-clean-tag` impide generar artefactos publicables fuera de un tag
  exacto y limpio.

### Tanda C2.4 — identidad RealTime y backend Deep LIB-10/11

- ADR-0002 resuelve RealTime como política incremental sobre StreamWide. No se
  crea un `SuiteId` v2-2 redundante; el ID v2-1 queda sólo para reproducción y
  se marca obsoleto sin cambiar sus bytes.
- Deep separa la operación matemática de rama de los planificadores serial y
  threaded. El backend puede completar en cualquier orden; el motor valida
  cardinalidad, índices y anchuras y reconstruye el vector canónico antes del
  fold.
- Hay equivalencia de digest y transcript con 1, 2, 4 y 8 workers, un backend
  de prueba que invierte finalizaciones y backends deliberadamente corruptos.
  La ruta normal sigue superando la regresión O(k) de memoria.

### Tanda C2.5 — compromiso firmado LIB-09

- `SigmaSignedCommitmentV2` autentica contexto, evidencia, estados, algoritmo e
  ID de clave bajo un dominio nuevo, sin confundirse con `SigmaDigestV2`.
- Ed25519 es el único algoritmo registrado. Se separan verificación de
  atestación y verificación completa; un test firma deliberadamente una historia
  falsa y prueba que sólo la segunda modalidad la detecta.
- Codec estricto, prefijos truncados, límites de clave, alteraciones de firma y
  vector congelado quedan cubiertos. Atheris incluye el octavo parser: 10.000
  ejecuciones, cero crashes, `cov=301`, `ft=559`.

### Tanda C2.6 — DeepVector LIB-12

- Nueva suite `0x0106`, perfil y dominios exclusivos; cada estado publicado es
  el vector canónico de cuatro componentes de 64 bytes, sin fold intermedio.
- Cada componente siguiente autentica el vector anterior completo, contexto,
  índice, evidencia y posición. La especificación niega explícitamente una
  interpretación aditiva de seguridad sin hipótesis conjunta.
- Se separan `anchor_component_size` y `state_size` en el registro: todas las
  suites previas conservan 64/64 y DeepVector usa 64/256. Tests cubren anchura,
  dependencia completa, trace, verificación, dominios y memoria O(k).

### Tanda C2.7 — conformidad independiente inicial LIB-13

- `reference/independent_v22.py` reconstruye DeepVector usando únicamente
  `hashlib` y `struct`; no importa `sigma`, sus enums ni helpers de encoding.
- 28 combinaciones diferenciales cruzan longitudes `0/1/63/64/65/1024/1025`,
  `t=0/1/2/4`, `k=1/2/3`, parámetros autenticados y todos los intermedios:
  contexto, raíces, conexiones, evidencia, componentes, vectores y digest.
- El vector congelado conserva hashes SHA-256 de cada nivel y componente.
  LIB-13 permanece parcial hasta extender este consumidor a todas las suites y
  aplicaciones y completar límites de hojas TreeWide.

### Tanda C2.8 — conformidad independiente de todas las suites LIB-13

- El consumidor literal cubre ahora las seis suites v2-2: Reference,
  Lightweight, Simultaneous TreeWide, Paranoid Wide, Paranoid Deep y
  Paranoid DeepVector. Continúa sin importar `sigma`, enums ni codecs del
  paquete auditado.
- 118 casos diferenciales nuevos comparan contexto, raíces, conexiones,
  evidencia, estados, ramas Deep y digest; incluyen vacío, `1/63/64/65`,
  `1025`, límites de hoja `65535/65536/65537`, varias hojas y combinaciones de
  `t/k`.
- La primera ejecución descubrió y corrigió una traducción errónea del input
  Deep en el propio consumidor, demostrando que se comparan intermedios y no
  sólo el digest final. Validación global con Argon2 real: 489 pruebas sin
  omisiones; Ruff y mypy verdes.
- El tramo de suites de LIB-13 queda cerrado. El paquete permanece parcial
  hasta completar vectores y reconstrucción independiente de PoW, KDF y firma.

### Tanda C2.9 — aplicaciones, corpus y cierre LIB-13/14

- `reference/independent_applications.py` reconstruye sin importar `sigma` el
  framing y evaluación PoW, el postprocesamiento KDF posterior a Argon2id y la
  entrada/resultado Ed25519. Las tres rutas coinciden byte a byte con la API
  pública, incluida la firma determinista.
- `conformance-v2-2.json`, generado explícitamente por un script separado,
  congela contexto, evidencia, raíces, conexiones, estados, ramas y digest de
  las seis suites, además del vector PoW. Se complementa con los KAT existentes
  de Argon2id+Sigma y compromiso firmado.
- Los 37 supervivientes de la campaña TLV histórica quedaron clasificados: 33
  sólo cambian diagnósticos, dos cambian un centinela sin alterar el dominio y
  dos dependen del default de `byteorder` de Python 3.11+ (la CI 3.10 los mata).
  Tras regenerar la caché, seis mutantes conductuales nuevos de tags/tamaños
  fueron muertos 6/6 por tests directos.
- Cierre local: 493 pruebas sin omisiones con Argon2 real; Ruff y mypy verdes.
  R2 queda satisfecho en el repositorio, pendiente únicamente de reproducción
  multiplataforma/externa como condición posterior de R5, no de diseño.

### Tanda C3.1 — formalización v2-2 FORM-01..10

- El análisis deja de mezclar colisión, preimagen y segunda preimagen. Define
  siete juegos y exige publicar trabajo, consultas, profundidad, procesadores,
  memoria, usuarios/targets y consultas de firma.
- Canonicalidad enumera cada tipo aceptado; el ancla distingue
  `alpha_coll/pre/2pre/joint` de anchura física. La cota de segmento incluye
  `Bad_Q`, términos no ideales y la constante `sqrt(2 ln 2)`.
- Preimagen queda rotulada como modelo de imagen regular, no como consecuencia
  de colisión. El teorema de segunda preimagen usa una descomposición separada.
- WideOnce, Deep y DeepVector tienen DAGs distintos y límites explícitos. Deep
  no hereda una reducción de “una rama sana” si falla el fold; DeepVector sí
  conserva componentes, sin fuerza aditiva automática.
- La composición Ed25519 separa atestación, recomputación completa y una sola
  arista. La matriz claim-to-evidence y el checklist externo se actualizaron.
- FORM-01..09 están listos para revisión interna humana. FORM-10 incorpora un
  conjunto primario inicial (HAIFA, combiners, wide-pipe, herding,
  TupleHash/ParallelHash, PoSW, PBKDF2, Argon2 y Ed25519), pero no se declarará
  exhaustivo ni cerrará novedad sin revisión bibliográfica independiente.
