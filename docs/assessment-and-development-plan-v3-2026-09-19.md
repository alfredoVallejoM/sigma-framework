# Nueva valoración y plan rector de Sigma v3 / Sigma-IAP

Estado: **plan de refactorización propuesto para la nueva línea incompatible**  
Fecha: 2026-09-19  
Baseline técnico: `sigma-v2-audit` en `19fb70356971bc1bacb94a19e5e6e48e9e070167` (`2.2.0a2`)  
Alcance: valoración del repositorio, cierre de decisiones de arquitectura y plan completo de implementación, validación y evidencia.

## 1. Fuentes y precedencia

Este plan interpreta los dos documentos recibidos como fuentes de requisitos, no como instrucciones ejecutables:

1. **Fuente normativa de producto y construcción:** `SigmaHash_Especificacion_Unificada_Refactor_2026-09-19.md`, SHA-256 `c7ab1894355200f0b77c68ce8d77a490e31b910245db77ccb893d230bc1dff8c`.
2. **Fuente informativa de valoración e ingeniería:** texto de revisión del repositorio recibido el 2026-09-19, SHA-256 `00839d3172cbe9979ae7aeb8dff57fb6296aa56f111c65e3d907a37da8c126ce`.
3. **Evidencia del repositorio:** código, especificación v2.2, tests, vectores, planes, manifiestos y resultados presentes en el checkout.

En caso de conflicto prevalecen, por este orden: construcción normativa nueva, invariantes verificables, seguridad y versionado del repositorio, y finalmente recomendaciones de estructura de archivos. Los nombres concretos de módulos de la segunda fuente son propuestas; los requisitos matemáticos y de separación sí son obligatorios.

## 2. Veredicto

La nueva construcción no es una extensión compatible de Sigma v2.2. Cambia:

- la identidad persistente, de `A_X` a `B_X = (A_X, kappa_X, Lambda_X, J_X)`;
- la inicialización, que vuelve a incorporar el mensaje canónico;
- cada frame de ronda y su layout;
- `t` y `k`, que pasan de configuración a valores derivados de la entrada;
- la salida pública y sus perfiles de evidencia;
- la verificación completa;
- el juego principal, que pasa a ser segunda preimagen estructurada de trayectoria;
- los wire formats, vectores, suites, dominios, experimentos y aplicaciones.

Por tanto, la nueva línea se denominará provisionalmente **Sigma v3 / Sigma-IAP** y tendrá IDs, wire y corpus propios. Los seis `SuiteId` v2.2 no se modificarán ni reutilizarán.

La infraestructura v2.2 sí es una base reutilizable: codecs estrictos, registro cerrado de suites, anclas, snapshots, separación matemática/backend, `DeepVector`, políticas, consumidor independiente, fuzzing, empaquetado e instrumentación. La estrategia correcta es preservar esos mecanismos y reemplazar la semántica central mediante módulos v3 separados.

## 3. Estado de partida y tratamiento de v2.2

### 3.1. Estado observado

- Rama de referencia: `sigma-v2-audit`, alineada con remoto en `19fb703...` y tag `f7-v2.2.0a2-20260903`.
- Paquete: `2.2.0a2`, alpha de investigación, no apto para producción y sin revisión criptográfica externa.
- F0–F6 figuran cerradas en la planificación v2.2.
- La suite actual de tests pasa localmente con `pytest -q`.
- F7 está incompleta: existen diez resúmenes Linux finalizados, con 3.625 de 5.289 tareas planificadas; no existen todavía las réplicas macOS/Windows, el segundo host ni todas las baterías externas.
- Nueve resultados finalizados fueron ejecutados con `2.2.0a1`; EXP-20 fue ejecutado con `2.2.0a2`. El freeze vigente referencia `2.2.0a2`, por lo que el conjunto no puede declararse un dataset canónico único sin reconciliación formal o repetición.
- El manuscrito v2.2 carece deliberadamente de resultados confirmatorios; F8 y F9 siguen abiertas.

### 3.2. Decisión de conservación

1. v2.2 queda **congelada como baseline histórico y de regresión**.
2. No se altera ninguna semántica detrás de IDs v2.2.
3. La evidencia F7 parcial se conserva íntegra, con sus hashes y procedencia, pero no se reutiliza como evidencia v3.
4. Antes de implementar v3 se genera un inventario de artefactos v2.2 y se documenta la discrepancia `a1/a2`; no se borran resultados.
5. El plan v2.2 continúa describiendo exclusivamente aquella línea. Este documento gobierna la nueva línea v3.
6. No se reanuda una campaña confirmatoria v2.2 por defecto. Cualquier decisión de terminarla debe justificarse como trabajo histórico independiente del desarrollo v3.

## 4. Definición normativa del producto v3

La cadena conceptual obligatoria es:

```text
CanonicalSource
  -> M_X = Can(X)
  -> kappa_X = Card(M_X)
  -> A_X = Anchor(C, kappa_X, M_X)
  -> Lambda_X = H_len(C, kappa_X)
  -> J_X = H_joint(C, kappa_X, M_X, A_X, Lambda_X)
  -> B_X = (A_X, kappa_X, Lambda_X, J_X)
  -> (t_X, k_X) = DeriveParameters(C, B_X)
  -> Pi_X,i = Schedule(C, Lambda_X, i, width)
  -> S_0 = F_init(C, M_X, Place(B_X))
  -> S_i+1 = F_round(C, i, Place(S_i, B_X))
  -> W_t,k = (S_t, ..., S_t+k-1)
  -> Sigma(X) = Enc(C, PublicHeader_X, W_t,k)
```

El encabezado público principal es:

```text
PublicHeader_X = (kappa_X, A_X, Lambda_X, t_X, k_X)
```

`J_X` forma parte del binding interno y se recomputa desde `X` durante `verify_full`. No se publica en el perfil normativo principal. Un perfil explícito puede publicarlo, pero debe disponer de un `OutputProfileId` o `SuiteId` distinto y declarar que, tras igualar binding y estado, las rondas posteriores coalescen determinísticamente.

### 4.1. Propiedad estructural central

Si `B_X != B_Y` pero `S_i(X) == S_i(Y)`, los siguientes frames son distintos. Mantener la igualdad en la ronda siguiente requiere una nueva colisión sobre entradas diferentes.

### 4.2. Juego principal

Dado `X` y `Sigma(X)`, el adversario debe producir `X'` semánticamente distinto con el mismo contexto, cardinalidad, ancla, firma de longitud, `t`, `k` y ventana. El éxito se divide en:

- `J_X' == J_X`: ataque contra el binding interno más coincidencia del estado objetivo;
- `J_X' != J_X`: coincidencias sucesivas de la ventana bajo frames distintos.

Las afirmaciones se clasificarán siempre como `proved`, `reduced`, `ideal-model`, `empirical` u `open`. No se sumarán anchuras de componentes como bits efectivos sin una reducción explícita.

## 5. Decisiones de arquitectura ya adoptadas

| ID | Decisión |
|---|---|
| ADR-V3-001 | Crear una familia v3 incompatible; v2.2 permanece inmutable. |
| ADR-V3-002 | Separar configuración previa a `X` (`SigmaContextV3`) de parámetros derivados (`TrajectoryParameters`). |
| ADR-V3-003 | Representar `Anchor`, `CardinalityDescriptor`, `LengthSignature`, `JointSignature`, `PersistentBinding` y `PublicHeader` mediante tipos distintos. |
| ADR-V3-004 | Mantener `J_X` fuera del wire normativo principal y recomputarlo en verificación completa. |
| ADR-V3-005 | Centralizar todos los bytes de inicialización y ronda en builders de frames; los motores sólo comprimen frames canónicos. |
| ADR-V3-006 | Los backends reciben tareas canónicas y sólo cambian scheduling, nunca framing ni matemática. |
| ADR-V3-007 | Soportar transcripciones canónicas streaming y fuentes replayable; no cargar mensajes grandes en un TLV monolítico. |
| ADR-V3-008 | Conservar componentes vectoriales de ancla, `J` y estado cuando la suite lo declare; cualquier fold es explícito y domain-separated. |
| ADR-V3-009 | Separar verificación estructural de verificación vinculada al mensaje. |
| ADR-V3-010 | Portar aplicaciones sólo después de congelar el núcleo; PoW queda al final por el sesgo de selección de nonces. |

## 6. Decisiones normativas que bloquean implementación irreversible

Estas decisiones deben cerrarse por escrito y acompañarse de vectores mínimos antes del gate indicado:

| ID | Decisión pendiente | Bloquea |
|---|---|---|
| SPEC-V3-001 | Transcript exacto y muestreo sin sesgo para derivar `t_X` y `k_X`; orden de extracción y rangos. | Preparación completa |
| SPEC-V3-002 | Separación exacta entre `LayoutInit` sobre `M_X` y `LayoutRound` sobre el estado; slots y domains. | Framing |
| SPEC-V3-003 | Dominios de entrada soportados inicialmente y reglas de equivalencia semántica/canonicalización. | API pública |
| SPEC-V3-004 | Primitivas, anchuras, perfiles escalares/vectoriales y política de independencia conservadora. | Registro de suites |
| SPEC-V3-005 | Catálogo inicial de suites v3; comenzar con una única suite reference. | Presets y wire |
| SPEC-V3-006 | Perfiles `IMPLICIT_J` y `EXPLICIT_BINDING`, campos exactos y asignación de IDs. | Digest/evidence |
| SPEC-V3-007 | Semántica de streams no seekable, spool, límites de disco, errores y limpieza segura. | I/O |
| SPEC-V3-008 | Límites de parser y orden de validaciones baratas antes de hashes, spool o trabajo costoso. | Seguridad operativa |
| SPEC-V3-009 | Perfil de trayectoria de KDF y límites de variación de coste por candidato. | KDF |
| SPEC-V3-010 | Derivación PoW excluyendo nonce o suspensión inicial del perfil. | PoW |
| SPEC-V3-011 | Política de convivencia, import paths y migración v2.2 -> v3; no habrá conversión de digests. | Release/API |
| SPEC-V3-012 | Regla exacta de estabilidad de fichero entre las pasadas de preparación e inicialización. | File API |

No se deben fijar wire, suite IDs ni campañas antes de cerrar estas decisiones.

## 7. Mapa de impacto del repositorio

### 7.1. Conservar como baseline

- `sigma/v2.py`, wire, presets, suites y aplicaciones v2.2: sólo mantenimiento crítico.
- `specification/test-vectors/conformance-v2-2.json`.
- `reference/independent_v22.py`.
- especificación, experimentos y evidencia v2.2.

### 7.2. Reutilizar o adaptar

- validación de límites e IDs cerrados;
- codecs TLV para objetos pequeños;
- `StreamWide`, `CrossWide` y `TreeWide` como familias de ancla;
- snapshots estables de fichero;
- instrumentación y scheduler experimental;
- `ResourcePolicy`, separando validación estática y derivada;
- ejecución serial, threads, procesos y mmap;
- build aislado, fuzzing y release artifacts.

### 7.3. Crear

```text
sigma/crypto/              primitivas compartidas e IDs de algoritmos
sigma/binding/             cardinalidad, Lambda, J, binding y parámetros
sigma/layout/              schedule, slots, tie ordering y placement
sigma/sources/             bytes, fichero estable y stream con spool
sigma/spec/transcript.py   writer canónico streaming
sigma/spec/context_v3.py   contexto previo a la entrada
sigma/rounds/framing.py    frames de init, ronda, Deep y vector
sigma/outputs/digest_v3.py digest y evidencia v3
sigma/v3.py                fachada/pipeline v3
reference/independent_v3.py
```

Los nombres finales pueden ajustarse para seguir las convenciones del paquete, pero las fronteras de responsabilidad son obligatorias.

### 7.4. Refactorizar profundamente

- `rounds/wide_once.py`: dejar de construir semántica y consumir frames canónicos.
- `rounds/deep*.py`: compartir framing y preservar la distinción entre estado escalar plegado y vector completo.
- `rounds/backends.py`: ejecutar tareas canónicas sin reconstruir bindings.
- registro de suites: describir todos los perfiles, dominios, primitivas, rangos y tamaños que afectan la función.
- `incremental.py`: producir digests reales de prefijo mediante fuente replayable; no reutilizar el checkpoint v2 como si fuera equivalente.
- aplicaciones de firma, KDF y PoW: utilizar `SigmaDigestV3` sin duplicar campos.

## 8. Plan de ejecución y gates

### R0 — Preservación y apertura de línea v3

Entregables:

- inventario con hashes de código, wheel, tags, vectores y datos F7 v2.2;
- nota de procedencia sobre resultados `a1/a2`;
- rama v3 creada desde `19fb703...`;
- regla automática que impida modificar IDs y vectores v2.2 accidentalmente.

Gate R0: baseline reproducible, ningún artefacto eliminado y suite v2.2 verde.

### R1 — Especificación ejecutable y tipos

Implementar contexto v3 y tipos de cardinalidad, firmas, binding, parámetros, header, layout y ventana, todavía sin rondas.

Gate R1: codecs canónicos, invariantes de construcción, igualdad/hash seguros, parsers negativos y límites aplicados.

### R2 — Primitivas, dominios y transcript streaming

Extraer primitivas compartidas, registrar nuevos domains y construir writer streaming equivalente al encoding canónico materializado para entradas pequeñas.

Gate R2: KAT por primitiva, ausencia de colisiones de transcript entre domains, chunk invariance y límites de tamaño.

### R3 — Fuentes y preparación del binding

Implementar `BytesSource`, `StableFileSource`, `SpoolingStreamSource`, cardinalidad, ancla, `Lambda`, `J` y `PersistentBinding`. Diseñar dos pasadas: ancla/J y luego init, evitando una tercera cuando sea posible.

Gate R3: misma salida para bytes, fichero y stream; detección de mutación de fichero; limpieza de spool; memoria acotada; `anchor.message_length == kappa.byte_length`.

### R4 — Derivación de `t` y `k`

Cerrar SPEC-V3-001 e implementar muestreo por rechazo dentro de rangos fijados por la suite.

Gate R4: determinismo, ausencia de módulo sesgado, tests exhaustivos en rangos pequeños, límites y vectores de derivación.

### R5 — Layout y placement

Implementar schedule separado para init/ronda, slots medidos sobre el objeto original, tie ordering total y campos tipados.

Gate R5: mismo layout entre plataformas/backends, slots válidos, distribución del muestreo comprobada, vectors de placement e inyectividad dentro del dominio soportado.

### R6 — Framing normativo

Construir `InitFrame`, `RoundFrame`, `DeepBranchFrame` y `VectorRoundFrame`. Sólo estos builders pueden decidir orden, domains y codificación.

Gate R6: vectores byte a byte para cada campo y mutaciones de un solo campo; ninguna concatenación ambigua ni endianness implícito.

### R7 — Primera suite reference end-to-end

Implementar una única suite v3 con WideOnce:

```text
X -> M -> kappa -> A -> Lambda -> J -> B -> t,k -> layouts -> states -> header -> digest
```

Gate R7: determinismo, cambios sensibles en cada componente, ventana correcta y prototipo independiente coincidente.

### R8 — Digest, wire y verificación

Implementar `SigmaDigestV3`, perfil `IMPLICIT_J`, perfil explícito separado, `verify_structure`, `verify_full`, recomputación de binding/ventana y verificación interna preparada.

Gate R8: round-trip canónico, rechazo de campos desconocidos/duplicados/no canónicos, comparación completa de cabecera y ventana, y ningún claim de vinculación desde `verify_structure`.

### R9 — Deep y DeepVector

Portar la semántica común. `Deep` conserva su fold escalar explícito; `DeepVector` conserva el vector completo y cada componente depende del vector previo completo.

Gate R9: igualdad serial/thread/process, preservación vectorial, tests de fallo controlado de componentes y diferenciación clara de claims.

### R10 — Backends e I/O completos

Integrar bytes, fichero, mmap, procesos, spool e incremental. El backend sólo recibe tareas/fragments canónicos.

Gate R10: todos los caminos producen idénticos frames y digest; pruebas de TOCTOU, cancelación, errores, límites de recursos y limpieza.

### R11 — Aplicaciones

Orden:

1. compromiso firmado sobre `digest.to_bytes()`;
2. composición Argon2id + Sigma con secreto no serializable y coste v3 acotado;
3. PoW sólo después de resolver SPEC-V3-010.

Gate R11: aislamiento de domains, wire propio por aplicación, regresiones de downgrade y modelos de amenaza específicos. No atribuir memory hardness a Sigma ni propiedades de VDF/constant-time/ASIC resistance sin evidencia independiente.

### R12 — Especificación, corpus e implementación independiente

Publicar una especificación byte-exacta y un corpus que contenga `M`, `kappa`, componentes de `A`, `Lambda`, componentes de `J`, `t`, `k`, layouts, placements, frames, estados, header y digest.

Gate R12: `reference/independent_v3.py` reproduce todo sin importar `sigma`; cero divergencias en todas las suites candidatas.

### R13 — Seguridad estructural y modelos reducidos

Formalizar y probar:

- separación exacta por cardinalidad;
- no coalescencia con binding distinto;
- coalescencia con binding y estado iguales;
- inicialización reforzada con mensajes distintos;
- ramas same-`J` y different-`J`;
- separación entre evidencia implícita y explícita.

Rehacer EXP-03, EXP-17, EXP-20 y EXP-21 para la semántica v3. Los datos v2.2 no se reinterpretan.

Gate R13: hipótesis, juegos, endpoints, oráculos y límites de claim revisados antes de recopilar resultados de producto.

### R14 — Validación integral y freeze candidato

El gate local debe cubrir formato, lint, tipado, compilación, tests, properties, diferencial, vectores, fuzzing, build aislado, ambos CLI, import real desde wheel y cobertura por subsistema.

Gate R14: wire y vectores sólo pueden marcarse congelados tras pasar el consumidor independiente y el gate desde un checkout limpio. La suite seguirá siendo experimental.

### R15 — Pilotos, prerregistro y confirmatorio v3

Ejecutar primero pilotos desechables para dimensionar:

- distribución conjunta de `(t,k)` y correlaciones;
- layouts, ties y difusión;
- same-`J`/different-`J`;
- segunda preimagen estructurada reducida;
- precomputación entre estratos;
- rendimiento, memoria y variabilidad por aplicación.

Después se congela un nuevo prerregistro, configuraciones, artefacto y hash. Sólo entonces comienza un confirmatorio v3 multihost/multiplataforma.

Gate R15: dataset único verificable; resultados positivos, negativos, errores, timeouts y censura conservados; artículo generado desde el dataset y no desde pilotos.

### R16 — Auditoría y publicación

Reproducir el gate y una muestra de campañas en otra máquina/persona, auditar wire, KDF, firma, PoW y claims, archivar artefactos con identificador persistente y solicitar revisión criptográfica externa.

Gate R16: ninguna afirmación estable o de producción antes de resolver hallazgos graves y mantener explícitos los límites no demostrados.

## 9. Obligaciones trazables

| Bloque | Contenido mínimo |
|---|---|
| CORE-01–06 | canonicalización, cardinalidad, `Lambda`, `J`, binding, parámetros derivados |
| LAYOUT-01–06 | XOF, rejection sampling, slots, ties, placement, inyectividad |
| FRAME-01–05 | init, ronda escalar, Deep branch, fold y vector round |
| TRAJ-01–06 | WideOnce, Deep, DeepVector, ventanas, coalescencia y no coalescencia |
| WIRE-01–06 | contexto, header, digest, evidencia explícita, parsers y versionado |
| IO-01–05 | bytes, snapshot, spool, incremental y multiproceso |
| APP-01–03 | firma, KDF y PoW |
| FORM-01–10 | teoremas estructurales, reducciones, TSP y límites de claims |
| EXP-01–08 | reduced models, layout, estratos, same/different `J`, TSP, dependencias y precomputación |
| CONF-01–05 | vectores, independiente, diferenciales, fuzzing y freeze |

Cada obligación se cierra mediante su invariante y evidencia asociada, no sólo porque el código compile.

## 10. Estrategia de pruebas

### Deterministas

- canonicalización y equivalencia semántica;
- codificación TLV/streaming y chunk invariance;
- límites, enteros, orden, unicidad y trailing bytes;
- cardinalidad exacta y redundancia con ancla;
- domain separation;
- derivación y rangos de `t/k`;
- layouts, ties y placements;
- frames completos e intermedios;
- serial/thread/process/mmap equivalentes;
- coalescencia/no coalescencia;
- perfiles de evidencia y verificadores;
- snapshot, spool, cancelación y recuperación de errores.

### Property/differential/fuzz

- round-trip sólo para encodings canónicos;
- una mutación de campo cambia el frame o es rechazada;
- implementación principal contra reference independiente;
- fuzz de todos los codecs y parsers antes de trabajo costoso;
- tamaños extremos, estados vectoriales y límites de profundidad;
- fallos concurrentes sin pérdida ni sobrescritura de artefactos.

### Experimentales

Se mantienen fuera de los tests de conformidad: difusión, independencia, distribuciones, correlaciones, rutas diferenciales, multicollisions, time-memory tradeoffs, segunda preimagen reducida y costes. Sus resultados no convierten hipótesis en teoremas.

## 11. Aplicaciones y restricciones específicas

### Firma digital

La firma autentica el digest v3 serializado. Sigma no aumenta la seguridad matemática del algoritmo de firma. No se duplican ancla ni estados fuera del digest.

### KDF/contraseñas

Argon2id conserva toda atribución de memory hardness. Sigma añade binding y trayectoria, no entropía. El perfil debe limitar la variación de `t/k`, verificar parámetros baratos antes del trabajo costoso y mantener separado el secreto del verificador público.

### PoW

No se derivan `t/k` de una entrada controlable por nonce sin analizar selección de candidatos baratos. La opción preferida es derivarlos de contexto, challenge y payload fijo, excluyendo nonce; si no se puede justificar, PoW v3 queda suspendido.

### Incremental

Cada checkpoint representa un Sigma completo del prefijo. La optimización no puede cambiar la función. Para fuentes no replayable se usa spool sujeto a política.

## 12. Riesgos principales y mitigaciones

| Riesgo | Mitigación |
|---|---|
| Cambiar accidentalmente v2.2 | módulos/IDs separados y regresión byte-exacta |
| Especificación incompleta de `t/k` o layout | cerrar SPEC-V3 antes de wire/rondas |
| Divergencia WideOnce/Deep/DeepVector | framing único y tareas canónicas |
| DoS por mensajes, spool o parámetros | `ResourcePolicy` estática/derivada y validación barata primero |
| TOCTOU entre pasadas | `StableFileSource` y snapshot obligatorio |
| Sesgo por módulo | rejection sampling y tests exhaustivos en rangos reducidos |
| Sobreafirmación criptográfica | etiquetas de claim y revisión externa |
| Reutilizar evidencia v2.2 | datasets, IDs, protocolos y artículo v3 separados |
| Complejidad excesiva de suites | una suite reference hasta R12 |
| Sesgo PoW o coste KDF variable | perfiles específicos y gates de aplicación |

## 13. Criterio global de terminado

Sigma v3 estará lista para un freeze experimental cuando:

1. la especificación sea byte-exacta y no queden decisiones normativas implícitas;
2. v2.2 siga reproduciéndose sin cambios;
3. contexto, binding, parámetros, layout, frames, wire y verificadores sean tipos y capas separados;
4. una implementación independiente reproduzca todos los intermedios y digests;
5. todos los backends e I/O produzcan los mismos bytes;
6. parsers y políticas rechacen entradas inválidas antes del trabajo costoso;
7. los teoremas estructurales, reducciones, modelos ideales e hipótesis experimentales estén diferenciados;
8. las aplicaciones dispongan de modelos de amenaza propios;
9. el gate local pase desde un checkout limpio y un wheel instalado fuera del árbol;
10. wire y vectores se congelen antes de cualquier confirmatorio;
11. exista un único dataset v3 trazable al artefacto y prerregistro congelados;
12. el manuscrito se genere desde esa evidencia y declare que la revisión criptográfica externa sigue pendiente.

La revisión externa, no el éxito de tests o campañas, será el requisito para considerar claims de seguridad estables. La adopción en producción requerirá además una decisión separada.

## 14. Próximo paso autorizado por este plan

El siguiente bloque de desarrollo es **R0–R1**, precedido por el cierre de SPEC-V3-003, SPEC-V3-004 y SPEC-V3-005. No se deben tocar aún WideOnce, Deep, DeepVector, aplicaciones ni campañas. Primero se preserva v2.2 y se hace ejecutable la nueva taxonomía de tipos; después se congelan los bytes de primitivas, parámetros y layout.
