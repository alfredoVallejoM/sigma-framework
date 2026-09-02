# Auditoría de brecha y campañas Sigma v2-2

Fecha de corte: 2026-09-02. Rama auditada: `sigma-v2-audit`. Baseline remoto:
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
| LIB-13 | parcial | hay KAT de referencia, pero cobertura intermedia incompleta y sin segunda implementación | corpus completo y consumidor independiente |
| LIB-14 | parcial | existe fuzz mutacional determinista de cuatro parsers | property, coverage-guided, mutation, parsers nuevos y presupuestos |
| LIB-15 | parcial | paquete `2.0.0a1`, suites `v2-1`, wire v2 y artefactos existen | nomenclatura unificada, política y tag limpio de campaña |

## Brecha formal

| ID | Estado | Acción vinculante |
|---|---|---|
| FORM-01 | abierto | definir siete juegos con presupuestos y capacidades separados |
| FORM-02 | bloqueado por LIB-03/04 | reescribir canonicalidad para todos los tipos aceptados |
| FORM-03 | abierto | separar colisión, preimagen, segunda preimagen y supuesto conjunto del ancla |
| FORM-04 | parcial | la intuición de reinyección existe; falta juego condicionado y controles |
| FORM-05 | parcial | modelo reducido existente; falta bound, constante de cumpleaños y censura |
| FORM-06 | abierto | teoremas independientes de preimagen y segunda preimagen |
| FORM-07 | parcial | contabilidad experimental existe; falta modelo de oráculo paralelo |
| FORM-08 | abierto | seguridad de Deep/DeepVector bajo ramas y fold defectuosos |
| FORM-09 | bloqueado por LIB-09 | reducción de reutilización de firma por modalidad de verificación |
| FORM-10 | abierto | related work y afirmación de novedad delimitada con fuentes primarias |

Ningún texto formal se considerará prueba revisada externamente. Las hipótesis
conjuntas se etiquetarán siempre como supuestos, no como bits sumados.

## Brecha experimental

### EXP-00 v2

El runner actual conserva config, semilla, entorno, CSV, resumen y hashes, pero
ejecuta un experimento completo en memoria y en un directorio indivisible. Le
faltan tareas deterministas por celda/repetición, append-only, resume sin
duplicados, estados timeout/error/censura, stdout/stderr, tag/wheel y series de
control del host. `passed` mezcla invariantes y resultados estadísticos.

### EXP-01R..21R

- EXP-01..10 existentes son pilotos funcionales, no los diseños R revisados.
- EXP-11, 12, 14 y 15 son smoke parciales y requieren los cambios declarados.
- EXP-17..21 no existen.
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
