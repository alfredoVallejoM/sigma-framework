# Sigma v3 — backends e I/O completos (R10)

Estado: **normativo para entradas y ejecución v3**  
Fecha: 2026-09-20

## Invariante

El origen y la política de scheduling no forman parte de la función
matemática. Para un mismo contexto y los mismos bytes canónicos, bytes, fichero,
mmap, reader spooled e incremental producen el mismo binding, parámetros,
layouts, frames, estados, ventana y digest.

Los backends Deep continúan recibiendo sólo `DeepBranchTaskV3(position,
algorithm, frame_bytes)`. Ningún backend de threads o procesos reconstruye
contexto, binding, layouts ni frames.

## Fuentes

- `BytesSource` conserva bytes inmutables en memoria.
- `StableFileSource` reabre el fichero en cada replay y comprueba identidad,
  tamaño, timestamps y SHA-256 completo. Cualquier cambio entre pasadas se
  rechaza como `SourceChangedError`.
- `MmapFileSource` copia primero un fichero estable a un temporal privado,
  verifica la identidad antes y después de la copia y mapea sólo esa snapshot
  inmutable. Así una mutación o truncado posterior del path original no puede
  provocar lecturas mezcladas ni `SIGBUS` sobre el mapping evaluado.
- `SpoolingStreamSource` captura una fuente no replayable con límites explícitos
  de memoria, spool total y tamaño de lectura. El temporal se cierra también en
  rutas de error.
- `IncrementalSpoolSource` admite `update()` acotado, snapshots independientes
  de prefijo y se vuelve `CanonicalSource` sólo tras `finalize()`.

`evaluate_file_v3` usa snapshot estable por defecto. `use_mmap=True` sólo cambia
el mecanismo de replay de esa snapshot. `evaluate_reader_v3` captura el reader
antes de evaluar. Todos los recursos poseen cierre determinista mediante
context manager o `finally`.

## Incremental

`IncrementalSigmaV3.checkpoint()` no clona un estado de ancla ni marca como
equivalente un digest provisional. Copia el prefijo actual a una fuente
replayable y evalúa una Sigma v3 completa e independiente para ese prefijo:

```text
prefix -> cardinality -> A -> Lambda -> J -> t,k -> S0 -> rounds -> digest
```

El checkpoint contiene offset, digest real del prefijo y `provisional=True`
porque pueden llegar más bytes. `finalize()` congela el spool, evalúa el mensaje
completo una sola vez y libera el recurso incluso si la evaluación falla o se
cancela.

## Cancelación y errores

`CancellationTokenV3` se comprueba antes de preparar la entrada, antes y después
de cada chunk canónico y entre rondas. La cancelación levanta
`EvaluationCancelledV3`; nunca devuelve un digest parcial. Un batch de proceso
en curso termina su frontera canónica y el executor se cierra antes de propagar
la cancelación.

Se rechazan explícitamente fuentes cerradas, cambios TOCTOU, chunks o readers
inválidos, límites de spool, uso incremental tras cierre/finalización y errores
de componentes de backend. No se rebajan límites ni se cambia la semántica para
preservar una API incremental antigua.

## Gate R10

- igualdad completa de evaluación y digest para bytes, file, snapshot mmap,
  reader/spool e incremental en WideOnce, Deep y DeepVector;
- checkpoint incremental igual al digest directo de cada prefijo;
- igualdad con backend process y ausencia de procesos hijo retenidos;
- detección TOCTOU para fichero estable y aislamiento de snapshot mmap;
- cancelación antes y durante I/O, y tras un batch de procesos;
- límites de memoria/spool, errores y uso tras cierre;
- ficheros vacíos y limpieza de todos los recursos;
- gate autoritativo acumulativo y baseline v2.2 verdes.
