# Sigma v3 — fuentes y preparación del binding (R3)

Estado: **normativo para `REFERENCE_IAP_V3`**  
Fecha: 2026-09-19

Este documento cierra la semántica de fuentes de SPEC-V3-007 para la primera
suite. Cambiar los transcripts siguientes exige nuevos IDs y nuevos vectores.

## Fuente canónica

El dominio inicial es una secuencia exacta de bytes. `CanonicalSource` declara
su longitud y debe reproducir esos mismos bytes completos en cada pasada.

- `BytesSource` conserva un objeto `bytes` inmutable.
- `StableFileSource` fija dispositivo, inode, tamaño, `mtime_ns` y `ctime_ns` al
  construirse; los comprueba antes, durante y después de cada pasada, y compara
  además SHA-256 del contenido entre pasadas. SHA-256 aquí es un guard operativo,
  no una primitiva normativa del binding.
- `SpoolingStreamSource` consume el stream una vez y lo hace replayable mediante
  `SpooledTemporaryFile`. El límite de memoria por defecto es 1 MiB y el límite
  total de spool es 1 GiB. Ambos son configurables y explícitos. Superar el
  límite aborta y limpia el temporal. Cerrar la fuente limpia cualquier spool;
  el stream entregado por el caller no se cierra.

La longitud se cuenta en bytes realmente consumidos. Toda discrepancia con la
longitud fijada aborta la preparación. `prepare_binding_v3` captura esa longitud
una sola vez y compara además un SHA-256 operativo de las dos pasadas para todos
los subtipos de fuente; ese digest tampoco forma parte del binding normativo.

## Transcripts normativos

Todos usan el framing de `sigma.spec.transcript`, el contexto serializado por
`SigmaContextV3.to_bytes()` y el descriptor canónico de cardinalidad.

`A_X` conserva cuatro componentes. Cada algoritmo de ancla recibe el mismo
transcript `ANCHOR_BRANCH`:

1. contexto;
2. cardinalidad;
3. mensaje canónico en streaming.

La elección distinta de primitiva por componente y la lista cerrada incluida en
el contexto identifican cada rama.

`Lambda_X` usa SHA3-512 y el transcript `LENGTH_SIGNATURE`:

1. contexto;
2. cardinalidad.

`J_X` conserva cuatro componentes. Cada algoritmo conjunto recibe el transcript
`JOINT_SIGNATURE`:

1. contexto;
2. cardinalidad;
3. mensaje canónico en streaming;
4. ancla canónica;
5. firma de longitud canónica.

El domain tag de la primitiva y el domain del transcript se conservan ambos de
forma deliberada.

## Pasadas y recursos

`prepare_binding_v3` hace exactamente dos replays: ancla en la primera y firma
conjunta en la segunda. `Lambda_X` no lee el mensaje. Un `second_pass_sink`
opcional observa los chunks de la segunda pasada para que el futuro framing de
inicialización pueda compartirla y evitar una tercera lectura. Es deliberadamente
streaming y no transaccional: si la preparación lanza cualquier excepción, el
caller debe descartar incondicionalmente todo estado producido por ese sink. Sólo
un retorno exitoso autoriza a conservarlo.

El resultado es `PersistentBinding(A_X, kappa_X, Lambda_X, J_X)` y su constructor
impone `A_X.message_length == kappa_X.byte_length`.
