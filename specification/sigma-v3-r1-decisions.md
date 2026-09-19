# Decisiones normativas Sigma v3 previas a R1

Estado: **cerradas para la primera suite reference**  
Fecha: 2026-09-19

Este documento cierra SPEC-V3-003, SPEC-V3-004, SPEC-V3-005 y SPEC-V3-006.
Cambiar cualquiera de estas decisiones exige nuevos identificadores y nuevos
vectores; no se cambia la semántica detrás de los IDs aquí asignados.

## SPEC-V3-003 — Dominio canónico inicial

La primera suite admite exclusivamente secuencias de bytes. Para `bytes`,
ficheros y streams, `M_X` es la secuencia exacta de bytes consumida. Dos entradas
son equivalentes si y sólo si producen exactamente esos mismos bytes. Nombres,
metadatos de fichero, Unicode, objetos estructurados y orden de mapas quedan
fuera del dominio inicial. Añadirlos requerirá un perfil de entrada y una
canonicalización nuevos.

## SPEC-V3-004 — Primitivas y anchuras

Todos los identificadores de algoritmo existentes representan salidas de 512
bits y sus componentes normativos tienen exactamente 64 bytes:

- ancla vectorial: SHA-512, SHA3-512, BLAKE2b-512 y SHAKE256-512;
- `H_len`: SHA3-512;
- `H_joint` vectorial: SHA-512, SHA3-512, BLAKE2b-512 y SHAKE256-512;
- estado WideOnce reference: SHA-512, 64 bytes;
- XOF de parámetros/layout: SHAKE256, con domains v3 distintos.

No se suman las anchuras como seguridad efectiva. El vector se conserva para
robustez frente al fallo parcial; cualquier fold futuro tendrá perfil y domain
propios.

## SPEC-V3-005 — Catálogo inicial

Sólo se registra inicialmente `REFERENCE_IAP_V3` (`0x0301`):

- input `CANONICAL_BYTES`;
- anchor `STREAM_WIDE` con cuatro algoritmos;
- cardinalidad `BYTE_LENGTH`;
- joint `VECTOR` con cuatro algoritmos;
- round `WIDE_ONCE`;
- output `IMPLICIT_J`;
- layout `SHAKE256_REJECTION`;
- trajectory `BINDING_DERIVED`;
- estado de 64 bytes;
- `t` en `[2, 32]` y `k` en `[2, 4]`.

R4 fijará el transcript y extracción exactos de `t/k`; R5 fijará layout. Hasta
entonces la suite tiene tipos y límites, pero no una función ejecutable completa.

## SPEC-V3-006 — Perfiles de evidencia

`IMPLICIT_J` (`0x0301`) es el único output registrado inicialmente. Publica
`(C, kappa, A, Lambda, t, k, W)` y recomputa `J` desde el mensaje durante
verificación completa.

`EXPLICIT_BINDING` (`0x0302`) queda reservado, pero no registrado en ninguna
suite durante R1–R3. Si se habilita, requerirá otro `SuiteId`, wire y claims: con
binding completo y un estado iguales, los estados posteriores coalescen por
determinismo.

R8 habilita ese perfil exclusivamente como envelope de auditoría bajo el ID
exterior `EXPLICIT_AUDIT_V3 (0x0302)`, con wire y domain propios. Se registra en
el catálogo cerrado de envelopes, no en el de suites ejecutables: no puede crear
un `SigmaContextV3`, ancla ni binding. La trayectoria contenida sigue identificada
por el digest implícito anidado; el ID exterior identifica el perfil de
publicación y sus claims adicionales.

## Layout tipado

Todo plan declara `INIT` o `ROUND`. La inicialización y las rondas tendrán
domains y schedulers distintos; un plan de una clase no es intercambiable sin
una comprobación explícita de tipo.
