# Auditoría de formatos y conformidad Sigma v2.2

Estado: **F2 cerrada localmente**  
Fecha: 2026-09-03  
Alcance: familia activa `v2-2`; F5 retiró las implementaciones v1/v2.1 y
conserva sus IDs únicamente como valores reservados.

Este documento registra el cierre de ingeniería de F2. Congelar el wire, los
vectores y la definición de suite significa que cualquier cambio posterior de
bytes o matemática exige identificadores nuevos. No significa que exista una
revisión criptográfica externa ni que el paquete sea apto para producción.

## Formatos auditados

| Codec | Esquema cerrado | Límites semánticos | Rechazos cubiertos |
|---|---|---|---|
| contexto | 11 TLV obligatorios | `t=0..1_000_000`, `k=1..16`, campos opacos hasta 4096 bytes, suite exacta | magic/versión, tags desconocidos, orden, duplicados, truncado, trailing, enteros y enums |
| evidencia | envelope v2, tipos Wide/Cross | suite, perfil, orden de ramas, número y anchura de componentes, longitud `u64` | tipo/ID incorrecto, campos ausentes, algoritmos desconocidos, componentes y trailing |
| digest | contexto más exactamente `k` estados | anchura exacta del descriptor: 64 o 256 bytes | contexto inválido, count downgrade, estado truncado/ancho, trailing y JSON no canónico |
| PoW3 | 5 TLV obligatorios | nonce `u64`, predicado cerrado, dificultad dentro de la anchura publicada y política local | magic, tags/IDs, anchos, dificultad imposible, truncado y trailing |
| Argon2id | 5 TLV obligatorios | v1.3, memoria `>=8p`, salida 16..1024, política local | versión, coste, paralelismo, anchos, truncado y trailing |
| registro KDF | parámetros, salt y digest | suite KDF v2.2 cerrada, salt y application-context ligados | downgrade, sustitución de parámetros/salt/digest, truncado y trailing |
| firma | 6 TLV obligatorios | suite v2.2, Ed25519, key-id 1..255, estados y evidencia exactos | algoritmo, claves/firmas, campos, orden, truncado y trailing |

`decode_uint` acepta exclusivamente `bytes` y anchuras 1, 2, 4 u 8. El codec
TLV acepta tags 1..65535, longitudes de campo hasta 1 MiB y orden estrictamente
creciente. Cada parser de esquema exige el conjunto exacto de tags. El corpus
negativo normativo contiene, para los ocho codecs públicos, mutaciones de
truncado, trailing y magic; las baterías unitarias añaden duplicados, cambios de
orden, campos desconocidos, anchos e identificadores cerrados.

## Constantes matemáticas

El descriptor `SuiteDescriptor` es ahora la autoridad de:

- ramas y orden;
- algoritmo de estado;
- anchura de componente de ancla;
- anchura de estado publicado;
- tamaño canónico de hoja TreeWide;
- perfiles de ancla, ronda y salida;
- familia y versión de evidencia.

El registro valida sus propias relaciones: una suite TreeWide debe declarar un
tamaño de hoja positivo; las demás declaran cero; DeepVector publica exactamente
`component_size * branch_count`; los perfiles escalares publican una anchura de
componente. TreeWide ya no valida hojas prehash contra un literal de 64 bytes,
los presets no duplican 65.536 y PoW deriva sus bits disponibles del descriptor
de la suite seleccionada.

## Conformidad diferencial

El consumidor `reference/` no importa `sigma`. La matriz compara bytes de
contexto, roots, cross-roots, evidencia, cada estado, cada salida Deep, cada
componente DeepVector y el digest final para:

- las seis suites v2.2;
- mensajes vacíos y límites 63/64/65, 1024/1025 y 65535/65536/65537;
- `t/k` en inicialización, varias rondas y distintas ventanas publicadas;
- los tres predicados PoW;
- las cuatro composiciones KDF registradas;
- compromisos firmados sobre las seis suites.

La matriz de ejecución compara adaptadores bytes/chunks/reader/file, anclas
directas/seriales, TreeWide serial/multiproceso/mmap y Deep serial/threaded. El
orden de finalización concurrente se normaliza por posición antes de construir
la entrada matemática.

## Corpus normativo

[`../specification/test-vectors/conformance-v2-2.json`](../specification/test-vectors/conformance-v2-2.json)
es el único corpus normativo. Su formato `sigma-conformance-v2` integra:

- seis trayectorias completas de suite;
- tres casos PoW;
- cuatro composiciones KDF desde una salida Argon2 conocida;
- seis compromisos Ed25519;
- 24 entradas negativas sobre los ocho codecs públicos.

Los JSON especializados y el vector draft1 fueron retirados en F5.

## Resultado del gate F2

- cero divergencias locales con el consumidor independiente;
- Deep y DeepVector comprobados nivel a nivel y por componentes;
- parsers binarios cerrados y corpus negativo ejecutable;
- backends y adaptadores invariantes en la matriz soportada;
- wire, vectores y matemática v2.2 congelados;
- `security_reviewed=False`: revisión externa todavía pendiente.

La validación de cierre aprobó 666 pruebas con el extra KDF disponible, Ruff,
mypy sobre 110 módulos, `compileall`, 10.000 mutaciones por cada uno de los ocho
codecs y regeneración byte-idéntica del corpus normativo. Sin el extra opcional
Argon2 se aprobaron 659 pruebas y se omitieron correctamente siete.

La reproducción en otros sistemas operativos y por terceros pertenece a R5/R6,
no a este cierre local.
