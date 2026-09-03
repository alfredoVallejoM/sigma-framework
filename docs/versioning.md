# Política de versiones de Sigma

Estado actual: `2.2.0a1` es la única línea experimental activa. Las suites v1 y
v2.1 fueron retiradas del árbol en F5; sus IDs permanecen reservados. Consulte
[`project-status-2026-09-03.md`](project-status-2026-09-03.md) para los gates de
promoción vigentes.

Sigma mantiene dimensiones independientes. Una coincidencia numérica entre
ellas no implica compatibilidad ni estabilidad.

| Dimensión | Valor actual | Significado |
|---|---:|---|
| paquete Python | `2.2.0a1` | evolución de API, herramientas y distribución |
| contexto wire | `2` | framing binario de `SigmaContextV2` |
| digest wire | `2` | framing binario de `SigmaDigestV2` |
| evidencia wire | `2` | envelope tipado `SIGMAAE` de las suites v2.2 |
| parámetros KDF wire | `2` | parámetros Argon2id `SIGMAKDF2` |
| verificador KDF wire | `2` | registro público `SIGMAKVR2` sin clave |
| PoW wire | `3` | aplicación `SIGMAPOW3` ligada a suite v2.2 |
| compromiso firmado wire | `2` | contenedor autenticado `SIGMASIG` |
| familia activa | `v2-2` | construcción matemática y semántica vigente |

Las constantes se publican en `sigma.version`. `pyproject.toml` y
`PACKAGE_VERSION` deben coincidir. El manifiesto CycloneDX conserva todos los
ejes wire, familias activas/transitorias, commit, tag y estado del árbol.

## Compatibilidad

- Los IDs v2-1 no se reciclarán, pero sus suites, presets y vectores no forman
  parte del producto final v2.2.
- Un cambio en bytes canónicos, dominios o semántica matemática requiere un
  `SuiteId` nuevo. Nunca se recicla un identificador v2-1.
- Las suites v2-2 usan evidencia tipada versión 2. Su descriptor separa
  `wire_frozen`, `vectors_frozen`, `suite_stable` y `security_reviewed`; ningún
  eje se infiere de otro.
- Tras F2, las seis suites v2-2 tienen wire, vectores y definición matemática
  congelados. `security_reviewed` permanece falso hasta la revisión externa.
- Parsear una estructura sólo prueba que el wire es canónico. Su aceptación
  semántica exige validarla contra una suite registrada y una política local.
- Una publicación auditable exige un checkout limpio en un tag exacto mediante
  `scripts/release_artifacts.py --require-clean-tag`.

El número de paquete puede avanzar sin alterar el wire y un wire puede alojar
múltiples familias. Por tanto, ninguna aplicación debe derivar una dimensión a
partir de otra.
