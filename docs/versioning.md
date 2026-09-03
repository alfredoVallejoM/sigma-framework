# Política de versiones de Sigma

Estado actual: `2.2.0a1` es la línea experimental activa; las suites v2.1 sólo
se conservan para interoperabilidad. Consulte
[`project-status-2026-09-03.md`](project-status-2026-09-03.md) para los gates de
promoción vigentes.

Sigma mantiene dimensiones independientes. Una coincidencia numérica entre
ellas no implica compatibilidad ni estabilidad.

| Dimensión | Valor actual | Significado |
|---|---:|---|
| paquete Python | `2.2.0a1` | evolución de API, herramientas y distribución |
| contexto wire | `2` | framing binario de `SigmaContextV2` |
| digest wire | `2` | framing binario de `SigmaDigestV2` |
| evidencia wire | `2` | envelope tipado `SIGMAAE` de las suites v2-2 |
| compromiso firmado wire | `2` | contenedor autenticado `SIGMASIG` |
| familia de suite | `v2-1`, `v2-2` | construcción matemática y semántica interoperable |

Las constantes se publican en `sigma.version`. `pyproject.toml` y
`PACKAGE_VERSION` deben coincidir. El manifiesto CycloneDX conserva las cuatro
dimensiones, el commit, el tag y el estado limpio/sucio del árbol.

## Compatibilidad

- Las suites v2-1 permanecen byte a byte congeladas y marcadas como estables.
- Un cambio en bytes canónicos, dominios o semántica matemática requiere un
  `SuiteId` nuevo. Nunca se recicla un identificador v2-1.
- Las suites v2-2 usan evidencia tipada versión 2 y permanecen experimentales
  (`stable=False`) hasta superar R1–R6 y revisión externa.
- Parsear una estructura sólo prueba que el wire es canónico. Su aceptación
  semántica exige validarla contra una suite registrada y una política local.
- Una publicación auditable exige un checkout limpio en un tag exacto mediante
  `scripts/release_artifacts.py --require-clean-tag`.

El número de paquete puede avanzar sin alterar el wire y un wire puede alojar
múltiples familias. Por tanto, ninguna aplicación debe derivar una dimensión a
partir de otra.
