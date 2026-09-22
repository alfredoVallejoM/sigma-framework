# Política de versiones de Sigma

Estado actual: `3.0.0a1` es el número de paquete de la línea de investigación
Sigma v3 / Sigma-IAP. v2.2 se conserva como oráculo histórico de regresión; R12
permanece byte-frozen y R12.5 usa IDs distintos para feedback histórico.
Ninguna suite v3 es todavía estable ni ha recibido revisión criptográfica
externa.

Sigma mantiene dimensiones independientes. Una coincidencia numérica entre
ellas no implica compatibilidad ni estabilidad.

| Dimensión | Valor actual | Significado |
|---|---:|---|
| paquete Python | `3.0.0a1` | evolución de API, herramientas y distribución |
| contexto wire | `2` | framing binario de `SigmaContextV2` |
| digest wire | `2` | framing binario de `SigmaDigestV2` |
| evidencia wire | `2` | envelope tipado `SIGMAAE` de las suites v2.2 |
| parámetros KDF wire | `2` | parámetros Argon2id `SIGMAKDF2` |
| verificador KDF wire | `2` | registro público `SIGMAKVR2` sin clave |
| PoW wire | `3` | aplicación `SIGMAPOW3` ligada a suite v2.2 |
| compromiso firmado wire | `2` | contenedor autenticado `SIGMASIG` |
| Sigma Tree wire | `1` | capa estructural independiente `SIGT*`; no es suite v2/v3 |
| baseline estable de regresión | `v2-2` | semántica histórica congelada |
| familia de investigación | `v3-r12`, `v3-r12.5` | candidatos incompatibles, sin security freeze |

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
- Sigma Tree V1 posee un eje wire propio. Cambiar framing, dominios o semántica
  estructural requiere una nueva versión de Tree; nunca se reinterpreta como
  una suite v2/v3 ni viceversa.
- Una publicación auditable exige un checkout limpio en un tag exacto mediante
  `scripts/release_artifacts.py --require-clean-tag`.

El número de paquete puede avanzar sin alterar el wire y un wire puede alojar
múltiples familias. Por tanto, ninguna aplicación debe derivar una dimensión a
partir de otra.


## Sigma v3 pre-freeze

- R12: suites `0x0301`, `0x0303`, `0x0304`; baseline de ablación con
  binding persistente fijo.
- R12.5: suites `0x0321`, `0x0323`, `0x0324`; binding efectivo
  `(P_X,H_i)` y layout ROUND history-adaptive.
- Los IDs R12 no se reciclan ni se reinterpretan.
- R12.5 puede evolucionar sólo mediante nuevos IDs si cambia cualquier byte
  normativo después de su eventual PASS/freeze.
- El número de paquete 3.x identifica la línea de API/paquete y no constituye
  por sí mismo una garantía de estabilidad o seguridad de las suites v3.
