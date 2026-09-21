# Trazabilidad Sigma v3 R0–R12

Fecha: 2026-09-20. Estado: candidato R12 pendiente únicamente de gate y PASS
adversario final.

## Cadena normativa

| Fase | Contrato | Implementación principal | Evidencia permanente |
|---|---|---|---|
| R0 | baseline v2.2 inmutable y plan v3 | `scripts/check_v22_baseline.py` | gate acumulativo y manifiesto baseline |
| R1 | IDs, suites, contexto y records cerrados | `sigma/spec/ids_v3.py`, `context_v3.py`, `codec_v3.py`, `suites/registry_v3.py` | `test_v3_types.py` |
| R2 | domains, hashes, transcript/XOF | `sigma/crypto/primitives.py`, `sigma/spec/transcript.py` | `test_v3_primitives_transcript.py` |
| R3 | fuente canónica y binding `A/κ/Λ/J` | `sigma/sources`, `sigma/binding` | `test_v3_sources_binding.py` |
| R4 | derivación uniforme `t/k` | `sigma/binding/parameters.py` | `test_v3_parameters.py` |
| R5 | layouts y placement tipado | `sigma/layout` | `test_v3_layout.py` |
| R6 | builders exclusivos de frames | `sigma/rounds/framing_v3.py` | `test_v3_framing.py`, corpus R6 |
| R7 | trayectoria WideOnce completa | `sigma/rounds/wide_once_v3.py` | `test_v3_wide_once.py` |
| R8 | digest implícito, audit explícito y verificación separada | `sigma/outputs/digest_v3.py` | `test_v3_digest.py` |
| R9 | Deep, DeepVector y backends canónicos | `sigma/rounds/deep_v3.py`, `backends_v3.py` | `test_v3_deep.py` |
| R10 | I/O, mmap, spool, incremental y cancelación | `sigma/io_v3.py`, `incremental_v3.py`, `sources/canonical.py` | `test_v3_io.py` |
| R11 | firma, Argon2id+Sigma y PoW nonce-complete | `sigma/applications/*_v3.py` | `test_v3_applications.py` |
| R12 | especificación, corpus e implementación independiente | `specification/sigma-v3.md`, `reference/independent_v3.py`, generador R12 | diferencial y vectores R12 |

Los documentos normativos incrementales `sigma-v3-r1-decisions.md` a
`sigma-v3-r11-applications.md` conservan la historia de decisiones. R12 los
consolida sin reinterpretar v2.2.

## Requisitos R12 y prueba de cierre

| Requisito | Artefacto | Comprobación |
|---|---|---|
| Especificación byte-exacta | `specification/sigma-v3.md` | tablas de registro, codecs, pseudocódigo y KAT |
| `M`, `κ`, `A`, `Λ`, `J`, `t`, `k` | corpus `conformance-v3-r12.json` | `test_v3_r12_vectors.py` |
| layouts y placements | corpus completo por suite | regeneración independiente y comparación productiva |
| frames, ramas y folds | corpus completo por transición | comparación byte a byte de builders productivos |
| estados, header, window y digest | corpus completo por suite | SHA-256 KAT y comparación de wires |
| segunda implementación | `reference/independent_v3.py` | AST sin imports `sigma` |
| todas las suites candidatas | `0x0301`, `0x0303`, `0x0304` | matriz fija y property diferencial generada |
| corpus reproducible | `scripts/generate_v3_r12_corpus.py` | modo `--check` y test de texto exacto |
| baseline v2.2 no deformado | manifiesto protegido | `python -m scripts.check_v22_baseline` |
| distribución íntegra | sdist/wheel | gate `scripts.validate_project` |

## Flujo byte-exacto cubierto

```text
M → κ → A → Λ → J → B → t,k
  → layouts/placements → frames → estados
  → header/window → digest
```

Cada flecha se compara entre:

1. implementación productiva streaming;
2. referencia stdlib independiente;
3. corpus JSON congelado.

Los casos generados por Hypothesis complementan los tres KAT completos. El
corpus usa deliberadamente `t=2,k=2` para mantener revisión humana viable; el
diferencial generado y el resto de la suite ejercitan otros parámetros.

## Trazabilidad adversaria versionada

| Cierre | candidato final | informe |
|---|---|---|
| R0–R4 acumulativo | `d38f6ba52c840f92b5121a10d05b33b8dd1398fe` | `adversarial-reviews/R4.md` |
| R5 | `3b079addf92abacf3ff08befedff96adf31a30d7` | `adversarial-reviews/R5.md` |
| R6 | `6b3f410909af34c46182f5d7e2c3e8dc58f48323` | `adversarial-reviews/R6.md` |
| R7 | `3d66cc25d3f0098a2c73a962ba2b3b6621a98b81` | `adversarial-reviews/R7.md` |
| R8 | `0166cf577803e2bee8f08a1c946dc46d143e36a0` | `adversarial-reviews/R8.md` |
| R9 | `5113997424c8b915130695d9f358c322761796fb` | `adversarial-reviews/R9.md` |
| R10 | `18446e902fc5ef1ab9151b2247b39fb460aa7375` | `adversarial-reviews/R10.md` |
| R11 | `7f28c5b4edec0cf66b88504e1e48ed4877d23127` | `adversarial-reviews/R11.md` |
| R12 | se fija al crear el candidato | `adversarial-reviews/R12.md` tras PASS |

R11 conserva en su informe tanto el FAIL documental como la corrección y el
PASS. Los informes son acumulativos: cualquier cambio posterior en artefactos
de una fase invalida su PASS previo y exige el gate/adversario de la fase nueva.

## Límites de claim

Esta trazabilidad demuestra conformidad de ingeniería y cierre byte-exacto, no
una auditoría criptográfica externa. No prueba suma de seguridades, memory
hardness de Sigma, VDF, constant-time ni resistencia ASIC/GPU. Las limitaciones
de cada fase permanecen en su especificación e informe adversario.
