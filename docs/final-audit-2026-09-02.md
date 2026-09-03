# Auditoría de cierre interno — Sigma Framework v2-1 alpha

> **Documento histórico y supersedido.** Conserva el cierre de v2.1 en su fecha
> original. Sigma avanzó después a `2.2.0a1`, DeepVector, evidencia tipada,
> aplicaciones revisadas y campañas R. Consulte
> [`project-status-2026-09-03.md`](project-status-2026-09-03.md) para el estado
> vigente. Las cifras, TH-01–09 y gates siguientes se leen aquí como fotografía
> histórica, no como descripción actual.

Fecha: 2026-09-02  
Baseline auditado: `9cf55bca43bea0da11994e820fcddaed0a8eb1c4`  
Veredicto: **candidato de investigación reproducible; no apto todavía para uso
criptográfico de producción**.

## Cobertura realizada

Se revisaron el código v1 completo, empaquetado, CLI, adaptadores, estrategias,
metrología, documentación y todas las obligaciones del plan maestro. La
reconstrucción v2 separa contexto/especificación, anclas, rondas, salida,
backends y aplicaciones. V1 permanece disponible sólo para reproducibilidad y
sus defectos no se corrigen alterando silenciosamente sus digests.

| Hallazgo inicial | Resolución interna | Evidencia |
|---|---|---|
| CLI v1 no compilaba | reparado y etiquetado legacy | tests CLI + compileall |
| cero tests | suite unit/vector/property-like/differential/integration | 186 casos recopilados |
| resultado dependía de CPU/backend | TreeWide canónico y backend neutral | corpus diferencial + EXP-01 |
| `rounds` ambiguo | `target_round`, `state_count`, suite y backend separados | contexto TLV y presets |
| memoria Lightweight lineal | StreamWide O(1); TreeWide O(log N) | invariantes + EXP-10 |
| RealTime no finalizaba correctamente | API incremental con `finalize()` único | tests de integración |
| `Psi` comprimía prematuramente | raíces retenidas; `Psi` aislado | TH-02/07 + EXP-04/15 |
| algoritmos dependientes del host | registro cerrado con IDs exactos | vectores de ramas |
| framing ambiguo | TLV estricto, tamaños fijos y parsers negativos | G1 + fuzzing |
| salida sin versión/parámetros | `SigmaDigestV2` autocontenido | codec + verificador completo |
| metrología sin datos reproducibles | CSV gzip, resumen, config y manifiesto con hashes | EXP-00 |
| claims no sustentados | eliminados o condicionados en código/paper | auditoría textual |
| packaging/CI incompletos | Python 3.10–3.13/SO, wheel/sdist, SBOM y constraints | G4 |

## Evidencia de cierre ejecutada

- Ruff limpio y `mypy` limpio sobre 118 fuentes incluidas en el chequeo.
- `compileall` limpio.
- 185 tests pasados y uno opcional Argon2 omitido en el entorno base; ese test
  pasó separadamente con `argon2-cffi==25.1.0` aislado en `/tmp`.
- 1.000 mutaciones por cada parser de contexto, digest, PoW y KDF sin aceptar
  representaciones no canónicas.
- Reproducción desde cero de EXP-01–10: diez runs verdes, configuraciones
  embebidas y 21 artefactos derivados en el manifiesto temporal.
- Selección publicada interna EXP-01–12/14/15: 72.013 observaciones, catorce
  resúmenes verdes y todos sus hashes comprobados.
- 14 figuras en SVG y PNG (28 imágenes), todas ligadas por hash a sus fuentes.
- sdist y wheel `2.0.0a1` construidos en aislamiento; contenido inspeccionado;
  SHA256SUMS y SBOM CycloneDX generados.
- Wheel instalado en un venv limpio; CLI JSON y flujo PoW verificados.
- YAML de CI parseado correctamente.

## Gates que no pueden declararse superados todavía

1. **Campaña confirmatoria.** Las diez configuraciones preregistradas existen,
   incluyendo 1 GiB streaming, `n` hasta 24, profundidad hasta 65.536 y estudio
   SAC con potencia planificada. No se han ejecutado por completo. Los datos
   actuales son smoke internos y no permiten claims a anchura de producción.
2. **Plataformas CI.** La matriz Linux/macOS/Windows está definida, pero esta
   auditoría local no sustituye ejecuciones remotas verdes asociadas a un commit.
3. **Archivo científico.** Falta ejecutar desde un commit/tag limpio, publicar
   dataset inmutable y asignar DOI. Los manifiestos actuales declaran árbol
   sucio de forma correcta.
4. **Revisión externa.** TH-01–09 y TreeWide requieren revisión criptográfica
   independiente y resolución pública de hallazgos.
5. **Pistas opcionales condicionadas.** EXP-13 no procede sin núcleo nativo;
   EXP-16 no procede sin RTL/síntesis. Por ello no hay claims de constant-time,
   potencia, área, energía o resistencia ASIC. EXP-15 avanzado (SAT/SMT/MILP,
   trails y grado algebraico) permanece abierto y `Psi` sigue fuera de confianza.

## Riesgo residual y decisión

La arquitectura, especificación, pruebas y reproducibilidad ya son adecuadas
para continuar investigación y solicitar revisión. No son evidencia suficiente
para promover `2.0.0a1` a estable. La promoción exige, como mínimo, campaña
confirmatoria versionada, CI remota completa y revisión independiente; ningún
resultado estadístico sustituye esos gates.
