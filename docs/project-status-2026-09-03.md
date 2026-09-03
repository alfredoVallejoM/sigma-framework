# Estado actual de Sigma Framework v2.2

Fecha de corte: 2026-09-03

Baseline funcional: cambios F0–F6 preparados en la rama de auditoría; el hash
definitivo se fijará al integrar y etiquetar el artefacto revisado.

Versión de paquete: `2.2.0a2`

Veredicto revisado: **plataforma alpha de investigación avanzada; todavía no es
una release candidate reproducible ni está aprobada para producción**.

Este documento es la fotografía de estado vigente. El trabajo restante se rige
exclusivamente por [`final-development-plan-v2-2.md`](final-development-plan-v2-2.md)
y el alcance por [`current-scope-v2-2.md`](current-scope-v2-2.md). Los documentos
anteriores no son planes ejecutables.

## Resumen ejecutivo

La reconstrucción v2.2 ha cerrado localmente F0–F6: alcance, correcciones
semánticas, arquitectura, codecs, conformidad independiente, corpus normativo,
gate local, infraestructura experimental y limpieza física. Los 20 pilotos F6
han pasado; el prerregistro y las 20 configuraciones confirmatorias están
congelados por hash y la ejecución F7 está autorizada.

La promoción a estable sigue bloqueada por completar las ejecuciones limpias
multihost/multiplataforma, las baterías externas, el archivo científico y la
revisión criptográfica independiente.

## Estado del producto

| Área | Estado actual | Límite vigente |
|---|---|---|
| Paquete | `2.2.0a2`, Python 3.10+ | alpha de investigación |
| Wire | contexto/digest/evidencia/KDF/PoW/firma versionados y congelados | un cambio exige IDs nuevos; no garantiza seguridad |
| Suites | seis v2.2 activas; IDs previos reservados, sin implementaciones v1/v2.1 publicables | un cambio wire exige IDs nuevos |
| Anclas | StreamWide, CrossWide y TreeWide | conexiones Cross no reciben fuerza aditiva automática |
| Rondas | WideOnce, Deep y DeepVector | profundidad del evaluador, no PoSW/VDF universal |
| Verificación | completa y adyacente explícitamente diferenciadas | una arista no demuestra el prefijo |
| Aplicaciones | PoW3 v2.2, clave Argon2id+Sigma, verificador KDF y compromiso Ed25519 | no sustituyen protocolos estándar ni crean entropía |
| Backends | serial, incremental y multiproceso/mmap | el backend no cambia los bytes matemáticos |
| Política | `ResourcePolicy` separa wire válido de aceptación local | los consumidores deben fijar sus mínimos/máximos |
| Conformidad | consumidor independiente para seis suites y tres aplicaciones | reproducción externa todavía pendiente |

## Evidencia local disponible

- Codec TLV estricto y parsers de contexto, digest, evidencia, PoW, KDF y firma.
- Corpus normativo único `conformance-v2-2.json`.
- Tests unitarios, de integración, propiedades, diferenciales, vectores, fuzzing
  mutacional, Atheris y campañas dirigidas de mutación.
- Formalización TH-01–TH-08 con juegos, presupuestos, hipótesis y fronteras de
  claim explícitas.
- Scheduler experimental v2: tareas aisladas, seeds derivados, escritura
  atómica, reanudación, censura, timeouts, logs, manifiestos y hashes.
- Veinte configuraciones piloto y un único informe de decisiones retenido. Los
  raw transitorios sólo dimensionaron el prerregistro y no son evidencia.
- Exportador de streams de EXP-08 y estimador medido de presupuesto de campaña.
- Generación de wheel/sdist, SHA-256 y SBOM CycloneDX con guard de tag limpio.

El gate F3 validado ejecuta Ruff, mypy, compileall, suite completa/cobertura,
fuzzing determinista, build limpio y una instalación aislada del wheel con los
dos CLI. La ejecución final aprobó 679 tests sin omisiones, 10.000 mutaciones
por cada uno de ocho codecs, el sdist/wheel y ambos CLI instalados fuera del
checkout. Coberturas: 97,244 % en core/formatos, 91,483 % en scheduler, 90,256 %
en release y 86,974 % global observada. Informe local:
`/tmp/sigma-gate-final.json`.

F4 añadió esquemas cerrados, procedencia del wheel/import, instrumentación
concurrente determinista e integridad/reintentos por tarea. F5 retiró código,
tests, vectores, configuraciones, resultados, figuras y documentos históricos.
F6 ejecutó 20 pilotos: 36.731 observaciones, todos los runs y controles de
calidad aprobados; EXP-07 exige al menos 677 muestras por bit y EXP-12 conservó
idéntico presupuesto Argon2id.

## Estado de gates vigentes

| Gate | Estado | Evidencia o dependencia |
|---|---|---|
| F0 — alcance | cerrado | línea v2.2, inventario, evidencia y jerarquía congelados |
| F1 — corrección | cerrado | KDF separada, defaults/PoW v2.2, madurez, política y snapshot único |
| F2 — conformidad | cerrado localmente | codecs cerrados, matrices independientes/backend y corpus v2.2 único |
| F3 — gate local | cerrado localmente | orden única, cobertura, build e instalación aislada |
| F4 — experimentos | cerrado localmente | esquema/procedencia/concurrencia/scheduler verificados |
| F5 — limpieza | cerrado | árbol actual sin evidencia ni implementación legacy |
| F6 — pilotos/prerregistro | cerrado | 20 pilotos, protocolo y 20 configuraciones/5.289 tareas congelados por hash |
| R5 — confirmatorio | en curso | requiere completar dataset, hosts controlados y baterías externas |
| R6 — publicación/revisión | abierto | requiere dataset/DOI, reproducción y revisión externa |

EXP-13 permanece no aplicable hasta disponer de un núcleo nativo especificado.
EXP-16 permanece no aplicable hasta existir RTL, testbench, tecnología, corners
y síntesis reproducible. Su ausencia prohíbe claims de constant-time, fugas,
área, energía o resistencia ASIC.

## Campañas revisadas

Las campañas candidatas cubren conformidad (EXP-01R), colisiones y persistencia
(02R–04R), dependencias/difusión/distribución (05R, 07R, 08R), trabajo,
rendimiento y memoria (06R, 09R, 10R), PoW/KDF/fallos (11R, 12R, 14R) y
criptoanálisis reducido ofensivo (17–21). Sus pilotos sólo validan runners y
presupuesto. Ninguna cifra piloto se utilizará como resultado del artículo.

El protocolo operativo, configuraciones y criterios de cierre están en
[`campaign-plan-v2-2.md`](campaign-plan-v2-2.md). El ledger confirmatorio sigue
marcado como borrador en
[`../experiments/preregistration-v2-2.md`](../experiments/preregistration-v2-2.md).

## Trabajo externo pendiente

1. Revisar y congelar el prerregistro y los tamaños muestrales.
2. Crear un tag exacto y construir/instalar el artefacto que ejecutará R5.
3. Ejecutar la matriz Linux/macOS/Windows y las réplicas multihost controladas.
4. Ejecutar NIST SP 800-22, PractRand y TestU01 preservando versión, comandos y
   salidas; no están instalados en el entorno de desarrollo auditado.
5. Archivar datos, logs, manifiestos, wheel, checksums, SBOM y figuras con un
   identificador persistente.
6. Obtener revisión criptográfica independiente y resolver públicamente sus
   hallazgos antes de cualquier claim estable o de producción.

## Jerarquía documental

- Construcción normativa: [`../specification/sigma-v2.md`](../specification/sigma-v2.md).
- Plan rector: [`final-development-plan-v2-2.md`](final-development-plan-v2-2.md).
- Alcance e inventario: [`current-scope-v2-2.md`](current-scope-v2-2.md).
- Estado observado: este documento.
- Análisis formal: [`../specification/security-analysis.md`](../specification/security-analysis.md).
- Decisiones incompatibles: [`adr/`](adr/).
- Trazabilidad claim-to-evidence: [`traceability.md`](traceability.md).
- Protocolo de campañas, subordinado al plan rector: [`campaign-plan-v2-2.md`](campaign-plan-v2-2.md).
- Metodología experimental: [`../experiments/README.md`](../experiments/README.md).
- Manuscrito de trabajo: [`../paper/manuscript.md`](../paper/manuscript.md).
- La historia reside exclusivamente en Git; el checkout documenta el estado actual.
