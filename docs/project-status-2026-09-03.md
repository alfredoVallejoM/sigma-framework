# Estado actual de Sigma Framework v2.2

Fecha de corte: 2026-09-03  
Baseline funcional auditado: `453b4831ea2b3ce274a1ecc94d794e4a80e2cf4d`  
Versión de paquete: `2.2.0a1`  
Veredicto: **plataforma de investigación reproducible y preparada para auditoría;
no aprobada para seguridad de producción**.

Este documento es la referencia de estado vigente. Las auditorías fechadas el
2026-09-02 conservan el diagnóstico y el cierre de v2.1 como historia del
proyecto, pero no describen por sí solas la implementación actual.

## Resumen ejecutivo

La reconstrucción v2.2 cierra localmente los gates de arquitectura, codecs,
conformidad independiente, endurecimiento de pruebas, formalización e
infraestructura experimental. Todas las campañas revisadas que pueden ejecutarse
sin hardware, núcleo nativo o servicios externos tienen runner, configuración
piloto y una ejecución de desarrollo. Los pilotos validan implementación,
análisis y dimensionamiento; no son datos confirmatorios.

La promoción a estable sigue bloqueada por la congelación humana del
prerregistro, ejecuciones limpias multihost/multiplataforma, baterías externas,
archivo científico y revisión criptográfica independiente.

## Estado del producto

| Área | Estado actual | Límite vigente |
|---|---|---|
| Paquete | `2.2.0a1`, Python 3.10+ | alpha de investigación |
| Wire | contexto/digest/evidencia/firma versionados | estabilidad de interoperabilidad, no garantía de seguridad |
| Suites | seis v2.1 congeladas y seis v2.2 experimentales | IDs incompatibles nunca se reciclan |
| Anclas | StreamWide, CrossWide y TreeWide | conexiones Cross no reciben fuerza aditiva automática |
| Rondas | WideOnce, Deep y DeepVector | profundidad del evaluador, no PoSW/VDF universal |
| Verificación | completa y adyacente explícitamente diferenciadas | una arista no demuestra el prefijo |
| Aplicaciones | PoW experimental, KDF Argon2id+Sigma y compromiso Ed25519 | no sustituyen protocolos estándar ni crean entropía |
| Backends | serial, incremental y multiproceso/mmap | el backend no cambia los bytes matemáticos |
| Política | `ResourcePolicy` separa wire válido de aceptación local | los consumidores deben fijar sus mínimos/máximos |
| Conformidad | consumidor independiente para seis suites y tres aplicaciones | reproducción externa todavía pendiente |

## Evidencia local disponible

- Codec TLV estricto y parsers de contexto, digest, evidencia, PoW, KDF y firma.
- Vectores congelados v2.1/v2.2 y corpus de conformidad de suites/aplicaciones.
- Tests unitarios, de integración, propiedades, diferenciales, vectores, fuzzing
  mutacional, Atheris y campañas dirigidas de mutación.
- Formalización TH-01–TH-08 con juegos, presupuestos, hipótesis y fronteras de
  claim explícitas.
- Scheduler experimental v2: tareas aisladas, seeds derivados, escritura
  atómica, reanudación, censura, timeouts, logs, manifiestos y hashes.
- Diecinueve configuraciones bajo `configs/pilots` para EXP-01R–12R, EXP-14R y
  EXP-17–20, más el runner instrumentado EXP-21R y su configuración smoke
  actualizada. EXP-15 se conserva como control histórico.
- Exportador de streams de EXP-08 y estimador medido de presupuesto de campaña.
- Generación de wheel/sdist, SHA-256 y SBOM CycloneDX con guard de tag limpio.

La validación del baseline funcional terminó con 540 pruebas aprobadas, Ruff
limpio, mypy limpio sobre 110 módulos, `compileall` correcto, build de wheel y
sdist, instalación en un entorno vacío y smoke de ambos CLI. Es una fotografía
fechada: la CI es la autoridad para commits posteriores.

## Estado de gates R1–R6

| Gate | Estado | Evidencia o dependencia |
|---|---|---|
| R1 — núcleo | cerrado localmente | tipos, rolling O(k), evidencia v2.2, política y snapshot |
| R2 — conformidad | cerrado localmente | segunda implementación, corpus, fuzz/property/mutación |
| R3 — modos/aplicaciones/formal | cerrado localmente | DeepVector, KDF, firma, paralelismo y TH-01–08 |
| R4 — prerregistro | abierto | borrador y pilotos existen; falta revisión/firma y congelación |
| R5 — confirmatorio | abierto | requiere tag limpio, artefacto instalado y hosts controlados |
| R6 — publicación/revisión | abierto | requiere dataset/DOI, reproducción y revisión externa |

EXP-13 permanece no aplicable hasta disponer de un núcleo nativo especificado.
EXP-16 permanece no aplicable hasta existir RTL, testbench, tecnología, corners
y síntesis reproducible. Su ausencia prohíbe claims de constant-time, fugas,
área, energía o resistencia ASIC.

## Campañas revisadas

Las campañas aplicables cubren conformidad (EXP-01R), colisiones y persistencia
(02R–04R), dependencias/difusión/distribución (05R, 07R, 08R), trabajo,
rendimiento y memoria (06R, 09R, 10R), PoW/KDF/fallos (11R, 12R, 14R) y
criptoanálisis reducido ofensivo (17–21). EXP-21R instrumenta los bytes reales
entregados a las primitivas; su piloto comparó 52.820 pares sin violaciones no
especificadas. Esta cifra no convierte el piloto en prueba exhaustiva.

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

- Estado vigente: este documento.
- Construcción normativa: [`../specification/sigma-v2.md`](../specification/sigma-v2.md).
- Análisis formal: [`../specification/security-analysis.md`](../specification/security-analysis.md).
- Decisiones incompatibles: [`adr/`](adr/).
- Trazabilidad claim-to-evidence: [`traceability.md`](traceability.md).
- Plan de ejecución restante: [`campaign-plan-v2-2.md`](campaign-plan-v2-2.md).
- Metodología experimental: [`../experiments/README.md`](../experiments/README.md).
- Manuscrito de trabajo: [`../paper/manuscript.md`](../paper/manuscript.md).
- Historia: `audit-2026-09-02.md` y `final-audit-2026-09-02.md`.
