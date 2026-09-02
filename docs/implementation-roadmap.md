# Hoja de ruta ejecutable de Sigma v2

Esta hoja traduce el plan maestro a gates comprobables. Un gate no se considera
cerrado por tener código: requiere especificación, tests y artefactos indicados.

## Fase 0 — Baseline y aislamiento de v1

- Corregir compilación de CLI sin modificar digests.
- Capturar vectores v1 de entradas límite y de cada modo estable/reproducible.
- Marcar API, README, metrología y `Psi` como experimentales/no producción.
- Definir versionado y política de compatibilidad.

Salida: v1 compila, sus límites son explícitos y sus vectores están congelados.

## Gate G1 — Especificación canónica

- Registro numérico de suites, algoritmos, perfiles y dominios.
- Tipos inmutables y límites de recursos.
- Codec TLV canónico con orden único y parser estricto.
- Formato exacto de `SigmaContextV2` y `SigmaDigestV2`.
- Vectores manuales y tests negativos: duplicados, orden, truncado, campos
  desconocidos, overflow, trailing bytes y mismatch entre `k`/estados.

Salida: `specification/sigma-v2.md` y tests de codec verdes. El formato sólo se
cambiará elevando versión/IDs y regenerando vectores deliberadamente.

## Gate G2 — Referencia criptográfica mínima

- Registro cerrado SHA-512, SHA3-512, BLAKE2b-512 y SHAKE256-512.
- `StreamWide` incremental conservando todas las raíces.
- `WideOnce` con ancla reinyectada y transcript opcional.
- salida real `S_t..S_(t+k-1)`, serialización y verificación completa.
- vectors para vacío, límites de chunk y `t={0,1,2}`, `k={1,2,3}`.

Salida: pseudocódigo, código y vectores coinciden byte a byte.

## Gate G3 — Robustez, modos y backends

- `CrossWide` preservando raíces; decidir `Psi` mediante criptoanálisis.
- Elegir y especificar una única semántica de árbol.
- Backend serial de referencia y backends incremental/mmap/multiproceso.
- Presets Lightweight, Simultaneous, RealTime, Paranoid Wide y Deep.
- Corpus diferencial por adapters, particiones y workers.

Salida: cero divergencias de contexto, ancla, transcript y digest.

## Gate G4 — Calidad y release

- Unit, property, fuzz, differential y known-answer tests.
- CI por Python/SO soportados; compile, lint, types, build e instalación limpia.
- CLI `hash`, `inspect`, `verify`, `vectors`, `benchmark` con JSON/binario.
- Dependencias por grupos, constraints reproducibles, checksums y SBOM.

Salida: release candidate reproducible; ningún release estable con CI o
vectores incompletos.

## Fase experimental y publicación

- Implementar EXP-00 antes de obtener nuevas cifras.
- Ejecutar EXP-01..10 con observaciones crudas, seeds y manifiestos.
- PoW/Argon2id sólo tras protocolo y baseline; side channels sólo con núcleo
  nativo; ASIC/energía sólo con artefacto RTL y síntesis real.
- Formalizar TH-01..09, reconstruir el paper y auditar correspondencia entre
  claim, código, evidencia y figura.

Salida final: especificación, implementación, tests, datos, scripts, paper y
revisión criptográfica externa. La revisión externa es una dependencia humana,
no una propiedad que pueda declarar el repositorio por sí solo.

## Estado

- [x] Auditoría inicial y trazabilidad de alto nivel.
- [x] CLI v1 compila y vectores reproducibles iniciales están congelados.
- [x] Aislamiento inicial y aliases explícitos `legacy-v1-*` (aliases cortos se
  mantienen temporalmente por compatibilidad).
- [x] Gate G1: contexto/digest y codec canónicos congelados.
- [x] Gate G2: referencia mínima, vector independiente y auditoría de binding
  byte a byte. Estabilidad significa interoperabilidad, no seguridad auditada.
- [x] CrossWide conserva raíces y conexiones sin compresión `Psi`.
- [x] TreeWide serial canónico y streaming O(log N), sin duplicación impar.
- [x] Backends serial/multiproceso+mmap, API incremental y cinco presets v2.
- [x] `Psi` aislado como legado experimental y fuera de todas las suites v2.
- [x] Gate G3: corpus diferencial de adapters, particiones, workers, anclas y
  transcripts sin divergencias.
- [x] CI definida para Linux 3.10–3.13, macOS y Windows; quality/build separado.
- [x] Ruff, mypy, compileall, tests y build local pasan.
- [x] Gate G4: CLI binaria/JSON, 186 tests, CI, wheel/sdist, instalación limpia,
  constraints, checksums y SBOM CycloneDX.
- [x] EXP-00: runner declarativo, semilla derivada, CSV crudo comprimido,
  resúmenes, manifiestos y checksums.
- [x] EXP-01 smoke: 261 observaciones y cero divergencias. La matriz de tamaños
  grandes y plataformas de CI sigue pendiente antes de llamarlo completo.
- [x] EXP-02/03 smoke: modelos reducidos, 49 920 observaciones totales y
  comprobaciones binomiales; no sustituyen las campañas completas.
- [x] EXP-04–10 smoke: dependencia, profundidad, SAC, distribución, rendimiento
  y memoria con datos crudos; siguen siendo validaciones exploratorias.
- [x] Flujo único EXP-01–10 → resúmenes → figuras, configuración embebida y
  manifiesto de entorno/checksums.
- [x] EXP-11: protocolo PoW canónico y smoke geométrico; no es un PoSW ni tiene
  verificación asimétricamente barata.
- [x] EXP-12: composición Argon2id opcional y comparación smoke contra Argon2id
  solo; no se atribuye nueva entropía ni memory hardness a Sigma.
- [x] EXP-14: propagación/detección de fallos; se retiró el claim DFA.
- [x] EXP-15 parcial: dimensiones, colisiones reducidas y difusión comparada de
  `Psi`; SAT/SMT/MILP y análisis algebraico completo siguen abiertos.
- [x] EXP-13/16 correctamente bloqueados por sus gates técnicos: no existe
  núcleo nativo ni RTL/síntesis, por lo que se prohíben esos claims.
- [x] TH-01–09, matriz de trazabilidad, paper de trabajo y 14 figuras derivadas.
- [ ] Campañas confirmatorias completas/multiplataforma y dataset archivado/DOI.
- [ ] Revisión criptográfica externa y resolución documentada de hallazgos.
