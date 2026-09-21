# Alcance vigente e inventario de Sigma v2.2

Estado: **fases 0–6 cerradas; F7 en ejecución**
Fecha: 2026-09-03  
Plan rector: [`final-development-plan-v2-2.md`](final-development-plan-v2-2.md)

## Línea de producto

Sigma v2.2 es la única línea activa, normativa y orientada al artículo. El
paquete permanece en estado alpha y no está aprobado para producción.

v1 y v2.1 se han retirado del paquete, tests, configuraciones, vectores y
evidencia presentes. Sus identificadores wire permanecen reservados para evitar
reutilización; los commits de Git son el único archivo histórico.

## Inventario de conservación

### Producto y especificación

- `sigma/`: sólo módulos usados por la API v2.2 final.
- `specification/sigma-v2.md`: única especificación normativa.
- `specification/security-analysis.md`: límites y argumentos formales.
- `specification/test-vectors/conformance-v2-2.json`: único corpus normativo.
- `reference/independent_v22.py`: consumidor independiente del núcleo.
- `reference/independent_applications.py`: consumidor de las tres aplicaciones.
- `docs/conformance-audit-v2-2.md`: cierre verificable de formatos y matrices F2.
- Packaging y constraints necesarios para construir y validar v2.2.

### Calidad local

- Tests de código v2.2 vigente.
- Fuzzers y corpus mínimos reproducibles de parsers v2.2.
- Gate local único `python -m scripts.validate_project`.
- Scripts de build, artefactos y reproducción utilizados.

### Investigación actual

- Runners de campañas incluidas en el artículo vigente.
- Pilotos finales necesarios para dimensionar el prerregistro.
- Prerregistro confirmatorio congelado.
- Scripts de análisis, tablas y figuras del dataset canónico.
- Manifiesto, hashes e índice del único dataset confirmatorio.
- Manuscrito y checklist de revisión actualizados.

### Documentación activa

- `README.md`.
- `docs/project-status-2026-09-03.md`, hasta adoptar un nombre no fechado.
- Este inventario y el plan rector.
- `docs/versioning.md`, ADR vigentes y trazabilidad.
- Manual experimental consolidado.

## Frontera del árbol actual

El checkout contiene únicamente producto, especificación, pruebas,
infraestructura experimental, pilotos de dimensionamiento y documentación
vigentes para v2.2. No conserva datasets, figuras, configuraciones, ejecutores
ni APIs de líneas anteriores; cualquier consulta histórica se realiza en Git.

## Evidencia del artículo

1. **Desarrollo:** ejecuciones ad hoc; no se conservan como evidencia.
2. **Piloto final:** valida código y presupuesto; sólo se conserva el informe
   de decisiones necesario para el prerregistro.
3. **Confirmatorio:** único dataset que alimenta resultados, tablas y figuras.

El raw confirmatorio podrá vivir fuera de Git, pero el repositorio conservará
índice verificable, hashes, configuración, manifiesto y reproducción.

## Jerarquía documental

1. `specification/sigma-v2.md`: matemática y wire.
2. `docs/final-development-plan-v2-2.md`: trabajo y gates.
3. `docs/current-scope-v2-2.md`: alcance e inventario.
4. `docs/project-status-2026-09-03.md`: estado observado.
5. `specification/security-analysis.md`: argumentos y claims.
6. `docs/traceability.md`: claim-to-evidence.
7. ADR vigentes: decisiones incompatibles concretas.
8. Manual experimental y prerregistro: protocolo.
9. `paper/manuscript.md`: consumidor de evidencia, nunca fuente normativa.

Los documentos históricos no pueden reabrir decisiones ni autorizar trabajo.

## Resultado de la fase 0

- [x] Única línea activa: v2.2.
- [x] GitHub Actions fuera del alcance actual.
- [x] Historia delegada a Git.
- [x] Dataset confirmatorio único.
- [x] Pilotos no confirmatorios.
- [x] Inventarios de conservación y retirada.
- [x] Jerarquía documental.
- [x] Gate local único implementado y validado.
- [x] Retirada física de v1/v2.1 y evidencia histórica completada.
- [x] Veinte pilotos actuales completados; sólo se retiene su informe de decisión.
- [x] Revisión y congelación humanas del prerregistro F6.
- [ ] Dataset confirmatorio F7 completo y verificado en todos los estratos.
