# Plan ejecutable de campañas Sigma v2-2

Estado: catálogo técnico subordinado al
[`plan final`](final-development-plan-v2-2.md). F4 y F6 están cerradas: los 20
pilotos finalizaron y las 20 configuraciones confirmatorias, con 7.233 tareas,
están congeladas por hash. Ningún piloto de este documento es evidencia del
artículo. F7 está en ejecución; estado global en
[`project-status-2026-09-03.md`](project-status-2026-09-03.md).

## Reglas de ejecución

1. No editar hipótesis, endpoints, exclusiones ni análisis después de congelar
   `experiments/preregistration-v2-2.md`.
2. La congelación requiere revisión humana, estado `frozen`, hash SHA-256,
   commit limpio, tag exacto y hash del wheel instalado. El runner lo impone.
3. Cada celda confirmatoria se divide en tareas reanudables; error, timeout y
   censura son estados distintos. Los intentos fallidos nunca se sobrescriben.
4. Los efectos adversos, ausencia de speedup, anomalías y celdas censuradas se
   archivan igual que los resultados favorables.
5. Las campañas de SO/host se ejecutan en hosts estabilizados y registran
   governor, frecuencia, temperatura, afinidad, artefacto y dependencias.

## Ola A — conformidad y estructura (bloquea todo resultado)

| Campaña | Config piloto | Cierre confirmatorio |
|---|---|---|
| EXP-01R | `pilots/exp01r-v2-2.json` | seis suites, bordes grandes, Linux/macOS/Windows y consumidor independiente; cero divergencias |
| EXP-05R | `pilots/exp05r-modes.json` | bits + cero/permutación de roots/cross, longitud de evidence y campos de contexto; cero no-ops |
| EXP-21R | `pilots/exp21r-domains.json` | matriz instrumentada de entradas primitivas y corpus exhaustivo de mutaciones; cero colisiones no especificadas |

Si cualquiera falla, no se ejecutan campañas de seguridad ni se regeneran
claims. Las cifras de pilotos anteriores no se trasladan al artículo.

## Ola B — mecanismo central reducido

| Campaña | Config piloto | Endpoint/análisis |
|---|---|---|
| EXP-02R | `pilots/exp02r-controls.json` | KM/RMST, bootstrap de pendiente y RMSE entre modelos de estado/ancla/segmento |
| EXP-03R | `pilots/exp03r-controls.json` | Clopper–Pearson, likelihood/deviance y Holm para ancla igual/diferente |
| EXP-04R | `pilots/exp04r-fault-matrix.json` | birthday genérico, colisión de una rama, anclas relacionadas y anchuras física/conservadora |
| EXP-17 | `pilots/exp17r-attacker-frontier.json` | direct, distinguished, rho, Hellman, rainbow y multicollision; frontera tiempo-memoria por ancla |
| EXP-18 | `pilots/exp18r-fold-vector-segments.json` | Fold/Vector por `t,k`, rama/fold roto, consultas y RMST censurado |
| EXP-19 | `pilots/exp19r-signed-reuse.json` | evento firmado exacto, cuello de botella, búsqueda y recomputación; Ed25519 no reducido |
| EXP-20R | `pilots/exp20r-preimage-games.json` | preimagen/segunda/multiobjetivo separados, tres atacantes, targets regular/uniforme y pendientes separadas |

Las anchuras confirmatorias se eligen con el estimador para obtener suficientes
eventos sin eliminar celdas censuradas. Las pendientes de EXP-20 con anchos 3/5
son inestables y no se reutilizan como estimación final.

## Ola C — implementación real y aplicaciones

| Campaña | Config piloto | Gate restante |
|---|---|---|
| EXP-06R | `pilots/exp06r-work-span.json` | replicar Theil–Sen, ancla/rondas separadas y speedup en hosts controlados |
| EXP-07R | `pilots/exp07r-sac-bic.json` | ejecutar al menos el `required_samples_per_input_bit` calculado y una réplica independiente |
| EXP-08R | `pilots/exp08r-independent-streams.json` | exportar con `scripts.export_distribution_streams`; ejecutar NIST/PractRand/TestU01 conservando versión/comando/salida |
| EXP-09R | `pilots/exp09r-operation-matrix.json` | archivo frío controlado, afinidad/ciclos fiables, firma y matriz multihost |
| EXP-10R | `pilots/exp10r-memory-matrix.json` | cuadrícula grande, normalización RSS por SO y bandas de confianza |
| EXP-11R | `pilots/exp11r-protocol-attacks.json`, `pilots/exp11r-parallel-nonces.json` | dificultad suficiente para amortizar procesos; conservar el resultado negativo de baja dificultad |
| EXP-12R | `pilots/exp12r-mode-budget.json` | calibrar igual presupuesto total; energía sólo con medición física |
| EXP-14R | `pilots/exp14r-fault-matrix.json` | aumentar localizaciones/repeticiones; nunca titularlo DFA |

EXP-13 sigue bloqueado por ausencia de núcleo nativo especificado. EXP-16
sigue bloqueado por ausencia de RTL, testbench, librería, corner y síntesis.
EXP-15/Psi queda fuera de la línea y campaña v2.2.

## Ola D — publicación y reproducción

1. Archivar config, observaciones comprimidas, resumen, manifiesto, logs de
   tareas, wheel, SHA256SUMS y SBOM en un dataset versionado.
2. Regenerar tablas/figuras exclusivamente desde ese dataset; el manifiesto de
   figuras debe enlazar todos los hashes de entrada.
3. Actualizar `docs/traceability.md` y el manuscrito claim por claim, incluyendo
   resultados negativos y amenazas a validez.
4. Reproducir al menos conformidad y mecanismo central en un entorno
   independiente.
5. Obtener DOI/identificador persistente y completar `paper/review-checklist.md`
   con revisor, alcance, hallazgos, commits de resolución y disposición final.

## Comandos normativos

```console
python -m experiments.runner CONFIG OUTPUT
python -m scripts.estimate_campaign_budget PILOT_OUTPUT --planned-tasks N
python -m experiments.runner CONFIG OUTPUT --resume
python -m scripts.export_distribution_streams EXP08_OUTPUT BATTERY_EXPORT
python -m scripts.release_artifacts dist --require-clean-tag
```

La definición de terminado y el orden de ejecución son F0–F9 en el plan rector.
Este catálogo no puede cerrar gates por sí solo ni sustituir el prerregistro.
