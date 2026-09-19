# Sigma v3 — primera suite end-to-end (R7)

Estado: **normativo para `REFERENCE_IAP_V3`**  
Fecha: 2026-09-19

La evaluación ejecuta estrictamente:

```text
source -> PreparedBindingV3 -> (t,k) -> LayoutInit -> InitFrame -> S0
       -> LayoutRound(i) -> RoundFrame(i) -> S(i+1)
       -> PublicTrajectoryHeader + TrajectoryWindow
```

`S0` es SHA-512 con domain `INIT_FRAME` sobre el InitFrame R6. Cada sucesor es
SHA-512 con domain `ROUND_FRAME` sobre su RoundFrame R6. Se calculan exactamente
los estados `S0..S(t+k-1)` y la ventana conserva `S(t)..S(t+k-1)`.

`WideOnceEvaluationV3` es un artefacto interno de evaluación y trazabilidad, no
el wire público. Retiene la fuente replayable fuera de su igualdad y
representación para recomponer en streaming `InitFrame -> S0` en cada
construcción o sustitución del artefacto; no acepta una trayectoria internamente
coherente cuya raíz no proceda de la fuente preparada. El digest, parsing y
verificación se fijan en R8.
