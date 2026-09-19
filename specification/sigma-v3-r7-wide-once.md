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
el wire público. El evaluador fija una procedencia interna con el `S0` calculado
y el SHA-256 operativo de la fuente ya comprobado por R3/R6. Toda construcción
o sustitución exige que `states[0]` y `PreparedBindingV3.source_sha256` coincidan
con esa procedencia. La procedencia no conserva la fuente, no añade replays y no
es evidencia pública serializable. El digest, parsing y verificación públicos se
fijan en R8.
