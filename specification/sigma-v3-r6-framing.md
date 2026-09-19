# Sigma v3 — framing normativo (R6)

Estado: **normativo para frames v3**  
Fecha: 2026-09-19

Todos los frames usan el transcript R2 y tags crecientes. `InitFrame` usa domain
`INIT_FRAME (0x0308)` con: (1) contexto, (2) `LayoutPlan INIT`, (3) placed stream
R5 de `M_X` y el binding. Recibe `PreparedBindingV3`, no un binding desnudo, y
compara durante el framing el SHA-256 operativo de la fuente con el fijado por
R3. El campo 3 se escribe en streaming con longitud exacta; ante error el sink se
descarta.

`RoundFrame` usa `ROUND_FRAME (0x0309)` con: (1) contexto, (2) índice `uint64`,
(3) `LayoutPlan ROUND`, (4) placed stream R5 del estado escalar y binding.

`VectorRoundFrame` usa `VECTOR_ROUND_FRAME (0x030e)` con los mismos tags y un
vector completo en el placed stream. `DeepBranchFrame` usa `DEEP_BRANCH_FRAME
(0x030d)` con: (1) contexto, (2) índice `uint64`, (3) posición `uint16`, (4)
`AlgorithmId uint16`, (5) `VectorRoundFrame` completo.

Los constructores rechazan contexto/binding incoherentes, layout de otra clase o
índice, anchura incorrecta y branch/algoritmo no correspondiente. Sólo estos
builders determinan orden, domains y codificación de frames v3.

El vector completo byte-a-byte de los cuatro builders está en
`specification/test-vectors/conformance-v3-r6.json`.
