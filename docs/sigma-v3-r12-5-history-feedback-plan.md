# Sigma v3 R12.5 — restauración del feedback histórico

Estado: **enmienda post-R12 obligatoria antes de R13**  
Fecha: 2026-09-20  
Baseline preservado: R12 candidato `f2fd75b1b99ef67b254dc1ba493e0600babeb214`, PASS adversarial registrado en `963ffe6f7fcd1b4f878ec1a210363c1989ab6023`.

## 1. Motivo de la enmienda

R12 cierra y audita una construcción coherente en la que el binding persistente

\[
P_X = (A_X,\kappa_X,\Lambda_X,J_X)
\]

se reinyecta en cada ronda sobre el estado actual:

\[
S_{i+1}=F(C,i,\operatorname{Place}(S_i,P_X)).
\]

Esa construcción tiene una propiedad no deseada para la intención completa de
Sigma-IAP: si dos ejecuciones comparten el mismo binding persistente y alcanzan
el mismo estado observable en el mismo índice, sus frames posteriores son
idénticos y las trayectorias coalescen determinísticamente.

La intención teórica recuperada exige que la historia anterior de la trayectoria
se retroalimente en el binding efectivo de cada ronda. El objetivo no es sumar
"bits de seguridad", sino impedir que una colisión puntual del estado observable
borre la separación causal de dos historias distintas.

R12 permanece como baseline histórico y de conformidad. No se reescriben su
especificación, corpus ni informe adversarial. R12.5 define una nueva semántica
que, si se adopta como Sigma v3 publicable, exige nuevos IDs/vectores o una
declaración explícita de que los IDs candidatos R12 nunca alcanzaron freeze
público.

## 2. Taxonomía normativa de estado

### 2.1 Binding persistente

\[
P_X=(A_X,\kappa_X,\Lambda_X,J_X).
\]

Identifica la entrada canónica y no cambia durante la evaluación.

### 2.2 Compromiso histórico

Se introduce un objeto tipado `HistoryCommitmentV3`.

Genesis:

\[
H_{X,0}=\operatorname{HistorySeed}(C,P_X).
\]

Actualización causal:

\[
H_{X,i+1}
=
\operatorname{HistoryStep}(C,i,H_{X,i},S_i).
\]

`H_{X,i}` resume el binding de entrada y los estados anteriores
`S_0,...,S_{i-1}`. No contiene `S_i`; por tanto no existe circularidad.

### 2.3 Binding efectivo de ronda

\[
E_{X,i}=(P_X,H_{X,i}).
\]

La ronda `i` consume simultáneamente el estado observable presente y el binding
efectivo:

\[
F_{X,i}
=
\operatorname{RoundFrame}
(C,i,\Pi_{X,i},\operatorname{Place}(S_i,E_{X,i})),
\]

\[
S_{i+1}=H_R(F_{X,i}),
\]

seguido de:

\[
H_{X,i+1}=\operatorname{HistoryStep}(C,i,H_{X,i},S_i).
\]

El orden anterior es normativo: el history utilizado en la ronda `i` sólo
compromete el pasado estricto de `S_i`.

### 2.4 Estado dinámico completo

El estado matemático real pasa a ser

\[
Z_{X,i}=(H_{X,i},S_i),
\]

mientras que `S_i` sigue siendo la proyección observable publicada en la
ventana. La propiedad buscada es que

\[
S_i^X=S_i^Y
\]

no implique

\[
Z_i^X=Z_i^Y.
\]

## 3. Propiedades estructurales objetivo

### HF-TH-01 — separación histórica de frames

Si

\[
H_i^X\neq H_i^Y
\]

aunque

\[
S_i^X=S_i^Y,
\]

los encodings canónicos de los frames de ronda deben ser distintos.

### HF-TH-02 — no coalescencia por colisión puntual

Una coincidencia puntual del estado observable no debe convertir dos historias
distintas en una única órbita futura. Bajo un RO ideal, una nueva igualdad de
estado requiere una nueva coincidencia sobre inputs distintos, salvo un evento
de colisión del history commitment o del framing.

### HF-TH-03 — persistencia de separación histórica

Si `HistoryStep` es collision-resistant bajo el modelo declarado y
`H_i^X != H_i^Y`, entonces una coincidencia accidental
`S_i^X = S_i^Y` no debe forzar `H_{i+1}^X = H_{i+1}^Y`.

### HF-TH-04 — coalescencia del estado completo

La coalescencia determinista sólo puede comenzar después de igualar el estado
dinámico completo necesario por la recurrencia, no por igualar una sola
proyección observable.

### HF-TH-05 — ventana multiestado

En la rama en la que las historias siguen siendo distintas, igualar una ventana

\[
W_{t,k}=(S_t,\ldots,S_{t+k-1})
\]

requiere coincidencias sucesivas sobre queries distintos. Cualquier bound
`2^{-kn}` debe aparecer únicamente bajo hipótesis explícitas de freshness,
regularidad e independencia del oráculo y siempre limitado por ataques contra
`P_X`, `H_i` y las primitivas subyacentes.

## 4. Decisiones normativas R12.5

| ID | Decisión | Estado |
|---|---|---|
| HIST-001 | Domain e encoding exactos de `HistorySeed`. | pendiente |
| HIST-002 | Domain e encoding exactos de `HistoryStep`. | pendiente |
| HIST-003 | Anchura y primitiva del history commitment. | pendiente |
| HIST-004 | Decidir si `LayoutRound` depende también de `H_i` o sólo el placed binding. | pendiente |
| HIST-005 | Tipos `HistoryCommitmentV3` y `RoundBindingV3`; prohibir `bytes` sin tipo. | pendiente |
| HIST-006 | Semántica equivalente para WideOnce, Deep y DeepVector. | pendiente |
| HIST-007 | Tratamiento de history en evidencia explícita y verificación full. | pendiente |
| HIST-008 | Reglas de versionado/IDs tras superseder la recurrencia R12. | pendiente |
| HIST-009 | Modelo de error si history, índice o estado no corresponden. | pendiente |
| HIST-010 | Política de dominio para aplicaciones que reutilizan el digest. | pendiente |

## 5. Diseño de implementación

Crear o extender:

- `sigma/binding/history.py`
  - `HistoryCommitmentV3`
  - `history_seed_v3`
  - `history_step_v3`
  - `RoundBindingV3`
- `sigma/layout/`
  - soporte explícito para `RoundBindingV3`
  - variante history-adaptive si HIST-004 la adopta
- `sigma/rounds/framing_v3.py`
  - `RoundFrame` y `VectorRoundFrame` reciben `RoundBindingV3`
- `sigma/rounds/wide_once_v3.py`
  - conserva `(H_i,S_i)` durante la evaluación
- `sigma/rounds/deep_v3.py`
  - Deep realimenta el estado escalar previo
  - DeepVector realimenta el vector completo previo
- `sigma/outputs/digest_v3.py`
  - `verify_full` reconstruye la cadena histórica completa
- `reference/independent_v3.py`
  - implementación independiente de seed, step y rounds
- `specification/`
  - nuevo documento byte-exacto y corpus R12.5

No se materializa toda la historia. `H_i` debe permitir coste y memoria
`O(1)` por ronda, manteniendo una cadena causal verificable.

## 6. Tests obligatorios de R12.5

### Conformidad

1. KAT de `HistorySeed`.
2. KAT de cada `HistoryStep`.
3. diferencial productivo/independiente para todos los `H_i`.
4. igualdad serial/thread/process/mmap.
5. igualdad entre bytes/file/spool/incremental.
6. mutar `H_i`, `S_i`, índice o binding y comprobar cambio/rechazo.
7. cross-suite y cross-domain rejection.
8. corpus completo con `(P_X,H_i,S_i,frame_i,S_{i+1})`.

### Propiedades

1. misma historia + mismo estado + mismo índice => mismo frame;
2. distinta historia + mismo estado => frame distinto;
3. misma historia + distinto estado => frame distinto;
4. distinto índice => frame distinto;
5. una mutación en cualquier `S_j`, `j<i`, cambia `H_i`;
6. chunking/I/O no cambia `H_i`;
7. DeepVector compromete el vector completo, no componentes aislados;
8. no hay actualización de history antes de consumir el estado causal correcto.

### Adversariales

1. collision injection en `S_i` con histories distintos;
2. replay de `H_{i-1}` en ronda `i`;
3. skip de un `HistoryStep`;
4. duplicación de un estado histórico;
5. reorder de índices;
6. truncado de history;
7. sustitución de binding persistente manteniendo `H_i`;
8. sustitución de `H_i` manteniendo binding persistente;
9. downgrade a frame R12 sin history;
10. mezcla de history de WideOnce/Deep/DeepVector.

## 7. Gate R12.5

R12.5 sólo se cierra cuando:

1. HIST-001..010 están resueltas;
2. la especificación es byte-exacta;
3. el consumidor independiente reproduce todos los `H_i`;
4. la matriz diferencial cubre las tres familias de ronda;
5. los ataques de coalescencia histórica fallan conforme al modelo;
6. el baseline R12 puede seguir reproduciéndose como construcción histórica;
7. existe un corpus nuevo inmutable;
8. el gate local pasa desde wheel aislado;
9. existe una revisión adversarial versionada `R12-5.md`;
10. se actualiza la matriz de claims antes de R13.

## 8. Consecuencia para R13

R13 ya no debe organizarse alrededor de `same-J` frente a `different-J` como
mecanismo principal de no-coalescencia. Esa separación sigue siendo relevante
para ataques contra la preparación de la entrada, pero la trayectoria se analiza
principalmente mediante:

\[
H_i^X = H_i^Y
\quad\text{vs.}\quad
H_i^X \neq H_i^Y.
\]

El objeto central del paper pasa a ser la dinámica

\[
Z_i=(H_i,S_i)
\]

y la proyección pública `S_i`.
