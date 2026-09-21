# Sigma v3 — Deep y DeepVector (R9)

Estado: **normativo para las suites R9**  
Fecha: 2026-09-19

## Identificadores y perfiles

R9 registra dos suites ejecutables nuevas. El ID `0x0302` permanece reservado
exclusivamente al envelope exterior de auditoría R8.

| Suite | `SuiteIdV3` | `RoundProfileIdV3` | Estado |
|---|---:|---:|---:|
| Deep | `0x0303` | `DEEP (0x0302)` | 64 bytes |
| DeepVector | `0x0304` | `DEEP_VECTOR (0x0303)` | `4 × 64` bytes |

Ambas suites usan los mismos cuatro algoritmos y perfiles de binding que la
suite reference R7. `DEEP_FOLD (0x0310)` es un domain nuevo y exclusivo del
plegado escalar.

## Inicialización

La preparación, el binding, los parámetros, el layout INIT y `InitFrame` son
los definidos en R3–R7.

- Deep obtiene `S_0` aplicando su `state_algorithm` al `InitFrame` completo.
- DeepVector aplica, en el orden registrado, cada algoritmo de `J_X` al mismo
  `InitFrame` completo y concatena los cuatro resultados. La lista ordenada y
  sin duplicados de algoritmos forma parte del contexto incluido en el frame;
  por ello posición, algoritmo y bytes de entrada quedan fijados sin cadenas
  independientes ni reordenación posible.

## Ronda Deep escalar

Para el estado escalar `S_i` se deriva el layout ROUND canónico y se construye
un `RoundFrame`. Cada rama `j` recibe exclusivamente:

```text
DeepBranchTaskV3(j, algorithm_j,
    DeepBranchFrame(C, i, j, algorithm_j, RoundFrame(C, B_X, Pi_i, i, S_i)))
```

El resultado de cada rama es:

```text
R_i,j = H_algorithm_j(DEEP_BRANCH_FRAME, DeepBranchFrame_i,j)
```

Las cuatro ramas ordenadas se codifican mediante `DeepFoldFrame`, que contiene
contexto, índice `uint64` y secuencia canónica de componentes. El sucesor es:

```text
S_i+1 = H_state(DEEP_FOLD, DeepFoldFrame(C, i, (R_i,0, ..., R_i,3)))
```

El fold es explícito y conserva un estado de 64 bytes. No se atribuye a Deep la
preservación vectorial ni se suman las resistencias nominales de las ramas.

## Ronda DeepVector

Para el vector completo `V_i` se deriva el layout ROUND canónico y se construye
un `VectorRoundFrame`. Cada rama recibe un `DeepBranchFrame` que contiene ese
mismo frame vectorial completo, además de posición y algoritmo:

```text
R_i,j = H_algorithm_j(DEEP_BRANCH_FRAME,
    DeepBranchFrame(C, i, j, algorithm_j,
        VectorRoundFrame(C, B_X, Pi_i, i, V_i)))

V_i+1 = R_i,0 || R_i,1 || R_i,2 || R_i,3
```

No existen cuatro cadenas independientes: cualquier cambio en cualquier
componente de `V_i` cambia los bytes de entrada de todas las ramas siguientes.
No hay fold en esta suite.

## Contrato de backend

El core crea una tupla canónica y ordenada de `DeepBranchTaskV3`. Los backends
serial, thread y process sólo reciben `(position, algorithm, frame_bytes)` y
sólo deciden scheduling. No reciben contexto, binding, layouts, estados ni
objetos semánticos con los que puedan reconstruir otra función.

El core rechaza de forma controlada excepciones, resultados no tipados,
componentes ausentes, duplicados, inesperados o de anchura distinta de 64
bytes. También recomputa cada tarea en el core y rechaza resultados de anchura
correcta con valor incorrecto. Antes de construir una evaluación pública,
revalida todas las tareas, ramas, folds, layouts y sucesores con el backend
serial canónico.

`DeepEvaluationV3` y `DeepVectorEvaluationV3` son objetos factory-only. El
digest y `verify_full_v3` despachan por `RoundProfileIdV3`; un perfil no puede
invocar el evaluador del otro ni el de WideOnce.

## Gate R9

- igualdad byte a byte de evaluación y digest entre serial, thread y process;
- Deep conserva 64 bytes y usa un fold canónico explícito;
- DeepVector conserva exactamente `4 × 64` y cada rama depende del vector
  previo completo;
- fallos controlados de rama y matrices de resultados incompletos, duplicados
  o de anchura incorrecta;
- separación de suite, perfil, tipo de evaluación y claims;
- digest round-trip y verificación completa para ambas suites;
- gate acumulativo R0–R9 y baseline v2.2 verdes.
