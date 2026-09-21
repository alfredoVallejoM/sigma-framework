# Sigma v3 — derivación de parámetros de trayectoria (R4)

Estado: **normativo para `REFERENCE_IAP_V3`**  
Fecha: 2026-09-19

Este documento cierra SPEC-V3-001. Cambiar cualquiera de los bytes, el orden de
extracción o el algoritmo siguiente exige un perfil nuevo y nuevos vectores.

## Semilla canónica

La derivación usa SHAKE256 bajo `PARAMETER_DERIVATION` (`0x0305`). Su semilla es
el transcript v3 del mismo dominio con dos campos, en orden estricto:

1. `SigmaContextV3.to_bytes()`;
2. `PersistentBinding.to_bytes()`.

Por tanto, la entrada efectiva al XOF es
`domain_tag_v3(PARAMETER_DERIVATION) || transcript`. El dominio aparece en ambas
capas deliberadamente: la primera identifica la primitiva y la segunda el
objeto canónico que ésta consume.

## Extracción uniforme

Se extrae primero `t_X` y después `k_X`, compartiendo un único cursor SHAKE256.
Para un rango inclusivo `[a,b]`:

1. `w = b - a + 1`;
2. `n = max(1, ceil(bit_length(w - 1) / 8))`;
3. `q = 2^(8n) - (2^(8n) mod w)`;
4. se leen `n` bytes como entero unsigned big-endian hasta obtener `x < q`;
5. el resultado es `a + (x mod w)`.

Los valores rechazados consumen bytes y nunca se reutilizan. Esto elimina el
sesgo de una reducción modular directa. Los rangos proceden exclusivamente del
descriptor de suite: para `REFERENCE_IAP_V3`, `t_X in [2,32]` y
`k_X in [2,4]`.

## Invariantes

- contexto y binding pertenecen a la misma suite registrada;
- todos los bytes que afectan a la derivación están en el transcript;
- misma pareja `(contexto, binding)` implica los mismos parámetros;
- `TrajectoryParameters` vuelve a imponer sus invariantes de construcción;
- la derivación no lee de nuevo la fuente canónica.
