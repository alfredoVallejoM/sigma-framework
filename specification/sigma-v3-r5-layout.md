# Sigma v3 — layout y placement (R5)

Estado: **normativo para `REFERENCE_IAP_V3`**  
Fecha: 2026-09-19

`LayoutInit` usa `LAYOUT_INIT (0x0306)`; `LayoutRound` usa `LAYOUT_ROUND
(0x0307)`. El seed del XOF es exactamente un transcript R2 del mismo domain con
estos tags estrictamente crecientes:

1. `SigmaContextV3.to_bytes()`;
2. `LengthSignature.to_bytes()`;
3. `LayoutKindV3` como `uint16` big-endian;
4. índice como `uint64` big-endian;
5. longitud original como `uint64` big-endian.

Init exige índice cero. La firma de longitud se recomputa desde contexto y
cardinalidad antes de aceptar el binding. Un único `ShakeReader(domain, seed)`
se consume, usando R4, en orden numérico `ANCHOR (0x0301)`, `CARDINALITY
(0x0302)`, `LENGTH_SIGNATURE (0x0303)`, `JOINT_SIGNATURE (0x0304)`. Cada
resultado es uniforme en `[0, base_length]`; los rechazos avanzan el mismo cursor.
Finalmente se ordenan placements por `(slot, field_id)`.

Los slots siempre se miden sobre los bytes originales. `iter_placed_binding_v3`
emite exactamente:

```text
"SIGMA3PS" || uint16(3) || uint32(len(plan)) || plan || uint64(len(body)) || body
```

Todos los enteros son big-endian. `body` intercala bytes originales e inserciones.
Cada inserción es:

```text
"SIGMA3BF" || domain_tag_v3(BINDING_FIELD) || uint16(field_id)
           || uint64(len(value)) || value
```

`value` es el codec canónico del tipo correspondiente. `body_length` incluye base
e inserciones y no puede exceder `uint64`. Así base, binding y plan quedan
delimitados y ninguna inserción desplaza el significado de slots posteriores.

La API streaming es normativa. `place_binding_v3` es sólo un helper materializado
limitado a bases de 1 MiB.
