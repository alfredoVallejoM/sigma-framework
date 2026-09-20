# Sigma v3 — especificación consolidada byte-exacta R12

Estado: normativa para R0–R12. Fecha: 2026-09-20.

Esta especificación consolida los documentos R1–R11. En caso de conflicto para
el core v3, prevalecen este documento y el corpus
`test-vectors/conformance-v3-r12.json`. Sigma v3 es incompatible con v2.2; no
existe conversión implícita de contexto, evidencia, digest ni aplicación.

## 1. Convenciones de bytes

- Todos los enteros son unsigned big-endian y de la anchura indicada.
- `u16seq(X)` es `uint16(len(X)) || Σ uint16(x)`.
- `byteseq(X)` es `uint16(len(X)) || Σ(uint32(len(x)) || x)`.
- Un campo TLV de record es `uint16(tag) || uint32(len(value)) || value`.
- `record(magic, fields)` es `magic[8] || uint16(3) || uint32(body_len) || body`.
- Los tags son estrictamente crecientes, únicos, completos y cerrados. Se
  rechazan campos desconocidos, duplicados, desordenados, ausentes, truncados o
  con trailing bytes.
- Un campo de transcript es `uint16(tag) || uint64(len(value)) || value`.
- `TR(D, fields)` es `ASCII("SIGMA3TR") || uint16(3) || uint16(D) || fields`.
- `DST(D)` es `ASCII("SIGMA3DS") || uint16(D)`.
- `H_alg(D, X)` procesa `DST(D) || X`. SHAKE256 produce exactamente 64 bytes.

Los records pequeños se limitan a 1 MiB, 64 items por secuencia y 65536 bytes
por item. Los frames streaming pueden superar ese límite sin materializarse.

## 2. Registro cerrado

### 2.1 Algoritmos y suites ejecutables

| Algoritmo | ID | salida |
|---|---:|---:|
| SHA-512 | `0x0001` | 64 |
| SHA3-512 | `0x0002` | 64 |
| BLAKE2b-512 | `0x0003` | 64 |
| SHAKE256-512 | `0x0004` | 64 |

El orden registrado es exactamente el de la tabla.

| Suite | ID | round profile | estado |
|---|---:|---:|---:|
| Reference/WideOnce | `0x0301` | `0x0301` | 64 |
| Deep | `0x0303` | `0x0302` | 64 |
| DeepVector | `0x0304` | `0x0303` | 256 |

`0x0302` no es ejecutable: identifica sólo el envelope de auditoría explícita.
Todas las suites ejecutables fijan input/anchor/output/cardinality/joint/layout/
trajectory a `0x0301`, cuatro ramas, chunk size `2^20`, `t ∈ [2,32]`,
`k ∈ [2,4]`, SHA3-512 para `Λ` y SHA-512 como algoritmo de estado escalar.

### 2.2 Dominios

| ID | uso | ID | uso |
|---:|---|---:|---|
| `0301` | anchor branch | `0302` | anchor end reservado |
| `0303` | length signature | `0304` | joint signature |
| `0305` | parameter derivation | `0306` | layout INIT |
| `0307` | layout ROUND | `0308` | init frame |
| `0309` | scalar round frame | `030a` | binding field |
| `030b` | public header reservado | `030c` | implicit evidence |
| `030d` | deep branch | `030e` | vector round frame |
| `030f` | explicit evidence | `0310` | deep scalar fold |
| `0311` | signed commitment | `0312` | KDF binding |
| `0313` | KDF final key | `0314` | PoW challenge |
| `0315` | PoW nonce | `0316` | PoW predicate |

## 3. Contexto pre-input

`SIGMACT3` contiene estos tags exactos:

| tag | valor | tag | valor |
|---:|---|---:|---|
| 1 | suite `u16` | 2 | input profile `u16` |
| 3 | anchor profile `u16` | 4 | round profile `u16` |
| 5 | output profile `u16` | 6 | cardinality profile `u16` |
| 7 | joint profile `u16` | 8 | layout profile `u16` |
| 9 | trajectory profile `u16` | 10 | anchor algorithms `u16seq` |
| 11 | joint algorithms `u16seq` | 12 | state algorithm `u16` |
| 13 | branch count `u16` | 14 | chunk size `u32` |
| 15 | state size `u16` | 16/17 | `t_min/t_max` `u32` |
| 18/19 | `k_min/k_max` `u16` | 20 | salt bytes |
| 21 | challenge bytes | 22 | application context bytes |
| 23 | length algorithm `u16` | | |

Suite, perfiles, algoritmos, tamaños y rangos deben coincidir exactamente con el
descriptor cerrado; salt, challenge y application context son bytes de hasta
4096 cada uno.

## 4. Preparación y binding persistente

Sea `M` la secuencia canónica exacta y `κ = record(SIGMA3CD, (1,u64(|M|)))`.

1. `TA = TR(ANCHOR_BRANCH, (1,C),(2,κ),(3,M))`.
2. Para cada algoritmo registrado, `A_j = H_j(ANCHOR_BRANCH, TA)`.
3. `A = SIGMA3AN{1:suite, 2:u64(|M|), 3:u16seq(algs), 4:byteseq(A_j)}`.
4. `TL = TR(LENGTH_SIGNATURE, (1,C),(2,κ))`.
5. `Λ_digest = H_SHA3-512(LENGTH_SIGNATURE, TL)`.
6. `Λ = SIGMA3LS{1:κ, 2:Λ_digest}`.
7. `TJ = TR(JOINT_SIGNATURE, (1,C),(2,κ),(3,M),(4,A),(5,Λ))`.
8. `J_j = H_j(JOINT_SIGNATURE, TJ)`.
9. `J = SIGMA3JS{1:u16seq(algs), 2:byteseq(J_j)}`.
10. `B = SIGMA3BI{1:A, 2:κ, 3:Λ, 4:J}`.

Los tags internos de binding son `ANCHOR=0x0301`, `CARDINALITY=0x0302`,
`LENGTH_SIGNATURE=0x0303`, `JOINT_SIGNATURE=0x0304`. La preparación streaming
reproduce exactamente los transcripts anteriores y fija además un SHA-256
operativo de la fuente para detectar replay mutable; ese SHA-256 no entra en la
función Sigma.

## 5. Derivación sin sesgo de `t` y `k`

`seed = TR(PARAMETER_DERIVATION, (1,C),(2,B))`. Un reader SHAKE256 contiene
`DST(PARAMETER_DERIVATION) || seed` y mantiene cursor monótono.

Para muestrear uniformemente `[min,max]`, sea `w=max-min+1`, `n` el mínimo de
bytes capaz de representar `w-1`, `space=2^(8n)` y
`limit=space-(space mod w)`. Se leen `n` bytes hasta obtener `x < limit` y se
devuelve `min + (x mod w)`. Primero se extrae `t∈[2,32]` y después `k∈[2,4]` del
mismo reader. El record es `SIGMA3TP{1:u64(t),2:u64(k)}`.

## 6. Layout y placed stream

Para `kind ∈ {INIT=0x0301, ROUND=0x0302}`, índice `i` y longitud base `L`:

```text
layout_seed = TR(domain(kind),
  (1,C),(2,Λ),(3,u16(kind)),(4,u64(i)),(5,u64(L)))
```

Un reader independiente del domain correspondiente muestrea, en orden de ID,
un slot uniforme `[0,L]` por cada campo de binding. Los pares `(field,slot)` se
ordenan por `(slot,field)`. Cada placement es `SIGMA3LP{1:u16(field),2:u64(slot)}`
y el plan es `SIGMA3PL{1:u64(i),2:u64(L),3:TLV(placements 1..4),4:u16(kind)}`.

Los slots se miden sobre la base original, nunca sobre bytes ya insertados. En
cada slot se insertan, en orden, records:

```text
SIGMA3BF || DST(BINDING_FIELD) || u16(field) || u64(len(value)) || value
```

El placed stream es:

```text
SIGMA3PS || u16(3) || u32(len(plan)) || plan || u64(len(body)) || body
```

## 7. Frames, estados y ventana

`InitFrame = TR(INIT_FRAME,(1,C),(2,INIT_plan),(3,placed(M,B)))`.

- WideOnce y Deep: `S_0 = H_SHA512(INIT_FRAME, InitFrame)`.
- DeepVector: `V_0 = H_1(INIT_FRAME,InitFrame)||...||H_4(...)`.

Se ejecutan exactamente `t+k-1` transiciones, con índices
`i = 0 .. t+k-2`. La ventana pública es exactamente
`(S_t,...,S_(t+k-1))` o su equivalente vectorial.

### 7.1 WideOnce

```text
F_i = TR(ROUND_FRAME,
  (1,C),(2,u64(i)),(3,ROUND_plan_i),(4,placed(S_i,B)))
S_(i+1) = H_SHA512(ROUND_FRAME, F_i)
```

### 7.2 Deep escalar

Se construye el mismo `F_i` escalar. Para cada posición/algoritmo registrado:

```text
D_i,j = TR(DEEP_BRANCH_FRAME,
  (1,C),(2,u64(i)),(3,u16(j)),(4,u16(alg_j)),(5,F_i))
R_i,j = H_j(DEEP_BRANCH_FRAME, D_i,j)
Q_i = TR(DEEP_FOLD,(1,C),(2,u64(i)),(3,byteseq(R_i,*)))
S_(i+1) = H_SHA512(DEEP_FOLD,Q_i)
```

### 7.3 DeepVector

`F_i` usa `VECTOR_ROUND_FRAME` y el vector completo `V_i`. Los `D_i,j` se
construyen como arriba sobre ese mismo frame completo y
`V_(i+1)=R_i,0||R_i,1||R_i,2||R_i,3`. No existe fold ni cadenas independientes.

Los backends reciben sólo `(position, algorithm, D_i,j_bytes)`: scheduling no
puede cambiar framing ni función.

## 8. Header, evidencia y verificación

- `SIGMA3PH{1:κ,2:A,3:Λ,4:parameters}`.
- `SIGMA3TW{1:parameters,2:byteseq(window_states)}`.
- Digest implícito:
  `SIGMA3DG{1:u16(0x0301),2:DST(EVIDENCE),3:C,4:header,5:window}`.
- Auditoría explícita:
  `SIGMA3EA{1:u16(0x0302),2:u16(0x0302),3:DST(EXPLICIT_EVIDENCE),`+
  `4:digest,5:B}`.

La verificación estructural sólo parsea. La verificación prepared compara una
evaluación ya calculada. La verificación full recompone binding, trayectoria y
ventana desde una fuente canónica. La auditoría explícita full además compara
`B`; nunca se trata `0x0302` como suite ejecutable.

## 9. Fuentes y aplicaciones

Bytes, fichero estable, snapshot mmap privado, spool e incremental deben dar los
mismos bytes canónicos. Un error, cambio TOCTOU o cancelación aborta sin digest
parcial. I/O y scheduling no alteran la función descrita arriba.

Los wires y modelos de amenaza de firma, KDF y PoW son normativos en
`sigma-v3-r11-applications.md`. En particular, PoW incluye el nonce `uint64` en
el record canónico antes de toda preparación. Por ancho fijo `κ/Λ` pueden
coincidir entre nonces, mientras que `A/J`, parámetros, estados y digest cambian.

## 10. Corpus R12 e implementación independiente

`reference/independent_v3.py` usa sólo stdlib y no importa `sigma`. Su función
`evaluate_suite` reproduce las tres suites ejecutables y expone `M`, `κ`,
componentes de `A`, `Λ`, componentes de `J`, `B`, `t`, `k`, layouts, placements,
frames, ramas, folds, estados, header, window y digest.

El corpus JSON R12 contiene esos valores completos. Se regenera con:

```text
python -m scripts.generate_v3_r12_corpus
python -m scripts.generate_v3_r12_corpus --check
```

KAT SHA-256 del wire de digest:

| suite | `t,k` | SHA-256 |
|---|---|---|
| WideOnce `0x0301` | `2,2` | `8a7827e9cab50b5a3b7a3fc95019ef567cf3944f5a9f756e771c5b7baf4c8090` |
| Deep `0x0303` | `2,2` | `964e80dc9a6e3dac3b23381e4a938c74848db1dc344f4caf58a9918fdaff4e48` |
| DeepVector `0x0304` | `2,2` | `7d7e80e233ddffe5a1b039088f0402adcfbfc76cc5fd641ab5d2906f2234e1e5` |

El gate permanente compara byte por byte implementación productiva,
implementación independiente y corpus en todas las suites, además de casos
generados por propiedades. Cualquier divergencia invalida el candidato R12.

## 11. Claims

Sigma v3 es un framework experimental de combinadores y trayectorias públicas.
No se suman bits nominales de algoritmos, no se afirma memory hardness de Sigma,
VDF, ejecución constant-time, verificación asimétricamente barata ni resistencia
ASIC/GPU. Argon2id es el único componente con claim memory-hard en su composición
KDF. Estas limitaciones forman parte del contrato normativo.
