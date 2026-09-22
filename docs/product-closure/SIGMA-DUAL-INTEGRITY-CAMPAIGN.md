# Sigma Dual Integrity — Campaña de implementación y cierre

Estado: PLAN ACTIVO DE PRODUCTO  
Ramal: campaign/sigma-dual-integrity-product-closure  
Dependencia científica: Sigma v3/IAP congelado; R14/R15 no se modifica  
Fecha: 2026-09-22

## 0. Principio rector

La campaña implementa funcionalidades de producto rápidas y algebraicamente certificables sin introducir nueva criptografía ni modificar la función Sigma v3.

El orden obligatorio es:

    extraer autoridad mínima
      -> cerrar ley estructural
      -> implementar referencia
      -> implementar optimización
      -> diferenciar contra referencia
      -> fuzz/adversarial
      -> medir complejidad
      -> congelar wire/API
      -> pasar al siguiente bloque

Cada etapa debe dejar un artefacto útil y cerrado. No existe una mega-feature cuyo valor dependa de completar toda la campaña.

## 1. Tracks

Track ST — Sigma Tree

    ST0 TreeCore
    ST1 Manifest
    ST2 Inclusion/Range Proofs
    ST3 Portable Resume
    ST4 Delta/Append
    ST5 Performance & Scale Closure

Track SV — Sigma Trajectory Product Surface

    SV0 Trajectory Audit
    SV1 Trajectory Checkpoint
    SV2 Verification Policy
    SV3 Receipts & Batch

Track SA — Sigma Artifact

    SA0 Canonical Artifact
    SA1 Dual Verification
    SA2 Provenance/Signature
    SA3 Product/CLI Closure

Track REL — Release

    REL0 Compatibility gate
    REL1 Independent consumer
    REL2 Packaging/docs/examples
    REL3 Adversarial release review

## 2. Ruta crítica

Ruta principal:

    ST0
      ├── ST1
      ├── ST2 -> ST3 -> ST4 -> ST5
      └── SV0 -> SV1 -> SV2 -> SV3

Convergencia:

    ST1 + ST2 + SV0 + SV2
      -> SA0 -> SA1 -> SA2 -> SA3
      -> REL0 -> REL1 -> REL2 -> REL3

ST1 y SV0 pueden comenzar en paralelo tras ST0 siempre que no modifiquen el core v3.

## 3. ST0 — TreeCore extraction

### Objetivo

Crear la autoridad única de geometría arbórea y un formato Sigma Tree V1 independiente de v2.2 y v3.

### Implementación mínima

- sigma/tree/ids.py
- sigma/tree/codec.py
- sigma/tree/model.py — profile/node/root/frontier canónicos
- sigma/tree/core.py — autoridad única de construcción/reducción
- sigma/tree/legacy_v22.py — compatibilidad histórica sólo lectura
- reference/tree_v1.py — oracle stdlib independiente
- scripts/product_closure/st0_gate.py — gate reproducible de cierre
- tests unit/property/differential/vectors de ST0

No se crea un index persistente en ST0: pertenece a etapas posteriores de proofs/delta. La frontier vive en el modelo canónico; separar un archivo por nombre no constituye una obligación arquitectónica.

### Decisiones congeladas

- chunk size V1 = 65,536 bytes;
- cuatro ramas estándar de 64 bytes;
- no odd duplication;
- perfect-subtree frontier;
- dominios SigmaTree independientes;
- TreeRoot V1 nunca es SigmaDigestV3;
- legacy_v22 sólo lectura.

### Obligaciones ST0

ST0-O01 — Deterministic chunking  
El mismo bytestring produce exactamente las mismas leaves.

ST0-O02 — Leaf framing injectivity  
Dos tuplas distintas de profile/index/offset/length/bytes no comparten encoding canónico.

ST0-O03 — Node framing injectivity  
Dos combinaciones estructuralmente distintas no comparten encoding.

ST0-O04 — Unique frontier decomposition  
Para n hojas, existe una única frontier normalizada por representación binaria de n.

ST0-O05 — Combine locality  
Combinar dos nodos válidos depende sólo de ambos nodos y del profile.

ST0-O06 — Backend neutrality  
Chunk read size no altera root. Cualquier backend paralelo es semánticamente neutro si produce la misma secuencia canónica ordenada de hojas prehasheadas; workers y scheduling deben normalizarse a esa secuencia antes de la reducción serial.

ST0-O07 — Empty root uniqueness  
El objeto vacío tiene una raíz canónica propia.

ST0-O08 — Legacy isolation  
Reproducir TreeWide v2.2 no permite confundir su root con TreeRoot V1.

ST0-O09 — Resource bounds  
Parser y builders rechazan tamaños fuera de policy antes de reservar memoria grande.

ST0-O10 — Complexity contract  
Build O(mB), frontier O(m log N), finalization O(m log N).

### Tests ST0

Unit:
- empty;
- 1 byte;
- chunk_size-1;
- chunk_size;
- chunk_size+1;
- 2^k leaves;
- 2^k ± 1 leaves.

Property:
- chunked reads equivalen a one-shot;
- reducer de hojas prehasheadas ordenadas coincide con build directo;
- cualquier backend con workers/scheduling debe normalizar a dicho orden antes de reducir;
- frontier serializa/deserializa;
- reconstrucción desde leaves coincide con build directo.

Differential:
- implementación optimized vs referencia puramente funcional;
- legacy adapter vs corpus v2.2 histórico.

Adversarial:
- wrong heights;
- non-adjacent children;
- duplicate frontier heights;
- malformed digest vector;
- overflow de offsets;
- truncated wire.

Fuzz:
- TreeProfile;
- TreeNode;
- TreeRoot;
- TreeFrontier;
- >=100k mutaciones deterministas/reproducibles en el gate de cierre;
- mutaciones estructurales missing/duplicate/reordered/unknown TLV.

### Gate ST0

PASS sólo si:
1. ninguna KAT v2.2/v3 cambia;
2. referencia e implementación productiva coinciden;
3. descomposición estructural exhaustiva >= 100k contadores de hojas y >= 2k casos diferenciales aleatorios sin divergencia;
4. parser fuzz >= 100k y mutation tests estructurales cubren errores críticos;
5. complejidad observada no contradice el contrato.

## 4. ST1 — Canonical Manifest

### Objetivo

Comprometer árboles lógicos de directorio, releases y datasets de forma reproducible
sin depender del path absoluto, del orden de traversal ni de metadata volátil del host.

### Autoridades y superficie

- `sigma/tree/path.py` — canonicalización portable de paths.
- `sigma/tree/manifest.py` — ManifestEntryV1, ManifestV1 y scanner de directorio.
- `reference/manifest_v1.py` — oracle stdlib independiente.
- `scripts/product_closure/st1_gate.py` — gate reproducible local/cross-platform.
- `scripts/product_closure/st1_benchmark.py` — ledger de complejidad.
- CLI provisional `sigma manifest`; SA3 conserva la autoridad sobre la CLI final.

ST1 consume TreeRoot V1 ya congelado. No modifica chunking, domains, hashes, frontier
ni root semantics de ST0 y no modifica Sigma v3.

### Perfil base congelado

Manifest profile `BASE_V1 = 0x0001`.

Entry kinds:
- FILE = 0x0001;
- DIRECTORY = 0x0002;
- SYMLINK = 0x0003.

Metadata profile base `BASE = 0x0001`.

Todo entry contiene:
1. canonical relative path;
2. entry kind;
3. metadata profile;
4. byte_length;
5. TreeRoot V1;
6. optional SigmaDigestV3 wire.

Payload comprometido por TreeRoot:
- FILE -> bytes exactos del fichero;
- DIRECTORY -> bytes vacíos / canonical empty TreeRoot;
- SYMLINK, sólo con policy explícita -> texto NFC del target UTF-8, sin seguirlo.

Así los directorios vacíos participan en el manifest y un symlink no adquiere
semántica implícita de lectura del objeto apuntado.

### Canonical path V1

Una ruta aceptada:
- es `str` Unicode válido y serializable como UTF-8 estricto;
- es relativa;
- usa sólo `/` como separador lógico;
- no tiene NUL;
- no tiene componentes vacíos, `.` ni `..`;
- no tiene drive/UNC de Windows;
- se normaliza a Unicode NFC;
- no aplica case folding;
- está limitada a 4096 bytes UTF-8.

El orden canónico es lexicográfico por los bytes UTF-8 NFC. Dos nombres distintos
que colapsan al mismo path tras NFC son un duplicate error, nunca aliases silenciosos.

### Symlink policy

Default: `REJECT`.

Modo explícito `TEXT`:
- usa `os.readlink`;
- normaliza sólo el texto del target a NFC;
- no resuelve `..`;
- no sigue el target;
- compromete esos bytes mediante TreeRoot V1.

Un loop o un target de traversal es por tanto dato comprometido, no traversal ejecutado.

### Metadata base

No forman parte del wire:
- mtime/ctime;
- uid/gid;
- inode;
- executable bit;
- path absoluto.

Un futuro profile que incluya executable bit necesita otro profile ID; no se
sobrecarga silenciosamente BASE_V1.

### Wire V1

ManifestEntry magic: `SIGTENT1`.

Campos TLV:
1. path UTF-8 NFC;
2. kind u16;
3. metadata profile u16;
4. byte_length u64;
5. canonical TreeRoot V1 wire;
6. optional trajectory digest wire, vacío si ausente.

Manifest magic: `SIGTMNF1`.

Campos:
1. manifest profile u16;
2. count-prefixed sequence de ManifestEntry wires en canonical path order.

El record completo conserva el límite Tree V1 de 8 MiB. Entry count máximo:
65,535. Un entry wire se limita a 1 MiB.

El optional trajectory digest se trata en ST1 como bytes estructuralmente
etiquetados por magic `SIGMA3DG`: ST1 los compromete exactamente pero no afirma
que sean válidos ni message-bound; esa validación pertenece al track Trajectory/Artifact.

### Obligaciones

ST1-O01 — Canonical relative paths.
ST1-O02 — Traversal independence.
ST1-O03 — Absolute root-path independence.
ST1-O04 — Duplicate canonical path rejection.
ST1-O05 — Base metadata excludes host-volatile fields.
ST1-O06 — Symlink safety and explicit policy.
ST1-O07 — Content/TreeRoot binding.
ST1-O08 — Optional trajectory digest exact binding.
ST1-O09 — Canonical UTF-8 byte ordering.
ST1-O10 — Complexity contract.

### Complexity contract

Con:
- B = bytes totales de ficheros/targets leídos;
- F = número de entries;
- m = 4 branches Tree V1;
- path length acotado por profile;

el contrato es:

    T_manifest = O(m B + F log F)
    IO_manifest = O(B + F)
    M_manifest = O(F) + max_file O(chunk + m log N_file)

La memoria O(F) es explícita: BASE_V1 materializa entries antes de ordenar.
ST5 podrá sustituir este coste accidental por sort externo/index policy sin
cambiar el wire.

### Tests/gate ST1

Blocking local gate:
- >= 50,000 canonical path cases;
- >= 1,000 traversal permutations;
- >= 1,000 product/reference differential manifests;
- >= 50,000 entry/manifest codec mutations;
- structural TLV missing/duplicate/reorder/unknown mutations;
- root relocation fixture;
- touch/chmod metadata invariance;
- content mutation;
- Unicode/NFC duplicate adversary;
- symlink default rejection;
- symlink loop/traversal TEXT-mode no-follow;
- independent filesystem scanner agreement.

Cross-platform gate:
- ejecutar el mismo `st1_gate.py` en Linux y macOS;
- ambos reports deben tener `local_passed=true`;
- ambos deben producir el mismo `fixture_manifest_sha256`;
- `closure_eligible=true` sólo aparece cuando el gate recibe reports válidos
  de ambas plataformas.

No se simula macOS cambiando `platform.system()`.

### Criterio de cierre

CANDIDATE exige todas las obligaciones con evidencia local y reference differential.

COMPLETE exige además:
1. peer report Linux/macOS byte-identical;
2. revisión adversarial post-candidate de ST1-O01..O10;
3. KAT/corpora ST0 intactos;
4. ausencia de cambios en Sigma v3.

## 5. ST2 — Inclusion and Range Proofs

### Objetivo

Añadir evidencia selectiva sobre Sigma Tree V1 sin modificar TreeRoot, TreeNode,
chunking, domains ni ninguna semántica ST0.

La etapa se divide en:
- ST2A — InclusionProof V1;
- ST2B — RangeProof V1.

### Implementación

- `sigma/tree/proofs.py`
  - InclusionStepV1;
  - InclusionProofV1;
  - RangeProofV1;
  - TreeProofIndex efímero;
  - prove_leaf / verify_inclusion;
  - prove_range / verify_range;
  - geometría canónica de inclusion/range.
- `reference/tree_proof_v1.py`
  - parser/verificador stdlib independiente;
  - no importa `sigma`.
- `scripts/product_closure/st2_gate.py`
  - campaña de cierre 100k/100k;
  - differential independent;
  - mutation/adversarial;
  - cover exhaustivo.
- `scripts/product_closure/st2_benchmark.py`
  - tamaño/verify ledger.
- `scripts/product_closure/generate_st2_vectors.py`
  - KAT hashes de wire revisados por verifier independiente.
- tests unit/property/differential/vectors ST2.

TreeProofIndex es sólo un índice efímero para amortizar proof generation. No forma
parte de Tree identity ni introduce un persistent index antes de ST4/ST5.

### ST2A — Inclusion proofs

Obligaciones:

ST2-O01 — Root reconstruction  
Proof válido reconstruye exactamente la TreeRoot declarada.

ST2-O02 — Position binding  
leaf_index determina también offset canónico; mover leaf a otra posición invalida.

ST2-O03 — Orientation binding  
Cada step serializa LEFT/RIGHT y su geometría debe coincidir con la path canónica.

ST2-O04 — Length/count binding  
Leaf length, sibling geometry y root byte_length/leaf_count se validan exactamente.

ST2-O05 — Profile binding  
Proof profile y root profile deben coincidir con el único TreeProfile V1 aceptado.

ST2-O06 — Independent verifier  
`reference/tree_proof_v1.py` parsea y verifica los wires sin importar `sigma`.

ST2-O07 — Size bound  
Path O(log N); cada step transporta un vector fijo de m=4 branches:

    inclusion wire = O(m log N)

### ST2B — Range proofs

ST2-O08 — Exact interval  
start y length están dentro del wire; range_bytes debe tener exactamente length bytes.

ST2-O09 — Canonical range cover  
El complement witness cover es la colección única de subárboles canónicos maximales
disjuntos del target leaf span.

ST2-O10 — Partial edge honesty  
Prefix/suffix son exactamente los bytes omitidos de los edge leaves y sus longitudes
se derivan del intervalo/root antes de hashing.

ST2-O11 — No rest-of-object read  
`verify_range(range_bytes, proof)` no recibe source/path/file handle; reconstruye
root sólo con esos bytes + proof.

ST2-O12 — Cheap invalid-range rejection  
One-shot generation valida bounds/overflow antes de construir TreeProofIndex; parser
y verifier validan geometry antes de leaf hashing.

### Wire freeze

Magics V1:

    InclusionStep  SIGTPST1
    InclusionProof SIGTIPF1
    RangeProof     SIGTRPF1

Los records usan el mismo strict TLV/version envelope de Sigma Tree V1.

KAT corpus:

    specification/test-vectors/sigma-tree-v1-st2.json

Corpus SHA-256:

    dea26a2bfdfe4906acf176ab8b57c1963b895c567aab7d9b614a485c5b17d674

### Test matrix ST2

Unit/adversarial:
- singleton;
- final short leaf;
- 2^k, 2^k±1 leaf counts;
- wrong leaf bytes;
- leaf-index mutation;
- side flip;
- sibling geometry mutation;
- root length/count mutation;
- profile mutation/rejection;
- one-byte range;
- exact chunk;
- crossing chunk;
- multi-chunk;
- full object;
- partial first/last edge;
- corrupted prefix/suffix;
- mixed-tree witness;
- empty/out-of-bounds/overflow;
- invalid one-shot range must reject before index build;
- range verification under an I/O bomb.

Structural:
- exhaustive canonical complement cover for all non-empty intervals on trees
  with 1..64 leaves;
- random inclusion/range property campaign;
- witness/step count logarithmic checks.

Differential:
- product verifier vs `reference/tree_proof_v1.py`;
- frozen vector replay;
- zero divergence.

Mutation:
- 20,000 deterministic bit mutations over inclusion/range proof wires;
- accepted changed wires must not verify original bytes in either verifier;
- explicit missing/duplicate/reordered/unknown top-level TLV mutations;
- explicit sibling/witness digest mutation.

### Gate ST2

Closure-scale gate requires:
- 100,000 generated inclusion proofs;
- 100,000 generated range proofs;
- >=500 independent differential cases;
- >=20,000 proof-wire bit mutations;
- exhaustive complement cover over N=1..64;
- independent verifier zero divergences;
- KAT generator/check exact;
- proof-size ledger compatible with O(m log N);
- adversarial review of ST2-O01..O12.

Execution result on isolated exact ST0+ST2 mirror:
- 45,760 exhaustive cover cases PASS;
- 100,000 inclusion proofs generated PASS;
- 100,000 range proofs generated PASS;
- 500 independent differential cases PASS;
- 20,000 proof mutations: 7,885 rejected malformed,
  12,115 accepted-but-invalid, zero still-valid mutations;
- maximum inclusion depth observed: 7;
- maximum range witness count observed: 11;
- focused compile/smoke PASS.

### Complexity evidence

Sweep N={1,2,4,8,16,32,64,128}:

- inclusion steps: 0..7;
- inclusion wire: 482..3,128 bytes;
- exact empirical increment: 378 bytes per log2(N) level;
- range witnesses: 0..6 in the benchmark boundary case;
- range edge complements stay bounded by 2*(65,536-1) bytes.

Thus observed wire growth is consistent with the derived contracts.

### Criterio de cierre

COMPLETE requiere:
1. O01..O12 con evidencia correspondiente;
2. gate closure-scale PASS;
3. independent verifier zero divergences;
4. KAT ST2 frozen;
5. ST0 KAT/wire unchanged;
6. no Sigma v3 source/semantic changes;
7. post-candidate adversarial review PASS.

## 6. ST3 — Portable Resume

### Objetivo

Reanudar Sigma Tree V1 desde estado estructural portable sin serializar state de
hashlib y sin rehashear el prefijo ya comprometido.

### Implementación

- `sigma/tree/checkpoint.py`
  - TreeResumeCheckpointV1;
  - TreeSourceHintV1;
  - checkpoint_builder / checkpoint_bytes;
  - restore_builder / resume_tree;
  - read_checkpoint / write_checkpoint_atomic;
  - source_hint_from_path / source_hint_matches_path.
- extensión aditiva de `TreeBuilder`:
  - checkpoint_state();
  - from_checkpoint_state().
- `reference/tree_checkpoint_v1.py`
  - parser y resume stdlib independiente;
  - no importa `sigma`.
- `scripts/product_closure/st3_gate.py`
  - 100k split/resume;
  - differential independiente;
  - repeated checkpoint cycles;
  - corruption/mutation;
  - atomic persistence failure injection.
- `scripts/product_closure/st3_benchmark.py`
  - wire/decode/restore vs frontier size.
- `scripts/product_closure/generate_st3_vectors.py`
  - KAT checkpoint/resume.
- tests unit/property/differential/vectors + CLI provisional.

### Obligaciones

ST3-O01 — Resume equivalence

    resume_tree(checkpoint(P), S)
      = tree(P || S)

para todo split cubierto.

ST3-O02 — Frontier canonicality  
Checkpoint sólo conserva la canonical frontier de hojas completas. Un short
rightmost subtree se rechaza aunque sea legal como ST0 final frontier.

ST3-O03 — Tail bound

    0 <= len(tail) < 65,536

ST3-O04 — Offset consistency

    completed_bytes
      = completed_leaf_count * 65,536 + len(tail)

ST3-O05 — Profile consistency  
Checkpoint profile, frontier profile y restored builder deben usar exactamente
TreeProfile V1. Unknown/cross-profile wire se rechaza.

ST3-O06 — Transactional checkpoint write  
La persistencia usa temporal same-directory + fsync + atomic replace. Fallo
antes de replace conserva el checkpoint anterior y limpia temporales.

ST3-O07 — Source hint honesty  
size/mtime_ns/inode/device son hints heurísticos. No son evidencia
criptográfica ni demuestran igualdad del prefijo.

ST3-O08 — Restore cost

    O(m log N + tail)

con tail < fixed chunk, por tanto O(m log N) en N para V1.

### Tests

Boundary:
- empty;
- 1 byte;
- chunk-1;
- exact chunk;
- chunk+1;
- multi-chunk;
- tail corto final.

Property:
- random prefix/suffix;
- checkpoint codec round-trip;
- repeated checkpoint->restore->checkpoint cycles;
- frontier completa + tail bounded tras random updates.

Differential:
- product checkpoint wire vs `reference/tree_checkpoint_v1.py`;
- product resumed root vs independent resumed root;
- ambos vs direct ST0 root.

Adversarial:
- tail de tamaño chunk;
- byte/leaf accounting drift;
- short node dentro de checkpoint frontier;
- finalized builder checkpoint;
- wrong profile;
- corrupted frontier;
- checkpoint bit mutations;
- TLV missing/duplicate/reordered/unknown;
- source hint mutation no debe cambiar root;
- destination replace failure conserva checkpoint previo.

Persistence:
- successful atomic write/read;
- failure injection en `os.replace`;
- no leaked temporary file.

### Gate ST3

Closure-scale gate exige:
- >=100,000 random split/resume cases;
- directed checks en todas las fronteras canónicas relevantes;
- >=500 independent differential cases;
- >=1,000 repeated resume/checkpoint cycles;
- >=20,000 checkpoint-wire mutations;
- structural TLV mutation suite;
- atomic persistence failure injection;
- independent checkpoint oracle zero divergences;
- KAT ST3 frozen;
- restore complexity ledger compatible con O(m log N);
- adversarial review O01..O08.

#### Diseño de los 100k splits

Para no convertir el gate en rehash redundante de terabytes:

- objeto: 4 full chunks + 4 KiB tail;
- los 100k offsets aleatorios viven dentro del tail final;
- todos parten de una frontier no trivial de cuatro hojas completas;
- cada caso restaura esa frontier y recomputa sólo la última leaf parcial;
- 13 offsets dirigidos adicionales cubren empty/chunk-1/chunk/chunk+1 y
  fronteras intermedias.

Esto conserva la semántica del gate sin bajar ningún umbral.

### Ejecución de cierre

Resultado del gate lógico sobre mirror ST0+ST3 exact-wire:

- split cases: 100,000 PASS;
- directed boundary splits: 13 PASS;
- independent differential: 500 PASS;
- repeated cycles: 1,000 PASS;
- checkpoint mutations: 20,000 PASS;
- malformed/rejected mutations: 8,503;
- accepted-but-invalid mutations: 11,497;
- altered checkpoints still reconstructing original root: 0;
- structural TLV mutations: 14 PASS.

Hashes de campaña:

    split:
    c2c4a71ef974e409e2c152adb5981bb509ebe4a33244bfe9b0875aa117b25787

    differential:
    5bc96789df2b68d77d2ad6cfe3aae7daa29ecdb247ebe0c32ba9407c87831f38

    repeated cycles:
    640780401d57d755f5618008397448117a2beed6ce45fb1277b3bfed054815c4

    mutation:
    5314999f5cf6ba3b6d4fc7a2d01cf07e98bfa1ca2ef467683985305022d46674

Expected direct root wire SHA-256:

    0fc0697e078c61df690bddec3a8e5bd01085c52bb1d46815d803745df38d42bc

### KAT freeze

Corpus:

    specification/test-vectors/sigma-tree-v1-st3.json

SHA-256:

    c46ad683e2c295aa251873c3de6b08eff8b78055f7bf3e5d80a4b308b9499e62

Casos:
- empty -> abc;
- one-byte prefix;
- exact chunk boundary;
- chunk + partial tail;
- three chunks + tail.

### Complexity evidence

Frontier synthetic sweep with 1,2,4,8,16,24,32,40 nodes.

Checkpoint wire growth observed:

    exactly 350 bytes / frontier node

más overhead fijo/tail.

Decode/restore grow linealmente con el número de frontier nodes, compatible con:

    O(m log N + tail).

No se rehashea ningún byte del prefijo al restaurar.

### Criterio de cierre

COMPLETE requiere:
1. ST3-O01..O08 con evidencia exacta;
2. 100k split gate PASS;
3. independent oracle zero divergence;
4. transactional failure injection PASS;
5. KAT checkpoint/resume frozen;
6. complexity ledger compatible;
7. ST0 root semantics/KAT intactos;
8. no cambios Sigma v3;
9. post-candidate adversarial review PASS.

## 7. ST4 — Delta and Append

### Objetivo

Cerrar la primera capa realmente incremental de Sigma Tree V1:

- ST4A — same-length replacement;
- ST4B — append.

El objetivo no es evitar el coste inicial de construir un índice. El contrato es:

    build index once: O(mB)
    local update afterwards: proportional al cambio + ancestor closure

sin rehacer silenciosamente O(B) para un cambio local.

### Implementación

- `sigma/tree/delta.py`
  - RebuildRequired;
  - TreeEditV1;
  - TreeDeltaIndex;
  - TreeUpdateTelemetryV1;
  - TreeUpdateResultV1;
  - normalize_tree_edits.
- `reference/tree_delta_v1.py`
  - normalización independiente;
  - full-rebuild delta oracle;
  - append oracle;
  - affected-leaf y ancestor-closure oracle.
- `scripts/product_closure/st4_gate.py`
  - cumulative local updates;
  - append campaign;
  - failure injection;
  - independent differential corpus;
  - locality work gate.
- `scripts/product_closure/st4_benchmark.py`
  - sweep 1 leaf / 0.1% / 1% / 10% / 100%;
  - incremental vs full rebuild;
  - allocations/RSS/work counters;
  - append reuse ledger.
- `scripts/product_closure/generate_st4_vectors.py`
  - frozen semantic KAT.
- unit/property/differential/vector tests.

No persistent TreeDeltaIndex wire se define en ST4. Persistencia/index layout/fallback
son ST5/SA3.

### ST4A — Same-length replacement

#### ST4-O01 — Delta equivalence

Para todo delta soportado:

    index(X).apply_delta(Δ).root
      = tree(apply_same_length(X,Δ))

#### ST4-O02 — Affected-leaf completeness

Toda leaf cuya byte interval interseca un edit normalizado se recomputa una vez.

La telemetría publica exactamente:

    affected_leaves.

#### ST4-O03 — Unaffected subtree preservation

Todo subtree canónico disjunto del affected set puede conservar exactamente su
TreeNode previo.

La batería incluye una comprobación por identidad de objeto, no sólo igualdad de
digests.

#### ST4-O04 — Ancestor closure completeness/minimality

Los node keys recomputados deben ser exactamente el cierre ancestral canónico de
las leaves afectadas:

    recomputed_nodes
      = affected leaves union ancestors required by ST0 geometry.

Un oracle independiente calcula la misma closure.

#### ST4-O05 — Overlap normalization

Edits:
- se ordenan;
- se validan;
- overlaps compatibles se fusionan;
- adyacentes se fusionan;
- overlaps contradictorios se rechazan.

La salida normalizada no depende del orden de entrada.

Durante revisión se eliminó una deuda accidental O(k^2): los edits normalizados
ahora se particionan a leaves en un único pase y cada leaf consume sólo sus
segmentos.

#### ST4-O06 — Transactionality

Todo hashing/composición sucede antes de publicar.

Además, el commit final mantiene rollback journal sobre:
- leaf bytes tocados;
- leaf nodes;
- cache nodes;
- root/length.

Se inyectan fallos:
1. durante combine antes de commit;
2. dentro de la publicación de `dict.update`.

En ambos:

    state_after = state_before.

#### ST4-O07 — Rebuild boundary

Si:

    delete_length != len(replacement)

se devuelve:

    RebuildRequired

antes de iniciar el camino incremental.

No hay support silencioso de insertion/interior deletion.

### ST4B — Append

#### ST4-O08 — Append equivalence

    index(X).append(Y).root = tree(X || Y)

incluyendo:
- Y vacío;
- 1 byte;
- 1 chunk;
- múltiples chunks;
- old tail parcial.

#### ST4-O09 — Frontier/subtree reuse

Append conserva todos los subárboles antiguos que:
1. eran canónicos en la Tree previa;
2. siguen enteramente dentro del prefijo full-leaf no modificado.

Si la Tree previa acaba en tail parcial, sólo esa leaf previa se vuelve a hashear.

La telemetría publica:

    frontier_nodes_reused
    reused_nodes
    leaf_payload_bytes_rehashed.

La cache puede contener geometrías históricas, pero sólo se reutiliza una key si
`_is_canonical_key(..., old_leaf_count)` confirma que pertenecía a la Tree
inmediatamente anterior.

### Correctness gate

`st4_gate.py` exige:

- >=5,000 delta cases acumulativos;
- >=1,000 append cases acumulativos;
- sampled direct full rebuilds durante ambas campañas;
- >=500 fresh independent differential cases;
- canonical overlap normalization;
- RebuildRequired boundary;
- exact ancestor closure;
- fault injection delta;
- fault injection append;
- one-leaf locality gate sobre 128 leaves.

Ejecución semántica aislada con los algoritmos ST0/ST4 exactos:

- delta cases: **5,000 PASS**;
- append cases: **1,000 PASS**;
- independent differential cases: **500 PASS**;
- max recomputed nodes para pequeños deltas: **12**;
- max leaf payload rehashed para pequeños deltas: **131,072 bytes**
  (casos que cruzan dos chunks);
- append frontier reuse events: **3,496**;
- one-leaf locality tree: 128 leaves;
- one-leaf recomputed nodes: **8**;
- one-leaf rehashed payload: **65,536 bytes**;
- unaffected 64-leaf subtree preserved by object identity.

Streams:

    delta:
    2c039f135ba2667166aaf4575d698e2436f50f1dcaa4ac9224de146a685fa511

    append:
    4bdf145f39d4dd0fa31a6ae00b63fd7a8f43a8c9c68f97d7c793000981a02c20

    independent differential:
    a284023f7d3d083b7078cb2e94eabd15e48e18517e8b3868823734bb2d108b61

La ejecución correctness principal fue del orden de ~18 s en el entorno aislado.

### Frozen semantic vectors

Corpus:

    specification/test-vectors/sigma-tree-v1-st4.json

SHA-256:

    ed94e768dd52c71039b938eec9eafdd8330465a974b4636c3a2a975129178999

Casos:
- one-byte delta;
- cross-chunk delta;
- consistent overlapping delta;
- full-file same-length replacement;
- append to partial tail;
- append full chunk + tail.

### Performance gate

El ledger grande usa:

    N = 1,000 leaves
    B = 65,536,000 bytes

de forma que:

    1 leaf = exactamente 0.1%.

El benchmark separa construcción inicial del índice del update incremental.

Resultado local con hashing ST0 exacto y rollback-journal overhead modelado:

| régimen | leaves | payload rehashed | recomputed nodes | speedup vs rebuild |
|---|---:|---:|---:|---:|
| one leaf | 1 | 65,536 B | 11 | ~342x |
| 0.1% | 1 | 65,536 B | 11 | ~369x |
| 1% | 10 | 655,360 B | 85 | ~49x |
| 10% | 100 | 6,553,600 B | 524 | ~6.0x |
| 100% | 1,000 | 65,536,000 B | 1,999 | ~0.71x |

Interpretación obligatoria:

- el régimen local es fuertemente sublineal respecto a B;
- 100% converge al rebuild y puede ser más lento por overhead del índice;
- el slowdown 100% es un resultado aceptado/publicado, no se oculta.

Peak Python allocations observadas aproximadamente:

- 1 leaf: 0.27 MiB;
- 1%: 0.84 MiB;
- 10%: 6.8 MiB;
- 100%: 64.7 MiB.

El script registra también process RSS high-water; esa cifra debe tomarse de un
proceso limpio para publicación porque el high-water es acumulativo.

### Append performance

Sobre el mismo índice de gran escala, una ejecución aislada obtuvo aproximadamente:

| suffix | frontier nodes reused | speedup vs rebuild |
|---|---:|---:|
| 1 byte | 6 | ~2,224x |
| 1 chunk | 6 | ~757x |
| 4 chunks + tail | 7 | ~187x |

Estas cifras son evidencia engineering local, no cross-host publication claims.

### Complexity contract

Después de index construction:

    T_delta =
      O(B_delta
        + bytes_de_leaves_afectadas
        + m |Anc(A)|)

con cota:

    O(B_delta + m k log N).

Append:

    O(old_tail + appended_bytes + m * bridge_nodes).

No hay término O(B_old) en el camino append.

### Criterio de cierre

COMPLETE requiere:
1. ST4-O01..O09 con evidencia exacta;
2. independent full-rebuild oracle zero divergences;
3. normalization/adversarial suite PASS;
4. transactionality failure injection antes y dentro de commit PASS;
5. performance local no aproximadamente O(B);
6. sweep 1 leaf/0.1%/1%/10%/100% publicado;
7. 100% slowdown, si existe, conservado;
8. append frontier reuse demostrado;
9. KAT ST4 frozen;
10. ST0/ST2/ST3 semantics sin drift;
11. post-candidate adversarial review PASS.

## 8. ST5 — Tree performance and scale closure

### Objetivo

Cerrar deuda accidental de rendimiento/memoria en Sigma Tree sin cambiar un solo
wire o claim criptográfico ST0-ST4.

ST5 no es una nueva primitive. Es:
- optimización byte-preserving;
- layout/memory audit;
- resource-policy closure;
- performance ledger freeze.

### Implementación

Cambios productivos:

- `sigma/tree/core.py`
  - leaf framing hasheado por partes;
  - full chunks procesados mediante memoryview;
  - no materialización de cuatro leaf records grandes.
- `sigma/tree/proofs.py`
  - TreeProofIndex con zero-copy leaf views;
  - `prove_leaf_streaming`;
  - `prove_range_streaming`;
  - `verify_range` con reconstrucción recursiva O(log N), sin target-node map O(range).
- `sigma/tree/scale.py`
  - TreeScalePolicyV1;
  - TreeIndexPlanV1;
  - FULL / STREAMING / REJECT;
  - estimadores conservadores;
  - scaled proof APIs;
  - delta budget rejection.
- `sigma/tree/manifest.py`
  - read requests limitados a un chunk de 65,536 bytes.

Tooling/evidencia:

- `scripts/product_closure/st5_gate.py`;
- `scripts/product_closure/st5_benchmark.py`;
- `docs/product-closure/ST5-PERFORMANCE-LEDGER.json`;
- tests unit/differential ST5.

### ST5-O01 — Reference preserved

Todo cambio optimizado debe reproducir exactamente la referencia independiente.

Gate:

- >=1,000 build cases random + boundary;
- >=500 proof corpora;
- FULL inclusion == STREAMING inclusion byte por byte;
- FULL range == STREAMING range byte por byte;
- independent proof verifier acepta ambos.

Ejecución local exact-semantic:

    build cases: 1,000
    build divergences: 0
    build stream SHA-256:
    18f439cb297bab461841384a6d02220c61794414061d40b5dc2aacca5ee9ce18

    proof cases: 500
    proof divergences: 0
    proof stream SHA-256:
    f83f23c39aa28defb75dd88d7e34313d30ae4658bc931ba275881c3c38770b55

### ST5-O02 — No hidden large copies

#### Leaf hashing

Antes de ST5 cada rama construía un record leaf completo con raw payload.

Ahora se hashea:

    domain
    + header
    + TLV prefix
    + leaf-field header
    + raw memoryview

sin construir un segundo leaf-sized frame.

#### ProofIndex

Antes:

    source bytes
    + bytes slices por cada leaf

Ahora:

    source bytes
    + memoryviews
    + summaries

Audit 16 MiB:

    source                 = 16,777,216 B
    peak extra allocation  =    392,534 B
    ratio                  =      2.34%

No existe otra copia B-sized.

#### Range verification

Se eliminaron dos deudas sucesivas encontradas durante ST5:

1. `prefix + range_bytes + suffix` copiaba todo el rango;
2. un dict de target leaf nodes crecía con el número de hojas verificadas.

La implementación final recorre recursivamente la geometría canónica.

Near-full 16 MiB range:

    selected bytes         ~= 16.78 MiB
    verification peak      ~= 138 KiB

#### Streaming range generation

También se eliminó un target-node map O(range) en
`prove_range_streaming`.

Near-full 16 MiB range:

    auxiliary peak         ~= 23 KiB

más el proof output obligatorio.

### ST5-O03 — Streaming memory budget

TreeBuilder conserva únicamente:
- tail < chunk;
- frontier O(log N);
- transient framing pequeño.

Sweep local:

| input | peak auxiliary allocation |
|---:|---:|
| 64 KiB | 3.3 KiB |
| 256 KiB | 4.1 KiB |
| 1 MiB | 5.2 KiB |
| 4 MiB | 6.3 KiB |
| 16 MiB | 7.3 KiB |
| 32 MiB | 8.2 KiB |

Gate independiente de 32 MiB:

    conservative observed peak ~= 24 KiB
    hard gate budget           = 2 MiB

El crecimiento observado corresponde a frontier/counters, no a B.

Manifest regular-file reads:

    request_size <= 65,536 bytes

por llamada.

### ST5-O04 — Scale fallback

Resource policy:

    TreeScalePolicyV1(
      max_index_bytes,
      proof_fallback,
      delta_fallback
    )

Decision object:

    TreeIndexPlanV1

con:
- operation;
- FULL / STREAMING / REJECT;
- source bytes;
- leaf count;
- estimate;
- budget;
- reason.

#### Proof estimate

    65,536 + 4,096 * leaves

Audit 16 MiB:
- measured peak: 392,534 B;
- estimate: 1,114,112 B.

#### Delta estimate

    65,536 + B + 4,608 * leaves

Audit 8 MiB:
- measured peak: 8,564,890 B;
- estimate: 9,043,968 B.

Delta over-budget:

    TreeIndexBudgetExceeded

antes de construir TreeDeltaIndex.

No hay fallback oculto a full rebuild.

### FULL vs STREAMING trade-off

FULL paga index build una vez y después genera proofs en microsegundos.

STREAMING elimina el full index, pero vuelve a hashear O(B) por proof.

Ejemplo local ~16 MiB:

    ProofIndex build                 ~= 191 ms
    FULL inclusion generation       ~= 24 us
    STREAMING inclusion generation  ~= 197 ms
    FULL range generation           ~= 46 us
    STREAMING range generation      ~= 205 ms

Los proof wires son idénticos.

Esto es una trade-off resource/time explícita, no una regresión silenciosa.

### Build baseline vs optimized

Referencia full-frame vs implementación ST5:

| B | speedup | optimized peak | reference peak |
|---:|---:|---:|---:|
| 64 KiB | ~1.27x | 3.1 KiB | 193 KiB |
| 256 KiB | ~1.14x | 3.8 KiB | 259 KiB |
| 1 MiB | ~1.07x | 4.9 KiB | 265 KiB |
| 4 MiB | ~1.11x | 5.9 KiB | 290 KiB |

Throughput local observado:

    ~75-88 MiB/s

No se publica como cifra cross-host.

### CPU profile

Tras eliminar copies accidentales, el coste dominante es el esperado:

    hashlib primitive update calls

Sobre un perfil local de 1 MiB:
- hash update principal ~7.7 ms;
- BLAKE2b update ~1.25 ms;
- parent composition <1 ms.

Conclusión:

    remaining dominant work is intrinsic hashing, not Python frame copying.

### Resume / Delta / Append / Manifest cross-check

ST5 no redefine estas semánticas.

Representative local ledger:

Resume (~16 MiB prefix):
- restore median ~5 us;
- prefix bytes no se rehashean.

Delta one-byte sobre ~16 MiB:
- rehashed payload 65,536 B;
- recomputed nodes 10;
- ~1.96 ms local.

Append one chunk + 17 B:
- rehashed payload 65,572 B;
- recomputed nodes 4;
- prior frontier reused;
- ~1.21 ms local.

Manifest 64 x 64 KiB:
- input 4 MiB;
- hashing fixture ~52 ms;
- peak auxiliary ~0.20 MiB;
- read request <= one Tree chunk.

Los sweeps más amplios de delta/append permanecen congelados en ST4.

### Persistent index decision

ST5 cierra el layout lógico y resource policy, pero no crea un sidecar wire.

No es necesario para O01-O04 y añadirlo aquí crearía:
- nuevo compatibility lifecycle;
- atomic persistence contract;
- mmap/storage policy;
- nuevo parser surface.

Puede añadirse en SA3/futura etapa de storage sin modificar Tree identity.

### Performance ledger

Autoridad local congelada:

    docs/product-closure/ST5-PERFORMANCE-LEDGER.json

Estado epistemológico:

    EMPIRICAL-PERFORMANCE

para timings.

PROVED-STRUCTURAL / TESTED-CONFORMANCE para:
- byte preservation;
- zero-copy source views;
- fallback determinista;
- bounded auxiliary-state architecture.

### Exit ST5

ST5 se marca COMPLETE sólo si:

1. ST5-O01..O04 pasan revisión adversaria;
2. 1,000 build differentials sin divergencia;
3. 500 FULL/STREAMING proof differentials sin divergencia;
4. ProofIndex no duplica B;
5. range generation/verification no conserva O(range) target structures;
6. streaming Tree memory permanece bounded;
7. proof over-budget selecciona STREAMING o REJECT según policy;
8. delta over-budget rechaza antes de index construction;
9. conservative estimators cubren los audit fixtures;
10. ST0-ST4 vector/wire semantics no cambian;
11. ledger baseline/optimized queda congelado y revisado.

## 9. SV0 — Trajectory Audit

### Objetivo

Exponer la trayectoria Sigma v3 ya calculada como evidencia canónica inspeccionable,
sin alterar evaluación, digest, suites, domains ni corpora históricos.

SV0 es estrictamente observacional:

    evaluate_v3
      -> EvaluationV3
      -> TrajectoryAuditV3

Nunca:

    Audit
      -> modifica evaluate_v3

### Implementación

Product:

- `sigma/trajectory/audit_v3.py`
  - TrajectoryAuditModeV3;
  - TrajectoryRoundAuditV3;
  - TrajectoryAuditV3;
  - audit_from_evaluation_v3;
  - evaluate_audit_v3;
  - project_digest_v3;
  - verify_trajectory_audit_structure_v3;
  - verify_trajectory_audit_full_v3.
- `sigma/trajectory/__init__.py`;
- exports aditivos en `sigma/v3.py`.

Independent:

- `reference/trajectory_audit_v3.py`
  - stdlib-only canonical encoder;
  - consume `reference.independent_v3.evaluate_suite()`;
  - no importa `sigma`.

Tests:

- `tests/unit/test_trajectory_audit_sv0.py`;
- `tests/differential/test_trajectory_audit_reference_sv0.py`;
- `tests/vectors/test_trajectory_audit_sv0_vectors.py`.

Gate:

- `scripts/product_closure/sv0_gate.py`.

### Wire freeze

Top-level magic:

    SIG3AUD0

Round-record magic:

    SIG3AUR0

Se reutiliza el codec record v3 existente.

No se añaden:
- SuiteIdV3;
- DomainIdV3;
- algorithm ID;
- primitive criptográfica.

### Modos

COMPACT:
- exact SigmaDigestV3;
- exact PersistentBinding;
- init layout;
- todos los states;
- todos los histories si HISTORY_FEEDBACK;
- todos los round layouts;
- FULL-only frame/branch fields vacíos.

FULL:
- todo COMPACT;
- exact RoundBindingV3 en history suites;
- exact round/vector frame wire;
- exact Deep branch frame wires;
- exact branch outputs;
- exact scalar fold frame cuando profile=DEEP.

FULL conserva más material de replay, no más bits de seguridad.

### SV0-O01 — Digest projection

Para todo EvaluationV3 E:

    project_digest_v3(audit_from_evaluation_v3(E))
      = digest_from_evaluation_v3(E)

byte por byte.

El Audit contiene el SigmaDigestV3 exacto, no una reinterpretación.

### SV0-O02 — Replay

Dos niveles separados:

Structural replay:

    verify_trajectory_audit_structure_v3(audit)

reconstruye la dinámica únicamente desde audit/context/binding.

Full source replay:

    verify_trajectory_audit_full_v3(source,audit)

reejecuta Sigma v3 desde source y exige igualdad del Audit canónico completo.

Structural PASS no se presenta como message-binding.

### SV0-O03 — Round cardinality

Registered suites actuales satisfacen:

    len(states) = t + k
    len(rounds) = t + k - 1

Round indices:

    0..t+k-2

sin gaps/reorder.

La public TrajectoryWindow debe coincidir exactamente con:

    states[t:t+k].

### SV0-O04 — Historical causality

Para HISTORY_FEEDBACK:

    H_0 = history_seed_v3(context,binding)

y:

    H_(i+1)
      = history_step_v3(
          context,
          binding,
          H_i,
          i,
          S_i
        )

El gate muta histories y exige rechazo.

### SV0-O05 — Layout/frame linkage

Cada audit conserva el layout wire exacto.

Replay vuelve a derivar:
- LayoutPlan o HistoryLayoutPlan;
- RoundBindingV3 cuando aplica;
- RoundFrame/VectorRoundFrame o history variants;
- DeepBranchFrame/history variants;
- DeepFoldFrame/history variant.

FULL exige igualdad byte por byte de esos wires.

No se inventa un "frame hash" alternativo.

### SV0-O06 — Deep fidelity

Deep scalar:

    S_(i+1) = Hash(FoldFrame(branch_outputs))

y FULL contiene fold frame.

DeepVector:

    S_(i+1) = concat(branch_outputs)

y FULL exige ausencia de fold frame.

El gate comprueba explícitamente ambas leyes para suites R12 y R12.5.

### SV0-O07 — COMPACT/FULL consistency

Para la misma EvaluationV3:

    COMPACT.digest == FULL.digest
    COMPACT.states == FULL.states
    COMPACT.histories == FULL.histories
    COMPACT.layouts == FULL.layouts

FULL sólo añade material redundante/reconstruible.

### SV0-O08 — No security inflation

Documentación/API no atribuyen al Audit:
- suma de bits;
- nueva collision/preimage resistance;
- timestamp;
- provenance;
- historical-execution truth.

Audit es evidence/inspection surface sobre Sigma v3 existente.

### Frozen R12.5 replay

El gate usa directamente:

    specification/test-vectors/conformance-v3-r12-5.json.gz.b64

No crea un segundo corpus criptográfico.

Para las tres history suites exige:
- digest_hex exacto;
- histories exactos;
- COMPACT product == independent audit encoding;
- FULL product == independent audit encoding;
- structural replay PASS;
- full source replay PASS.

### Cross-suite differential gate

Threshold bloqueante:

    >= 600 cases

repartidos entre las seis suites ejecutables:

    0x0301
    0x0303
    0x0304
    0x0321
    0x0323
    0x0324

Cada caso compara:
- product evaluation vs independent_v3;
- COMPACT product vs independent audit encoder;
- FULL product vs independent audit encoder;
- digest projection;
- codec round-trip;
- structural replay.

### Source-binding campaign

Threshold:

    >= 60 full-source replays

incluyendo wrong-source rejection.

### Mutation/adversarial campaign

Threshold:

    >= 2,000 directed mutations

Superficies:
- S_i bit mutation;
- H_i bit mutation en history suites;
- layout wire mutation;
- state-frame mutation;
- branch-output mutation en Deep/DeepVector.

Además:
- delete round;
- wrong round cardinality;
- non-contiguous round index;
- COMPACT carrying FULL evidence;
- wrong branch count;
- wrong fold-frame presence.

Todo debe rechazar en construcción o replay.

### Complexity contract

Sea:

    R = t+k-1
    s = state_size
    m = joint branch count.

Audit construction from an existing evaluation:

COMPACT:

    O(output_size)

sin source I/O ni nuevo hashing de trayectoria.

FULL:

    O(full_audit_size)

para materializar frames ya derivables; branch outputs existentes se reutilizan.

Structural replay:

    O(R * round_cost)

sin source I/O.

Full source replay:

    O(cost(evaluate_v3(source)) + audit_size).

### Gate SV0

`sv0_gate.py` sólo puede reportar `closure_eligible=true` si:

1. frozen R12.5 corpus replay PASS;
2. >=600 independent cross-suite cases PASS;
3. >=2,000 directed mutations reject;
4. >=60 source-binding replays PASS;
5. COMPACT/FULL projection equality PASS;
6. history causality PASS;
7. Deep/DeepVector distinction PASS;
8. audit codec round-trip PASS;
9. `security_width_claim=false`.

### Criterio de cierre

CANDIDATE:
- implementación completa;
- referencia independiente completa;
- tests/gate presentes;
- revisión estática/adversarial sin blocker conceptual.

COMPLETE:
- gate SV0 ejecutado desde checkout real o mirror exacto;
- report de gate congelado;
- revisión post-ejecución O01..O08 PASS;
- diff confirma que Sigma v3 core/corpora no cambiaron.

## 10. SV1 — Trajectory Checkpoint

### Objetivo

Reanudar la trayectoria iterada después de haber fijado C, P_X y (t,k), sin
volver a ejecutar source preparation/anchor.

SV1 es distinto de `IncrementalSigmaV3/SigmaCheckpointV3`, que checkpointa
prefijos de source y produce digests provisionales.

### Implementación

- `sigma/trajectory/checkpoint_v3.py`
  - TrajectoryCheckpointV1;
  - TrajectoryContinuationV1;
  - checkpoint_from_evaluation_v3;
  - advance_trajectory_checkpoint_v3;
  - continue_trajectory_checkpoint_v3;
  - finalize_trajectory_checkpoint_v3;
  - verify_trajectory_checkpoint_source_v3.
- `reference/trajectory_checkpoint_v3.py`
  - encoder stdlib independiente.
- `scripts/product_closure/sv1_gate.py`.
- tests unit/differential SV1.

### Estado mínimo all-index

Para estado index i:

    Q_i =
      context,
      PersistentBinding,
      TrajectoryParameters,
      i,
      S_i,
      H_i?,
      window_prefix.

Con:

    window_prefix = ()
      si i <= t

y:

    window_prefix = (S_t,...,S_(i-1))
      si i > t.

Este campo corrige la planificación mínima original: sin él un checkpoint dentro
de la ventana pública no puede reconstruir exactamente el digest final.

### Obligaciones

SV1-O01 — Continuation equivalence

Para todo índice válido:

    continue(Q_i).states
      = states[i:].

History suites:

    continue(Q_i).histories
      = histories[i:].

SV1-O02 — Final digest identity

    finalize(Q_i)
      = digest_from_evaluation_v3(E)

para todo i.

SV1-O03 — Binding immutability

Constructor/parser exige:

    derive_parameters(context,binding)
      = checkpoint.parameters.

No puede cambiar:
- C;
- P_X;
- t/k;
- suite/profile;
- state width.

SV1-O04 — Round index exactness

    0 <= i <= t+k-1.

`advance(...,rounds=n)`:
- rechaza n<0;
- rechaza i+n>final;
- no rewind;
- no wrap;
- no silent skip.

SV1-O05 — Source rebind distinction

Internal continuation:

    continue(Q_i)

no necesita source.

Source binding:

    verify_trajectory_checkpoint_source_v3(X,Q_i)

reevalúa v3 y compara el checkpoint canónico en el mismo i.

SV1-O06 — Codec canonicality

Magic:

    SIG3TCK0

Strict record v3 con:
- context;
- binding;
- parameters;
- i;
- state;
- optional history;
- window prefix.

Missing/duplicate/reordered/unknown fields se rechazan.

### Differential tests

`tests/differential/test_trajectory_checkpoint_reference_sv1.py`:

- las seis suites ejecutables;
- múltiples inputs por suite;
- **todos los índices i válidos**;
- product checkpoint wire == independent encoder;
- continuation suffix exacto;
- final digest exacto;
- history suffix exacto.

### Adversarial/unit

- parameter mutation;
- cross-suite context;
- wrong history index;
- wrong window-prefix length;
- advance before zero/after final;
- final-index checkpoint;
- correct/wrong source rebind;
- TLV missing/duplicate/reorder/unknown.

### Gate SV1

`sv1_gate.py` exige al menos:

    60 evaluations
    all valid indices per evaluation
    >=500 directed checkpoint mutations
    >=30 source-rebind checks

y produce stream hashes de:
- checkpoint wires;
- continuation final digests.

No fija todavía performance thresholds.

### Complexity contract

Desde Q_i:

    T_continue
      = O((t+k-1-i) * round_cost)

sin source I/O ni anchor/preparation.

Checkpoint size:

    O(context + binding + state + history + k*state_size)

por el window_prefix, acotado por k<=64.

### Cierre

CANDIDATE:
- implementation/reference/tests/gate completos;
- review de invariantes sin blocker.

COMPLETE:
- SV0 COMPLETE;
- sv1_gate ejecutado y report congelado;
- all-index differential PASS;
- revisión post-ejecución O01..O06 PASS.

Los benchmarks/empíricos finos se difieren por decisión de campaña.

## 11. SV2 — Verification Policy

### Objetivo

Convertir parseabilidad/verificabilidad/aceptabilidad en contratos separados y
dar una decisión semántica exhaustiva sin trabajo caro innecesario.

### Implementación

- `sigma/trajectory/policy_v1.py`
  - VerificationPolicyV1;
  - VerificationCapabilitiesV1;
  - ParsedVerificationEvidenceV1;
  - VerificationDecisionV1;
  - four-way decision enums/codes;
  - parse_verification_evidence_v1;
  - verify_with_policy_v1;
  - policy_is_stricter_or_equal_v1.
- `scripts/product_closure/sv2_gate.py`.
- unit/property/vector tests.
- frozen policy-ID KAT:
  `specification/test-vectors/sigma-verification-policy-v1.json`.

### Wire

Magic:

    SIGPOLY1

Policy format version:

    1

Strict TLV independiente del wire v2/v3.

### Obligaciones

SV2-O01 — Parse vs accept separation

Known evidence puede parsear correctamente y después:

    Rejected(policy reason).

Parser soporta:
- SigmaDigestV3;
- TrajectoryAuditV3;
- SigmaDigestV2 v2.2.

SV2-O02 — Explicit four-way decision

Exhaustivo:

    Accepted
    Rejected
    Inconclusive
    Unsupported.

Decision conserva kind/code/reason/policy_id/evidence_id y flags de verification
cuando existen.

SV2-O03 — Cheap checks first

Orden bloqueado:

    parse
      -> capabilities
      -> suite/history
      -> committed input size
      -> round bound
      -> audit requirement
      -> structural replay
      -> source reevaluation.

Bomb tests/sources garantizan que oversized/disallowed objects no llegan al
verifier caro.

SV2-O04 — Determinism

Mismo:
- evidence;
- canonical policy;
- capabilities;
- source/verifier;

produce la misma VerificationDecisionV1.

Gate y property suite generan policies de forma determinista.

SV2-O05 — Normalized policy identity

    policy_id = SHA256(canonical SIGPOLY1 wire).

Es content ID, no security-width claim.

Frozen KAT IDs:

    default
    strict-history-audit
    weak-all-v3
    legacy-opt-in.

Codec rechaza:
- missing;
- duplicate;
- reordered;
- unknown fields.

SV2-O06 — Monotonic subset

Para subset normalizado:

    policy_is_stricter_or_equal_v1(strict,weak).

Se exige:

    Accept(strict,x)
      => Accept(weak,x).

El property corpus cubre generated strict/weak history-suite pairs.

SV2-O07 — Legacy control

Default:

    allow_legacy_v22 = false.

Legacy válido:
- default -> Rejected(LegacyDisabled);
- explicit opt-in + valid bytes source -> Accepted.

No puede satisfacer history/audit requirements.

### Artifact-facing requirements

Aunque SA todavía no existe, policy wire ya fija:
- Tree required;
- DUAL required;
- signature required;
- provenance required;
- Tree-proof size;
- artifact metadata profiles;
- symlink mode;
- working-memory estimate.

`VerificationCapabilitiesV1` aporta esos hechos sin cambiar PolicyId.

Falta de requirement conocida:

    Rejected.

Falta de estimación necesaria para un bound activo:

    Inconclusive.

### Gate SV2

`sv2_gate.py` exige:

    >=400 decision cases
    >=100 normalized monotonic cases
    >=100 cheap-reject bomb-source cases

además de:
- four-way coverage exacta;
- codec/PolicyId round-trip;
- determinism;
- default legacy reject;
- explicit legacy accept;
- future unknown evidence -> Unsupported;
- DUAL capability requirements.

No fija timings/throughput.

### Complexity contract

Policy parsing/preflight:

    O(policy wire + evidence header/codec).

Cheap rejection no ejecuta source replay.

Cuando policy exige message binding:

    cost = cost(selected verifier).

Los benchmarks de policy throughput, memoria y decisiones por segundo se difieren
a la futura campaña empírica.

### Cierre

CANDIDATE:
- canonical wire/KAT;
- implementation/tests/gate;
- semantic/adversarial review.

COMPLETE:
- SV0 COMPLETE;
- sv2_gate ejecutado y report congelado;
- policy adversarial/property suite PASS;
- revisión post-ejecución O01..O07 PASS.

## 12. SV3 — Receipts and Batch

### Receipt obligations

SV3-O01 — Receipt binds artifact identity, policy identity, verifier identity and result.
SV3-O02 — Receipt signature, if present, covers full canonical record.
SV3-O03 — Receipt does not imply semantic truth of opaque provenance.
SV3-O04 — Unsigned receipt is marked unsigned.

### Batch obligations

SV3-O05 — Pointwise equivalence

    batch[i] = verify(item_i)

SV3-O06 — Isolation  
Failure/crash de un item no altera evidencias de otros.

SV3-O07 — Deterministic result ordering  
Output sigue input ordering o canonical key ordering declarado.

## 13. SA0 — Canonical Artifact

### Objetivo

Crear objeto único de producto que pueda consumir Tree, Trajectory o ambos.

### Obligaciones

SA0-O01 — Exactly declared evidence  
TREE exige TreeRoot; TRAJECTORY exige SigmaDigestV3; DUAL exige ambos.

SA0-O02 — ArtifactId non-circularity  
ArtifactId se calcula sin signature externa.

SA0-O03 — Canonical descriptor  
Descriptor tiene wire único.

SA0-O04 — Parent binding  
Cambiar parent artifact cambia ArtifactId.

SA0-O05 — Manifest binding  
Si manifest está presente, queda incluido en identity.

### Tests

Round-trip, mutation, missing evidence, extra evidence, wrong profile, parent reorder.

## 14. SA1 — Dual Verification

### Ley principal

SA1-O01

    VerifyDual(X,A)
      = VerifyTree(X,A.tree)
        AND VerifyTrajectory(X,A.trajectory)

### Otras obligaciones

SA1-O02 — Failure attribution  
Resultado explica qué lado falló.

SA1-O03 — Independent claims  
No se colapsan los dos informes a una sola fuerza criptográfica.

SA1-O04 — Policy integration  
VerificationPolicy puede requerir TREE/TRAJECTORY/DUAL.

SA1-O05 — Selective manifest verification  
Manifest puede contener Tree-only entries y trajectory-critical entries según policy explícita.

## 15. SA2 — Provenance and Signature

### Obligaciones

SA2-O01 — Claim type registry cerrado.
SA2-O02 — Opaque claims verifican bytes, no verdad.
SA2-O03 — Signature usa primitive estándar ya soportada.
SA2-O04 — Signature domain separada de signed commitment histórico.
SA2-O05 — Adapters externos no modifican ArtifactId.
SA2-O06 — Unknown claim type se rechaza o preserva sólo en profile future-safe explícito, nunca silenciosamente.

## 16. SA3 — Product/API/CLI closure

### Workflows obligatorios

1. Commit file as tree.
2. Commit file as trajectory.
3. Commit file as dual.
4. Commit directory manifest.
5. Verify whole artifact.
6. Prove leaf.
7. Prove byte range.
8. Resume tree build.
9. Resume trajectory.
10. Delta same-length update.
11. Append.
12. Verify with policy.
13. Produce receipt.
14. Batch verify.
15. Inspect artifact/audit.

### UX invariants

- errores estructurados;
- no traceback crudo en CLI normal;
- JSON machine-readable opcional;
- exit codes documentados;
- progress no forma parte de semántica;
- no nombres como secure/paranoid usados como grados de seguridad sin definición.

## 17. REL0 — Compatibility gate

Ejecutar antes de release:

- v2.2 frozen corpus;
- v3 R12 corpus;
- v3 R12.5 corpus;
- new Tree corpus;
- new Artifact corpus.

No release si cualquier baseline previo cambia.

## 18. REL1 — Independent consumer

Crear reference/independent_dual_integrity.py o scripts separados:

- TreeRoot;
- InclusionProof;
- RangeProof;
- Manifest;
- Artifact decode/identity.

No importa sigma.

Objetivo: reproducir todos los wires mínimos de conformance.

## 19. REL2 — Packaging

Obligaciones:

- clean wheel;
- isolated install;
- no implicit optional dependencies;
- SBOM actualizado;
- exact package data;
- CLI smoke outside checkout;
- Python API smoke;
- docs examples executed.

## 20. REL3 — Adversarial release review

Revisión manual obligation-by-obligation.

Preguntas obligatorias:

1. ¿Alguna feature modifica el core v3?
2. ¿Alguna claim de Tree se ha presentado como claim v3?
3. ¿Alguna dual evidence suma seguridad nominal?
4. ¿Algún parser hace trabajo caro antes de policy?
5. ¿Delta soporta silenciosamente un caso no probado?
6. ¿Resume serializa estado opaco de hashlib?
7. ¿Manifest depende accidentalmente del host?
8. ¿Audit puede mentir sobre rounds omitidas?
9. ¿Checkpoint puede saltar rounds?
10. ¿Receipt se presenta como verdad de provenance?
11. ¿Legacy v2.2 puede confundirse con V1?
12. ¿Las complejidades publicadas coinciden con código/benchmarks?

REL3 sólo cierra con matriz de respuestas y remediación.

## 21. Estructura general de pruebas

Cada obligación se asocia al menos a una de estas clases:

T0 — type/invariant tests
T1 — unit examples
T2 — property/metamorphic
T3 — differential/reference
T4 — adversarial negative
T5 — fuzz/mutation
T6 — complexity/performance
T7 — independent implementation
T8 — clean package consumer

Una obligación no se marca COMPLETE sólo por tener tests. El cierre exige revisar que la evidencia corresponde exactamente a la afirmación.

## 22. Convención de estados

PLANNED
No implementado.

ACTIVE
Implementación abierta.

IMPLEMENTED
Código presente, obligaciones no auditadas.

CANDIDATE
Todas las evidencias requeridas presentes.

COMPLETE
Revisión adversarial posterior aprueba todas las obligaciones.

REOPENED
Un contraejemplo, cambio de dependencia o claim obliga a reabrir.

## 23. Criterio de salida comercial

La campaña está lista para una primera presentación pública cuando:

- ST0-ST4 COMPLETE;
- SV0-SV2 COMPLETE;
- SA0-SA1 COMPLETE;
- REL0-REL3 COMPLETE;
- R15 científico se mantiene separado;
- README de producto no afirma production security;
- demo de los tres modos TREE/TRAJECTORY/DUAL funciona desde wheel limpio;
- benchmarks principales son reproducibles;
- la GUI puede consumir JSON estructurado sin importar módulos internos.

SV3, SA2 y ST5 pueden cerrarse antes del lanzamiento si no amenazan el calendario; si no, pasan a la primera actualización estable de producto.

## 24. Doctrina de implementación

1. Extensión mínima.
2. Una autoridad.
3. Ley antes de optimización.
4. Referencia antes de camino rápido.
5. No nueva primitive si composición basta.
6. Fallar explícitamente mejor que fingir soporte.
7. Medir accidental vs intrínseco.
8. Cerrar cada bloque antes de abrir el siguiente dependiente.
9. No mezclar evidencia científica R15 con evidencia de ingeniería de producto.
10. Cada feature debe mejorar una demo o workflow real, no sólo ampliar una lista de capacidades.
