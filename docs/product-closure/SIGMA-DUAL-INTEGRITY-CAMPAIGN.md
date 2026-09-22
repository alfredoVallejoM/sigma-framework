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

### ST4A — Same-length replacement

Obligaciones:

ST4-O01 — Delta equivalence

    update(tree(X), Δ) = tree(apply(X,Δ))

ST4-O02 — Affected-leaf completeness  
Toda leaf que intersecta Δ se recomputa.

ST4-O03 — Unaffected subtree preservation  
Subárbol disjunto conserva root.

ST4-O04 — Ancestor closure completeness  
Todos y sólo los ancestros requeridos se invalidan.

ST4-O05 — Overlap normalization  
Ranges superpuestos tienen forma canónica antes de ejecutar.

ST4-O06 — Transactionality  
No se publica root parcial.

ST4-O07 — Rebuild boundary  
Edits que desplazan chunk boundaries devuelven RebuildRequired.

### ST4B — Append

ST4-O08 — Append equivalence

    append(tree(X),Y) = tree(X || Y)

ST4-O09 — Frontier reuse  
El trabajo previo válido no se rehace salvo lo exigido por tail/frontier.

### Tests

- one-byte replacement;
- changes on chunk edges;
- multiple disjoint ranges;
- overlapping ranges;
- full-file replacement;
- append 0/1/chunk/multiple chunks;
- random differential vs full rebuild.

### Performance gate

Medir:
- N;
- k affected leaves;
- B_delta;
- ancestor count;
- bytes read;
- bytes hashed;
- wall time;
- peak RSS;
- allocations.

Sweeps:
- 1 leaf;
- 0.1%;
- 1%;
- 10%;
- 100%.

ST4 no se cierra si la implementación denominada incremental hace trabajo aproximadamente O(B) en los casos locales soportados sin justificarlo.

## 8. ST5 — Tree performance and scale closure

### Objetivo

Cerrar deuda accidental de Tree sin modificar semántica.

### Campaign

- profile CPU;
- allocations;
- memory;
- index layout;
- proof generation;
- range verification;
- resume;
- delta;
- manifest.

### Invariantes

ST5-O01 — Reference preserved  
Optimización no altera bytes.

ST5-O02 — No hidden copies  
Objetos grandes no se copian sin ledger explícito.

ST5-O03 — Streaming memory budget  
Build y verify pueden ejecutarse con memoria acotada respecto a B salvo index explícito.

ST5-O04 — Scale fallback  
Si index completo excede policy, operar sin él o rechazar explícitamente.

### Exit

Publicar baseline + optimized ledger y razones para cualquier regresión aceptada.

## 9. SV0 — Trajectory Audit

### Objetivo

Exponer la dinámica actual Z_i=(H_i,S_i) como evidencia inspeccionable sin modificar Sigma v3.

### Obligaciones

SV0-O01 — Digest projection

    project_digest(audit(X)) = sigma_v3(X)

SV0-O02 — Replay

    verify_audit(X,audit(X)) = Verified

SV0-O03 — Round cardinality  
Audit tiene exactamente los estados/rondas requeridos por t,k y suite.

SV0-O04 — Historical causality  
H_{i+1} debe coincidir con HistoryStep(H_i,S_i).

SV0-O05 — Layout linkage  
Cada round audit referencia el plan/frame exacto consumido.

SV0-O06 — Deep fidelity  
Deep/DeepVector audit conserva la distinción entre fold escalar y vector completo.

SV0-O07 — Compact/full consistency  
COMPACT y FULL proyectan al mismo digest.

SV0-O08 — No security inflation  
Audit no se presenta como bits de seguridad adicionales.

### Tests

- product implementation vs independent_v3;
- mutate H_i;
- mutate S_i;
- mutate round index;
- mutate plan hash;
- delete round;
- reorder rounds;
- cross-suite audit.

### Gate

Todo corpus R12.5 v3 debe poder renderizarse como Audit y revalidarse.

## 10. SV1 — Trajectory Checkpoint

### Obligaciones

SV1-O01 — Continuation equivalence

    continue(checkpoint(Eval(X),i)) = suffix(Eval(X),i)

SV1-O02 — Final digest identity  
Continuación produce mismo SigmaDigestV3.

SV1-O03 — Binding immutability  
No puede cambiar C, P_X, t,k ni suite.

SV1-O04 — Round index exactness  
No rewind/skip silencioso.

SV1-O05 — Source rebind distinction  
Checkpoint interno y verificación contra X son APIs distintas.

SV1-O06 — Codec canonicality  
Checkpoint wire injectivo y versionado.

### Tests

Todos los i válidos sobre corpus de conformidad + random inputs.

## 11. SV2 — Verification Policy

### Obligaciones

SV2-O01 — Parse vs accept separation  
Parse válido no implica policy accept.

SV2-O02 — Explicit four-way decision  
Accepted / Rejected / Inconclusive / Unsupported.

SV2-O03 — Cheap checks first  
Policy bounds se aplican antes de trabajo caro.

SV2-O04 — Determinism  
Mismo objeto/policy/verifier produce misma decision semántica.

SV2-O05 — Normalized policy identity  
Policies canónicas tienen hash/ID estable.

SV2-O06 — Monotonic subset  
Para subset de policies donde P_strict <= P_weak está definido:

    Accept(P_strict,x) => Accept(P_weak,x)

SV2-O07 — Legacy control  
v2.2 aceptación exige opt-in explícito.

### Tests

- policy mutation;
- wrong suite;
- oversized input;
- disallowed symlink;
- require dual evidence;
- require signature;
- unsupported future profile.

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
