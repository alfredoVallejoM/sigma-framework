# Sigma Dual Integrity — Especificación funcional y técnica

Estado: PLANIFICACIÓN NORMATIVA DE PRODUCTO  
Ramal: campaign/sigma-dual-integrity-product-closure  
Base de trabajo: r15-exploratory-engineering-apps  
Fecha: 2026-09-22

## 0. Propósito

Esta especificación define una capa de producto construida encima del Sigma actual sin modificar la función criptográfica Sigma v3/IAP ni reabrir los cierres científicos R12.5/R13.

La arquitectura reconoce dos objetos distintos y complementarios:

1. Sigma Tree: integridad estructural local, pruebas parciales, reanudación y actualización incremental.
2. Sigma Trajectory: integridad histórica global sobre la dinámica vigente Z_i = (H_i, S_i).

Ambas capas pueden combinarse en Sigma Artifact, que representa un artefacto verificable mediante una o las dos evidencias.

El principio rector es:

    estructura local + trayectoria global, sin confundir sus claims.

Sigma v2.2 permanece congelado como baseline histórico y oráculo de regresión. La estructura combinatoria útil de TreeWide se extrae como inspiración y compatibilidad, pero las nuevas APIs y wires pertenecen a Sigma Tree V1 y no reinterpretan ningún digest v2.2.

## 1. Invariantes no negociables

DI-INV-001 — Inmutabilidad del core v3
Ninguna extensión de producto cambia SigmaContextV3, PersistentBinding, derivación t/k, HistoryCommitmentV3, layout, framing, round dynamics, SigmaDigestV3, IDs, domains ni corpus de conformidad v3.

DI-INV-002 — Inmutabilidad v2.2
No se modifica ningún vector, suite ID, wire ni semántica v2.2. La compatibilidad histórica es sólo lectura/verificación.

DI-INV-003 — Claims separados
Una evidencia de árbol no se presenta como evidencia de trayectoria. Una evidencia de trayectoria no se presenta como prueba de inclusión o localización.

DI-INV-004 — No suma de bits
Un artefacto dual no suma nominalmente la anchura de TreeRoot y SigmaDigestV3 como nueva fuerza de seguridad. La composición dual significa conjunción de verificaciones, no fuerza criptográfica aditiva.

DI-INV-005 — Autoridad única por estructura
La geometría del árbol tiene una única implementación de referencia interna. Proof, range, resume, delta y manifest consumen la misma autoridad TreeCore.

DI-INV-006 — Fallback explícito
Cuando una operación incremental no pertenece al dominio soportado se devuelve RebuildRequired, Unsupported o Inconclusive. Nunca se degrada silenciosamente.

DI-INV-007 — Parser barato antes de trabajo caro
Magic, versión, tamaños, IDs, cardinalidades y políticas se validan antes de hashing, I/O masivo, multiprocessing o asignaciones grandes.

DI-INV-008 — Evidencia reconstruible
Toda respuesta positiva importante debe poder acompañarse de un objeto de evidencia verificable. No se usa un booleano desnudo cuando la evidencia forma parte natural del contrato.

DI-INV-009 — No nueva criptografía innecesaria
Las extensiones usan primitivas estándar ya registradas y/o la función Sigma v3 existente. No se introduce un hash, MAC, firma, KDF, VDF o PoSW propio.

DI-INV-010 — Complejidad auditable
Toda nueva operación declara parámetros de tamaño, fórmula de coste esperada, memoria pico esperada y benchmark diferencial contra referencia.

## 2. Arquitectura de producto

    sigma/
    ├── tree/
    │   ├── ids.py
    │   ├── codec.py
    │   ├── core.py
    │   ├── frontier.py
    │   ├── index.py
    │   ├── proof.py
    │   ├── range.py
    │   ├── resume.py
    │   ├── delta.py
    │   ├── manifest.py
    │   └── legacy_v22.py
    │
    ├── trajectory/
    │   ├── audit_v3.py
    │   ├── checkpoint.py
    │   ├── policy.py
    │   ├── receipt.py
    │   └── batch.py
    │
    ├── artifact/
    │   ├── ids.py
    │   ├── codec.py
    │   ├── record.py
    │   ├── verify.py
    │   ├── provenance.py
    │   └── signature.py
    │
    └── product/
        ├── api.py
        └── cli.py

No es obligatorio mover el core v3 existente. La capa trajectory consume las autoridades actuales bajo sigma.binding, sigma.layout, sigma.rounds, sigma.outputs y sigma.v3.

## 3. Namespaces y versionado

Se crean tres dimensiones nuevas, independientes de las suites criptográficas:

- TreeFormatVersion
- ArtifactFormatVersion
- VerificationPolicyVersion

Nunca se derivan de PackageVersion ni de Sigma suite IDs.

Objetos iniciales:

- SIGTREE1 — TreeRoot / TreeProfile
- SIGTPRF1 — InclusionProof
- SIGTRNG1 — RangeProof
- SIGTRSM1 — TreeResumeCheckpoint
- SIGTDLT1 — TreeDelta
- SIGTMAN1 — Manifest
- SIG3AUD0 — TrajectoryAuditV3
- SIG3TCK0 — TrajectoryCheckpoint V1 (reservado; SV1)
- SIGPOLY1 — VerificationPolicy
- SIGRCPT1 — VerificationReceipt
- SIGARTF1 — SigmaArtifact

Todos siguen:

    magic[8] || version:u16 || body_length:u32 || strict TLV body

Los tags son únicos, crecientes, completos y cerrados.

## 4. Familia A — Sigma Tree V1

### 4.1. Objetivo

Proporcionar una estructura canónica de compromiso por bloques que permita:

- raíz reproducible;
- pruebas de inclusión;
- pruebas de rango;
- reanudación portable;
- actualizaciones locales de igual longitud;
- append eficiente;
- manifiestos de directorio;
- compatibilidad histórica de lectura con TreeWide v2.2.

Sigma Tree V1 no es una suite v3 y no utiliza la dinámica Z_i.

### 4.2. TreeProfileV1

El perfil inicial queda deliberadamente estrecho:

- chunk size: 65,536 bytes;
- leaf ordering: orden por offset creciente;
- empty object: raíz vacía explícita;
- no odd-node duplication;
- combinación de perfect subtrees de igual tamaño;
- finalización mediante plegado canónico de frontier;
- cuatro primitivas estándar ya usadas históricamente:
  SHA-512, SHA3-512, BLAKE2b-512, SHAKE256-512;
- cada branch produce 64 bytes;
- la raíz es un vector ordenado de cuatro componentes;
- domain separation propia de Sigma Tree V1.

La semántica combinatoria coincide con la forma histórica de TreeWide, pero los bytes de Sigma Tree V1 usan sus propios domains y records.

### 4.3. TreeNode

TreeNode representa:

    start_leaf
    leaf_count
    byte_length
    height
    digests[4]

Restricciones:

- leaf_count > 0 salvo EmptyRoot;
- start_leaf >= 0;
- byte_length >= 0;
- len(digests) = 4;
- cada digest tiene 64 bytes;
- un nodo perfecto cumple leaf_count = 2^height.

No se almacena información que pueda derivarse de forma ambigua.

### 4.4. Leaf

Para chunk i:

    LeafFrame_j =
      domain ||
      profile ||
      algorithm_id_j ||
      leaf_index ||
      byte_offset ||
      byte_length ||
      bytes

Cada rama j:

    L_i,j = H_j(LeafFrame_j)

La inclusión de índice, offset y longitud evita interpretar el mismo bloque como otra posición sin cambiar el input hasheado.

### 4.5. Internal node

Para left, right adyacentes:

    NodeFrame =
      domain ||
      profile ||
      start_leaf ||
      leaf_count ||
      byte_length ||
      height ||
      left_digest ||
      right_digest

Se calcula de forma independiente por rama.

Precondiciones:

- left y right son adyacentes;
- right.start_leaf = left.start_leaf + left.leaf_count;
- el subárbol izquierdo es byte-full;
- para n = left.leaf_count + right.leaf_count, left.leaf_count es la mayor potencia de dos estrictamente menor que n;
- sólo el carry interno de frontier exige además hijos perfectos de igual altura.

Esta regla hace coincidir la composición incremental con la partición recursiva
canónica y excluye árboles alternativos con los mismos intervalos.

### 4.6. TreeFrontier

Después de n hojas completas:

    n = Σ b_h 2^h

La frontier contiene como máximo un perfect subtree por altura h con b_h = 1.

Invariante:

    frontier heights son estrictamente decrecientes y únicas
    en orden izquierda -> derecha.

La frontier es la autoridad para resume y append.

### 4.7. Finalización

La raíz final se obtiene plegando la frontier en el orden canónico definido por TreeCore. Ningún consumidor reimplementa este plegado.

### 4.8. Complejidad

Con B bytes, N hojas y m = 4 branches:

- build: O(mB);
- frontier memory: O(m log N);
- finalization: O(m log N);
- index completo opcional: O(mN) almacenamiento.

## 5. InclusionProof V1

### 5.1. Objeto

Una prueba de inclusión es autocontenida respecto a la raíz declarada y contiene:

- TreeProfile V1;
- TreeRoot V1 completo;
- target leaf index;
- target leaf byte length;
- secuencia leaf-to-root de InclusionStepV1.

Cada InclusionStepV1 contiene:

- side = LEFT o RIGHT, que indica dónde se sitúa el sibling respecto al nodo
  reconstruido;
- un TreeNode V1 sibling completo: start_leaf, leaf_count, byte_length, height y
  vector de cuatro digests.

El target byte offset no se serializa: se deriva de forma única como

    leaf_index * 65,536

para evitar una segunda autoridad de geometría.

### 5.2. Wire

InclusionStep magic:

    SIGTPST1

Campos:
1. side:u16;
2. sibling TreeNode V1 wire.

InclusionProof magic:

    SIGTIPF1

Campos:
1. TreeProfile V1;
2. TreeRoot V1;
3. leaf_index:u64;
4. leaf_byte_length:u32;
5. secuencia canónica de InclusionStep wires.

El constructor/parser valida toda la geometría antes de hacer hashing:
- path length exacta;
- side exacto en cada nivel;
- sibling start/count/length/height exactos;
- leaf length derivada de TreeRoot;
- profile/root profile idénticos.

### 5.3. Contrato

Con un índice efímero ya construido:

    index.prove_leaf(i) -> InclusionProofV1

One-shot:

    prove_leaf(data, i) -> InclusionProofV1

Verificación:

    verify_inclusion(leaf_bytes, proof) -> bool

El proof contiene la TreeRoot contra la que se reconstruye. Un consumidor que
quiera imponer una root externa compara además proof.root con su identidad esperada.

### 5.4. Ley principal

Para toda hoja válida i de X:

    verify_inclusion(
      leaf_i,
      TreeProofIndex(X).prove_leaf(i)
    ) = true

La verificación comienza reconstruyendo la leaf frame exacta y aplica cada sibling
en su orientación declarada mediante la misma ley canónica Parent de ST0.

### 5.5. Binding

Cambiar cualquiera de:
- leaf bytes;
- leaf index;
- leaf length;
- sibling orientation;
- sibling geometry;
- sibling digest vector;
- TreeRoot;
- TreeProfile;

produce rechazo salvo la correspondiente colisión criptográfica subyacente.

### 5.6. Complejidad

Sea m=4 y N el número de hojas:

    inclusion steps = O(log N)
    proof size      = O(m log N)
    verification    = O(m log N)

TreeProofIndex es un artefacto efímero de generación, no identidad ni wire.
Construirlo desde bytes cuesta O(mB); una vez construido, generar el camino cuesta
O(log N) sobre nodos cacheados.

En el profile V1 actual, cada nivel añadido incrementa el wire de inclusión en
378 bytes; el sweep 1..128 hojas muestra exactamente esa pendiente.

## 6. RangeProof V1

### 6.1. Alcance

Sólo rangos no vacíos contiguos:

    [start, start + length)

dentro de un objeto no vacío.

La proof acredita exactamente ese intervalo y reconstruye la misma TreeRoot V1
sin leer el resto del objeto.

### 6.2. Objeto

RangeProofV1 contiene:

- TreeProfile V1;
- TreeRoot V1;
- start:u64;
- length:u64;
- prefix bytes omitidos del primer edge leaf;
- suffix bytes omitidos del último edge leaf;
- witness nodes del complemento.

Wire magic:

    SIGTRPF1

Campos:
1. TreeProfile;
2. TreeRoot;
3. start;
4. length;
5. prefix;
6. suffix;
7. secuencia de TreeNode witnesses.

### 6.3. Canonical complement cover

Sea L=[first_leaf,last_leaf) el span de hojas que intersecta el rango.

El witness cover es la única colección de subárboles canónicos maximales que
cubre exactamente las hojas fuera de L.

Definición recursiva para un subtree canonical C:
- si C es disjunto de L, incluir C y no descender;
- si C es singleton intersectando L, no incluirlo;
- si C intersecta parcialmente L, dividir por la canonical largest-power split
  de ST0 y continuar en ambos hijos.

Esto produce un cover único y de cardinalidad O(log N), con a lo sumo dos
boundary paths.

### 6.4. Partial edge honesty

El verificador recibe sólo:

    range_bytes + RangeProofV1

Para poder reconstruir las hojas de borde:
- prefix contiene exactamente los bytes anteriores a start dentro del first leaf;
- suffix contiene exactamente los bytes posteriores al final dentro del last leaf.

Sus longitudes se derivan de start/length/TreeRoot y se validan antes de hashing.

Por tanto el verifier reconstruye exactamente:

    prefix || range_bytes || suffix

sobre el span de hojas tocado, vuelve a hashear esas hojas con sus índices/offsets
canónicos, añade los witness subtrees y reconstruye la raíz.

### 6.5. Contrato

Con índice efímero:

    index.prove_range(start, length) -> RangeProofV1

One-shot:

    prove_range(data, start, length) -> RangeProofV1

Verificación:

    verify_range(range_bytes, proof) -> bool

verify_range no recibe source/path/file handle. Por construcción API no puede leer
bytes fuera de range_bytes y proof.

### 6.6. Ley

Para todo rango válido [a,b) de X:

    verify_range(
      X[a:b],
      TreeProofIndex(X).prove_range(a, b-a)
    ) = true

### 6.7. Cheap rejection

El helper one-shot valida tipo, positividad, overflow u64 y bounds del rango antes
de construir TreeProofIndex o ejecutar hashing.

El parser RangeProofV1 valida bounds, edge lengths y witness geometry antes de
reconstruir leaves.

### 6.8. Complejidad

Witness nodes:

    O(log N)

Witness digest material:

    O(m log N)

Edge complement bytes:

    <= 2 * (chunk_size - 1)

Por tanto el wire total es:

    O(m log N + chunk_size)

donde chunk_size=65,536 es constante del profile V1.

Verification I/O:

    O(length + edge complements + proof wire)

sin acceso al resto del objeto.

### 6.9. Disclosure boundary

RangeProof V1 no es una selective-disclosure proof privada ni zero-knowledge.

Para un rango que empieza/termina dentro de chunks, prefix/suffix revelan los bytes
restantes de esos edge leaves. El leakage adicional máximo es:

    2 * (65,536 - 1) bytes.

Evitar ese leakage requeriría una geometría interna por subchunk/byte distinta y
pertenece a un profile/futura etapa separada; no se finge privacidad en V1.

### 6.10. No claims

Una range proof acredita integridad estructural respecto a TreeRoot V1.
No acredita frescura, propiedad, timestamp, provenance, confidencialidad ni
trayectoria v3.

## 7. TreeResumeCheckpoint V1

### 7.1. Objetivo

Reanudar una construcción Sigma Tree V1 sin serializar estados internos opacos de
`hashlib` y sin volver a hashear el prefijo ya comprometido.

El checkpoint sólo conserva estructura canónica ST0:

- TreeProfile V1;
- número total de bytes ya consumidos;
- número de hojas completas ya comprometidas;
- canonical frontier de esas hojas completas;
- tail raw de longitud estrictamente menor que 65,536 bytes;
- source hint operativo opcional.

### 7.2. Wire V1

Magic:

    SIGTCHK1

Campos TLV:
1. TreeProfile V1;
2. completed_bytes:u64;
3. completed_leaf_count:u64;
4. TreeFrontier V1;
5. tail bytes;
6. optional TreeSourceHintV1 wire o vacío.

SourceHint magic:

    SIGTSRC1

Campos:
1. size:u64;
2. mtime_ns:u64;
3. inode:u64;
4. device:u64.

El source hint forma parte del checkpoint record para reproducibilidad operacional,
pero no participa en TreeRoot ni en la semántica criptográfica de continuación.

### 7.3. Invariantes canónicos

La frontier de checkpoint sólo puede contener hojas completas:

    frontier.byte_length
      = completed_leaf_count * 65,536

La tail satisface:

    0 <= len(tail) < 65,536

y:

    completed_bytes
      = frontier.byte_length + len(tail)

por tanto:

    completed_bytes mod 65,536 = len(tail).

La frontier conserva la descomposición binaria única de ST0. No se acepta un
TreeFrontier estructuralmente válido que contenga un rightmost short subtree:
esa representación corresponde a una root finalizada, no a un checkpoint
reanundable.

### 7.4. Snapshot y restauración

`TreeBuilder.checkpoint_state()` devuelve:

    frontier, tail, completed_bytes, completed_leaf_count

sin exponer estado de ninguna primitive hash.

`TreeBuilder.from_checkpoint_state(frontier,tail)` reconstruye el builder con:
- canonical frontier;
- next leaf index = frontier.leaf_count;
- raw tail;
- byte counter exacto.

No rehace hash alguno del prefijo.

API pública:

    checkpoint_builder(builder) -> TreeResumeCheckpointV1
    checkpoint_bytes(prefix) -> TreeResumeCheckpointV1
    restore_builder(checkpoint) -> TreeBuilder
    resume_tree(checkpoint,suffix) -> TreeRoot

### 7.5. Ley principal

Para todo:

    X = P || S

y todo checkpoint canónico producido tras consumir P:

    resume_tree(checkpoint(P), S)
      = build_tree(P || S)

byte por byte.

Además, para cualquier partición:

    P = P0 || P1 || ... || Pk

se puede repetir:

    checkpoint
      -> restore
      -> update(Pi)
      -> checkpoint

sin modificar la raíz final.

### 7.6. Source hint honesty

TreeSourceHintV1 es una heurística de UX/operación.

Puede detectar cambios comunes de:
- size;
- mtime_ns;
- inode;
- device.

No demuestra que una fuente actual tenga el mismo prefijo comprometido.

En particular:

    hint_match = true

NO implica:

    current_prefix == checkpoint_prefix.

La única semántica fuerte de `resume_tree` es continuidad desde el estado
comprometido dentro del checkpoint.

Una futura API de source rebind/verificación fuerte deberá comparar evidencia
criptográfica del prefijo y pertenece a una etapa separada.

### 7.7. Persistencia transaccional

`write_checkpoint_atomic(path,checkpoint)`:

1. serializa el record completo;
2. crea temporal en el mismo directorio;
3. escribe y `fsync` el temporal;
4. publica mediante `os.replace`;
5. intenta `fsync` del directorio;
6. elimina cualquier temporal residual.

Si falla antes del replace:

    checkpoint_after = checkpoint_before

para un destino ya existente.

No se publica un checkpoint parcial.

### 7.8. Complejidad

Sea N el número de hojas completas y m=4.

La frontier tiene:

    O(log N)

nodos, cada uno con m digests.

Con tail acotada por el chunk fijo:

    checkpoint wire = O(m log N + chunk_size)
    decode          = O(m log N + tail)
    restore         = O(m log N + tail)

Como chunk_size=65,536 es constante del profile V1:

    restore = O(m log N)

respecto al tamaño lógico del árbol.

El prefijo P no se vuelve a leer ni rehashear durante restore.

### 7.9. CLI provisional

    sigma checkpoint-tree FILE --offset N --output state.chk
    sigma resume-tree state.chk FILE [--require-hint-match] [--output root.bin]

`--require-hint-match` es sólo una barrera operacional heurística. La salida
JSON marca explícitamente:

    source_hint_security_evidence = false

para impedir convertir esa comprobación en una claim de seguridad.

## 8. TreeDelta V1

### 8.1. Objetivo y frontera

ST4 añade actualización incremental a Sigma Tree V1 sin cambiar ninguna ley de
TreeRoot/TreeNode/chunking de ST0.

V1 soporta:

A. same-length replacement;
B. append.

No soporta como update incremental:
- inserción interior;
- borrado interior;
- replacement con longitud distinta.

Esos casos desplazan las fronteras de chunk y devuelven:

    RebuildRequired

en vez de ejecutar silenciosamente un algoritmo O(B) bajo el nombre incremental.

ST4 define un índice **efímero en memoria** `TreeDeltaIndex`. El formato de un
índice persistente, mmap, fallback de escala y políticas de almacenamiento se
reservan para ST5/SA3.

### 8.2. TreeEditV1

Un edit contiene:

    start:u64
    delete_length:u64
    data:bytes

Un edit pertenece al dominio incremental V1 sólo si:

    delete_length = len(data)

Un edit vacío es un no-op canónico.

### 8.3. Normalización de edits

Antes de hashear se ejecuta:

    normalize_tree_edits(edits,total_bytes)

Reglas:
- ordenar por start/end;
- validar bounds;
- rechazar cambios de longitud con RebuildRequired;
- fusionar rangos adyacentes;
- fusionar overlaps si escriben exactamente los mismos bytes en la intersección;
- rechazar overlaps contradictorios.

La normalización es independiente del orden de entrada.

Por tanto no existe semántica oculta de "last write wins".

### 8.4. Índice efímero

`TreeDeltaIndex(data)` materializa una vez:

- bytes por leaf;
- TreeNode de cada leaf;
- cache de subárboles canónicos de la Tree actual;
- TreeRoot actual.

Construcción inicial:

    O(mB)

y memoria base:

    O(B + mN)

aproximadamente, antes de optimizaciones ST5.

El índice no forma parte de la identidad criptográfica del objeto.

### 8.5. Same-length replacement

Para edits normalizados se calcula el conjunto A de leaves intersectadas.

Los edits se particionan en un único pase edit -> leaf. No se cruza cada leaf
contra todos los edits; esto evita deuda O(k^2) en updates fragmentados.

Para cada leaf afectada:
1. copiar únicamente esa leaf;
2. aplicar sus segmentos;
3. recomputar su leaf frame/digest vector.

Después se calcula el cierre ancestral canónico exacto:

    Anc(A)

sobre la geometría ST0.

Sólo se recomputan:

    A union Anc_internal(A).

Un subtree canónico disjunto se reutiliza sin modificar su TreeNode.

### 8.6. Ley de equivalencia delta

Para todo delta soportado:

    Delta(TreeDeltaIndex(X), Δ).root
      = Tree(apply_same_length(X, Δ))

byte por byte.

Además:

    recomputed_nodes = exact_ancestor_closure(A)

y todo subtree disjunto conserva su node summary.

### 8.7. Transactionality

Hashing, composición y construcción de la nueva root ocurren antes de publicar.

El commit en memoria mantiene un rollback journal limitado a:
- leaves tocadas;
- leaf nodes tocados;
- cache keys invalidadas/recalculadas;
- root previa.

Si falla hashing/composición:

    state_after = state_before.

Si falla una operación durante la publicación del commit, el journal restaura:

    leaves_after = leaves_before
    cache_after  = cache_before
    root_after   = root_before.

No se publica una root parcial.

### 8.8. Telemetría

Cada update devuelve `TreeUpdateTelemetryV1` con:

- operation;
- old/new byte length;
- replacement/appended bytes;
- affected leaves;
- invalidated node keys;
- recomputed node keys;
- reused node keys;
- leaf payload bytes rehashed;
- branch hash invocations;
- frontier nodes reused para append.

Esta telemetría es evidencia de complejidad/ingeniería, no una claim criptográfica.

### 8.9. Append

Para X con:
- canonical full-leaf frontier F;
- optional rightmost tail T;

append(Y) conserva todos los subárboles previos que siguen siendo canónicos y
disjuntos del tail modificado.

Sólo se vuelve a hashear:

    T || Y

particionado en nuevas leaves, más los bridge/ancestor nodes necesarios para la
nueva geometría.

Si X termina exactamente en frontera de chunk, no se vuelve a hashear ninguna
leaf antigua.

Si X tiene tail parcial, sólo esa leaf antigua puede cambiar.

Ley:

    Append(TreeDeltaIndex(X),Y).root
      = Tree(X || Y).

Para Y vacío:

    Append(index,b"").root = index.root

sin hashing adicional.

### 8.10. Cache correctness tras crecimiento

La cache puede conservar summaries de geometrías históricas. Un node previo sólo
se reutiliza si:

1. su key existe;
2. esa key era un subtree canónico de la Tree inmediatamente anterior;
3. su intervalo queda completamente dentro del prefijo de hojas completas no
   modificado.

Así un summary obsoleto de una geometría previa nunca se reutiliza por coincidencia
accidental de key.

### 8.11. Complejidad delta

Sea:
- B_delta = bytes de replacement canónico;
- k = leaves afectadas;
- Anc(A) = cierre ancestral;
- m=4.

Después de construir el índice:

    T_delta =
      O(B_delta partitioning
        + bytes_de_leaves_afectadas
        + m |Anc(A)|).

Como cada leaf tiene tamaño fijo:

    T_delta = O(B_delta + m k log N)

como cota estructural conservadora.

Para cambios de un byte, el payload mínimo rehasheado es una leaf completa,
porque ST0 compromete a granularidad de 65,536 bytes.

### 8.12. Complejidad append

Sea t la tail previa (< chunk) y Y el suffix:

    T_append =
      O(t + |Y| + m * bridge_nodes).

No hay término O(B_old) de rehash del prefijo.

### 8.13. Performance boundary

Incremental no se presenta como universalmente más rápido.

Cuando:

    k/N -> 1

la ventaja desaparece y el overhead del índice puede hacer delta más lento que un
rebuild directo.

El criterio de valor de ST4 es el régimen local.

El ledger obligatorio mide:
- 1 leaf;
- 0.1%;
- 1%;
- 10%;
- 100%.

y publica también cualquier slowdown en 100%.

### 8.14. API

    index = TreeDeltaIndex(data)

    index.apply_delta([
      TreeEditV1(start, delete_length, replacement),
      ...
    ]) -> TreeUpdateResultV1

    index.append(suffix) -> TreeUpdateResultV1

`materialize()` existe para export/testing y es explícitamente O(B); no participa
en el camino incremental.

### 8.15. No claims

ST4 no introduce nueva seguridad criptográfica.

Incremental reuse no convierte una root en prueba de provenance/frescura y no
autoriza mutaciones fuera del dominio same-length/append.

## 8A. Tree Scale Policy V1

### 8A.1. Objetivo

ST5 cierra deuda accidental de rendimiento/memoria sin introducir una nueva
semántica criptográfica ni un nuevo Tree wire.

Las optimizaciones deben preservar exactamente:

    TreeRoot V1
    InclusionProof V1
    RangeProof V1
    TreeResumeCheckpoint V1
    TreeDelta/Append results

respecto a las referencias ya congeladas.

### 8A.2. Leaf hashing sin frame grande materializado

ST0 define la leaf preimage canónica:

    domain || record(SIGTLEAF, profile, algorithm, index, offset, length, raw_leaf)

ST5 conserva exactamente esos bytes pero alimenta la primitive hash en partes:

    domain
    record header
    TLV prefix fields 1..5
    field-6 TLV header
    raw leaf buffer

No se construyen cuatro records grandes completos para las cuatro ramas.

`leaf_node(...)` conserva la API bytes histórica. Internamente
`_leaf_node_buffer` admite bytes/bytearray/memoryview para evitar copies de
chunks completos.

### 8A.3. Streaming TreeBuilder

`TreeBuilder.update(bytes)` conserva su contrato público.

Los full chunks dentro del input se procesan mediante `memoryview`, sin crear
slices bytes de 65,536 bytes por chunk.

Sólo la tail incompleta puede copiarse al buffer interno.

Por tanto, aparte del input propiedad del caller:

    M_builder = O(chunk_size + m log N)

y en V1 chunk_size es fijo.

### 8A.4. ProofIndex layout

El layout FULL de `TreeProofIndex` conserva:
- una referencia al source bytes del caller;
- memoryviews por leaf;
- leaf summaries;
- canonical subtree summaries.

No conserva una segunda copia B-sized del payload.

Los memoryviews deben referenciar exactamente al source original.

### 8A.5. Streaming proof fallback

Se añaden:

    prove_leaf_streaming(data, leaf_index)
    prove_range_streaming(data, start, length)

Ambos producen **exactamente el mismo proof wire** que TreeProofIndex.

Trade-off:

FULL:
- index build O(mB);
- proof generation O(m log N);
- memoria index explícita.

STREAMING:
- no full index;
- O(B) hashing work por proof en el peor caso;
- O(log N) auxiliary tree state;
- RangeProof conserva sólo sus witnesses/edge bytes de salida.

El fallback no cambia la evidencia, sólo el resource plan.

### 8A.6. Range verification scale closure

`verify_range(range_bytes,proof)` no concatena el rango completo ni almacena
todos sus target leaf nodes.

La reconstrucción recorre recursivamente la geometría canónica:

- subtree fuera del target -> consumir un witness;
- target singleton -> hashear esa leaf;
- partial subtree -> reconstruir left/right y combinar.

Auxiliary tree state:

    O(log N)

más como máximo los dos edge chunks que ST2 ya exige materializar.

La memoria no crece linealmente con `length` salvo el `range_bytes` que ya
pertenece al caller y el output/input proof.

### 8A.7. Scale policy

`TreeScalePolicyV1` fija:

    max_index_bytes
    proof_fallback
    delta_fallback

Modos:

    FULL
    STREAMING
    REJECT

Operaciones indexadas:

    PROOF
    DELTA

La decisión queda materializada en `TreeIndexPlanV1`:

- operation;
- mode;
- source bytes;
- leaf count;
- estimated index bytes;
- budget bytes;
- reason.

Nunca existe fallback invisible.

### 8A.8. Presupuesto de ProofIndex

Estimador V1:

    estimate_proof_index
      = 65,536 + 4,096 * leaf_count

El source bytes del caller se excluye porque no se copia dentro del index.

El coeficiente es deliberadamente conservador y no pretende ser una fórmula
portable de RSS.

Si:

    estimate <= max_index_bytes

se selecciona FULL.

Si excede budget:
- STREAMING si la proof policy lo permite;
- REJECT si la policy exige no degradar tiempo.

### 8A.9. Presupuesto de DeltaIndex

DeltaIndex sí necesita estado mutable del objeto para la aceleración ST4.

Su copia B-sized es intencional y presupuestada:

    estimate_delta_index
      = 65,536
        + source_bytes
        + 4,608 * leaf_count

Si excede budget:

    TreeIndexBudgetExceeded

antes de construir el índice.

ST5 no define "streaming delta = rebuild completo"; hacerlo violaría la frontera
incremental ST4.

### 8A.10. APIs escaladas

    plan_tree_index(byte_length, operation, policy)
    estimate_index_bytes(byte_length, operation)

    prove_leaf_scaled(data, leaf_index, policy=...)
    prove_range_scaled(data, start, length, policy=...)

    delta_index_scaled(data, policy=...)

Las proof APIs devuelven:

    ScaledProofResultV1(proof, plan)

de modo que el caller puede auditar si se usó FULL o STREAMING.

### 8A.11. Manifest I/O bound

El scanner ST1 conserva la semántica de manifest.

ST5 limita cada `os.read` de fichero regular a:

    65,536 bytes

en lugar de bloques de 1 MiB.

El coste de manifest sigue:

    O(mB + F log F)

pero la memoria transitoria por fichero queda acotada por el chunk V1 más el
estado TreeBuilder.

### 8A.12. Persistent index decision

ST5 **no** crea un wire de índice persistente.

Razones:
1. un index no forma parte de la identidad criptográfica;
2. el layout óptimo depende de mmap/storage/resource policy;
3. introducir un nuevo record persistente exigiría su propio lifecycle,
   compatibility y atomic-update contract;
4. no es necesario para cerrar O01-O04.

ST5 sí congela:
- layout lógico FULL;
- zero-copy proof payload policy;
- mutable DeltaIndex budget;
- fallback behaviour;
- estimadores de resource policy.

Un sidecar persistente puede añadirse en SA3/una etapa posterior sin cambiar
ningún wire ST0-ST4.

### 8A.13. Claim boundary

Los timings ST5 son EMPIRICAL-PERFORMANCE locales.

No se convierten en:
- claim criptográfica;
- garantía cross-host;
- claim ASIC;
- claim constant-time.

La evidencia estructural ST5 es:
- byte preservation;
- absence/presence explícita de payload copies;
- bounded auxiliary memory contracts;
- deterministic resource-policy decisions.

## 9. Manifest V1

### 9.1. Objetivo

Comprometer directorios, releases, datasets y colecciones de artefactos sin depender
del path absoluto, traversal order ni metadata volátil del host.

### 9.2. ManifestEntry

Campos V1:
- canonical_relative_path;
- entry_type;
- metadata_profile;
- byte_length;
- TreeRoot V1;
- optional SigmaDigestV3 wire.

Entry types:
- regular file;
- directory;
- symbolic link sólo bajo policy explícita.

La semántica del TreeRoot por tipo es:
- regular file: TreeRoot de sus bytes;
- directory: canonical empty TreeRoot;
- symbolic link: TreeRoot del target textual NFC/UTF-8, sin seguirlo.

De este modo un directorio vacío queda comprometido y un symlink no se convierte
implícitamente en lectura del objeto apuntado.

### 9.3. Canonical path

- Unicode serializable como UTF-8 estricto;
- relativo;
- separador lógico `/`;
- sin NUL;
- sin componentes vacíos;
- sin `.`;
- sin `..`;
- sin drive/UNC de Windows;
- normalización Unicode NFC;
- no case folding;
- máximo 4096 bytes UTF-8;
- orden lexicográfico por bytes UTF-8 NFC.

Si dos nombres distintos colapsan al mismo path tras NFC, el manifest se rechaza
por duplicate path.

### 9.4. Metadata profile base

`BASE = 0x0001`.

No incluye:
- mtime;
- ctime;
- uid;
- gid;
- inode;
- executable bit.

Un futuro profile que incluya executable bit necesita un profile ID distinto.

### 9.5. Symlink policy

Default: REJECT.

TEXT mode:
- lee `os.readlink`;
- normaliza el texto a NFC;
- no resuelve el target;
- no sigue `..`, absolute targets ni loops;
- compromete exactamente el texto mediante TreeRoot.

### 9.6. Wire

ManifestEntry V1 usa magic `SIGTENT1` y TLV:
1. path;
2. entry type;
3. metadata profile;
4. byte_length;
5. TreeRoot wire;
6. optional trajectory digest wire.

Manifest V1 usa magic `SIGTMNF1` y TLV:
1. manifest profile;
2. sequence de entries ordenada canónicamente.

Límites V1:
- máximo 65,535 entries por count field;
- máximo 1 MiB por entry wire;
- máximo 8 MiB por manifest record.

### 9.7. Trajectory binding boundary

Si una entry regular incluye un SigmaDigestV3, ST1 compromete exactamente sus bytes.
ST1 sólo exige el magic estructural `SIGMA3DG`: no convierte esa presencia en una
afirmación de validez o message binding. Esa verificación pertenece a SV/SA.

### 9.8. Leyes

Traversal independence:

    Manifest(FS) no depende del orden devuelto por os.scandir.

Root independence:

    copiar el mismo árbol lógico a otro path absoluto produce el mismo manifest.

Content sensitivity:

    cambiar TreeRoot, path, entry type o SigmaDigest incluido cambia el manifest
    canónico salvo colisión subyacente en el componente comprometido.

Cross-platform canonicality:

    LogicalTree_Linux = LogicalTree_macOS
      => Manifest_Linux = Manifest_macOS

para nombres representables bajo el profile V1.

### 9.9. Complejidad

Para B bytes leídos y F entries:

    T_manifest = O(m B + F log F)
    IO_manifest = O(B + F)
    M_manifest = O(F) + max_file O(chunk + m log N_file)

con m=4 y path length acotado por profile.

## 10. Familia B — Sigma Trajectory Product Surface

### 10.1. Autoridad

Consume la construcción vigente:

    Z_i = (H_i, S_i)

con PersistentBinding P_X, parámetros derivados, layout histórico y digest v3.

No redefine ninguna fórmula.

## 11. TrajectoryAudit V1

### 11.1. Objetivo

Hacer visible y auditable la trayectoria Sigma v3 ya calculada sin modificar:
- SigmaContextV3;
- PersistentBinding;
- derivación t/k;
- layout;
- HistoryCommitmentV3;
- framing;
- round dynamics;
- SigmaDigestV3.

Audit es estrictamente downstream de `evaluate_v3()`.

Ley de no interferencia:

    digest_from_evaluation_v3(E)
      = project_digest_v3(audit_from_evaluation_v3(E))

y construir un Audit nunca participa en la evaluación que produce E.

### 11.2. Wire

Magic top-level:

    SIG3AUD0

Round record magic:

    SIG3AUR0

El envelope usa el record codec v3 existente:

    magic[8] || record_version=3:u16 || body_length:u32 || strict TLV

No se registra:
- nueva suite;
- nuevo DomainId criptográfico;
- nueva primitive hash.

### 11.3. Campos top-level

TrajectoryAuditV3 contiene:

1. mode;
2. SigmaDigestV3 exacto;
3. PersistentBinding exacto;
4. init LayoutPlan wire;
5. secuencia completa de states S_0..S_(t+k-1);
6. secuencia H_0..H_(t+k-1), sólo para HISTORY_FEEDBACK;
7. secuencia de round audit records, exactamente t+k-1.

Por construcción:

    len(states) = t + k
    len(rounds) = t + k - 1

y:

    digest.window.states
      = states[t:t+k].

### 11.4. Round audit record

Cada round record contiene:

- round index;
- canonical layout wire;
- optional round-binding wire;
- optional state-frame wire;
- optional branch-frame sequence;
- optional branch-output sequence;
- optional fold-frame wire.

Round indices son exactamente:

    0,1,...,t+k-2.

### 11.5. COMPACT

COMPACT conserva únicamente lo necesario para reconstruir semánticamente la
trayectoria:

- digest;
- persistent binding;
- init layout;
- states;
- histories si existen;
- round layouts.

No serializa:
- round binding redundante;
- state-frame wire;
- branch frames;
- branch outputs;
- fold frames.

Todos ellos se derivan de context/binding/history/layout/state durante replay.

COMPACT no almacena hashes sustitutivos de esos objetos: evita introducir una
segunda primitive o identidad paralela.

### 11.6. FULL

FULL conserva además los wires canónicos exactos ya definidos por Sigma v3:

WideOnce:
- state frame.

Deep:
- state frame;
- cada DeepBranchFrame;
- cada branch output;
- DeepFoldFrame.

DeepVector:
- vector state frame;
- cada DeepBranchFrame;
- cada branch output;
- sin fold frame porque:

    S_(i+1) = branch_0 || ... || branch_(m-1).

History suites:
- RoundBindingV3;
- HistoryRoundFrame o HistoryVectorRoundFrame;
- HistoryDeepBranchFrame;
- HistoryDeepFoldFrame cuando corresponde.

Por tanto FULL no inventa "frame IDs"; conserva el frame wire canónico exacto.

### 11.7. Replay estructural

API:

    verify_trajectory_audit_structure_v3(audit) -> bool

No recibe source.

Verifica:
- persistent binding/header/parameters consistency;
- init layout exacto;
- state count y widths;
- public window projection;
- H_0 = history_seed_v3(...) en history suites;
- H_(i+1) = history_step_v3(...,H_i,i,S_i);
- round layout derivado exactamente;
- state frame derivado exactamente;
- Deep branch frames/outputs;
- scalar fold o vector concatenation;
- S_(i+1) exacto;
- FULL-only wires exactos cuando mode=FULL.

Resultado positivo significa:

    "esta trayectoria es internamente coherente con su binding/context".

No significa todavía:

    "el binding corresponde al source X".

### 11.8. Verificación full contra source

API:

    verify_trajectory_audit_full_v3(source,audit) -> bool

Procedimiento:
1. ejecutar `evaluate_v3(audit.digest.context, source)`;
2. construir un audit del mismo mode;
3. exigir igualdad byte por byte del audit canónico.

Por tanto:

    verify_full(X,audit(X)) = true

y cambiar X produce rechazo salvo igualdad completa de la evaluación subyacente.

Esta API es la única de SV0 que realiza message-binding.

### 11.9. Ley de proyección

Para todo evaluation válido E:

    project_digest_v3(audit_from_evaluation_v3(E))
      = digest_from_evaluation_v3(E)

byte por byte.

COMPACT y FULL proyectan exactamente el mismo SigmaDigestV3:

    project(COMPACT(E)) = project(FULL(E)).

### 11.10. Causalidad history-feedback

Para suites R12.5:

    Z_i = (H_i,S_i)

y el audit conserva todos los H_i y S_i.

Replay exige:

    H_0 = HistorySeed(C,P_X)

    H_(i+1)
      = HistoryStep(C,P_X,H_i,i,S_i)

antes de aceptar la transición.

Mutar H_i sin recomputar el suffix causal invalida replay.

### 11.11. Deep vs DeepVector

Audit conserva la diferencia existente; no la normaliza.

Deep scalar:

    branches_i = (b_i^0,...,b_i^(m-1))
    S_(i+1) = Fold(branches_i)

y FULL contiene fold frame.

DeepVector:

    S_(i+1) = b_i^0 || ... || b_i^(m-1)

y FULL no contiene fold frame.

La anchura del state sigue siendo:
- 64 bytes para Deep;
- 256 bytes para DeepVector en el profile actual.

### 11.12. Codec canonicality

Top-level y round records usan strict TLV v3.

Secuencias:
- count:u16;
- cada item con length:u32;
- máximo 64 items;
- máximo 64 KiB por item.

COMPACT rechaza cualquier evidencia FULL presente.

FULL exige:
- state frame por round;
- branch count exacto para Deep/DeepVector;
- fold frame exactamente cuando profile=DEEP;
- round binding exactamente cuando trajectory=HISTORY_FEEDBACK.

### 11.13. Complejidad

Sea:

    R = t + k - 1
    s = state_size
    m = número de joint algorithms.

Construcción desde un Evaluation ya existente:

COMPACT:

    T = O(output_size)
    M/output = O((R+1)s + R*layout + history)

FULL añade serialización de frames ya derivables:

    T = O(full_audit_size)
    output = O(R * frame_material)

No vuelve a leer el source ni a recalcular el digest.

Replay estructural:

    O(R * round_cost)

sin source I/O.

Full source verification:

    O(cost(evaluate_v3(source)) + audit_size).

### 11.14. Claim boundary

TrajectoryAudit:
- no añade nominalmente bits de seguridad;
- no es un segundo hash del mensaje;
- no convierte COMPACT en una prueba más débil ni FULL en una primitive más fuerte;
- no prueba timestamp, provenance ni ejecución histórica real;
- no reemplaza SigmaDigestV3.

FULL contiene más evidencia inspeccionable, no más fuerza criptográfica nominal.

### 11.15. Disclosure boundary

TrajectoryAudit no es una superficie de privacidad.

COMPACT expone:
- PersistentBinding;
- todos los states S_i;
- todos los histories H_i cuando existen;
- layouts.

FULL expone además:
- round bindings;
- state-frame wires;
- branch-frame wires;
- branch outputs;
- fold frames.

Por tanto un Artifact/Receipt posterior no debe adjuntar Audit por defecto si sólo
necesita SigmaDigestV3. Publicar Audit es una decisión explícita de disclosure.

SV0 no afirma que estos intermedios sean secretos; sólo evita afirmar lo contrario.

## 12. TrajectoryCheckpoint V1

### 12.1. Alcance y separación

TrajectoryCheckpointV1 reanuda **la fase iterada de la trayectoria** una vez ya
existen:

    context C
    PersistentBinding P_X
    TrajectoryParameters (t,k).

Es distinto de `sigma.incremental_v3.SigmaCheckpointV3`.

El checkpoint incremental histórico:
- representa un prefijo de source;
- es provisional;
- reevalúa ese prefijo para obtener un digest.

SV1:
- representa el estado interno S_i/H_i de una trayectoria ya preparada;
- no contiene bytes del source;
- continúa sin volver a ejecutar preparación/anchor sobre X.

### 12.2. Wire

Magic:

    SIG3TCK0

Se reutiliza el strict record envelope v3.

Campos:
1. SigmaContextV3;
2. PersistentBinding;
3. TrajectoryParameters;
4. round_index i;
5. state S_i;
6. HistoryCommitmentV3 H_i o vacío;
7. public-window prefix sequence.

### 12.3. Por qué existe window_prefix

La planificación mínima original:

    Q_i = (C,P_X,t,k,i,H_i,S_i)

es suficiente para continuar transiciones, pero no para reconstruir el mismo
SigmaDigestV3 si el checkpoint se toma **dentro de la ventana pública**.

Si:

    i > t

ya se han consumido estados públicos:

    S_t,...,S_(i-1).

Por tanto el estado mínimo portable para todos los índices es:

    Q_i =
      C,
      P_X,
      t,k,
      i,
      H_i?,
      S_i,
      W_i

donde:

    W_i = ()
      si i <= t

y:

    W_i = (S_t,...,S_(i-1))
      si i > t.

La longitud es canónica:

    len(W_i) = max(0,i-t).

### 12.4. Invariantes

Para:

    r = t+k-1

se exige:

    0 <= i <= r
    len(S_i) = context.state_size.

History suites:

    H_i.round_index = i.

Non-history suites:

    history = None.

Además:

    derive_trajectory_parameters(C,P_X) = (t,k).

No puede cambiar silenciosamente:
- suite;
- context;
- binding;
- t;
- k;
- trajectory profile.

### 12.5. Construcción desde EvaluationV3

API:

    checkpoint_from_evaluation_v3(E,i)

acepta cualquier:

    i in [0,t+k-1].

El wire producido se compara contra un encoder stdlib independiente que consume
`reference.independent_v3.evaluate_suite()`.

### 12.6. Continuación

API:

    advance_trajectory_checkpoint_v3(Q_i, rounds=n)

produce exactamente:

    Q_(i+n)

si:

    i+n <= t+k-1.

No existe:
- rewind;
- wrap;
- skip beyond final state.

Negative rounds y avances fuera de rango se rechazan.

### 12.7. Ley all-index

Si una evaluación directa produce:

    S_0,...,S_r

y, cuando aplica:

    H_0,...,H_r,

entonces para todo i:

    Continue(Q_i).states
      = (S_i,...,S_r)

y:

    Continue(Q_i).histories
      = (H_i,...,H_r)

en history suites.

### 12.8. Digest identity

Al alcanzar:

    r=t+k-1

la ventana pública se reconstruye como:

    W_r || S_r

que tiene exactamente k states.

Por tanto:

    finalize_trajectory_checkpoint_v3(Q_i)
      = digest_from_evaluation_v3(E)

para todo i.

### 12.9. Source rebind

Un checkpoint interno no demuestra por sí mismo que P_X procede de un source
actual X.

API separada:

    verify_trajectory_checkpoint_source_v3(X,Q_i)

Procedimiento:
1. reevaluar v3 sobre X;
2. reconstruir Q_i;
3. exigir igualdad canónica byte por byte.

Así se conserva:

    internal continuation consistency
      !=
    current source binding.

### 12.10. Codec canonicality

Top-level record:
- campos completos;
- tags estrictamente crecientes;
- sin aliases;
- sequence count/length exactos;
- nested context/binding/parameters/history usan sus codecs existentes.

Missing/duplicate/reordered/unknown fields se rechazan.

### 12.11. Complejidad estructural

Sea:

    r=t+k-1.

Crear Q_i desde una Evaluation materializada:

    O(k * state_size)

como máximo por el window_prefix; normalmente menor.

Continuar desde i:

    O((r-i) * round_cost)

sin source I/O y sin repetir anchor/preparation.

Finalizar desde Q_i no introduce un segundo pase: el digest se construye desde el
checkpoint final alcanzado.

Los timings empíricos se difieren a una campaña posterior; SV1 cierra primero la
equivalencia semántica all-index.

## 13. VerificationPolicy V1

### 13.1. Objetivo

Separar explícitamente:

    parseabilidad
    estructura/verificabilidad
    aceptabilidad operacional.

Una evidencia sintácticamente válida nunca implica por sí sola aceptación.

SV2 no sustituye al antiguo `ResourcePolicy` v2.2: define una policy de producto
independiente y versionada.

### 13.2. Wire

Magic:

    SIGPOLY1

Policy format version:

    1

Envelope:

    magic[8] || policy_version:u16 || body_length:u32 || strict TLV.

Campos canónicos:

1. allowed v3 suite IDs;
2. require history-feedback;
3. allow legacy v2.2;
4. require message binding;
5. require TrajectoryAudit;
6. require Tree evidence;
7. require DUAL evidence;
8. require signature;
9. require provenance;
10. allow Tree-only artifacts;
11. max input bytes;
12. max trajectory rounds;
13. max Tree-proof bytes;
14. max working-memory estimate;
15. allowed artifact metadata profiles;
16. symlink mode.

Suite/profile lists son sorted+unique.

### 13.3. Policy identity

La identidad compacta es:

    policy_id = SHA256(canonical_policy_wire).

Es un content ID estable, no una nueva claim de seguridad ni un aumento de
security width.

KATs congelados fijan default/strict/weak/legacy-opt-in.

### 13.4. Evidencias parseables

Parser V1 reconoce:

- SigmaDigestV3;
- TrajectoryAuditV3;
- SigmaDigestV2 v2.2.

Unknown/future magic:

    Unsupported.

Known magic pero codec inválido:

    Rejected(MalformedEvidence).

### 13.5. VerificationCapabilitiesV1

Para no acoplar SV2 prematuramente a SigmaArtifact, requisitos que pertenecen a
capas futuras se expresan mediante capabilities explícitas:

- has_tree_evidence;
- has_signature;
- has_provenance;
- tree_proof_bytes;
- artifact_metadata_profile;
- contains_symlink;
- estimated_working_memory_bytes.

SA0/SA1 podrán rellenar este objeto sin cambiar VerificationPolicyV1 ni su
PolicyId.

### 13.6. Cuatro decisiones

Toda decisión es exactamente una de:

    Accepted
    Rejected
    Inconclusive
    Unsupported.

Cada `VerificationDecisionV1` conserva:
- kind;
- reason code estable;
- reason text;
- policy_id;
- evidence_id si existe;
- evidence kind;
- structure_valid si se pudo determinar;
- message_binding_verified si se ejecutó.

### 13.7. Semántica de decisión

Accepted:
- evidence soportada;
- todos los checks de policy pasan;
- el nivel de verificación exigido por policy se ha satisfecho.

Rejected:
- evidence conocida pero malformada;
- violación de policy;
- replay/verificación falla;
- source incorrecto.

Inconclusive:
- evidence soportada y no rechazada;
- falta información necesaria para decidir, por ejemplo source requerido,
  tree-proof size requerido o memory estimate requerido.

Unsupported:
- evidence/profile desconocido;
- tipo de source no soportado para una ruta legacy explícita.

### 13.8. Cheap checks first

Orden obligatorio:

1. identificar/parsear tipo;
2. capabilities/policy triviales;
3. suite/history allowlist;
4. committed input size;
5. trajectory-round bound;
6. audit requirement;
7. sólo entonces structural replay;
8. sólo entonces source reevaluation.

Por tanto oversized/disallowed inputs no alcanzan:
- `evaluate_v3`;
- trajectory replay caro;
- source I/O.

Tests usan bomb verifiers/sources para fijar este contrato.

### 13.9. Message binding

Para v3:

Si:

    require_message_binding = false

una evidence estructural válida puede ser Accepted sin source, con:

    message_binding_verified = false.

Si:

    require_message_binding = true

y no hay source:

    Inconclusive(SourceRequired).

Con source:
- SigmaDigestV3 usa `verify_full_v3`;
- TrajectoryAuditV3 usa `verify_trajectory_audit_full_v3`.

### 13.10. Legacy v2.2

Default:

    allow_legacy_v22 = false.

Por tanto un SigmaDigestV2 válido se rechaza por policy antes de verificación
cara.

Sólo una policy con opt-in explícito puede aceptarlo.

Legacy v2.2 no puede satisfacer:
- history-feedback requirement;
- TrajectoryAudit requirement.

La ruta legacy full exige source bytes explícitos; no se materializa
silenciosamente un CanonicalSource arbitrario.

### 13.11. DUAL/Tree/signature/provenance

Aunque SigmaArtifact todavía no existe, la policy ya fija estas restricciones.

Si una requirement no está satisfecha por VerificationCapabilitiesV1:

    Rejected.

Esto permite que SA0/SA1 reutilicen la policy sin cambiar el wire.

### 13.12. Resource uncertainty

Para límites cuya estimación no forma parte de la evidence:
- max Tree-proof bytes;
- max working memory;

si el bound es activo pero la capability correspondiente no está disponible:

    Inconclusive.

Nunca se asume un valor favorable.

### 13.13. Orden parcial normalizado

Se implementa:

    policy_is_stricter_or_equal_v1(P_strict,P_weak)

para el subset normalizado.

Condiciones principales:
- suites_strict subset suites_weak;
- requirements strict >= weak;
- legacy allowance strict <= weak;
- maxima strict <= weak;
- metadata profiles strict subset weak;
- REJECT symlink <= TEXT.

Ley exigida:

    Accepted(P_strict,x)
      => Accepted(P_weak,x)

cuando ambas decisions reciben la misma evidencia/capabilities y el mismo
verificador necesario.

### 13.14. Default policy

La policy default:
- permite suites history-feedback R12.5 activas;
- exige history-feedback;
- niega v2.2;
- exige message binding;
- no exige Audit/Tree/DUAL/signature/provenance;
- max input = 1 GiB;
- max trajectory rounds = 64;
- symlink mode = REJECT.

### 13.15. Claim boundary

PolicyId y EvidenceId son content identifiers para determinismo/auditoría.

No:
- autentican autores;
- prueban provenance;
- añaden bits de seguridad;
- sustituyen firmas.

Los benchmarks de coste/policy throughput se difieren; SV2 cierra primero
determinismo, orden de checks y semántica de decisión.

## 14. VerificationReceipt V1

### 14.1. Objetivo

Registrar de forma canónica:

    qué identidad de artefacto
    qué policy
    qué verificador
    qué evidencia
    qué decisión

produjeron un resultado de verificación.

SV3 no depende de SA0. Por tanto `artifact_identity` es un identificador opaco
canónico de 1..255 bytes. Cuando SA0 defina ArtifactId, su wire/ID se inserta en
este campo sin cambiar VerificationReceiptV1.

### 14.2. Wire

Magic:

    SIGRCPT1

Envelope:

    record-version-3 strict TLV.

Campos:

1. artifact_identity;
2. policy_id;
3. verifier_package;
4. verifier_version;
5. verifier_build opcional;
6. evidence_kind opcional;
7. evidence_id opcional;
8. decision_kind;
9. decision_code;
10. decision_reason;
11. structure_valid tri-state;
12. message_binding_verified tri-state;
13. canonical evidence_hashes;
14. claimed_unix_time opcional;
15. signature_status;
16. signature_algorithm;
17. public_key_id;
18. signature.

Los strings son UTF-8 NFC y no admiten NUL.

`policy_id` y todo evidence hash son exactamente 32 bytes.

### 14.3. Result binding

`receipt_from_decision_v1` exige:

    receipt.policy_id = decision.policy_id.

Si existe:

    decision.evidence_id

debe aparecer en:

    receipt.evidence_hashes.

El receipt permite reconstruir:

    VerificationDecisionV1

mediante `decision_projection()`, incluyendo:
- Accepted/Rejected/Inconclusive/Unsupported;
- reason code;
- reason text;
- evidence identity;
- structure-valid state;
- message-binding state.

No existe un `verification_mode` redundante. El nivel realmente ejecutado queda
representado por:

    structure_valid
    message_binding_verified.

Esto evita un enum que pudiera contradecir al decision real.

### 14.4. Verifier identity

La identidad del verificador queda ligada por:

    verifier_package
    verifier_version
    verifier_build.

Default product:

    verifier_package = "sigma-framework"
    verifier_version = PACKAGE_VERSION.

`verifier_build` es opcional y puede contener commit/build identity.

### 14.5. Unsigned receipts

Estado explícito:

    ReceiptSignatureStatusV1.UNSIGNED.

Un receipt unsigned exige canónicamente:

    signature_algorithm = None
    public_key_id = b""
    signature = b"".

Nunca se interpreta la ausencia de bytes como una firma implícita.

### 14.6. Signed receipts

Única primitive de firma en SV3:

    Ed25519.

No se introduce una nueva primitive criptográfica.

Para signed receipts:

    signature_status = SIGNED
    signature_algorithm = ED25519
    public_key_id != empty
    len(signature) = 64.

Signing input:

    "SIGMA-VERIFICATION-RECEIPT-V1\0"
      || canonical_receipt_record_with_empty_signature

donde el record ya contiene:
- todos los campos de resultado/evidencia;
- SIGNED status;
- ED25519 algorithm;
- public_key_id.

Por tanto sólo se excluyen los 64 bytes que deben ser calculados.

Mutar cualquier campo ligado invalida la firma.

### 14.7. Receipt identity

Se define:

    ReceiptId = SHA256(canonical receipt wire).

Es un content identifier; no es una nueva security-width claim.

### 14.8. Timestamp boundary

`claimed_unix_time` es sólo una claim firmable.

Una firma válida sobre:

    claimed_unix_time = T

demuestra que el signer autenticó un record que contenía T.

No demuestra:
- que el reloj fuera fiable;
- que el evento ocurriera realmente en T;
- existencia histórica externa;
- timestamp authority.

### 14.9. Provenance boundary

Un receipt puede autenticar bytes/identidades/claims, pero no convierte una
provenance opaca en verdad semántica.

En particular:

    valid receipt signature
      !=
    true provenance.

La semántica de provenance pertenece a SA2.

## 15. Batch verification

### 15.1. Modelo

Batch es una capa de scheduling:

    BatchVerify(items)
      = map(PointwiseVerify, items).

No existe state sharing criptográfico entre items.

Cada `BatchVerificationItemV1` contiene:
- artifact_identity;
- evidence;
- VerificationPolicyV1;
- source opcional;
- VerificationCapabilitiesV1;
- evidence hashes opcionales;
- claimed timestamp opcional.

### 15.2. Pointwise law

La autoridad semántica es:

    verify_batch_item_v1(item,index).

Para todo input tuple:

    verify_batch_v1(items).items[i]
      =
    verify_batch_item_v1(items[i],index=i).

El gate compara esta igualdad directamente.

### 15.3. Result wire

Per-item magic:

    SIGBCRI1

Batch magic:

    SIGBCHT1

Cada item result contiene:
- input index;
- artifact_identity;
- VerificationReceiptV1 si hubo decision;
- error_type/error_message si una excepción del item impidió producir decision.

El batch record contiene la secuencia ordenada de item-result wires.

### 15.4. Failure isolation

`verify_batch_item_v1` captura excepciones de un item como:

    BatchItemResultV1(
      receipt=None,
      error_type=...,
      error_message=...
    ).

No captura errores de configuración global del batch de forma silenciosa:
- invalid max_workers;
- signer config incoherente;
- batch vacío/oversized

se rechazan antes de scheduling.

Los textos de excepción capturados se:
- NFC-normalizan;
- eliminan NUL como representación escapada;
- limitan a 4096 bytes UTF-8.

Así incluso un error hostil no puede hacer fallar el registro del propio error.

### 15.5. Ordering

El orden canónico declarado es:

    input order.

Resultado:

    item[i].index = i.

No se ordena por artifact identity, evidence ID ni completion order.

`ThreadPoolExecutor.map` se usa cuando `max_workers>1` porque conserva input
ordering.

### 15.6. Serial/threaded equivalence

Para inputs deterministas y el mismo verifier configuration:

    Batch_serial.to_bytes()
      =
    Batch_threaded.to_bytes().

El paralelismo sólo cambia scheduling.

### 15.7. Signed batch receipts

Batch puede producir receipts unsigned o firmar cada receipt con Ed25519 usando
la misma configuración explícita del batch.

La firma sigue siendo per-item.

No existe:
- shared batch signature;
- shared cryptographic state;
- aggregate security claim.

### 15.8. Batch identity

Se define:

    BatchId = SHA256(canonical batch-result wire).

Es sólo content identity.

### 15.9. Complejidad

Sea n el número de items y C_i el coste del verifier seleccionado para item i.

Trabajo total:

    O(sum_i C_i + total receipt/result encoding).

Memoria de resultados:

    O(total result wire size).

Serial:
- wall time aproximadamente suma de C_i.

Threaded:
- scheduling puede reducir wall time según workload/host;
- no se congela aquí ninguna claim empírica de speedup.

SV3 cierra primero equivalencia/aislamiento/canonicalidad. Throughput y scaling
empíricos se dejan para una campaña posterior.


## 16. Familia C — Sigma Artifact V1

### 16.1. Objetivo

SigmaArtifact V1 es el objeto canónico de producto que declara qué evidencia
primaria representa un artefacto y cuál es su identidad estable.

SA0 define:
- formato;
- descriptor;
- perfiles TREE / TRAJECTORY / DUAL;
- ArtifactId;
- manifest identity;
- parent binding;
- optional TrajectoryAudit attachment.

SA0 **no** define todavía la semántica de verificación conjunta. Eso pertenece a
SA1.

### 16.2. Eje de versión

Artifact mantiene su propio eje:

    ARTIFACT_WIRE_VERSION = 1

independiente de:
- package version;
- Sigma suite IDs;
- Tree wire version;
- policy version.

### 16.3. Magics

Descriptor:

    SIGADSC1

Identity preimage:

    SIGAIDN1

Artifact envelope:

    SIGARTF1

Todos usan el artifact record envelope:

    magic[8] || artifact_version:u16 || body_length:u32 || strict TLV.

### 16.4. Artifact profiles

`ArtifactProfileV1`:

TREE:

    TreeRoot = required
    SigmaDigestV3 = absent

TRAJECTORY:

    TreeRoot = absent
    SigmaDigestV3 = required

DUAL:

    TreeRoot = required
    SigmaDigestV3 = required

La evidencia primaria debe coincidir **exactamente** con el profile.

No se permite:
- TREE sin TreeRoot;
- TREE con digest;
- TRAJECTORY con TreeRoot;
- DUAL con sólo uno de los dos.

Además, DUAL rechaza antes de SA1 si:

    tree_root.byte_length
      !=
    trajectory_digest.header.cardinality.byte_length.

Esto es una consistencia estructural barata, no la verificación dual completa.

### 16.5. ArtifactDescriptorV1

Descriptor profile inicial:

    BASE_V1 = 1

Campos:

    logical_name
    media_type

`logical_name`:
- UTF-8;
- NFC;
- sin NUL;
- máximo 4096 bytes;
- puede estar vacío.

`media_type`:
- opcional;
- ASCII;
- lowercase;
- forma canónica `type/subtype`;
- sin parámetros en V1;
- máximo 255 bytes.

El descriptor forma parte de ArtifactIdentityV1 y por tanto modifica ArtifactId.

### 16.6. ArtifactIdentityV1

Identity contiene exactamente:

1. ArtifactProfileV1;
2. ArtifactDescriptorV1;
3. optional TreeRoot;
4. optional SigmaDigestV3;
5. optional ManifestId;
6. canonical parent ArtifactId sequence.

Wire:

    SIGAIDN1

Este record es la única preimagen de ArtifactId.

### 16.7. ArtifactId

Domain:

    b"SIGMA-ARTIFACT-ID-V1\0"

Definición:

    ArtifactId =
      SHA256(
        domain
        || ArtifactIdentityV1.to_bytes()
      ).

ArtifactId tiene 32 bytes.

No contiene:
- el propio ArtifactId;
- TrajectoryAudit auxiliar;
- signatures futuras;
- provenance claims futuras;
- receipts.

Por tanto la definición es no circular.

El envelope serializa ArtifactId explícitamente y el parser exige:

    stored ArtifactId
      =
    recomputed ArtifactId.

Una mutación del ID almacenado se rechaza.

ArtifactId es un content identifier de producto; no se presenta como un aumento
de security width.

### 16.8. SigmaArtifactV1 envelope

`SigmaArtifactV1` contiene:

1. stored ArtifactId;
2. ArtifactIdentityV1;
3. optional TrajectoryAuditV3.

Wire:

    SIGARTF1.

El Audit es evidencia auxiliar inspeccionable.

Si está presente:
- el profile debe tener trajectory evidence;
- `audit.digest` debe ser byte-idéntico a `identity.trajectory_digest`.

TREE no puede transportar un TrajectoryAudit.

### 16.9. Audit attachment stability

COMPACT/FULL son dos representaciones de evidencia auxiliar sobre el mismo digest.

SA0 fija deliberadamente:

    ArtifactId(base)
      =
    ArtifactId(base + COMPACT audit)
      =
    ArtifactId(base + FULL audit).

Pero:

    artifact envelope wire

sí cambia al adjuntar audit.

Esto permite enriquecer evidencia de inspección sin renombrar el artefacto lógico.

### 16.10. Manifest identity

Domain:

    b"SIGMA-MANIFEST-ID-V1\0"

Definición:

    ManifestId =
      SHA256(
        domain
        || ManifestV1.to_bytes()
      ).

ManifestId tiene 32 bytes.

Si está presente, forma parte de ArtifactIdentityV1.

Por tanto:

    manifest change
      =>
    ManifestId change
      =>
    ArtifactId change

salvo la colisión criptográfica subyacente.

`create_artifact_v1` acepta:
- `manifest`;
- o `manifest_id`;

pero no ambos simultáneamente.

### 16.11. Parent artifacts

`parent_artifact_ids` es una secuencia canónica de IDs de 32 bytes.

Reglas:
- máximo 1024;
- sorted lexicographically by raw bytes;
- unique;
- no duplicates;
- no input-order semantics.

La API helper puede recibir una Sequence y normaliza a sorted+unique.

El constructor/parser canónico exige ya la forma ordenada.

Parents forman parte de ArtifactIdentityV1:

    parent set mutation
      =>
    ArtifactId mutation.

SA0 sólo liga IDs de parent. No prueba la existencia ni semántica de esos parents.

### 16.12. External signature/provenance boundary

SA0 no contiene firma externa ni provenance.

Esto evita circularidad y mantiene ArtifactId estable cuando SA2 añada capas de
autenticación/provenance.

El gate SA0 congela explícitamente:

    external_signature_in_artifact_identity = false.

SA2 podrá autenticar ArtifactId/record sin redefinir ArtifactId.

### 16.13. Canonical corpus

Corpus congelado:

    specification/test-vectors/sigma-artifact-v1-sa0.json

SHA-256:

    60a0405516dd55b5ce52f14a442c12f836128357ac7b838a28f8d7b5eb748631

Contiene seis casos:
- TREE empty;
- TREE + parents + manifest;
- TRAJECTORY;
- TRAJECTORY + COMPACT audit;
- DUAL;
- DUAL + FULL audit + parents + manifest.

Los vectores sólo se emiten después de comparar descriptor/identity/envelope
contra el encoder stdlib independiente.

### 16.14. Independent oracle

`reference/artifact_v1.py` no importa `sigma`.

Implementa independientemente:
- descriptor wire;
- identity wire;
- ArtifactId;
- artifact envelope wire;
- ManifestId.

SA0 diferencial exige igualdad byte por byte.

### 16.15. Complejidad estructural

Sea:
- D = descriptor wire size;
- P = número de parents;
- E = tamaño de primary evidence;
- A = tamaño del optional audit.

Construcción de identity:

    O(D + 32P + E).

ArtifactId:

    O(identity wire size)

por SHA-256 de la identidad canónica.

Envelope:

    O(identity wire + A).

No se vuelve a hashear el source para construir un Artifact desde TreeRoot /
SigmaDigest ya materializados.

SA0 no congela todavía claims empíricas de throughput.

### 16.16. Claim boundary

TREE:
- declara structural evidence identity.

TRAJECTORY:
- declara Sigma trajectory evidence identity.

DUAL:
- declara la presencia canónica de ambas.

SA0 no afirma todavía:

    VerifyDual = VerifyTree AND VerifyTrajectory.

Esa ley pertenece a SA1.

Tampoco suma nominalmente bits de seguridad.

### 16.17. SA1 verification result schema

SA1 introduce un resultado de verificación **no colapsado**:

    ArtifactVerificationResultV1

con:

    artifact_id
    profile
    tree: ArtifactSideResultV1
    trajectory: ArtifactSideResultV1
    policy: ArtifactPolicyResultV1.

Cada side result conserva:
- status;
- reason code;
- reason text;
- expected wire cuando existe;
- actual recomputed wire cuando existe.

Estados de side:

    NOT_APPLICABLE
    NOT_RUN
    VERIFIED
    FAILED
    ERROR.

Por tanto una verificación positiva o negativa conserva evidencia reconstruible
de qué se comprobó en cada familia.

### 16.18. Tree side

Para un artifact con Tree evidence:

1. comprobar byte_length antes de hashing;
2. reconstruir TreeRoot con la única autoridad TreeBuilder;
3. comparar el wire canónico exacto.

Resultado:

    tree.verified
      iff
    Tree(source).to_bytes()
      =
    artifact.tree_root.to_bytes().

Source errors pertenecen al side Tree y no se reinterpretan como fallo
Trajectory.

### 16.19. Trajectory side

Para un artifact con SigmaDigestV3:

1. comprobar cardinality/byte_length;
2. ejecutar evaluate_v3 usando el context del digest;
3. reconstruir SigmaDigestV3;
4. exigir igualdad byte por byte.

Si el artifact adjunta TrajectoryAuditV3:
- se reconstruye un Audit del mismo mode;
- también debe ser byte-idéntico.

Por tanto un audit auxiliar incoherente puede hacer fallar el side Trajectory,
aunque su digest embebido sea correcto.

### 16.20. Ley DUAL

Para:

    profile = DUAL

se define:

    dual_conjunction
      =
    tree.verified
      AND
    trajectory.verified.

Y:

    VerifyDual(X,A)
      =
    VerifyTree(X,A.tree)
      AND
    VerifyTrajectory(X,A.trajectory)

antes de aplicar requirements adicionales de policy.

No existe:
- XOR;
- fallback de un side al otro;
- aceptación por "al menos uno";
- score agregado;
- security-bit addition.

### 16.21. Failure attribution

Casos distintos permanecen distintos:

Tree-only failure:

    tree = FAILED
    trajectory = VERIFIED.

Trajectory-only failure:

    tree = VERIFIED
    trajectory = FAILED.

Both failure:

    tree = FAILED
    trajectory = FAILED.

La decisión final de policy puede además ser REJECTED, pero nunca borra estos
side results.

### 16.22. Policy integration

SA1 consume VerificationPolicyV1 sin cambiar su wire ni PolicyId.

Artifact-level preflight aplica antes de hashing caro:
- require_dual_evidence;
- require_tree_evidence;
- allow_tree_only_artifacts;
- require_audit;
- suite allowlist;
- history-feedback requirement;
- input-byte bound;
- trajectory-round bound;
- descriptor/metadata profile;
- signature/provenance capabilities;
- symlink capability;
- Tree-proof size bound;
- working-memory bound.

Policy short-circuit produce:

    side.status = NOT_RUN

para evidencia que deliberadamente no se evalúa.

TREE sólo puede aceptarse como Tree-only si:

    allow_tree_only_artifacts = true

y no contradice requirements explícitos como DUAL/Audit.

TRAJECTORY se rechaza si policy exige Tree.

DUAL se rechaza si policy exige condiciones adicionales que no están satisfechas.

### 16.23. Source requirement

SA1 es full message-binding verification.

Sin source:

    ArtifactPolicyResultV1.kind = Inconclusive
    code = SOURCE_REQUIRED.

No convierte un Artifact canónico en una verificación positiva sólo por ser
parseable.

### 16.24. Selective manifest trajectory criticality

SA1 define tres modos explícitos:

    TREE_ONLY
    DECLARED
    REQUIRE_ALL_FILES.

TREE_ONLY:
- verificar TreeRoot de cada regular file;
- no verificar trajectory digests aunque estén adjuntos.

DECLARED:
- siempre verificar TreeRoot;
- verificar Trajectory únicamente en entries que declaran trajectory_digest.

REQUIRE_ALL_FILES:
- toda regular-file entry debe declarar trajectory_digest;
- ausencia de digest es un fallo explícito.

Esto permite manifests mixtos sin inferencias ocultas.

Directories/symlinks no se convierten implícitamente en trajectory-critical
entries.

### 16.25. Independent side oracle

`reference/dual_verification_v1.py` no importa `sigma`.

Tree:
- usa `reference.tree_v1.root_wire`.

Trajectory:
- usa `reference.independent_v3.evaluate_suite`.

La referencia devuelve separadamente:

    tree_ok
    trajectory_ok
    tree_ok AND trajectory_ok.

SA1 gate exige igualdad exacta con los side results productivos.

### 16.26. Complexity contract

Para B bytes de source:

TREE side:

    O(Tree(B)).

Trajectory side:

    O(SigmaV3(B)).

DUAL full:

    O(Tree(B) + SigmaV3(B))

porque ambos commitments deben verificarse independientemente.

Policy preflight:

    O(policy/artifact metadata)

antes de estos costes cuando puede decidir rechazo/inconclusive.

Manifest selective verification:

    O(sum Tree(file_i))
      +
    O(sum SigmaV3(file_j))

sólo sobre los entries j marcados trajectory-critical por el modo explícito.

SA1 no congela todavía throughput empírico.

### 16.27. Claim boundary

DUAL expresa conjunción de dos claims independientes.

No se afirma:

    security_bits(DUAL)
      =
    security_bits(Tree)
      +
    security_bits(Trajectory).

El gate congela:

    dual_security_width_addition_claim = false
    tree_trajectory_claims_independent = true.


## 17. Provenance V1

Claims iniciales:

- SOURCE_COMMIT;
- BUILD_TOOLCHAIN;
- BUILD_COMMAND_DIGEST;
- PARENT_ARTIFACT;
- DATASET_SOURCE;
- EXPERIMENT_CONFIG;
- CUSTOM_OPAQUE.

Cada claim tiene:

- type ID;
- canonical payload o payload digest;
- optional external reference;
- claim issuer identity opcional.

Verificar bytes no verifica veracidad semántica de una claim opaca.

Adapters a SLSA/in-toto pueden añadirse sin convertir esos estándares en autoridad interna.

## 18. Compatibilidad histórica v2.2

Sigma Tree incluye un módulo legacy_v22 sólo de lectura.

Objetivos:

- parsear metadata necesaria;
- reproducir/verificar raíces TreeWide v2.2 existentes;
- convertir la geometría a una vista TreeInspection común cuando sea posible.

No se permite:

- convertir un digest v2.2 a v3;
- reetiquetar una root v2.2 como SigmaTree V1;
- producir nuevos artefactos v2.2 desde la API de producto salvo herramientas explícitas de reproducción histórica.

## 19. CLI funcional objetivo

Superficie final deseada:

    sigma tree file
    sigma prove file --leaf N
    sigma prove file --range START:LENGTH
    sigma verify-proof proof.sigma data
    sigma checkpoint-tree file
    sigma resume-tree checkpoint file

    sigma manifest directory
    sigma verify-manifest manifest directory
    sigma update-tree old.index changed-file

    sigma trajectory file
    sigma trajectory-audit file
    sigma trajectory-resume checkpoint

    sigma artifact create path --mode tree|trajectory|dual
    sigma artifact verify artifact path --policy policy
    sigma artifact inspect artifact

    sigma verify-many manifest-or-list

El CLI no es autoridad; consume las mismas APIs Python.

## 20. API Python funcional objetivo

    sigma.tree.build(...)
    sigma.tree.prove_leaf(...)
    sigma.tree.prove_range(...)
    sigma.tree.verify_proof(...)
    sigma.tree.checkpoint(...)
    sigma.tree.resume(...)
    sigma.tree.update(...)
    sigma.tree.manifest(...)

    sigma.trajectory.evaluate(...)
    sigma.trajectory.audit(...)
    sigma.trajectory.checkpoint(...)
    sigma.trajectory.continue_(...)
    sigma.trajectory.verify(...)

    sigma.artifact.create(...)
    sigma.artifact.verify(...)
    sigma.artifact.inspect(...)

## 21. Estados epistemológicos

Toda documentación usa uno de:

PROVED-STRUCTURAL
Ley derivada de encoding/algoritmo exacto y cerrada por referencia/differential proof obligations.

TESTED-CONFORMANCE
Propiedad de implementaciones/backends acreditada empíricamente.

CRYPTO-CONDITIONAL
Resultado condicionado a propiedades de primitivas.

EMPIRICAL-PERFORMANCE
Medición reproducible.

OPEN
Sin cierre.

Ningún benchmark eleva una hipótesis criptográfica a PROVED.

## 22. No objetivos de la primera campaña

- content-defined chunking;
- delta arbitrario con inserciones interiores eficientes;
- filesystem snapshot distribuido;
- red P2P;
- blockchain;
- consenso;
- timestamp authority;
- transparency service;
- VDF/PoSW;
- nueva firma;
- nuevo MAC;
- nuevo KDF;
- afirmar producción criptográfica antes de revisión externa;
- optimización nativa/constant-time;
- GUI en el core de esta campaña.

## 23. Criterio funcional de terminado

La capa Dual Integrity se considera funcionalmente cerrada cuando:

1. Sigma v3 y v2.2 siguen byte-exactos respecto a sus corpus.
2. TreeCore tiene una única autoridad.
3. Manifest, proof, range, resume y delta consumen esa autoridad.
4. Toda operación optimizada coincide diferencialmente con la referencia.
5. TrajectoryAudit proyecta exactamente al digest v3.
6. TrajectoryCheckpoint continúa exactamente la trayectoria.
7. VerificationPolicy distingue Accepted/Rejected/Inconclusive/Unsupported.
8. SigmaArtifact TREE/TRAJECTORY/DUAL verifican según contrato.
9. Existe implementación independiente para TreeRoot y proofs.
10. Parsers, fuzz y mutation tests cierran todos los wires nuevos.
11. Existe ledger de complejidad y rendimiento.
12. La documentación mantiene separados los claims de Tree, v3 y Artifact.
13. Un consumer limpio instalado desde wheel puede ejecutar los workflows principales.
14. Ninguna feature requiere modificar el freeze científico R14/R15.
