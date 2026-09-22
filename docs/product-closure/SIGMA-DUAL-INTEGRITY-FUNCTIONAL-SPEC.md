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
    │   ├── audit.py
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
- SIGTAUD1 — TrajectoryAudit
- SIGTCHK1 — TrajectoryCheckpoint
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

### 7.1. Objeto

Contiene:

- TreeProfile;
- completed_bytes;
- completed_leaf_count;
- canonical frontier;
- tail bytes de longitud < chunk_size;
- optional source identity hint.

No serializa estados internos opacos de hashlib.

### 7.2. Ley de reanudación

Para X = P || S:

    finalize(resume(checkpoint(P), S)) = build_tree(P || S)

byte por byte.

### 7.3. Source identity

mtime, inode y file size pueden registrarse como hints operativos, pero no son evidencia criptográfica.

Opcionalmente se puede guardar una raíz de prefijo o digest auxiliar estándar para detectar fuente equivocada antes de continuar.

## 8. TreeDelta V1

### 8.1. Operaciones soportadas

V1 soporta:

A. Same-length replacement.
B. Append.
C. Truncate sólo si se implementa y demuestra antes de closure.

Inserción o borrado interior que desplaza fronteras de chunk:

    RebuildRequired

### 8.2. Same-length replacement

Dado conjunto normalizado de rangos cambiados, se identifican leaves afectadas A y su cierre ancestral Anc(A).

Se recomputan sólo:

- bytes afectados;
- leaf roots afectados;
- ancestors afectados.

### 8.3. Ley de equivalencia

    update(Tree(X), Δ) = Tree(apply(X, Δ))

para todo Δ perteneciente al dominio soportado.

### 8.4. Transactionality

La nueva root no se publica hasta completar y verificar todo el update.

Si falla cualquier lectura, hash, policy o persistencia:

    state_after = state_before

### 8.5. Complejidad

Para k hojas afectadas:

    T_delta = O(B_delta + m |Anc(A)|)

con cota estructural aproximada O(B_delta + m k log N).

El ledger empírico debe contrastar esta predicción.

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

Hacer visible y auditable la trayectoria calculada sin alterar el digest.

### 11.2. Campos

- context identity;
- PersistentBinding identity o wire según modo;
- t,k;
- round count;
- H_i para cada ronda;
- S_i o hashes de S_i según audit profile;
- layout plan identity;
- round frame identity;
- Deep branch/fold identities cuando corresponda;
- resulting SigmaDigestV3.

Se definen dos perfiles:

FULL:
conserva intermedios necesarios para replay exhaustivo.

COMPACT:
conserva IDs/hashes suficientes para comparar contra una reevaluación, sin duplicar frames grandes.

### 11.3. Ley de proyección

    project_digest(audit(X)) = SigmaV3(X)

### 11.4. Ley de replay

    verify_audit(X, audit(X)) = Verified

### 11.5. Integridad de ronda

Alterar H_i, S_i, round index, layout identity o frame identity debe producir rechazo en replay salvo la correspondiente colisión criptográfica subyacente.

## 12. TrajectoryCheckpoint V1

### 12.1. Alcance

Reanuda la fase iterada después de que P_X y t,k hayan sido calculados.

No pretende reanudar arbitrariamente la primera pasada de preparación del input.

### 12.2. Estado mínimo

    Q_i =
      context,
      PersistentBinding,
      TrajectoryParameters,
      round_index i,
      H_i,
      S_i,
      suite/profile identifiers

### 12.3. Ley

Si Eval(X) produce Z_0,...,Z_r:

    Continue(Q_i, r-i) = Z_i,...,Z_r

y el digest final coincide exactamente con la evaluación directa.

### 12.4. Seguridad semántica

Un checkpoint válido prueba consistencia interna con su P_X. Para demostrar que P_X corresponde a una fuente X concreta se exige verify_checkpoint_source(X,Q_i).

## 13. VerificationPolicy V1

### 13.1. Objetivo

Separar parseabilidad, verificabilidad y aceptabilidad operacional.

Una policy puede fijar:

- allowed v3 suite IDs;
- require history-feedback;
- allow/deny legacy v2.2;
- allow/deny Tree-only artifacts;
- require dual evidence;
- require signature;
- max input bytes;
- max tree proof size;
- max trajectory rounds;
- max memory/work policy;
- allowed artifact metadata profiles;
- symlink policy;
- provenance requirements.

### 13.2. Orden de policies

Se define una relación partial order de restricción:

    P_strict <= P_weak

si todo objeto aceptado por P_strict es también aceptado por P_weak bajo los mismos verificadores.

No es obligatorio decidir automáticamente el orden para policies arbitrarias en V1; puede existir para un subconjunto normalizado.

### 13.3. Resultado

    verify(..., policy=P) -> VerificationDecision

con:

- Accepted;
- Rejected(reason);
- Inconclusive(reason);
- Unsupported(reason).

## 14. VerificationReceipt V1

### 14.1. Objetivo

Registrar qué verificador ejecutó qué policy sobre qué objeto.

Campos:

- artifact identity;
- policy identity;
- verifier package version;
- verifier build/commit identity opcional;
- verification mode;
- result;
- evidence hashes;
- optional timestamp claim;
- optional standard signature.

### 14.2. Claim boundary

El receipt prueba que un verificador produjo ese record. No convierte una claim de provenance en verdadera por sí mismo.

## 15. Batch verification

BatchVerify es una capa de scheduling:

    BatchVerify(items) = map(Verify, items)

Puede paralelizar, pero cada item conserva su resultado, evidence identity y error.

No hay state sharing criptográfico entre items.

Ley:

    batch[i] = single_verify(item_i)

para todo i.

## 16. Familia C — Sigma Artifact V1

### 16.1. Modos

TREE:
contiene evidencia Sigma Tree.

TRAJECTORY:
contiene SigmaDigestV3 y opcional TrajectoryAudit.

DUAL:
contiene TreeRoot + SigmaDigestV3.

### 16.2. Record

SigmaArtifactV1 contiene:

- artifact format version;
- artifact profile;
- canonical descriptor;
- optional TreeRoot;
- optional SigmaDigestV3;
- optional manifest identity;
- optional provenance claims;
- optional parent artifact IDs;
- optional signature.

### 16.3. Dual verification

Para profile DUAL:

    VerifyDual(X,A) =
      VerifyTree(X,A.tree)
      AND
      VerifyTrajectory(X,A.trajectory)

No se deriva ninguna claim criptográfica adicional salvo esta conjunción lógica.

### 16.4. Artifact identity

ArtifactId se calcula sobre el record canónico sin su firma externa para evitar circularidad.

La firma autentica ArtifactId + record canónico versionado.

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
