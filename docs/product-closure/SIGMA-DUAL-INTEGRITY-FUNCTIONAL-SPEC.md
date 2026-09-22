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

    LeafFrame =
      domain ||
      profile ||
      leaf_index ||
      byte_offset ||
      byte_length ||
      bytes

Cada rama j:

    L_i,j = H_j(LeafFrame)

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
- mismo height;
- mismo leaf_count;
- right.start_leaf = left.start_leaf + left.leaf_count.

### 4.6. TreeFrontier

Después de n hojas completas:

    n = Σ b_h 2^h

La frontier contiene como máximo un perfect subtree por altura h con b_h = 1.

Invariante:

    frontier heights son estrictamente crecientes y únicas.

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

Una prueba de inclusión contiene:

- TreeProfile;
- root identity;
- total byte length;
- total leaf count;
- target leaf index;
- target byte offset;
- target byte length;
- path geometry;
- sibling digest vectors.

La geometría se almacena una vez y cada sibling transporta un vector de cuatro digests.

### 5.2. Contrato

    prove_leaf(tree_index, i) -> InclusionProof

    verify_leaf(root, leaf_bytes, proof) -> VerifiedLeaf | Rejected

VerifiedLeaf incluye root reconstruido, leaf identity y proof identity.

### 5.3. Ley principal

Para toda hoja válida i:

    verify_leaf(root(T), leaf_i, prove_leaf(T, i)) = Verified

### 5.4. Complejidad

- proof size: O(m log N);
- generation con index: O(m log N);
- verification: O(m log N);
- verification memory puede mantenerse O(m) más parser.

## 6. RangeProof V1

### 6.1. Alcance

Sólo rangos contiguos [a,b) dentro de un objeto inmutable.

Se distinguen:

- partial first leaf;
- perfect covered subtrees;
- partial final leaf;
- complement frontier necesaria para reconstruir root.

### 6.2. Contrato

    prove_range(index, start, length) -> RangeProof

    verify_range(root, start, data, proof) -> VerifiedRange | Rejected

### 6.3. Ley

Para un rango extraído exactamente de X:

    verify_range(root(Tree(X)), a, X[a:b], prove_range(Tree(X), a, b-a)) = Verified

### 6.4. No claims

Una range proof no acredita frescura, propiedad, timestamp ni trayectoria v3.

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

Comprometer directorios, releases, datasets y colecciones de artefactos sin depender del path absoluto del host.

### 9.2. ManifestEntry

Campos mínimos:

- canonical_relative_path;
- entry_type;
- byte_length;
- TreeRoot;
- optional SigmaDigestV3;
- metadata profile.

Entry types V1:

- regular file;
- directory;
- symbolic link sólo si la policy lo permite explícitamente.

### 9.3. Canonical path

- UTF-8 válido;
- relativo;
- separador /;
- sin NUL;
- sin componentes vacíos;
- sin .;
- sin ..;
- no case folding;
- orden por bytes UTF-8 canónicos.

### 9.4. Metadata profile base

No incluye por defecto:

- mtime;
- ctime;
- uid;
- gid;
- inode.

Puede incluir executable bit mediante un profile ID separado.

### 9.5. Leyes

Traversal independence:

    Manifest(FS) no depende del orden devuelto por os.scandir.

Root independence:

    copiar el mismo árbol lógico a otro path absoluto produce el mismo manifest.

Content sensitivity:

    si una entrada cambia su TreeRoot o SigmaDigest incluido, cambia el manifest canónico.

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
