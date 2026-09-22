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

Comprometer árboles de directorio, releases y datasets de forma reproducible.

### Implementación

- sigma/tree/manifest.py
- sigma/tree/path.py
- CLI provisional: sigma manifest
- tests/tree/test_manifest_*.py

### Obligaciones

ST1-O01 — Canonical relative paths  
No absolute path, ., .., NUL ni separadores alternativos.

ST1-O02 — Traversal independence  
El orden del sistema de ficheros no afecta el manifest.

ST1-O03 — Root-path independence  
Mover/copiar el mismo árbol lógico no cambia el manifest.

ST1-O04 — Duplicate rejection  
No existen dos entradas con path canónico idéntico.

ST1-O05 — Metadata profile exactness  
mtime/uid/gid/inode no participan en profile base.

ST1-O06 — Symlink safety  
Symlinks se rechazan por defecto; si se habilitan, se compromete el target textual y no se sigue implícitamente.

ST1-O07 — Content binding  
Cambiar TreeRoot de una entrada cambia el manifest.

ST1-O08 — Optional trajectory binding  
Si una entry incluye SigmaDigestV3, dicho digest forma parte exacta del manifest.

ST1-O09 — Deterministic ordering  
Entries ordenadas por bytes UTF-8 canónicos.

ST1-O10 — Complexity  
O(B + F log F) en profile base.

### Tests

Metamórficos:
- touch sin cambio de bytes no cambia base manifest;
- rename sí cambia;
- reorder traversal no cambia;
- copy to another absolute root no cambia;
- executable bit sólo cambia profiles que lo incluyan.

Adversarial:
- symlink loops;
- path traversal;
- invalid UTF-8 source names según policy;
- very large number of entries;
- duplicate normalized paths.

### Gate ST1

Manifest independiente debe reconstruir el mismo wire a partir de fixture directory en Linux/macOS cuando la representación lógica sea la misma.

## 5. ST2 — Inclusion and Range Proofs

### ST2A — Inclusion proofs

Obligaciones:

ST2-O01 — Root reconstruction  
Proof válido reconstruye exactamente la root declarada.

ST2-O02 — Position binding  
Mover leaf a otro índice invalida.

ST2-O03 — Orientation binding  
Swap left/right invalida salvo colisión subyacente.

ST2-O04 — Length binding  
Alterar byte_length o leaf_count invalida.

ST2-O05 — Profile binding  
Proof de un profile no verifica bajo otro.

ST2-O06 — Independent verifier  
reference/tree_proof_v1.py no importa sigma.

ST2-O07 — Size bound  
O(m log N).

### ST2B — Range proofs

Obligaciones:

ST2-O08 — Exact interval  
La proof acredita exactamente [start,start+length).

ST2-O09 — Minimal canonical cover  
La descomposición del intervalo tiene una única forma canónica.

ST2-O10 — Partial edge honesty  
Los bloques extremos parciales se verifican con offset/length exactos.

ST2-O11 — Range reconstruction  
El verificador reconstruye root sin acceder al resto del objeto.

ST2-O12 — Empty/out-of-bounds rejection  
Rangos inválidos se rechazan antes de hashing caro.

### Test matrix

- first/last leaf;
- full object;
- one byte;
- exact chunk;
- crossing chunk;
- 2^k boundaries;
- N = 2^k ± 1;
- corrupted sibling;
- corrupted geometry;
- mixed proof from another tree;
- truncated path;
- duplicate sibling.

### Gate ST2

- 100k generated inclusion proofs;
- 100k generated ranges;
- single-field mutation campaign;
- independent verifier zero divergences;
- proof size empirical slope compatible con O(log N).

## 6. ST3 — Portable Resume

### Objetivo

Reanudar construcción SigmaTree sin serializar estado interno de hashlib.

### Obligaciones

ST3-O01 — Resume equivalence

    finalize(resume(checkpoint(P), S)) = tree(P || S)

ST3-O02 — Frontier canonicality  
Checkpoint sólo contiene una frontier normalizada.

ST3-O03 — Tail bound  
tail < chunk_size.

ST3-O04 — Offset consistency  
completed_bytes = completed_leaf_count * chunk_size + len(tail), salvo último prefijo parcial explícito.

ST3-O05 — Profile consistency  
No se restaura con otro TreeProfile.

ST3-O06 — Transactional checkpoint write  
Un fallo de persistencia no destruye checkpoint anterior.

ST3-O07 — Source hint honesty  
mtime/inode/size se marcan heurísticos; no evidence.

ST3-O08 — Restore cost  
O(m log N).

### Tests

- crash after every leaf boundary;
- crash mid-tail;
- resume multiple times;
- checkpoint corruption;
- wrong source;
- wrong profile;
- append after resume;
- direct vs resumed differential.

### Gate ST3

Property campaign sobre particiones aleatorias del mismo objeto:
100k prefix/suffix splits sin divergencia.

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
