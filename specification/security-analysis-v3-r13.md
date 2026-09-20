# Sigma v3 / R12.5 — análisis formal de seguridad R13

Estado: **R13 formalization candidate; no cryptographic-review claim**  
Fecha: 2026-09-20  
Construcción de referencia: R12.5 candidate \`5ac306bb23acae0e0a4ef03eb56b3062343c2127\`.

Este documento comienza R13. Distingue propiedades de encoding, reducciones,
modelos ideales, predicciones genéricas y preguntas abiertas. Ninguna anchura
física se convierte automáticamente en "bits de seguridad".

## 1. Objetos

Para un contexto canónico válido \`C\` y mensaje canónico \`M\`:

\[
P_M=(A_M,\kappa_M,\Lambda_M,J_M)
\]

es el binding persistente. Los parámetros públicos son

\[
(t_M,k_M)=\operatorname{DeriveParameters}(C,P_M).
\]

La inicialización produce \`S_0\`. La historia causal es

\[
H_0=\operatorname{HistorySeed}(C,P_M),
\qquad
H_{i+1}=\operatorname{HistoryStep}(C,P_M,i,H_i,S_i).
\]

El estado dinámico completo es

\[
Z_i=(H_i,S_i).
\]

La transición WideOnce-history usa

\[
Q_i=\operatorname{EncRound}(C,i,P_M,H_i,S_i)
\]

y

\[
S_{i+1}=F(Q_i).
\]

Deep sustituye una llamada escalar por ramas más fold; DeepVector conserva el
vector completo. La ventana pública es

\[
W_{t,k}=(S_t,\ldots,S_{t+k-1}).
\]

## 2. Recursos del adversario

Todo resultado R13 debe publicar al menos

\[
\mathcal R=(W,Q_A,Q_J,Q_H,Q_R,d,p,\mu,u),
\]

donde:

- \`W\`: trabajo total;
- \`Q_A\`: consultas/ejecuciones del anchor;
- \`Q_J\`: consultas/ejecuciones de joint signature;
- \`Q_H\`: consultas al history mechanism;
- \`Q_R\`: consultas de ronda/branch/fold;
- \`d\`: profundidad adaptativa;
- \`p\`: procesadores;
- \`\mu\`: memoria;
- \`u\`: objetivos/usuarios.

Wall time, query count y profundidad adaptativa no son intercambiables.

## 3. Juegos

### G-COLL

El adversario devuelve dos entradas canónicas distintas aceptadas por la misma
política cuya evidencia pública completa coincide.

### G-PRE

El challenger fija una distribución objetivo y entrega un digest. El adversario
devuelve cualquier mensaje que verifique contra ese digest. La min-entropía de
la fuente forma parte del juego.

### G-2PRE

El challenger entrega \`(C,M,\Sigma(C,M))\`. El adversario devuelve
\`M'\neq M\` con el mismo digest.

### G-SEG-COLL

El adversario devuelve dos ejecuciones distintas cuya ventana pública
\`W_{t,k}\` coincide. Igualar una ventana no se interpreta como prueba externa de
que el adversario ejecutó honestamente el prefijo.

### G-TRAJ-2PRE

Segunda preimagen estructurada: dado \`M\`, producir \`M'\neq M\` con el mismo
header público y la misma ventana, registrando además si
\`P_{M'}=P_M\`, si sólo difiere \`J\`, y el primer índice donde difieren
\`H_i\` o \`S_i\`.

### G-STATE-CROSS

El challenger presenta dos estados dinámicos válidos del mismo índice con

\[
S_i=S'_i,\qquad H_i\neq H'_i.
\]

El adversario gana si consigue que las trayectorias se comporten como si
hubieran coalescido sin pagar los eventos criptográficos necesarios.

### G-FULLSTATE-COLL

Encontrar ejecuciones distintas con

\[
Z_i=Z'_i=(H_i,S_i)
\]

en un índice especificado.

### G-HIST-COLL / G-HIST-2PRE

Juegos separados contra \`HistorySeed/HistoryStep\`. No se infiere su seguridad
de la anchura del digest.

### G-MULTI

Ataque contra cualquiera de \`u\` objetivos explícitos. Todo bound paga el
factor multi-target correspondiente; no existe "multi-user security gratis".

### G-CONFORM

Un adversario de implementación elige adapters, chunking, backend, workers e
I/O. Gana si dos ejecuciones conformes sobre los mismos bytes/contexto discrepan.
Éste no es un juego criptográfico.

## 4. FORM-01 — canonicalidad

**TH-R13-01 (injectividad de objetos aceptados).** Condicionado a que cada
parser aplique el contrato byte-exacto R12.5, los encodings aceptados de
contexto, persistent binding, history, round binding, layout, placed stream,
frames, header, window y digest son inyectivos dentro de su tipo.

**Estatus:** \`proved-from-codec-contract\` + evidencia ejecutable.

El argumento usa tags cerrados/ordenados, anchuras fijas, longitudes explícitas,
magic/version/domain y rechazo de unknown/duplicate/reordered/truncated/trailing
bytes. Fuzzing y property tests son evidencia de implementación, no sustitutos
del argumento.

## 5. FORM-02 — historia causal

**TH-R13-02 (prefijo causal exacto).** Para toda ejecución conforme,

\[
H_i=\Phi(C,P_M,S_0,\ldots,S_{i-1})
\]

para una función determinista \`\Phi\`, y \`H_i\` no depende de \`S_i\`.

**Prueba.** Inducción. \`H_0\` depende sólo de \`(C,P_M)\`. Si el enunciado vale
para \`i\`, \`HistoryStep(C,P_M,i,H_i,S_i)\` produce \`H_{i+1}\`, que depende
exactamente del prefijo extendido hasta \`S_i\`. QED.

**Estatus:** \`proved\` respecto de la especificación.

## 6. FORM-03 — separación histórica de frames

**TH-R13-03 (frame separation).** Fijados contexto, suite e índice válidos:

\[
(H_i,S_i)\neq(H'_i,S'_i)
\Longrightarrow
Q_i\neq Q'_i
\]

si ambos frames son aceptados bajo el mismo contrato semántico.

En particular,

\[
S_i=S'_i,\quad H_i\neq H'_i
\Longrightarrow
Q_i\neq Q'_i.
\]

**Argumento.** \`H_i\` es un campo explícito del effective binding y del placed
stream; además participa en la seed del layout. Aunque dos histories produjeran
el mismo plan de slots, el field record de history seguiría siendo diferente.
Si sólo cambia \`S_i\`, cambia la base length-framed. La injectividad del frame
concluye el resultado.

**Estatus:** \`proved-from-encoding\`. No requiere supuesto de hash.

## 7. FORM-04 — no coalescencia condicionada

Sea \`F\` un RO ideal de \`n\` bits para la transición escalar. Por TH-R13-03,
si

\[
S_i=S'_i,\quad H_i\neq H'_i,
\]

las dos consultas de ronda son distintas. Si ambas son fresh,

\[
\Pr[S_{i+1}=S'_{i+1}]=2^{-n}.
\]

Esto es una probabilidad de modelo ideal, no una afirmación concreta sobre
SHA-512.

Para el history oracle ideal de \`h\` bits, los inputs de
\`HistoryStep\` también son distintos cuando \`H_i\neq H'_i\`, por lo que,
condicionado a freshness,

\[
\Pr[H_{i+1}=H'_{i+1}]=2^{-h}.
\]

No se multiplican ambos factores salvo que se justifique independencia entre
los oráculos/instancias concretas.

**Estatus:** \`ideal-model\`.

## 8. FORM-05 — coalescencia del estado completo

**TH-R13-04 (suficiencia de igualdad completa).** Para contexto, persistent
binding e índice iguales, si

\[
Z_i=Z'_i,
\]

entonces los frames y successors deterministas de las dos ejecuciones son
iguales. Además \`HistoryStep\` recibe los mismos bytes, luego

\[
Z_{i+1}=Z'_{i+1}.
\]

Por tanto igualdad del estado dinámico completo es una condición suficiente para
coalescencia futura. Igualdad de \`S_i\` sola no lo es.

**Estatus:** \`proved\`.

## 9. FORM-06/07 — ventana multiestado

Condicionado al evento de que las histories permanezcan distintas durante una
ventana de \`k\` estados y a consultas fresh/separadas de un RO ideal de \`n\`
bits, cada igualdad observable requiere una nueva igualdad entre outputs de
queries distintas.

Bajo independencia ideal explícita:

\[
\Pr[W_{t,k}=W'_{t,k}\mid
H_{t+r}\neq H'_{t+r}\ \forall r]
=2^{-kn}.
\]

El bound completo debe incluir al menos:

\[
\Pr[\text{window match}]
\le
\Pr[\text{history merge}]
+
2^{-kn}
+
\Pr[\mathrm{Bad}_{Q}]
+
\epsilon_{\mathrm{inst}}.
\]

No se sustituye \`\Pr[\text{history merge}]\` por \`2^{-h}\` en un teorema de
instanciación concreta sin reducción separada.

**Estatus:** \`ideal-model / reduction obligation\`.

## 10. FORM-06 — collision, preimage y second-preimage siguen separados

Collision resistance del anchor o del history no implica preimage resistance.

Definimos parámetros abstractos, no anchuras físicas:

- \`\alpha_{\rm coll}(P)\`;
- \`\alpha_{\rm pre}(P)\`;
- \`\alpha_{\rm 2pre}(P)\`;
- \`\alpha_{\rm coll}(H)\`;
- \`\alpha_{\rm 2pre}(H)\`;
- \`\alpha_{\rm coll}(R)\`, según perfil de ronda.

Toda reducción futura debe usar el parámetro correspondiente.

Para G-TRAJ-2PRE se distinguen al menos:

1. \`P_{M'}=P_M\`: ataque contra binding persistente más trayectoria;
2. mismo header público pero \`P_{M'}\neq P_M\` (por ejemplo \`J\` distinto):
   histories separadas desde genesis;
3. header público distinto: no es una segunda preimagen del digest canónico.

No se declara todavía un bound final de instanciación.

## 11. FORM-08 — Deep

Deep produce ramas y un fold escalar. History separa los inputs de branch entre
historias distintas, pero el estado visible final sigue limitado por el fold de
64 bytes.

Una propiedad fuerte de una rama no basta para atribuirla al digest Deep si el
fold no satisface la propiedad requerida. El análisis debe nombrar:

- propiedad de cada branch;
- propiedad del fold;
- hipótesis de composición/correlación.

**Estatus:** \`reduction obligation\`.

## 12. FORM-09 — DeepVector

DeepVector mantiene el vector completo y cada branch consume el vector previo
completo, el effective binding y el history. Igualdad del vector publicado
implica igualdad de cada componente.

Un componente conservadoramente seguro puede soportar una reducción
seleccionada; cuatro componentes de 512 bits no autorizan afirmar 2048 bits de
seguridad. La correlación entre SHA3/SHAKE y entre ramas permanece explícita.

**Estatus:** \`conditional reduction\`.

## 13. FORM-10 — parámetros derivados y grinding

El rejection sampling elimina sesgo modular para una semilla fija en el modelo
XOF. No elimina selección adversaria entre muchas semillas/bindings.

Si un estrato tiene probabilidad \`p\`, un adversario capaz de generar bindings
independientes necesita geométricamente un número esperado \`1/p\` de
preparaciones para encontrarlo. Para un par exacto \`(t,k)\` bajo distribución
uniforme sobre 31×3 pares, el valor ideal es \`p=1/93\`; esto no modela por sí
solo el coste total ni la correlación de una instanciación.

Consecuencia: KDF y PoW requieren juegos de grinding propios antes de afirmar
coste uniforme por candidato.

**Estatus:** \`proved probability identity / empirical instantiation open\`.

## 14. FORM-11 — layout

El layout R12.5 depende de \`C,\Lambda,H_i,i,L\`. Es history-adaptive.

Una colisión del layout no coalesce histories porque \`H_i\` se serializa además
como field value dentro del placed stream. El placement se considera estructura
de separación/difusión, no una fuente independiente de bits de seguridad.

**Estatus:** \`proved-from-encoding\`.

## 15. FORM-12 — aplicaciones

### Firma

Ed25519 autentica el digest serializado. Sigma no incrementa la fuerza EUF-CMA
de Ed25519. \`verify_signed_digest_v3\` y \`verify_full_signed_v3\` responden
preguntas distintas.

### KDF

Argon2id conserva toda atribución de memory-hardness. Sigma añade binding y
trabajo determinista. Antes de afirmar coste adicional por guess debe medirse
PARAM-04: un candidato incorrecto podría ser descartado por \`(t,k)\` antes de
pagar toda la trayectoria.

### PoW

El nonce entra antes de \`P,t,k,H_0\`. El adversario puede buscar nonces que
caigan en estratos baratos. PARAM-05 debe cuantificar el efecto. No existe claim
VDF/PoSW/consenso/ASIC.

## 16. FORM-13 — Bad events

Los proofs R13 deben enumerar explícitamente:

- \`BadEnc\`: fallo de canonicalidad/domain separation;
- \`BadFresh\`: una consulta tratada como fresh ya apareció;
- \`BadHist\`: colisión/segunda preimagen relevante del history;
- \`BadP\`: ataque contra persistent binding;
- \`BadFold\`: fallo de fold en Deep;
- \`BadInst\`: desviación de las primitivas concretas frente al modelo ideal.

No se ocultan dentro de un único \`\epsilon\` si tienen interpretación distinta.

## 17. Obligaciones abiertas antes de R14

1. completar reducción G-TRAJ-2PRE;
2. ejecutar modelos reducidos HIST-01..06;
3. cuantificar grinding \`(t,k)\`;
4. implementar atacantes TMTO;
5. comparar R12 vs R12.5 bajo coste normalizado;
6. validar Deep/DeepVector con ramas/folds rotos;
7. congelar claim matrix y atacantes antes del prerregistro;
8. revisión criptográfica externa sigue fuera de R13.

R13 sólo cierra cuando la matriz claim→supuesto→teorema→ataque→experimento está
completa y ningún claim depende de una batería estadística como prueba de
seguridad.
