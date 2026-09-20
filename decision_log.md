# Decision Log

## 2026-09-19 — Sigma-IAP es una familia v3 incompatible

Decision:
Sigma v2.2 permanece congelada. La nueva construcción usa IDs, contexto, wire,
vectores y evidencia v3 separados.

Reason:
El binding persistente, la inicialización, las rondas, los parámetros derivados
y el juego de seguridad cambian la función matemática.

Impact:
La implementación se desarrolla en `sigma-v3-iap`; el baseline v2.2 se protege
con hashes y regresiones byte-exactas.

## 2026-09-19 — Cierre normativo previo a R1

Decision:
Se cierran SPEC-V3-003/004/005/006 según
`specification/sigma-v3-r1-decisions.md`: dominio de bytes, primitivas de 512
bits, una sola suite reference con evidencia `IMPLICIT_J`, y layout tipado como
`INIT` o `ROUND`.

Reason:
Los tipos, IDs y codecs no pueden fijarse antes de decidir qué función y wire
representan.

Impact:
Todo cambio posterior de esas decisiones exige nuevos IDs y vectores.

## 2026-09-19 — Cierre normativo R3 de fuentes y binding

Decision:
La suite reference usa fuentes replayables de bytes exactos, dos pasadas normativas y los
transcripts de ancla, longitud y firma conjunta fijados en
`specification/sigma-v3-r3-binding.md`. Los streams no seekable se capturan con límites
explícitos y los ficheros se vigilan con metadata más digest de consistencia.

Reason:
`A_X` precede a `J_X`, por lo que hacen falta dos lecturas, pero la segunda puede
compartirse con la futura inicialización. La estabilidad de los bytes forma parte del
contrato criptográfico, no es una suposición del caller.

Impact:
Cambiar orden, tags, dominios, política de replay o componentes requiere nuevos IDs y
vectores v3.

## 2026-09-19 — Los PASS adversarios son artefactos versionados

Decision:
Ningún hito `Rn` se considera cerrado si su revisión adversaria no está guardada en
`docs/adversarial-reviews/Rn.md` y registrada en el mismo historial de Git que el
cierre. El informe debe identificar el candidato revisado, comandos y resultados
del gate, baseline v2.2, hallazgos y correcciones, revalidación final y veredicto
`PASS`. Un mensaje de chat o un resultado de agente no versionado no constituye
evidencia de cierre.

Reason:
El veredicto debe poder relacionarse de forma reproducible con los bytes exactos
revisados y sobrevivir fuera de la sesión que lo produjo.

Impact:
Los PASS atribuidos anteriormente a R0–R8 quedan como antecedentes no trazables.
Cada fase deberá someterse de nuevo a una única revisión adversaria y versionar su
informe antes de recuperar el estado de cerrada. No se avanzará desde un candidato
de fase mientras falte esa evidencia.

## 2026-09-19 — Deep y DeepVector v3 son suites y claims distintos

Decision:
R9 asigna `0x0303` a Deep escalar y `0x0304` a DeepVector. Deep pliega
explícitamente todas las ramas bajo `DEEP_FOLD (0x0310)`; DeepVector conserva
`4 × 64` bytes y cada rama recibe el vector anterior completo. Los backends sólo
ejecutan tareas canónicas construidas por el core.

Reason:
Un fold escalar y un estado vectorial no preservan la misma información ni
admiten los mismos claims. Entregar semántica a cada backend permitiría que
serial, threads y procesos implementasen funciones accidentalmente distintas.

Impact:
Los perfiles tienen IDs, contextos, anchos, evaluaciones y verificadores
despachados distintos. No se describirá Deep como vectorial ni DeepVector como
cuatro cadenas independientes.

## 2026-09-20 — I/O y scheduling no cambian la función v3

Decision:
R10 fija una única evaluación canónica para bytes, fichero estable, snapshot
mmap, reader spooled e incremental. El fichero mmap siempre se deriva de una
snapshot privada verificada. Cada checkpoint incremental ejecuta una Sigma v3
completa sobre su prefijo. La cancelación sólo ocurre en fronteras canónicas y
nunca publica resultados parciales.

Reason:
La construcción necesita múltiples replays idénticos del mensaje. Reutilizar un
anchor incremental, mapear directamente un path mutable o permitir que cada
backend reconstruya frames produciría funciones distintas según el camino de
I/O o abriría carreras TOCTOU.

Impact:
Los caminos de entrada deben ser byte-idénticos, los límites de spool son
explícitos y todos los temporales, mappings y procesos se liberan en éxito,
error y cancelación.


## 2026-09-20 — El estado histórico forma parte del binding efectivo de ronda

Decision:
R12 se conserva como baseline histórico de la recurrencia con binding
persistente fijo. Antes de R13 se abre R12.5 para introducir un compromiso
histórico H_i y un binding efectivo E_i=(P_X,H_i). El estado matemático de la
trayectoria pasa a ser Z_i=(H_i,S_i); una igualdad puntual de S_i no debe
coalescer dos historias distintas.

Reason:
La intención completa de Sigma-IAP exige retroalimentar causalmente el pasado de
la trayectoria. El R12 actual reinyecta S_i como base del frame y P_X como
binding fijo, pero no conserva una memoria criptográfica separada de estados
anteriores.

Impact:
Se deben definir HistorySeed/HistoryStep, decidir la dependencia del layout,
actualizar frames y evaluadores, regenerar corpus/KAT/reference y repetir la
revisión adversarial antes de formalizar R13. Los IDs y artefactos R12 no se
reescriben silenciosamente.

## 2026-09-20 — El paper se gobierna por una matriz científica de ataques y evidencia

Decision:
La planificación de publicación se divide en R13 seguridad/criptoanálisis,
R14 freeze y prerregistro, R15 confirmatorio y R16 reproducción/auditoría
externa. Las campañas y baselines están definidas en
docs/paper-cryptographic-validation-plan-v3.md.

Reason:
Tests de conformidad, difusión o aleatoriedad no sustituyen juegos de seguridad,
reducciones ni ataques. Cada claim debe ser falsable y trazable a raw data,
artefacto, baseline y nivel de evidencia.

Impact:
Ninguna cifra de piloto se usa como resultado confirmatorio. R12 se mantiene
como baseline de ablación para medir exactamente el efecto del feedback
histórico.
