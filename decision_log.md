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
