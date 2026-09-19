# Sigma v3 — evidencia, wire y verificación (R8)

Estado: **normativo para `REFERENCE_IAP_V3`**  
Fecha: 2026-09-19

`SigmaDigestV3` usa magic `SIGMA3DG`, versión 3 y campos TLV: (1)
`IMPLICIT_J (0x0301)` como uint16, (2) `domain_tag_v3(EVIDENCE)`, (3) contexto,
(4) `PublicTrajectoryHeader`, (5) `TrajectoryWindow`. No serializa `J`.

`ExplicitAuditEvidenceV3` es un envelope distinto con magic `SIGMA3EA`: (1) suite
exterior `EXPLICIT_AUDIT_V3 (0x0302)`, (2) perfil `EXPLICIT_BINDING (0x0302)`,
(3) domain `EXPLICIT_EVIDENCE (0x030f)`, (4) digest implícito completo y (5)
`PersistentBinding`. La suite exterior identifica el perfil de publicación; la
trayectoria permanece identificada por el contexto del digest anidado. No es
intercambiable con el digest principal y comprueba
que sus campos públicos coincidan y que el binding completo, incluido `J`, derive
exactamente los `(t,k)` publicados. Esta comprobación aún no vincula `J` al
mensaje: `verify_explicit_full_v3` recomputa además binding y trayectoria desde la
fuente canónica.

`verify_structure_v3` sólo parsea/coteja invariantes y devuelve explícitamente
`message_binding_verified=False`. `verify_prepared_v3` compara contra una
evaluación completa ya preparada. `verify_full_v3` recibe bytes canónicos,
recalcula binding, parámetros, layouts y toda la ventana, y compara el wire
completo en tiempo constante respecto de los bytes finales.
