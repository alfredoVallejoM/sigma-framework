# Revisiones adversarias de Sigma v3

Un hito `Rn` sólo puede marcarse como cerrado cuando existe un informe
`docs/adversarial-reviews/Rn.md` versionado junto con el candidato aprobado.

Cada informe debe contener, como mínimo:

- fase y fecha UTC;
- commit o identificador inmutable del candidato revisado;
- alcance y requisitos del gate;
- identidad de la revisión adversaria;
- comandos exactos ejecutados y sus resultados;
- resultado de `python -m scripts.check_v22_baseline`;
- hallazgos, severidad y correcciones aplicadas;
- revalidación posterior a las correcciones;
- limitaciones pendientes;
- veredicto final `PASS` o `FAIL`.

Un `PASS` comunicado únicamente en una conversación no es evidencia válida. Si el
candidato cambia después del informe, el `PASS` queda invalidado y debe repetirse
la revisión. Los informes históricos no se fabrican retrospectivamente: R0–R8
requieren una nueva revisión sobre un candidato identificable.
