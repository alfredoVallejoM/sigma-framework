# Inventario de preservación Sigma v2.2

Estado: baseline histórico de sólo lectura para el desarrollo v3.  
Commit: `19fb70356971bc1bacb94a19e5e6e48e9e070167`.  
Tag: `f7-v2.2.0a2-20260903`.  
Versión: `2.2.0a2`.

## Activos semánticos protegidos

`constraints/v2-2-baseline.sha256` fija los SHA-256 de los IDs, contexto,
encoding, digest, suites, presets, fachada, aplicaciones, anclas, rondas,
backends, especificación, corpus normativo e implementaciones independientes
v2.2. El guard exige cobertura completa de todos los archivos versionados bajo
`sigma/`, `reference/` y `specification/` en el commit baseline. La comprobación
es:

```console
python -m scripts.check_v22_baseline
```

El manifiesto protege la semántica congelada; cualquier corrección futura de
v2.2 exige una decisión explícita, nuevos IDs cuando corresponda y una
actualización revisada de este baseline.

## Artefactos de release locales

| Artefacto | SHA-256 |
|---|---|
| `dist/sigma_framework-2.2.0a2-py3-none-any.whl` | `d9860e0929a64e4d230799ea54a28be2cb69bf2a2a3cd365c05fb25d2f8ac1b5` |
| `dist/sigma_framework-2.2.0a2.tar.gz` | `25714efa8df2f34d64cc5bc2bf3da879ad2e709de79935d43b8028a507c94d4c` |
| `dist/SHA256SUMS` | `9b140127f3564dd0ba522e74d8d8042e58dd439791f9d1eed112d22a52a94e02` |
| `dist/sigma-framework.cdx.json` | `11d49438d2e18ae3a74ddcaa7f743d10049f894231d2b4d070b1e5b0c75418a7` |

Los artefactos `dist/` están ignorados por Git y deben archivarse por separado.
Su manifiesto local verificable es `constraints/v2-2-local-artifacts.sha256`:

```console
python -m scripts.check_v22_baseline --verify-local-artifacts
```

## Evidencia F7 local

El árbol local `dist/f7-dataset-v2-2` ocupa 5.383.985.608 bytes. Su snapshot
canónico está descrito en `constraints/v2-2-f7-snapshot.json` y tiene SHA-256
`4011ab870bfb4ff632ca66aa78afdbec6cd016b2052703dbee89f3d6b43d1b1a`.
La huella se obtiene incluyendo la ruta raíz y normalizando orden, mtime,
propietario y grupo mediante el comando exacto registrado en ese JSON. Se
verifica, por streaming, con:

```console
python -m scripts.check_v22_baseline \
  --verify-local-artifacts \
  --verify-f7-snapshot
```

La evidencia está incompleta y no constituye el dataset canónico final:

- diez campañas Linux tienen resumen finalizado y reúnen 3.625 de las 5.289
  tareas previstas;
- nueve campañas finalizadas proceden del commit `65adbc6...` y del wheel
  `2.2.0a1`;
- EXP-20 procede de `19fb703...` y del wheel `2.2.0a2`;
- el freeze vigente referencia `2.2.0a2`;
- faltan campañas, segundo host, macOS/Windows y baterías externas.

Por ello estos datos se conservan como evidencia histórica v2.2 y nunca se
reinterpretarán como evidencia de Sigma v3.
