# Endurecimiento de pruebas v2-2

Fecha de corte: 2026-09-02. Estos resultados son campañas de desarrollo, no
resultados confirmatorios ni evidencia criptográfica.

## Capas permanentes

- Tests de ejemplo y vectores para comportamiento exacto.
- Propiedades Hypothesis deterministas para contextos registrados, round-trip
  de digest/evidencia/KDF, bytes arbitrarios y rechazo sin coerciones.
- Fuzzer mutacional reproducible (`scripts.fuzz_codecs`) sobre siete codecs.
- Objetivo Atheris (`scripts.fuzz_atheris`) con selector de codec, límite de
  64 KiB, corpus canónico compartido y fallo ante aceptación no canónica.
- Mutmut 3 configurado sobre `sigma/`, con tests unitarios y de propiedades en
  un árbol aislado. `mutants/` es un artefacto local ignorado por Git.

## Campañas ejecutadas

### Atheris 3.1.0 / CPython 3.13.12

Comando:

```console
python scripts/fuzz_atheris.py --write-corpus /tmp/sigma-v22-fuzz-corpus
python scripts/fuzz_atheris.py /tmp/sigma-v22-fuzz-corpus \
  -atheris_runs=10000 -max_len=65537
```

Resultado: 10.000 ejecuciones, cero crashes, cobertura final comunicada por el
motor `cov=265`, `ft=467`, corpus minimizado/ampliado a 54 entradas. Estas
magnitudes sólo son comparables dentro del mismo build e instrumentación.

### Mutmut 3.7.0 / codec TLV

Primera pasada: 125 de 189 mutantes muertos. Se añadieron fronteras exactas de
anchura, tags, longitudes TLV, truncados en posiciones posteriores, secuencias
vacías y máximas y dominios. Segunda pasada: 149 muertos; tres supervivientes
conductuales seleccionados quedaron muertos en la repetición dirigida. Estado
actual del módulo: 152/189 muertos (80,4 %) y 37 supervivientes pendientes de
clasificación completa. La inspección muestreada incluye mutaciones equivalentes
del centinela inicial y mutaciones sólo de texto diagnóstico; no se declararán
equivalentes las restantes sin revisión individual.

## Política del gate

Un crash inesperado, una representación aceptada que no round-trip o un mutante
conductual confirmado bloquea el gate. La tasa bruta de mutación no se usa como
umbral de publicación porque incluye mutaciones equivalentes y texto fuera del
contrato; el informe debe conservar muertos, supervivientes, timeouts y errores
por separado.
