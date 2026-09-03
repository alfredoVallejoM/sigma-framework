# Endurecimiento de pruebas v2-2

Fecha de corte: 2026-09-03. Estos resultados son campañas de desarrollo, no
resultados confirmatorios ni evidencia criptográfica.

El cierre integral posterior al endurecimiento dirigido ejecutó 540 pruebas,
Ruff, mypy sobre 110 módulos y `compileall` sin fallos, y validó el wheel en un
entorno limpio. Esta cifra corresponde al baseline funcional `453b483`; la CI
es la fuente de verdad para revisiones posteriores.

## Capas permanentes

- Tests de ejemplo y vectores para comportamiento exacto.
- Consumidor independiente de las seis suites y PoW/KDF/firma, sin importar
  código `sigma`, usado en pruebas diferenciales byte a byte.
- Propiedades Hypothesis deterministas para contextos registrados, round-trip
  de digest/evidencia/KDF, bytes arbitrarios y rechazo sin coerciones.
- Fuzzer mutacional reproducible (`scripts.fuzz_codecs`) sobre ocho codecs,
  incluido el compromiso firmado.
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

Tras incorporar el compromiso firmado se repitieron 10.000 ejecuciones con
ocho semillas válidas: cero crashes, `cov=301`, `ft=559` y 55 entradas finales.

### Mutmut 3.7.0 / codec TLV

Primera pasada: 125 de 189 mutantes muertos. Se añadieron fronteras exactas de
anchura, tags, longitudes TLV, truncados en posiciones posteriores, secuencias
vacías y máximas y dominios. Segunda pasada: 149 muertos; tres supervivientes
conductuales seleccionados quedaron muertos en la repetición dirigida. Estado
histórico del módulo: 152/189 muertos (80,4 %) y 37 supervivientes.

La clasificación individual de esos 37 produjo 33 cambios exclusivamente de
texto diagnóstico, dos cambios equivalentes del centinela inicial (`-1` a
`-2`, con tags válidos desde 1) y dos omisiones del argumento `byteorder`.
Estas últimas son equivalentes en el intérprete 3.13 de la campaña, cuyo valor
por defecto es big-endian, pero fallan en Python 3.10 y quedan cubiertas por la
matriz CI soportada; no se etiquetan como equivalentes multiplataforma.

Una refactorización posterior introdujo `encode_tlv_field`, por lo que se
descartó la caché histórica para sus mutantes. Se añadieron tests directos de
tipo de excepción, tags `0/65535/65536`, `bool`, float, texto y longitudes
`MAX/MAX+1`. Una campaña limpia dirigida mató los seis mutantes conductuales
identificados (6/6); los restantes de esa función alteran sólo mensajes. La
caché histórica se movió a `/tmp/sigma-mutants-stale-20260903` y no forma parte
del repositorio.

## Política del gate

Un crash inesperado, una representación aceptada que no round-trip o un mutante
conductual confirmado bloquea el gate. La tasa bruta de mutación no se usa como
umbral de publicación porque incluye mutaciones equivalentes y texto fuera del
contrato; el informe debe conservar muertos, supervivientes, timeouts y errores
por separado.
