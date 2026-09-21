# Sigma v3 confirmatory preregistration — R14 template

Estado: **TEMPLATE / NOT FROZEN / NOT AUTHORIZED FOR CONFIRMATORY RUNS**

Este archivo define la estructura obligatoria del prerregistro v3. Durante R14
se sustituirán todos los placeholders por valores congelados y se cambiará el
estado a FROZEN sólo mediante el gate R14.

## 1. Frozen baselines

- R12.5 construction commit: <R12_5_COMMIT>
- R13 design commit: <R13_COMMIT>
- R14 freeze commit/tag: <R14_COMMIT_TAG>
- wheel SHA-256: <WHEEL_SHA256>
- sdist SHA-256: <SDIST_SHA256>
- SBOM SHA-256: <SBOM_SHA256>
- freeze manifest SHA-256: <FREEZE_SHA256>

## 2. Primary claims

Por cada claim:

- claim_id;
- statement;
- evidence class;
- primary/secondary;
- attack_ids;
- baseline;
- falsification condition;
- interpretation if negative;
- limitations.

## 3. Campaign table

Por cada attack/config:

- attack_id;
- construction/suite;
- factors/cell IDs;
- widths/workloads;
- ResourceBudget;
- sample size;
- replicates;
- discovery/holdout/confirmatory status;
- timeout;
- stopping rule;
- censoring rule;
- raw schema;
- primary metric;
- secondary metrics;
- analysis function;
- multiplicity family;
- figure/table output.

## 4. Seed derivation

Confirmatory seeds:

`SHA256("sigma-v3-r15" || freeze_id || attack_id || cell_id || replicate_id)`.

Discovery usa un namespace distinto y nunca reutiliza seeds confirmatorias.

## 5. Statistical analysis

Debe fijar antes de freeze:

- estimators;
- confidence levels;
- bootstrap method/replicates;
- survival/censoring method;
- GOF method;
- paired/unpaired design;
- primary multiplicity correction;
- exploratory correction;
- treatment of missing/error/timeout data.

## 6. Stopping and censoring

No optional stopping por p-value o dirección del efecto.

Cada run termina sólo por:

- success definido;
- agotamiento del budget;
- censoring rule predefinida;
- timeout predefinido;
- execution error.

## 7. Discovery/holdout

Para attackers heurísticos:

- discovery fraction: <...>;
- holdout fraction: <...>;
- tuning parameters: <...>;
- freeze point: <...>.

## 8. Hosts and environments

Por host:

- OS;
- architecture;
- CPU;
- Python;
- dependency lock;
- worker/process policy;
- power/governor policy;
- warm-up;
- measurement instrumentation.

## 9. Figures and tables

Cada figura/tabla debe indicar:

- source attack IDs;
- raw fields;
- filtering rules;
- transform;
- estimator;
- uncertainty;
- axis definitions;
- whether primary or descriptive.

## 10. Exclusions

Lista cerrada de:

- conditional attacks no ejecutados;
- side-channel no aplicable;
- hardware no aplicable;
- cualquier claim explícitamente fuera de R15.

## 11. Integrity

El freeze final debe hash-ear:

- este prerregistro;
- todos los configs;
- schemas;
- attackers;
- analysis scripts;
- synthetic fixtures;
- wheel/sdist/SBOM;
- corpus/reference;
- figure builders.

Cualquier cambio posterior invalida el freeze.
