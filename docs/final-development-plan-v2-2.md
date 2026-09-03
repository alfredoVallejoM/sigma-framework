# Plan final de desarrollo de Sigma v2.2

Estado: **plan rector vigente**  
Fecha de congelación de alcance: 2026-09-03  
Línea activa: Sigma v2.2 (`2.2.0a1` durante el desarrollo)  
Ejecución: fases 0–6 cerradas; F7 congelada y preparada para ejecución;
F8–F9 pendientes

Este documento es la única planificación ejecutable del proyecto. El addendum,
las auditorías fechadas y los planes anteriores conservan contexto hasta su
retirada, pero no autorizan trabajo ni definen el estado actual.

## 1. Objetivo de entrega

La entrega final debe contener una única implementación Sigma v2.2 coherente,
su especificación normativa, pruebas locales reproducibles, una implementación
independiente, campañas confirmatorias preregistradas, un dataset canónico y un
manuscrito generado desde esa evidencia.

Sigma seguirá declarándose experimental hasta recibir revisión criptográfica
externa. Pasar pruebas, observar difusión o publicar un artículo no constituye
por sí mismo una garantía de seguridad.

## 2. Decisiones vinculantes

1. Sigma v2.2 es la única línea activa, normativa y publicable.
2. v1 y v2.1 no aportarán resultados, vectores ni claims al artículo vigente.
3. La historia reside en Git; no se duplicará como evidencia en el árbol final.
4. GitHub Actions queda fuera de este programa. La calidad se controlará con un
   gate local único, reproducible y con salida verificable.
5. Los pilotos validan runners y dimensionan el prerregistro. Sus datos no son
   evidencia del artículo y se descartan al comenzar el confirmatorio.
6. Sólo existirá un dataset confirmatorio oficial para la versión final.
7. Ninguna cifra, tabla o figura del artículo se editará manualmente.
8. EXP-13 y EXP-16 seguirán fuera de alcance mientras no existan un núcleo
   nativo y un artefacto RTL reproducible, respectivamente.

## 3. Gates y orden obligatorio

Las fases se ejecutan en orden. Un gate exige código, tests y evidencia de
aceptación; una implementación parcial no lo cierra.

### Fase 0 — Alcance y línea vigente

Entregables:

- este plan rector;
- [`current-scope-v2-2.md`](current-scope-v2-2.md), con inventario de
  conservación y retirada;
- v2.2 declarada como única línea activa;
- jerarquía documental y política de evidencia únicas;
- decisión transitoria sobre v1/v2.1.

Criterio: cualquier lector puede distinguir implementación vigente, material
transitorio y trabajo futuro sin recurrir a documentos históricos.

Estado: **cerrada documentalmente**. La retirada física se ejecuta en fase 5,
después de disponer del gate local.

### Fase 1 — Corrección funcional y semántica

Estado: **cerrada**. KDF usa secreto no serializable y verificador público
separado; defaults y PoW están ligados a v2.2; los ejes de madurez son
independientes; trazas y snapshots cumplen la política definida.

#### F1.1 — Composición KDF cerrada

- Centralizar la validación de las suites admitidas por KDF.
- Aplicarla en construcción, `bind`, deserialización y verificación.
- Rechazar v1, v2.1, suites v2.2 no registradas, IDs desconocidos y contextos
  alterados.
- Verificar salt, parámetros Argon2id, application context y política antes del
  trabajo costoso.
- Añadir regresiones de downgrade y manipulación de wire.

#### F1.2 — Separación entre secreto y verificador

- Separar el resultado secreto de derivación del registro público de
  verificación.
- Impedir que un registro serializado exponga o permita reconstruir una clave
  de aplicación.
- Definir ciclo de vida y persistencia permitida de cada tipo.
- Regenerar los vectores KDF conforme al modelo definitivo.

#### F1.3 — API inequívocamente v2.2

- Eliminar defaults implícitos v2.1 o sustituirlos por un preset v2.2 normativo.
- Exigir contexto explícito en operaciones sensibles.
- Versionar de nuevo PoW si el cambio altera su wire o sus vectores.
- Retirar aliases ambiguos de la API publicable.

#### F1.4 — Estados de madurez separados

Definir por separado wire congelado, vectores congelados, suite estable y
revisión criptográfica completada.

#### F1.5 — Política y snapshots

- Aplicar `ResourcePolicy` a trazas y a toda ruta costosa.
- Separar el contrato de archivo mutable del de snapshot ya estable.
- Garantizar una sola copia temporal en el backend multiproceso.

Gate F1:

- todos los bypass KDF rechazados;
- ningún verificador público contiene una clave de aplicación;
- API y aplicaciones seleccionan v2.2 sin ambigüedad;
- terminología de madurez coherente;
- una sola estabilización por archivo;
- regresión automatizada para cada corrección.

### Fase 2 — Arquitectura, formatos y conformidad

Estado: **cerrada localmente**. La auditoría, matrices y corpus normativo están
registrados en [`conformance-audit-v2-2.md`](conformance-audit-v2-2.md). La
reproducción externa continúa siendo una obligación de R5/R6.

- Auditar todos los TLV: orden, unicidad, campos obligatorios, longitudes,
  enteros canónicos, trailing bytes e IDs cerrados.
- Revisar límites de profundidad, estados, ramas, mensaje, contexto, chunks,
  dificultad PoW y Argon2id.
- Mover al descriptor de suite toda constante que afecte a la matemática.
- Verificar WideOnce, Deep y DeepVector nivel por nivel.
- Comparar contexto, ancla, evidencia, estados intermedios y digest entre todos
  los backends.
- Cubrir las aplicaciones vigentes en el consumidor independiente.
- Regenerar un único corpus v2.2 y retirar vectores no vigentes.

Gate F2: cero divergencias con el consumidor independiente, parsers cerrados,
DeepVector validado por componentes, backends invariantes y un único conjunto
de vectores normativos.

### Fase 3 — Gate local reproducible

Estado: **cerrada localmente**. La orden normativa es
`python -m scripts.validate_project`; construye en un árbol temporal, instala
el wheel fuera del checkout y emite un informe JSON verificable.

Crear una orden normativa, por ejemplo `python -m scripts.validate_project`,
que ejecute y registre:

1. formato, lint y tipado, incluida `reference/`;
2. `compileall`;
3. tests unitarios, integración, properties, diferenciales y vectores;
4. fuzzing mutacional determinista corto;
5. build de wheel y sdist;
6. instalación en un entorno aislado;
7. smoke de ambos CLI fuera del checkout;
8. comprobación de la ruta real desde la que se importa `sigma`;
9. enlaces documentales, limpieza del árbol y artefactos accidentales;
10. cobertura con salida humana y JSON.

Todas las dependencias importadas por tests pertenecerán al extra instalado por
el gate. Objetivos de cobertura: 95 % en núcleo/formatos/aplicaciones, 90 % en
infraestructura experimental y 85 % en release/reproducción.

Gate F3: un entorno limpio valida el proyecto con una sola orden y cualquier
fallo produce código de salida distinto de cero.

### Fase 4 — Infraestructura experimental cerrada

Estado: **cerrada localmente**. Esquemas cerrados, procedencia del wheel/import,
captura concurrente, integridad por tarea y reanudación transaccional tienen
regresiones automatizadas.

#### F4.1 — Esquemas por experimento

- Campos obligatorios y opcionales explícitos.
- Tipos, rangos, enumeraciones y reglas cruzadas.
- Rechazo de campos desconocidos y versión del esquema.
- Validación antes de crear el directorio de salida.

#### F4.2 — Procedencia local demostrable

El manifiesto enlazará commit, versión, hash y metadata del wheel, ruta real del
paquete importado, configuración canónica, intérprete, dependencias, política,
host y hardware. No bastará con hashear un archivo arbitrario.

#### F4.3 — Instrumentación concurrente

- Capturar eventos primitivos de serial, threads y procesos.
- Consolidarlos determinísticamente en el coordinador.
- Verificar TreeWide multiproceso y Deep paralelo.

#### F4.4 — Scheduler transaccional

- Reanudación y deduplicación deterministas.
- Estados separados para éxito, error, timeout y censura.
- Intentos fallidos inmutables y detección de resultados incompletos.
- Hashes de todos los artefactos no autocontenidos.

Gate F4: toda salida se relaciona inequívocamente con artefacto, configuración,
tarea y entorno; ninguna configuración desconocida se acepta silenciosamente.

### Fase 5 — Limpieza física del árbol

Estado: **cerrada**. Se retiraron código, tests, configuraciones, vectores,
resultados, figuras y documentación histórica; su recuperación queda en Git.

La limpieza siguió [`current-scope-v2-2.md`](current-scope-v2-2.md), verificó
ausencia de imports/consumidores y retiró resultados, vectores, configuraciones,
documentación, runners, figuras y código ajenos a v2.2. Los pilotos conservan
sólo el informe de dimensionamiento necesario; la historia reside en Git.

Gate F5: el checkout describe exclusivamente el producto actual y F3 permanece
verde.

### Fase 6 — Pilotos finales y prerregistro

Estado: **cerrada**. Los 20
runs vigentes pasaron y el único informe retenido es
`experiments/pilot-decision-record-v2-2.json`. La campaña sumó 36.731
observaciones; EXP-07 fija un mínimo de 677 muestras por bit y EXP-12 conserva
el mismo presupuesto Argon2id entre modos. Estos datos no son evidencia del
artículo.

El propietario revisó y autorizó la ejecución el 2026-09-03. El prerregistro
quedó congelado con SHA-256
`373f7b7fcc244d755b5c8f3de9daa56eb98ef5b32c0de6b706bc55a06f9fc5f5`;
el manifiesto vincula las 20 configuraciones y 7.233 tareas efectivas.

Repetir los pilotos necesarios para validar runners, medir tiempo/RAM/disco,
elegir tamaños, fijar potencia, exclusiones, censura, análisis y figuras antes
de observar datos confirmatorios.

El prerregistro final incluirá hipótesis, variables, endpoints, tamaños, seeds,
exclusiones, censura, análisis, figuras, presupuesto y tratamiento de resultados
positivos y negativos. Su versión congelada tendrá hash canónico.

Gate F6: no comienza el confirmatorio hasta revisión y congelación humanas.

### Fase 7 — Campaña confirmatoria

Estado: **autorizada y preparada; ejecución en curso**. El estrato local Linux
no sustituye las réplicas macOS/Windows, el segundo host físico ni las baterías
externas exigidas por el protocolo.

- Ejecutar únicamente el artefacto validado y configuraciones congeladas.
- No modificar runners, análisis ni exclusiones durante la campaña.
- Conservar resultados positivos, negativos, fallidos y censurados.
- Ejecutar réplicas multihost cuando el diseño lo exija.
- Producir un único dataset oficial.

El repositorio conservará configuraciones, manifiesto, hashes, índice y
resúmenes. Si el raw data es grande se publicará como artefacto externo con
identificador persistente; no habrá datasets antiguos en paralelo.

Gate F7: todas las tareas están completas o censuradas según protocolo y el
dataset canónico verifica íntegramente sus hashes.

### Fase 8 — Artículo y reproducción

Flujo obligatorio:

```text
dataset canónico
  -> validación
  -> análisis versionado
  -> tablas y figuras
  -> fragmentos del manuscrito
  -> paquete de reproducción
```

- Generar automáticamente todas las cifras.
- Informar intervalos, tamaños de efecto, repeticiones y censura.
- Separar observación empírica, argumento formal y claim criptográfico.
- Actualizar claim-to-evidence y eliminar cifras piloto de resultados.
- Completar bibliografía, amenazas a validez y resultados negativos.

Gate F8: cada cifra enlaza dataset, script, configuración, hash, entorno, claim
permitido y limitación.

### Fase 9 — Auditoría y reproducción final

- Ejecutar F3 desde cero e instalar el artefacto aislado.
- Reproducir una muestra de cada familia experimental.
- Auditar formatos, KDF, firma, PoW y claims.
- Verificar que el árbol no contiene evidencia histórica.
- Reproducir conformidad y mecanismo central en otra máquina o por otra persona.

Sólo después se abordarán integración continua alojada, actualización de
`main`, pull request, tag público, DOI/release y revisión externa.

## 4. Orden de implementación

1. KDF y modelo de secretos.
2. Defaults v2.2, estados de madurez y políticas.
3. Snapshot y arquitectura de archivos.
4. Codecs, conformidad y vectores.
5. Gate local.
6. Esquemas experimentales.
7. Procedencia y artefactos.
8. Instrumentación concurrente.
9. Limpieza del árbol.
10. Pilotos finales y presupuesto.
11. Prerregistro.
12. Confirmatorio y dataset único.
13. Artículo y paquete de reproducción.
14. Auditoría final.

## 5. Definición global de terminado

El programa termina cuando v2.2 es la única línea activa; KDF, API, formatos y
madurez son inequívocos; principal e independiente coinciden; el gate local
pasa desde limpio; no queda evidencia histórica; existe un único dataset
confirmatorio; el artículo se genera desde él; otra máquina puede reproducir el
paquete; y todos los límites pendientes de revisión externa siguen explícitos.
