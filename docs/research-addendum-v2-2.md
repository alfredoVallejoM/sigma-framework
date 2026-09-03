# Addendum de investigación — fortalecimiento de Sigma v2 y campaña del artículo

Estado original: plan de trabajo posterior a la reconstrucción `v2-1 alpha`.
Estado de ejecución a 2026-09-03: R1–R3 cerrados localmente, runners y pilotos
aplicables implementados, R4 pendiente de congelación humana y R5/R6 pendientes
de infraestructura/publicación/revisión externa. El estado vigente y el mapa de
evidencia están en [`project-status-2026-09-03.md`](project-status-2026-09-03.md);
las secciones siguientes conservan los requisitos originales y no son
instrucciones ejecutables.

Este addendum convierte los hallazgos de la revisión interna en un programa
ejecutable de desarrollo, experimentación y publicación. Su propósito es que
cada resultado del artículo pueda trazarse hasta una construcción especificada,
un commit limpio, observaciones crudas y un análisis estadístico previamente
declarado.

El objetivo científico no es obtener a toda costa un resultado favorable. Es
someter las hipótesis de Sigma a pruebas capaces de confirmarlas dentro de su
modelo o de mostrar con precisión dónde dejan de cumplirse. Esa falsabilidad es
la que permite presentar evidencia empírica de primer orden.

## A. Tesis central que debe preservar el rediseño

Para un contexto canónico `C`, mensaje `M`, ancla `A_C(M)`, función de estado
`F`, profundidad `t` y número de estados publicados `k`:

```text
A       = A_C(M)
S_0     = F(DST_init  || Enc(C,A))
S_(i+1) = F(DST_round || Enc(C,i,A,S_i))
D_(t,k) = Enc(C,S_t,...,S_(t+k-1))
```

La campaña debe separar cuatro propiedades diferentes:

1. **Binding de entrada.** El ancla compromete canónicamente `C` y `M`.
2. **No coalescencia entre anclas.** Si `A != A'` y `S_i = S'_i`, las consultas
   siguientes siguen siendo distintas y una nueva igualdad requiere otra
   coincidencia.
3. **Profundidad por candidato.** `t` añade niveles adaptativos y coste por
   evaluación, sin impedir el paralelismo entre candidatos.
4. **Compromiso de segmento.** Publicar `k` estados impone hasta `k*n`
   igualdades, limitado por la fuerza efectiva del ancla.

El artículo no equiparará estas propiedades con acumulación de entropía,
memory-hardness, prueba sucinta de trabajo secuencial, autenticación, resistencia
ASIC o seguridad poscuántica.

## B. Jerarquía de evidencia

No todas las métricas tienen el mismo valor probatorio. El artículo distinguirá
cuatro niveles.

| Nivel | Evidencia | Qué puede sostener |
|---:|---|---|
| E1 | especificación, reducción formal y vectores independientes | definición de la función e implicaciones dentro del modelo |
| E2 | enumeración exacta o simulación reducida con controles | mecanismo de no coalescencia, cuellos de botella y leyes de escala |
| E3 | medición de la implementación real | conformidad, coste, memoria, difusión y comportamiento operativo |
| E4 | reproducción externa y revisión criptográfica | credibilidad independiente y cierre de publicación |

SAC, entropía empírica, tests de frecuencia o ausencia de colisiones observadas
son controles E3. Nunca se presentarán como demostración de resistencia a
colisión o preimagen a 512 bits.

## C. Mejoras obligatorias de la librería

Cada obligación tiene un identificador estable, implementación esperada,
criterio de aceptación y evidencia requerida.

### LIB-01 — Anchura de estado gobernada por la suite

**Problema.** `SigmaDigestV2` acepta estados de 1 a 1024 bytes aunque las suites
actuales fijan 64 bytes. Un digest canónico de un byte puede provocar acceso
fuera de rango en el predicado PoW.

**Implementación.**

- Resolver la suite durante `SigmaDigestV2.__post_init__()` y `from_bytes()`.
- Exigir `len(state) == suite.state_size` para cada estado.
- Hacer que todos los predicados validen longitud antes de inspeccionar bits.
- Convertir entradas no válidas en `DecodeError` o rechazo booleano, nunca en
  `IndexError`.

**Aceptación.**

- Tests para longitudes `0, 1, 63, 64, 65, 1024, 1025`.
- Fuzzing dirigido sobre `state_count`, longitudes y dificultad PoW.
- Cero excepciones no clasificadas ante digests arbitrarios.

### LIB-02 — Evaluación rodante O(k) respecto a `t`

**Problema.** `WideOnce.evaluate()` y `Deep.evaluate()` retienen todos los
estados; Deep retiene además todas las salidas de rama.

**Implementación.**

- Crear un camino normativo `evaluate_digest()` sin transcript.
- Mantener sólo el estado actual y una ventana final de `k` estados.
- Reservar `evaluate_trace()`/`trace_bytes()` para captura diagnóstica explícita.
- Permitir un `TracePolicy` con `NONE`, `SELECTED`, `EVERY_N` y `FULL`.
- Incorporar límites de tamaño y advertencia cuando se solicite `FULL`.

**Aceptación.**

- El digest debe ser idéntico antes y después del refactor.
- La pendiente de memoria frente a `t` debe ser estadísticamente compatible con
  cero para `TracePolicy.NONE`.
- `FULL` debe reproducir exactamente los vectores de transcript existentes.

### LIB-03 — Codec canónico y tipado de evidencia de ancla

**Problema.** `AnchorEvidence` y `CrossWideEvidence` no tienen parser y
comparten un prefijo sin etiqueta inequívoca de variante.

**Implementación.**

- Añadir `evidence_version` y `evidence_type`.
- Implementar `to_bytes()`/`from_bytes()` como inversos estrictos.
- Validar número, orden, ID y longitud de raíces contra la suite.
- Rechazar campos desconocidos, duplicados, truncados o trailing.
- Decidir si el cambio genera `CONTEXT_VERSION=3`, nuevos `SuiteId` o una
  familia `v2-2`; no alterar silenciosamente digests congelados.

**Aceptación.**

- Prueba exhaustiva de round-trip para todas las suites.
- Corpus negativo y fuzzing independiente de ambos parsers.
- Prueba formal de inyectividad restringida a registros aceptados.

### LIB-04 — Validación semántica única de contexto

**Problema.** `SigmaContextV2.from_bytes()` valida la gramática, pero no que la
combinación de suite, perfiles, ramas y chunk pertenezca a una suite registrada.

**Implementación.**

- Separar `parse_context()` de `validate_registered_context()`.
- Hacer que todas las fronteras públicas ejecuten ambas operaciones.
- Mantener una ruta explícita para inspección de contextos sintácticos no
  registrados, sin permitir su evaluación.

**Aceptación.** Matriz negativa completa de todas las combinaciones cruzadas de
suite, ancla, rondas, salida, ramas y tamaño de hoja.

### LIB-05 — Políticas de recursos y defensa contra downgrade/DoS

**Implementación.**

- Añadir `ResourcePolicy` independiente del wire format.
- Establecer máximos y mínimos locales de `t`, `k`, tamaño, dificultad PoW y
  parámetros Argon2id.
- Distinguir `well_formed`, `suite_valid` y `policy_acceptable`.
- Rechazar parámetros antes de realizar trabajo costoso.
- Registrar la política aplicada en verificaciones y benchmarks, sin hacerla
  parte del digest matemático salvo que el protocolo lo requiera.

**Aceptación.** Tests de límites, downgrade y presupuestos agotados; tiempo de
rechazo acotado para parámetros no aceptables.

### LIB-06 — Semántica de snapshot para archivos

**Implementación.**

- Definir que un digest corresponde a una secuencia inmutable de bytes, no a un
  nombre de archivo mutable.
- En serial, abrir una sola vez y comprobar `fstat` antes/después.
- En multiprocessing, usar snapshot temporal, descriptor compartido seguro o
  mecanismo equivalente por plataforma.
- Registrar `device`, `inode/file-id`, tamaño, `mtime` y `ctime` cuando existan.
- Abortar ante sustitución, truncado o modificación concurrente.

**Aceptación.** Tests que modifiquen, reemplacen y trunquen el archivo durante
el cálculo; nunca se aceptará silenciosamente un digest híbrido.

### LIB-07 — Validación total de tipos numéricos

**Implementación.**

- Rechazar `bool`, floats, strings, negativos y overflow en nonce, workers,
  intentos, rondas, dificultades y parámetros KDF.
- Unificar excepciones públicas.
- Añadir tests property-based sobre fronteras enteras.

### LIB-08 — Composición KDF segura y explícita

**Problema.** La API devuelve la clave Argon2id intermedia junto al digest,
facilitando que un consumidor descarte involuntariamente el postprocesamiento.

**Implementación.**

- Diseñar `SigmaKdfResult` con parámetros, salt y resultado final.
- No exponer `base_key` salvo mediante API diagnóstica inequívoca.
- Definir si el resultado final es un digest autocontenido, una clave derivada de
  longitud solicitada o ambos mediante dominios separados.
- Añadir `verify_password()` con comparación constante donde la implementación
  subyacente lo permita.
- Fijar perfiles Argon2id de prueba y políticas mínimas externas.

**Aceptación.** Vectores KDF, pruebas de contraseña correcta/incorrecta,
interoperabilidad y comparación justa contra Argon2id solo.

### LIB-09 — Compromiso firmado de estados consecutivos

Definir un objeto separado del digest:

```text
SigmaSignedCommitmentV2 = {
    context,
    anchor_evidence,
    states[S_t..S_(t+k-1)],
    signature_algorithm,
    public_key_id,
    signature
}
```

La firma se realizará sobre un dominio específico y la serialización completa.
Se mantendrán dos verificadores:

- `verify_full_signed(message, commitment)`: recalcula todo y verifica firma;
- `verify_signed_attestation(commitment)`: autentica la declaración, pero no
  demuestra que `S_t` tenga historia válida.

No se diseñará un algoritmo de firma propio. Se integrará una interfaz para
firmas estándar y vectores con al menos una implementación consolidada.

### LIB-10 — Backend Deep intrarronda

**Implementación.**

- Separar la función matemática Deep de la política de scheduling.
- Implementar backend serial normativo y backend paralelo de ramas.
- El fold sólo puede comenzar cuando estén disponibles todas las ramas.
- El orden de finalización no puede alterar el orden canónico del vector.

**Aceptación.** Cero divergencias entre 1, 2, 4 y más workers; tests que fuercen
órdenes de terminación distintos.

### LIB-11 — Resolver la identidad de RealTime

Debe escogerse y documentarse una de dos alternativas:

1. **Política de ejecución.** RealTime deja de ser una suite criptográfica
   distinta y pasa a ser la API incremental de StreamWide.
2. **Suite diferenciada.** Se especifica una función matemática propia y una
   hipótesis que justifique el nuevo `SuiteId`.

No se mantendrán dos suites idénticas salvo por domain separation sin explicar
qué propiedad científica se estudia con esa duplicación.

### LIB-12 — Nuevo modo DeepVector/LinkedWide

Para estudiar una composición que no comprima inmediatamente las ramas:

```text
V_i = (S_i^1,...,S_i^m)
S_(i+1)^j = H_j(DST_vector || Enc(C,i,A,V_i,j))
```

El digest puede publicar `V_t,...,V_(t+k-1)` como estados estructurados o como
vectores concatenados de longitud fijada por suite.

**Objetivos.**

- Forzar que cada nivel siguiente consuma todas las ramas anteriores.
- Conservar una reducción por componente sin un fold único de 512 bits.
- Comparar garantía conservadora, hipótesis de independencia y coste físico.

**Decisión de diseño obligatoria.** Las conexiones no recibirán fuerza aditiva
por ser simplemente funciones deterministas de raíces ya publicadas. Cualquier
cota superior a “una rama sana” requerirá una hipótesis conjunta explícita.

### LIB-13 — Vectores completos y segunda implementación

- Vectores para todas las suites y aplicaciones.
- Casos vacío, 1 byte, límites `63/64/65`, límites de hoja, varias hojas y
  `t={0,1,2,4}`, `k={1,2,3}`.
- Valores intermedios: contexto, raíces, conexiones, nodos, estados y digest.
- Generador de vectores separado del consumidor.
- Implementación independiente mínima, preferentemente en otro lenguaje o
  escrita directamente desde la especificación sin importar `sigma`.

La conformidad entre dos implementaciones independientes será evidencia E1/E4
más fuerte que comparar dos adaptadores que comparten el mismo núcleo.

### LIB-14 — Endurecimiento de parsers y API

- Property-based testing con generación de objetos válidos y mutaciones.
- Fuzzing coverage-guided de contexto, digest, ancla, PoW, KDF y firma.
- Mutation testing de validadores.
- Presupuestos de longitud antes de reservar memoria.
- Comparaciones constantes para valores autenticados cuando proceda.
- Mensajes de error que no expongan secretos ni conviertan fallos en aceptación.

### LIB-15 — Versionado, release y trazabilidad

- Unificar `2.0.0a1`, `v2-1`, `draft1` y flags `stable`.
- Distinguir versión de paquete, versión de wire y versión de suite.
- Mantener los digests v2-1 sólo como vectores históricos si hay cambios
  incompatibles.
- Dividir el trabajo posterior en commits revisables por obligación.
- Etiquetar el commit exacto usado para la campaña.
- Construir wheel, sdist, checksums y SBOM desde ese tag limpio.

## D. Obligaciones formales nuevas o revisadas

### FORM-01 — Juegos y presupuestos de adversario

Definir por separado juegos de:

- colisión;
- preimagen;
- segunda preimagen;
- colisión de segmento;
- multiobjetivo/multiusuario;
- conformidad de backend;
- reutilización de firma.

Cada juego declarará consultas al ancla, consultas de ronda, profundidad
paralela, memoria, acceso a contextos y capacidad de elegir mensajes/adaptarse a
respuestas.

### FORM-02 — Canonicalidad por tipo y suite

Reescribir TH-01 después del codec de evidencia. La prueba debe cubrir cada
contenedor aceptado y no depender de un parser inexistente.

### FORM-03 — Propiedades separadas del ancla

Introducir al menos:

```text
alpha_coll(A)   fuerza de colisión
alpha_pre(A)    fuerza de preimagen
alpha_2pre(A)   fuerza de segunda preimagen
alpha_joint(A)  fuerza bajo una hipótesis conjunta declarada
```

La longitud física de raíces y conexiones se mantendrá separada de estas
cantidades.

### FORM-04 — Teorema de no coalescencia

Formalizar el evento condicionado:

```text
A != A' and S_i = S'_i
```

y demostrar, bajo consultas frescas y encodings inyectivos, que las siguientes
entradas son distintas. Incluir los controles “sólo índice”, “sólo ancla” y
“ancla+índice”.

### FORM-05 — Colisión de segmentos

Reformular TH-04 con un bound concreto en función de consultas y eventos de
repetición. La aproximación de cumpleaños usará también su constante:

```text
median(Q_collision) ~= sqrt(2 * ln(2)) * 2^(b/2)
```

para una imagen ideal de `b` bits, no simplemente `2^(b/2)`.

### FORM-06 — Preimagen y segunda preimagen

Sustituir la parte correspondiente de TH-05 por teoremas separados. No inferir
seguridad de preimagen a partir de resistencia de colisión.

### FORM-07 — Profundidad paralela

Modelar WideOnce y Deep en oráculo aleatorio paralelo:

- WideOnce: un nivel adaptativo por transición;
- Deep serial: `m+1` consultas implementadas por nivel;
- Deep idealmente paralelo: una capa de ramas más una capa de fold;
- DeepVector: una capa de ramas por nivel si todas consumen el vector previo.

La dependencia del código no se presentará por sí sola como cota criptográfica
contra cualquier algoritmo alternativo.

### FORM-08 — Seguridad de Deep y DeepVector

Especificar qué ocurre si:

- falla una rama;
- varias ramas están correlacionadas;
- falla el fold;
- sólo una rama conserva colisión/preimagen;
- el adversario elige anclas relacionadas.

### FORM-09 — Composición con firma

Demostrar por reducción qué necesita un adversario para reutilizar una firma en
los casos:

1. firma de `D_(t,k)`;
2. firma de `(A,D_(t,k))`;
3. verificación completa;
4. verificación de una sola arista.

### FORM-10 — Posicionamiento y novedad

Comparar explícitamente Sigma con:

- PBKDF2 y PRFs con clave reinyectada;
- HAIFA y contadores/salts por bloque;
- wide-pipe/double-pipe;
- robust hash combiners;
- multicollisions, herding y ataques de segunda preimagen;
- TupleHash/ParallelHash y árboles paralelos;
- hash chains, time-lock puzzles, VDF y PoSW;
- memory-hard functions y pebbling.

La novedad candidata debe formularse como la combinación concreta de ancla
ancha retenida, reinyección completa por nivel, separación de ronda y compromiso
de varios estados consecutivos, no como la primera iteración con tweak o salt.

## E. Infraestructura experimental común — EXP-00 v2

Antes de generar cifras nuevas se reforzará el runner.

### E.1 Proveniencia obligatoria

Cada run conservará:

- configuración canónica embebida;
- commit y tag exactos;
- `dirty=false` obligatorio para campaña publicable;
- hash del ejecutable/wheel instalado;
- comando completo;
- semilla maestra y derivaciones etiquetadas;
- versiones de Python, SO, dependencias y compilador;
- modelo de CPU, microcode, RAM, afinidad y governor;
- temperatura y frecuencia como serie temporal cuando se mida rendimiento;
- observaciones crudas comprimidas;
- resumen derivado;
- stdout/stderr y estado de salida;
- hashes de todos los artefactos.

### E.2 Ejecución reanudable

- Una tarea atómica por celda/repetición.
- Identificador determinista de tarea.
- Escritura append-only o particiones por tarea.
- Reanudación sin duplicar observaciones.
- Registro explícito de timeout, error y censura.
- Unión final que compruebe completitud respecto a la configuración.

### E.3 Separación de resultados

El campo `passed` se sustituirá o complementará con:

```text
execution_complete
invariants_passed
hypothesis_outcome
quality_controls_passed
```

Un resultado estadístico contrario a la hipótesis es un resultado científico,
no un fallo de ejecución.

### E.4 Plan estadístico común

- Hipótesis primaria y métrica primaria por experimento.
- Tamaño muestral determinado antes del confirmatorio.
- Intervalos de confianza y tamaños de efecto, no sólo p-values.
- Corrección familiar predeclarada cuando existan múltiples tests.
- Modelos de supervivencia para observaciones censuradas.
- Seeds de análisis distintas de las seeds de generación.
- Sin exclusión de outliers salvo regla previa y publicación de ambas versiones.
- Publicación de todos los resultados negativos y celdas agotadas.

## F. Campaña experimental principal

### EXP-01R — Conformidad canónica e interoperabilidad

**Pregunta.** ¿La misma secuencia de bytes y contexto produce exactamente el
mismo ancla, transcript seleccionado y digest en todos los adaptadores,
backends, workers, sistemas operativos e implementación independiente?

**Matriz.**

- Todas las suites.
- Memoria, reader, archivo, incremental y multiprocessing.
- Particiones aleatorias y adversariales.
- Workers `1,2,3,4,8,cpu_count`.
- Tamaños `0,1,63,64,65,65535,65536,65537,1 MiB,16 MiB,256 MiB,1 GiB`.
- Linux, macOS y Windows.

**Métrica primaria.** Número de divergencias byte a byte.

**Criterio.** Cero divergencias. Una sola divergencia es un defecto de
implementación, no variación estadística.

**Gráficas.** Heatmap de celdas ejecutadas/divergentes y curva tiempo/tamaño por
backend; los valores canónicos se documentarán en tablas/vectores.

### EXP-02R — Ley de colisión de segmentos

**Pregunta.** ¿La colisión de `k` estados reinyectados escala con
`min(a,k*n)`, mientras una cadena que pierde el ancla queda limitada por `n`?

**Construcciones de control.**

- cadena simple sin índice ni ancla;
- sólo índice;
- sólo ancla;
- ancla e índice;
- salida de un estado;
- salida de `k` estados.

**Diseño.** Anchuras reducidas con enumeración exacta cuando sea posible y
Monte Carlo en el resto. La cuadrícula se escogerá para que la mayor parte de
las celdas tenga eventos observables. Las celdas grandes usarán censura derecha.

**Métricas.**

- candidatos hasta primera colisión;
- curva Kaplan-Meier de supervivencia;
- mediana e intervalo de confianza;
- pendiente de `log2(Q)` frente a bits efectivos;
- desviación respecto a `sqrt(2 ln 2) 2^(b/2)`;
- tasa y patrón de censura.

**Criterio de apoyo.** La pendiente estimada de las celdas no censuradas debe
contener `0.5` en su intervalo predeclarado y el modelo `min(a,k*n)` debe superar
en ajuste predictivo a los modelos alternativos registrados.

**Gráficas.** Predicho frente a observado, curvas de supervivencia y superficie
3D/heatmap sobre `(a/n,k)`.

### EXP-03R — Persistencia condicional y no coalescencia

**Pregunta.** Condicionadas a `S_i=S'_i`, ¿qué construcciones hacen persistir la
igualdad?

**Grupos.** Mismas cuatro construcciones de control de EXP-02R, con anclas
iguales y diferentes como factores separados.

**Métricas.** Probabilidad por longitud de segmento, intervalo binomial exacto,
likelihood ratio frente a `1` y frente a `2^(-n*l)`.

**Diseño de potencia.** Sólo se usarán combinaciones con número esperado de
eventos suficiente o enumeración exacta. Las combinaciones destinadas a
producir cero eventos se etiquetarán como límites superiores, no como
confirmación puntual.

**Gráfica principal.** Probabilidad de persistencia en escala logarítmica frente
a longitud, con líneas teóricas y controles.

### EXP-04R — Fuerza y cuellos de botella del ancla

**Construcciones.**

- una sola rama;
- raíces concatenadas;
- raíces más conexiones CrossWide;
- sólo conexiones;
- compresión estrecha;
- fold único;
- DeepVector.

**Fallos modelados.** Rama constante, colisionable, truncada, correlacionada,
permutada y omitida; fold constante/estrecho; anclas relacionadas.

**Métricas.** Trabajo de colisión del ancla y del digest, componentes iguales,
éxito de reutilización de colisiones, censura y coste por candidato.

**Resultado que debe quedar visible.** CrossWide no puede recibir bits extra por
sus conexiones deterministas; DeepVector sí puede compararse bajo hipótesis
conservadora y conjunta claramente separadas.

### EXP-05R — Dependencia estructural de primer orden

**Intervenciones.** Flip de cada familia de bits en mensaje, contexto, índice,
raíz, conexión, estado y vector de rama; ablación y permutación de componentes.

**Métricas.**

- cobertura de salida afectada;
- distancia de Hamming por capa;
- matriz fuente-destino;
- componentes invariantes inesperados;
- tasa de rechazo estructural.

**Criterio determinista.** Toda ablación/permutación prohibida debe ser
rechazada. La ausencia de cambio ante una intervención autenticada es un
hallazgo crítico.

**Gráficas.** Matriz de dependencia y diagrama de propagación por ronda.

### EXP-06R — Profundidad, coste y paralelismo

**Preguntas.**

- ¿Crece el número de niveles con `t+k-1`?
- ¿Cuál es el coste marginal de una ronda?
- ¿Qué paralelismo existe dentro de Deep y entre candidatos?
- ¿Puede amortizarse trabajo entre anclas?

**Métricas.** Consultas por dominio, profundidad adaptativa, wall time, CPU time,
throughput por candidato, speedup, eficiencia paralela y coste de ancla separado.

**Análisis.** Regresión robusta de tiempo frente a niveles después de warm-up;
intervalos por host; comparación serial/paralelo sin atribuir la linealidad
temporal medida a una prueba formal.

**Gráficas.** Tiempo frente a `t`, throughput frente a candidatos, speedup frente
a workers y diagrama work/span de cada modo.

### EXP-07R — SAC, BIC y difusión por capas

**Alcance.** Control de calidad descriptivo sobre primitivas, ancla, conexiones,
estados y digest.

**Métricas.** Probabilidad de flip por bit, máximo sesgo con intervalo,
dependencia entre pares de bits de salida, distancia media y velocidad de
difusión por ronda.

**Estadística.** Tamaño muestral por precisión del intervalo y sesgo detectable,
no mediante una etiqueta genérica de “power”. Se publicará la familia completa
de celdas y la corrección aplicada.

**Criterio.** No se exigirá cero p-values significativos, porque incluso una
fuente ideal produce falsos positivos. Se exigirá ausencia de sesgo sistemático
replicable y se informará del peor efecto con intervalo.

### EXP-08R — Baterías de distribución

**Datos.** Streams separados por construcción, corpus, estado y dominio; nunca
mezclar estructuras de framing con bytes que se presentan como aleatorios.

**Tests.** Frecuencia, runs, autocorrelación y chi-cuadrado actuales, más una
batería escalonada y reproducible:

- NIST SP 800-22 para streams con longitud y número de secuencias admisibles;
- PractRand hasta un umbral de bytes fijado antes de la campaña;
- TestU01 SmallCrush y Crush sobre un generador adaptador definido como
  `H(context || counter)`; BigCrush sólo si el presupuesto y el adaptador lo
  permiten sin reciclar muestras;
- hashes estándar sobre exactamente el mismo corpus, framing y adaptador como
  controles de calibración de la metodología.

Se conservarán versión, comando, endianness, transformación bit/byte, tests no
aplicables y salida completa de cada batería.

**Interpretación.** La batería sólo detecta anomalías estadísticas accesibles.
Pasarla no acredita resistencia criptográfica.

**Gráficas.** Distribución uniforme esperada de p-values, QQ plot y tasa de
rechazo por construcción/corpus.

### EXP-09R — Rendimiento justo y reproducible

Separar tareas:

- hash en memoria;
- lectura de archivo caliente/fría;
- construcción de ancla;
- rondas sobre ancla precalculada;
- serialización;
- verificación completa;
- verificación local/firmada.

**Métricas.** Nanosegundos, ciclos cuando sean fiables, operaciones/s,
bytes/s sólo para operaciones que procesan bytes, CPU%, context switches y
variabilidad inter-run.

**Controles.** Orden aleatorio, warm-up, afinidad, governor, series térmicas,
buffers equivalentes y baseline de concatenación de las mismas ramas.

**Gráficas.** Latencia y throughput con intervalos, descomposición del coste y
puntos de cruce entre perfiles. No se inferirá resistencia ASIC.

### EXP-10R — Memoria respecto a mensaje, `t`, `k` y workers

**Métricas.** `tracemalloc`, RSS actual/pico, RSS agregado padre+hijos, nodos de
frontera, buffers, memoria por nivel de trace y espacio en disco temporal.

**Hipótesis.**

- StreamWide normal: O(1) respecto al mensaje y `t`.
- TreeWide serial: O(log N) respecto a hojas y O(1) respecto a `t`.
- Multiprocessing: O(workers * leaf_size) más overhead medido.
- Trace completo: O(t) y explícitamente diagnóstico.

**Gráficas.** Log-log de memoria frente a tamaño, memoria frente a `t` y memoria
agregada frente a workers con bandas de confianza.

### EXP-11R — PoW como aplicación acotada

**Métricas.** Distribución geométrica de intentos, tasa de aceptación, coste de
minado, coste de verificación completa, paralelismo de nonces y efecto de
`t,k`.

**Ataques de protocolo.** Challenge repetido, parámetros degradados, digest
malformado, replay y agotamiento de recursos.

**Interpretación.** Demuestra que el predicado implementa la dificultad
declarada. No demuestra PoSW, VDF ni verificación barata.

### EXP-12R — KDF compuesta

**Comparaciones.** Argon2id, Argon2id+WideOnce y Argon2id+Deep/DeepVector con
el mismo presupuesto total calibrado.

**Métricas.** Guess rate, latencia, memoria, energía sólo si se mide físicamente,
overhead marginal y verificación correcta.

**Hipótesis.** Sigma añade binding y coste determinista, pero no entropía ni una
nueva cota de memory-hardness.

### EXP-13 — Side channels, condicionado

No ejecutar hasta disponer de núcleo nativo especificado. Entonces:

- dudect/TVLA con adquisición válida;
- perf counters y cache traces;
- comparación fixed-vs-random;
- compilador, flags y ensamblado archivados.

Python sólo puede utilizarse para detectar variabilidad operativa, nunca para
declarar constant-time del diseño.

### EXP-14R — Propagación de fallos

Ampliar los flips actuales a omisión de rama, repetición de ronda, índice
incorrecto, reorder, truncado y corrupción del fold/vector.

**Métricas.** Tasa de detección, latencia hasta propagación y distancia por
capa. Mantener fuera cualquier claim de resistencia DFA sin modelo y análisis
específico.

### EXP-15 — Psi como control histórico

Mantenerlo separado de v2. Si se continúa:

- trails diferenciales reducidos;
- análisis algebraico;
- SAT/SMT/MILP en rondas reducidas;
- búsqueda de simetrías, invariantes y fixed points;
- comparación con SHA-512 sobre el mismo dominio.

Ningún resultado de difusión rehabilitará Psi como raíz de confianza.

### EXP-16 — Hardware, condicionado

No realizar claims de puertas, área, potencia, energía o ASIC hasta tener RTL,
testbench, síntesis reproducible, librería/corner y reportes completos.

### EXP-17 — Precomputación, multicollisions y compromisos tiempo-memoria

**Objetivo.** Comprobar en anchuras reducidas si anclas diferentes impiden
reutilizar el trabajo que sí se comparte en una cadena estacionaria.

**Atacantes implementados.** Pollard rho, distinguished points, tablas de
Hellman/rainbow, multicollisions y búsqueda multiobjetivo.

**Métricas.** Tiempo online, tiempo offline, memoria, consultas totales,
profundidad paralela y speedup amortizado por objetivo/ancla.

**Gráficas.** Frontera tiempo-memoria, coste amortizado frente a número de
objetivos y tasa de reutilización entre anclas.

### EXP-18 — Deep Fold frente a DeepVector

**Factores.** Número de ramas, `k`, anchura reducida, ramas rotas/correlacionadas
y fold sano/roto.

**Métricas.** Trabajo de colisión, dependencia, coste por ronda, ancho físico y
cuello de botella efectivo.

**Gráfica principal.** Seguridad reducida observada frente a coste normalizado,
separando garantía conservadora y modelo de independencia.

### EXP-19 — Reutilización de compromiso firmado

En anchuras reducidas, medir el trabajo para encontrar dos mensajes que
permitan reutilizar:

- firma de un estado;
- firma de dos o más estados;
- firma de ancla más estados.

**Métricas.** Candidatos, consultas, éxito, cuello de botella atacado y coste de
verificación. El algoritmo de firma estándar no se reducirá artificialmente; se
reducirá el digest Sigma o se utilizará una firma de test sólo para aislar el
evento de reutilización.

### EXP-20R — Preimagen, segunda preimagen y búsqueda multiobjetivo

**Objetivo.** Contrastar por separado FORM-06 y evitar que el artículo use la
ley de colisión como sustituto de propiedades que tienen otro exponente.

**Diseño.** Suites reducidas con objetivos uniformes y objetivos obtenidos de
mensajes reales. Para segunda preimagen, fijar el primer mensaje antes de la
seed de búsqueda. Variar `n`, anchura efectiva del ancla, `t`, `k` y número de
objetivos; incluir cadena simple, ancla reinyectada y DeepVector.

**Atacantes.** Búsqueda exhaustiva/aleatoria, inversión con tabla cuando sea
aplicable y algoritmo multiobjetivo registrado. No se describirá la ausencia de
un ataque especializado como resistencia frente a todos los ataques.

**Métricas.** Consultas de ancla y ronda, candidatos, tiempo, memoria, tasa de
éxito y censura. Ajustar por separado el exponente de preimagen, segunda
preimagen y multiobjetivo, con intervalos y comparación contra las predicciones
del modelo reducido.

**Gráficas.** `log2` del trabajo mediano frente a bits efectivos y speedup por
número de objetivos, separando claramente colisión, preimagen y segunda
preimagen.

### EXP-21R — Separación de dominios y confusión entre contextos

**Objetivo.** Verificar como invariante estructural que objetos semánticamente
distintos no generan la misma entrada al mismo oráculo por ambigüedad de
serialización, omisión de campos o reutilización de etiquetas.

**Diseño.** Instrumentar el transcript de entradas a primitivas y generar pares
entre tipos, suites, versiones, rondas, índices, ramas, aplicaciones y perfiles.
Incluir mutaciones de longitud, concatenaciones ambiguas, campos desconocidos,
reordenamientos y downgrade de versión.

**Métricas y criterio.** Número de colisiones de framing, campos sin influencia
y cruces de dominio aceptados. El criterio es determinista: cero casos, salvo
igualdad semántica explícitamente especificada. Cualquier caso invalida el gate
de conformidad aunque el digest final parezca aleatorio.

**Gráfica.** Matriz dominio-origen/dominio-destino de pares ejercitados; los
fallos se publicarán como tabla de contraejemplos, no se ocultarán en un
porcentaje agregado.

## G. Catálogo de figuras previsto para el artículo

| Figura | Fuente | Mensaje permitido |
|---:|---|---|
| F1 | EXP-01R | backend/adaptador no altera valores en la matriz probada |
| F2 | EXP-02R | escala de colisión compatible con `min(a,k*n)` en modelo reducido |
| F3 | EXP-03R | la reinyección evita coalescencia automática entre anclas |
| F4 | EXP-04R | el ancla estrecha limita y las conexiones no añaden anchura independiente |
| F5 | EXP-05R | mapa de dependencia de mensaje/contexto/ancla/rondas |
| F6 | EXP-06R | profundidad, work/span y paralelismo entre candidatos |
| F7 | EXP-07R | difusión por capa con intervalos y peor sesgo |
| F8 | EXP-08R | controles de distribución, sólo descriptivos |
| F9 | EXP-09R | coste descompuesto y puntos de cruce de modos |
| F10 | EXP-10R | memoria frente a mensaje, profundidad y workers |
| F11 | EXP-17 | frontera de precomputación y tiempo-memoria |
| F12 | EXP-18 | Deep Fold frente a DeepVector |
| F13 | EXP-19 | coste de reutilización de firma frente a `k` |
| F14 | EXP-20R | escalas separadas de preimagen, segunda preimagen y multiobjetivo |
| F15 | EXP-21R | cobertura y ausencia de confusión entre dominios en la matriz probada |

Cada figura incluirá intervalos, número de observaciones, definición de ejes,
unidades y hash de la fuente. No se generarán figuras sólo desde resúmenes sin
conservar la cadena hasta config, raw data y manifiesto.

## H. Criterios globales de aceptación antes de redactar resultados

### Gate R1 — Corrección del núcleo

- LIB-01 a LIB-07 cerrados.
- Cero divergencias de vectores.
- Cero crashes en parsers y predicados durante fuzzing.
- Evaluación normal sin crecimiento lineal en `t`.

### Gate R2 — Modos y aplicaciones

- Decisión RealTime documentada.
- Deep paralelo conforme.
- DeepVector especificado e implementado o descartado con justificación.
- Perfil firmado y KDF final con semántica inequívoca.

### Gate R3 — Formalización

- FORM-01 a FORM-10 revisados internamente.
- Separación estricta de propiedades y supuestos.
- Tabla claim-to-theorem-to-experiment actualizada.

### Gate R4 — Prerregistro

- Configuraciones y análisis congelados antes de datos confirmatorios.
- Pilotos etiquetados y excluidos del confirmatorio.
- Presupuesto de cómputo y reglas de censura cerrados.

### Gate R5 — Campaña confirmatoria

- Commit limpio y artefacto instalable identificado.
- Todos los runs completos o censurados conforme al protocolo.
- Resultados negativos conservados.
- Reproducción en al menos un entorno independiente para E4.

### Gate R6 — Publicación

- Manuscrito generado desde datos versionados.
- Bibliografía y related work completos.
- Dataset y artefactos archivados con identificador persistente.
- Hallazgos de revisión externa registrados y resueltos o declarados.

## I. Orden de ejecución y dependencias

| Fase | Trabajo | Depende de | Salida |
|---:|---|---|---|
| 1 | LIB-01, 02, 03, 04, 07 | v2-1 actual | núcleo corregido y nuevos vectores |
| 2 | LIB-05, 06, 08, 14, 15 | fase 1 | API y release endurecidos |
| 3 | LIB-09, 10, 11, 12, 13 | fase 1 | modos finales e implementación independiente |
| 4 | FORM-01..10 | decisiones de fase 3 | modelo y claims congelados |
| 5 | EXP-00 v2 y pilotos | fases 2–4 | configuraciones factibles y análisis cerrado |
| 6 | EXP-01R..21R aplicables | tag limpio + prerregistro | dataset confirmatorio |
| 7 | figuras, tablas y paper | fase 6 | manuscrito sometible |
| 8 | reproducción/revisión externa | fase 7 | evidencia E4 y release candidato |

LIB-02 bloquea EXP-06R y EXP-10R. LIB-12 bloquea EXP-18. LIB-09 bloquea
EXP-19. FORM-03/05/06 bloquean la interpretación de EXP-02R/04R. FORM-06
bloquea EXP-20R y LIB-03/04 bloquean EXP-21R. Ninguna cifra confirmatoria se
obtendrá antes de cerrar estas dependencias.

## J. Estructura prevista del paper final

1. Problema, alcance y contribuciones.
2. Related work y delimitación de novedad.
3. Modelo, notación y juegos de seguridad.
4. Anclas StreamWide, CrossWide y TreeWide.
5. Rondas WideOnce, Deep y, si supera el gate, DeepVector.
6. Compromiso multiestado y composición firmada.
7. Reducciones y límites formales.
8. Implementación, backends y vectores.
9. Metodología experimental prerregistrada.
10. Resultados principales EXP-01R–06R y EXP-17–21R.
11. Rendimiento y memoria EXP-09R/10R.
12. Aplicaciones y controles secundarios.
13. Limitaciones, resultados negativos y amenazas a la validez.
14. Reproducibilidad y disponibilidad de artefactos.

El resultado principal será la relación entre ancla, reinyección, profundidad y
segmento consecutivo. Difusión, distribución, PoW, KDF, fallos, side channels y
hardware permanecerán subordinados a esa tesis.

## K. Definición de terminado

El proyecto estará preparado para someter el artículo cuando pueda responderse
para cada claim:

1. ¿Cuál es su definición exacta?
2. ¿Bajo qué supuesto se sostiene?
3. ¿Qué código implementa la construcción?
4. ¿Qué vector o test demuestra conformidad?
5. ¿Qué experimento puede refutar la predicción?
6. ¿Dónde están los datos crudos y su commit?
7. ¿Qué resultado negativo limita el claim?
8. ¿Qué parte ha sido reproducida o revisada independientemente?

Si una afirmación no tiene respuesta para los ocho puntos, se presentará como
hipótesis, observación preliminar o trabajo futuro, no como resultado establecido.
