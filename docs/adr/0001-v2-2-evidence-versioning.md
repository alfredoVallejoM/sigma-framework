# ADR-0001: versionado de evidencias de ancla v2-2

- Estado: aceptado para implementación
- Fecha: 2026-09-02
- Obligatoriedad: LIB-03, LIB-11, LIB-12 y LIB-15

## Contexto

Los bytes v2-1 de `AnchorEvidence` no contienen versión ni variante. Los de
`CrossWideEvidence` insertan el entero `3` después del mismo dominio, posición
que en el formato simple representa el número de raíces. Añadir un discriminante
al formato actual alteraría `S_0` y todos los digests, porque la evidencia forma
parte de la entrada canónica de inicialización y de cada ronda.

## Decisión

1. Los `SuiteId` v2-1, sus contextos, evidencias y KAT quedan congelados como
   familia histórica interoperable. No se reinterpretarán sus bytes.
2. Las suites v2-2 recibirán identificadores nuevos. Un contexto con un ID v2-1
   seguirá usando exclusivamente el serializer histórico.
3. La evidencia v2-2 tendrá un envelope autocontenido con:

   ```text
   EVIDENCE_MAGIC || evidence_version:u16 || evidence_type:u16 ||
   suite_id:u16 || body_length:u32 || canonical_TLV_body
   ```

4. `evidence_type` distinguirá al menos `WIDE_ROOTS` y `CROSS_WIDE`; futuros
   vectores DeepVector tendrán un tipo nuevo, nunca una interpretación implícita.
5. El parser recibirá o recuperará la suite, comprobará que el `suite_id` del
   envelope coincide, y validará cantidad, orden, algoritmo y longitud de cada
   componente contra el descriptor registrado.
6. El contexto wire seguirá en versión 2 mientras su gramática no cambie. La
   modificación matemática se identifica mediante nuevos `SuiteId`; elevar la
   versión del contexto sin cambiar su gramática sólo duplicaría formatos.
7. La versión de paquete y la familia de suites se documentarán separadamente.

## Consecuencias

- Los digests v2-1 continúan verificándose byte a byte.
- Ningún digest producido por una suite v2-2 puede confundirse con v2-1.
- El parser v2-2 puede ser total e inequívoco sin inventar un parser ambiguo
  para el formato interno histórico.
- La migración exige nuevos vectores y no puede marcarse como parche compatible.

## Gate de implementación

- registro de IDs y tipos cerrado;
- serializers/parsers estrictos para ambos tipos v2-2;
- corpus negativo de magic, versión, tipo, suite, orden, duplicados, longitudes,
  algoritmos, truncado y trailing bytes;
- fuzzing y prueba de round-trip para todas las suites v2-2;
- KAT v2-1 sin cambios y KAT v2-2 publicados por separado.
