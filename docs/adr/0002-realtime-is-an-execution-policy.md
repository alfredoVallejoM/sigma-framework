# ADR-0002: RealTime es una política de ejecución

- Estado: implementada
- Fecha: 2026-09-02
- Obligación: LIB-11

## Decisión

RealTime deja de ser una suite criptográfica activa. El procesamiento en tiempo
real se expresa con `IncrementalSigmaV2` y una suite StreamWide registrada. Para
la familia v2-2 se usa `lightweight_v2_2()`; actualizar por fragmentos y
finalizar produce exactamente el mismo digest que procesar los mismos bytes de
una vez.

No se asignará un `SuiteId` RealTime v2-2 porque no existe una función
matemática ni una hipótesis de seguridad diferente. El ritmo de llegada, tamaño
de las llamadas a `update()` y backend son políticas locales y no entran en el
wire.

## Compatibilidad

`REALTIME_STREAM_WIDE_V2` y el preset `realtime-v2` v2-1 permanecen disponibles
exclusivamente para reproducir objetos congelados. Su descriptor queda marcado
como obsoleto. No se reinterpreta su identificador, no se modifica su digest y
no se promociona a la familia v2-2.

## Consecuencias

- La documentación y nuevos experimentos no cuentan RealTime como construcción.
- La latencia incremental se compara como política sobre la misma suite.
- Los checkpoints siguen siendo provisionales: sólo `finalize()` representa el
  mensaje completo y no se presenta como firma ni autenticación.
