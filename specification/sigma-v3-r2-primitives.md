# Sigma v3 — primitivas, dominios y transcript R2

Estado: contrato ejecutable de R2.  
Versión de transcript: `3`.

## Primitivas

Los `AlgorithmId` heredados identifican las mismas primitivas estándar que en
v2.2, pero todas las invocaciones v3 comienzan con un domain tag v3. La salida
normativa es siempre de 64 bytes; SHAKE256 se lee a 512 bits.

## Domain tag

```text
ASCII("SIGMA3DS") || uint16_be(DomainIdV3)
```

Los IDs v3 están en `sigma/spec/ids_v3.py`; no se reutiliza ningún `DomainId`
v2.2. Longitud, joint, parámetros, layouts init/round, frames init/round,
binding, header y evidence tienen domains distintos.

## Transcript streaming

```text
ASCII("SIGMA3TR")
|| uint16_be(3)
|| uint16_be(domain_id)
|| field_1 || ... || field_n

field := uint16_be(tag) || uint64_be(length) || exact_payload_bytes
```

Los tags son positivos, únicos y estrictamente crecientes. La longitud se
declara antes del payload y el writer exige consumo exacto. Los chunks no
afectan a los bytes matemáticos. El transcript permite campos de hasta
`2^64-1` bytes sin materializar el mensaje completo.

`TranscriptWriter` escribe sobre un sink incremental. Si una fuente incumple
su longitud, el writer falla y el sink parcial debe descartarse; nunca se usa
su digest.
