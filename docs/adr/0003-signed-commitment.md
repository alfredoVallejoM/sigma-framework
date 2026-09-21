# ADR-0003: compromiso firmado Ed25519

- Estado: implementada
- Fecha: 2026-09-02
- Obligación: LIB-09

## Formato

El compromiso es un objeto distinto del digest y sólo admite suites v2-2:

```text
"SIGMASIG" || version:u16 || TLV(
  1=context,
  2=anchor_evidence,
  3=count:u16 || repeated(state_length:u16 || state),
  4=signature_algorithm:u16,
  5=public_key_id,
  6=signature
)
```

La versión inicial es 2 y el único algoritmo registrado es Ed25519 (`0x0001`).
El identificador de clave contiene 1..255 bytes opacos; resolverlo a una clave y
su ciclo de vida pertenece al protocolo consumidor.

La entrada firmada es `DST_SIGNED_COMMITMENT || unsigned_bytes`, donde
`unsigned_bytes` contiene magic, versión y los TLV 1..5 completos. Excluir el
campo 6 evita una definición circular; todos los demás bytes, incluidos ancla,
estados, algoritmo e ID de clave, quedan autenticados.

## Semántica de verificación

- `verify_signed_attestation` prueba que la clave indicada firmó la declaración.
  No prueba que los estados tengan una historia válida.
- `verify_full_signed` verifica primero la firma y después recalcula desde el
  mensaje toda el ancla y la trayectoria, comparando ambas en tiempo constante.

No se define una firma propia. La implementación opcional usa Ed25519 de
`cryptography`; claves públicas/privadas raw tienen 32 bytes y la firma 64.
