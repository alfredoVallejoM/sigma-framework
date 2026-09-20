# Sigma v3 R11 — perfiles de aplicación

Estado: normativo para el candidato R11.

## Regla común

Las tres aplicaciones usan wire propio, versión de record v3 y dominios que no
se reutilizan. Ningún record v2 se acepta como v3 ni un record de una aplicación
se acepta como otra. Un cambio de suite, parámetros, salt, challenge, key id,
nonce o digest cambia los bytes autenticados o recomputados.

Asignaciones:

| Uso | Magic / domain |
|---|---|
| compromiso firmado | `SIG3SIGN` / `SIGNED_COMMITMENT (0x0311)` |
| binding KDF | `SIG3KDFP`, `SIG3KDFR` / `KDF_BINDING (0x0312)` |
| clave final KDF | framing interno `SIG3KDFS` / `KDF_FINAL_KEY (0x0313)` |
| parámetros PoW | `SIG3POWP` / `POW_CHALLENGE (0x0314)` |
| input PoW | `SIG3POWI` / `POW_NONCE (0x0315)` |
| predicado y prueba PoW | `SIG3POWR` / `POW_PREDICATE (0x0316)` |

## Compromiso Ed25519

El objeto firmado contiene exactamente `SigmaDigestV3.to_bytes()`, algoritmo,
`public_key_id` y dominio. La entrada de Ed25519 es:

```text
domain_tag_v3(SIGNED_COMMITMENT) || unsigned_record
```

`verify_signed_digest_v3` sólo autentica esos bytes. No afirma que exista un
mensaje concreto. `verify_full_signed_v3` añade la recomputación completa del
input canónico y es la única API que afirma binding con el mensaje.

Modelo de amenaza: evita sustitución del digest, algoritmo o identidad de clave
y cross-protocol entre wires registrados. No proporciona confidencialidad,
timestamp, revocación, identidad semántica de la clave ni auditabilidad de
estados internos no publicados.

## Argon2id + Sigma

Argon2id se ejecuta primero. Su salida secreta completa se evalúa como input
canónico de Sigma v3 bajo un contexto que fija suite, salt y parámetros
Argon2id. La clave final es un SHAKE256 domain-separated sobre salida Argon2id,
parámetros, salt y `SigmaDigestV3.to_bytes()`.

El record persistente contiene sólo parámetros, salt y digest. La clave final
usa `repr=False`, no tiene `to_bytes()` y rechaza pickle. Las suites admitidas
tienen `t_max <= 32` y `k_max <= 4`; Argon2id se valida contra la política local
antes de ejecutar trabajo costoso.

Modelo de amenaza: Argon2id aporta el coste memory-hard frente a búsqueda de
contraseñas; Sigma sólo aporta binding y coste adicional acotado. El record
sigue siendo un verificador offline. No se atribuye a Sigma memory hardness,
resistencia a extracción del proceso, borrado seguro de `bytes`, constant-time
global ni protección frente a una contraseña débil.

## Resolución de `SPEC-V3-010` y PoW

Decisión: el nonce se incluye en el input canónico antes de toda preparación.
Para payload `P` y nonce `N`, la única entrada evaluada es:

```text
record(SIG3POWI,
       domain_tag_v3(POW_NONCE),
       payload=P,
       nonce=uint64_be(N))
```

Por tanto ancla, cardinalidad, firmas `A/Λ/J`, parámetros derivados, `S0` y
todas las rondas dependen de `N`. Queda prohibido derivar una trayectoria sobre
`P` y añadir o comprobar el nonce después. Ésta es la resolución normativa de
`SPEC-V3-010`.

El único predicado R11 es `DIGEST_SHA512`: SHA-512 sobre dominio del predicado,
parámetros PoW y wire del digest debe comenzar con `difficulty_bits` ceros. La
verificación recomputa la trayectoria completa y compara el digest antes de
aplicar el predicado.

Modelo de amenaza: el perfil demuestra búsqueda verificable bajo una dificultad
localmente aceptada y evita reutilización entre challenge, suite o predicado.
No es una VDF; verificar no es asimétricamente barato. No se afirma ejecución
constant-time, memory hardness, resistencia ASIC/GPU, imparcialidad económica ni
finalidad de consenso. La selección de nonces es precisamente la búsqueda PoW,
no una fuente de aleatoriedad para otras propiedades criptográficas.

## Gate R11

El cierre exige round-trip y rechazo canónico de los tres wires, aislamiento de
dominios, regresiones de downgrade/cross-wire, autenticación y recomputación
separadas, secreto KDF no serializable, política previa a Argon2id, dependencia
del nonce en parámetros y digest, baseline v2.2 inalterado y revisión adversaria
versionada.
