# Encoding specification

> Last Updated: 2026-05-22

Byte-level reference for the PKCS#8, SPKI, and PEM
artefacts this crate produces. Tracks IETF
[`draft-ietf-lamps-kyber-certificates`][lamps].

## OID table

| Algorithm | Dotted OID | Length |
|---|---|---|
| ML-KEM-512 | `2.16.840.1.101.3.4.4.1` | 11 bytes |
| ML-KEM-768 | `2.16.840.1.101.3.4.4.2` | 11 bytes |
| ML-KEM-1024 | `2.16.840.1.101.3.4.4.3` | 11 bytes |

DER encoding of the OID (universal tag `06`, length `0b`):

```text
06 0b 60 86 48 01 65 03 04 04 NN
                              ^^
                              01 = ML-KEM-512
                              02 = ML-KEM-768
                              03 = ML-KEM-1024
```

## SubjectPublicKeyInfo (public keys)

Per RFC 5280 §4.1:

```text
SubjectPublicKeyInfo ::= SEQUENCE {
    algorithm        AlgorithmIdentifier,
    subjectPublicKey BIT STRING
}

AlgorithmIdentifier ::= SEQUENCE {
    algorithm  OBJECT IDENTIFIER,
    parameters ANY DEFINED BY algorithm OPTIONAL
}
```

For ML-KEM, `parameters` is **absent** (the OID encodes
the parameter set). The `subjectPublicKey` BIT STRING
wraps the raw `kyberlib::MlKem*EncapKey::as_bytes()` byte
string with zero unused bits.

### ML-KEM-768 SPKI byte layout

```text
30 LL                           ; SEQUENCE, length LL
   30 0d                        ; SEQUENCE (AlgorithmIdentifier)
      06 0b 60 86 48 01 65 03 04 04 02   ; OID for ML-KEM-768
   03 KL                        ; BIT STRING, length KL
      00                        ; unused bits = 0
      <1184 bytes of raw EncapKey>
```

Total DER size: ~1203 bytes (SEQUENCE overhead + AlgorithmId
overhead + BIT STRING overhead + 1184 raw payload).

## PKCS#8 PrivateKeyInfo (secret keys)

Per RFC 5958 §2:

```text
OneAsymmetricKey ::= SEQUENCE {
    version       Version,
    algorithm     AlgorithmIdentifier,
    privateKey    OCTET STRING,
    attributes    [0] Attributes OPTIONAL,
    publicKey     [1] BIT STRING OPTIONAL
}
```

For ML-KEM:

* `version` = `INTEGER 0` (v1) or `INTEGER 1` (v2 with
  the optional `publicKey` field).
* `algorithm` matches the SPKI algorithm identifier.
* `privateKey` wraps the raw
  `kyberlib::MlKem*DecapKey::as_bytes()` byte string as an
  inner OCTET STRING (the LAMPS draft picked the
  "OCTET STRING-wrapping-OCTET STRING" convention to match
  Ed25519's PKCS#8).
* `attributes` is absent.
* `publicKey` (v2 only) carries the matching SPKI public
  bytes for in-line use without a separate certificate.

### ML-KEM-768 v1 PKCS#8 byte layout

```text
30 LL                           ; SEQUENCE, length LL
   02 01 00                     ; INTEGER version = 0
   30 0d                        ; SEQUENCE (AlgorithmIdentifier)
      06 0b 60 86 48 01 65 03 04 04 02   ; OID for ML-KEM-768
   04 KL                        ; OCTET STRING, length KL
      04 KL'                    ; inner OCTET STRING
         <2400 bytes of raw DecapKey>
```

The double-OCTET-STRING wrapping matches OpenSSL 3.5+'s
ML-KEM PKCS#8 output (verified empirically against `openssl
genpkey -algorithm ML-KEM-768 -outform DER`).

## PEM encoding (feature = "pem")

Per RFC 7468 §13:

```text
-----BEGIN PUBLIC KEY-----
<base64-encoded SPKI DER, 64 chars per line>
-----END PUBLIC KEY-----
```

```text
-----BEGIN PRIVATE KEY-----
<base64-encoded PKCS#8 DER, 64 chars per line>
-----END PRIVATE KEY-----
```

The PEM headers are *generic* `PUBLIC KEY` / `PRIVATE KEY`
(not `ML-KEM PUBLIC KEY`) per RFC 7468's preference for
the SPKI/PKCS#8-wrapped form over algorithm-specific
labels. This matches OpenSSL's output exactly.

## Encrypted PKCS#8

PKCS#8 §6.2 defines `EncryptedPrivateKeyInfo` (`PBES2`
with AES-256-GCM or AES-256-CBC). This crate will support
it via the optional `pkcs8::EncryptedPrivateKeyInfo`
surface in the RustCrypto stack once [#168] lands.
Encryption parameters at parity with OpenSSL 3.5 defaults:

* `PBES2` outer
* `PBKDF2-SHA256` KDF, 600,000 iterations (per OWASP 2024)
* `AES-256-GCM` cipher

## Test vectors

The Phase 2(b) test set will include:

1. Round-trip with deterministic
   `MlKem768::generate(&mut chacha20_seeded_rng())` → SPKI
   → DER → parse → byte-equal EncapKey.
2. OpenSSL 3.5 cross-check: `openssl asn1parse -inform
   DER -in our_output.der` produces the expected
   `OBJECT :2.16.840.1.101.3.4.4.2` line.
3. Bouncy Castle 1.78 cross-check: load with
   `KeyFactory.getInstance("ML-KEM-768")` and verify the
   resulting `PublicKey.getEncoded()` matches our DER
   output byte-for-byte.

[lamps]: https://datatracker.ietf.org/doc/draft-ietf-lamps-kyber-certificates/
