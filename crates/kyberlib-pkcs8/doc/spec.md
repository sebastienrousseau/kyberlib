# Encoding specification

> Last Updated: 2026-11-07

Byte-level reference for what `kyberlib-pkcs8` reads and writes. The
normative source is [RFC 9935][rfc]. Every layout below was taken from
OpenSSL 3.5.9 output (`tests/vectors/`) and is checked byte for byte by
`tests/openssl_interop.rs`.

## Algorithm identifier

| Algorithm   | OID                      | DER                                  |
|-------------|--------------------------|--------------------------------------|
| ML-KEM-512  | `2.16.840.1.101.3.4.4.1` | `06 09 60 86 48 01 65 03 04 04 01`   |
| ML-KEM-768  | `2.16.840.1.101.3.4.4.2` | `06 09 60 86 48 01 65 03 04 04 02`   |
| ML-KEM-1024 | `2.16.840.1.101.3.4.4.3` | `06 09 60 86 48 01 65 03 04 04 03`   |

The `AlgorithmIdentifier` is `30 0b` followed by the OID. Its
`parameters` field MUST be absent (RFC 9935 §3); a decoder here rejects
any value, including `NULL`.

## Public key: `SubjectPublicKeyInfo`

```text
30 82 04 b2                         SEQUENCE (ML-KEM-768: 1206 bytes)
   30 0b 06 09 60 86 48 01 65 03 04 04 02
   03 82 04 a1 00                   BIT STRING, 0 unused bits
      <1184-byte FIPS 203 encapsulation key>
```

Sizes: 822 / 1206 / 1590 bytes for ML-KEM-512 / 768 / 1024. A key with
unused bits, the wrong length, or a coefficient not reduced mod q
(FIPS 203 §7.2) is rejected.

## Private key: PKCS#8 `OneAsymmetricKey`

```text
30 ..          SEQUENCE
   02 01 00    version 0 (v1); v2 with a [1] publicKey is also read
   30 0b 06 09 60 86 48 01 65 03 04 04 0N
   04 ..       privateKey OCTET STRING, containing the CHOICE below
```

The `privateKey` octets hold one of three forms (RFC 9935 §6):

```text
ML-KEM-PrivateKey ::= CHOICE {
  seed        [0] OCTET STRING (SIZE (64)),
  expandedKey     OCTET STRING (SIZE (1632 | 2400 | 3168)),
  both            SEQUENCE {
                    seed        OCTET STRING (SIZE (64)),
                    expandedKey OCTET STRING (SIZE (1632 | 2400 | 3168)) } }
```

| Form       | First inner bytes | ML-KEM-768 total | Written by                              |
|------------|-------------------|------------------|-----------------------------------------|
| `seed`     | `80 40`           | 86 B             | this crate by default (RFC recommended) |
| `expanded` | `04 82 09 60`     | 2428 B           | keys imported without a seed            |
| `both`     | `30 82 09 a6 04 40` | 2498 B         | OpenSSL 3.5 by default                  |

The seed is `d ‖ z` (FIPS 203 `ML-KEM.KeyGen_internal(d, z)`). The form
is identified by its tag, never by length. On decode:

- `seed`: the key pair is derived from the seed.
- `expanded`: the FIPS 203 §7.3 hash check runs, and the embedded
  encapsulation key gets the §7.2 check.
- `both`: the expanded key must equal the one the seed derives
  (compared without an early exit); otherwise the key is rejected.
- A v2 `publicKey` must equal the derived encapsulation key.

Re-encoding writes the form that was read, so files round-trip
unchanged. The pre-standard layouts (raw seed or raw key directly in
`privateKey`, OpenSSL's `bare-seed` / `bare-priv`) are rejected.

## PEM

RFC 7468 labels `PUBLIC KEY` and `PRIVATE KEY`, 64-character lines, as
OpenSSL writes them (feature `pem`).

## Not implemented

Encrypted PKCS#8 (`EncryptedPrivateKeyInfo`).

[rfc]: https://www.rfc-editor.org/rfc/rfc9935
