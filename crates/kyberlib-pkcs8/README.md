# kyberlib-pkcs8

> Last Updated: 2026-05-22

> **Skeleton.** PKCS#8 / SubjectPublicKeyInfo / PEM encoding for
> kyberlib ML-KEM keys. Not yet usable.

Implements the IETF LAMPS draft (`draft-ietf-lamps-kyber-certificates`)
and CMS RFC 9936 wire formats for ML-KEM key material.

| Algorithm    | OID                       |
|--------------|---------------------------|
| ML-KEM-512   | `2.16.840.1.101.3.4.4.1`  |
| ML-KEM-768   | `2.16.840.1.101.3.4.4.2`  |
| ML-KEM-1024  | `2.16.840.1.101.3.4.4.3`  |

## Status

`publish = false`. The OID table and encoding trait surface are
in place. Full PKCS#8 / SPKI / PEM round-trip lands with
[#168](https://github.com/sebastienrousseau/kyberlib/issues/168) once
[#147](https://github.com/sebastienrousseau/kyberlib/issues/147)
(Phase 2(b) FIPS 203 patch) is settled — until then the wrapped
bytes would not interop with OpenSSL 3.5+ ML-KEM keys.
