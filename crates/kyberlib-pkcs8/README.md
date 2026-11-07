# kyberlib-pkcs8

> Last Updated: 2026-11-07

PKCS#8, `SubjectPublicKeyInfo` and PEM encodings for kyberlib's ML-KEM
keys, per [RFC 9935](https://www.rfc-editor.org/rfc/rfc9935). Keys move
to and from OpenSSL 3.5 and later without conversion.

| Algorithm   | OID                      | Public key (SPKI DER) | Private key, seed form (DER) |
|-------------|--------------------------|-----------------------|------------------------------|
| ML-KEM-512  | `2.16.840.1.101.3.4.4.1` | 822 B                 | 86 B                         |
| ML-KEM-768  | `2.16.840.1.101.3.4.4.2` | 1206 B                | 86 B                         |
| ML-KEM-1024 | `2.16.840.1.101.3.4.4.3` | 1590 B                | 86 B                         |

```rust
use kyberlib::MlKem768;
use kyberlib_pkcs8::{DecodePrivateKey, EncodePrivateKey, PrivateKey};

fn main() -> Result<(), kyberlib_pkcs8::pkcs8::Error> {
    let key = PrivateKey::<MlKem768>::generate(&mut rand::rngs::OsRng).expect("RNG");
    let der = key.to_pkcs8_der()?; // seed form, 86 bytes
    let back = PrivateKey::<MlKem768>::from_pkcs8_der(der.as_bytes())?;
    assert_eq!(back.decapsulation_key(), key.decapsulation_key());
    Ok(())
}
```

`PrivateKey` and `PublicKey` implement RustCrypto's
`EncodePrivateKey` / `DecodePrivateKey` and `EncodePublicKey` /
`DecodePublicKey`, so the `pem` feature adds `to_pkcs8_pem`,
`from_public_key_pem` and the rest. See
`examples/pem_roundtrip.rs`.

## Features

| Feature | Default | Adds |
|---------|---------|------|
| `alloc` | yes     | Encoding. Decoding works without it (`no_std`, no allocator). |
| `pem`   | no      | PEM (RFC 7468) methods. |
| `std`   | no      | File helpers; `std::error::Error` on kyberlib's error type. |

## What decoding checks

- The OID matches the parameter set, and the parameters field is absent.
- The private-key form is read from its ASN.1 tag; sizes are exact; no
  trailing data. The pre-standard "bare" layouts are rejected.
- An expanded key passes the FIPS 203 §7.3 hash check; a public key
  passes the §7.2 modulus check.
- In the `both` form, the expanded key must be the one the seed derives.
- An optional `publicKey` field must match the private key.

## How it is checked

`tests/openssl_interop.rs` decodes keys made by OpenSSL 3.5.9 from
fixed seeds (`tests/vectors/regen.sh`), in all three private-key forms,
SPKI and PEM, for every parameter set, and re-encodes each byte for
byte. `tests/rejects.rs` covers the rules above. Layouts are in
[`doc/spec.md`](doc/spec.md).

## Status

`publish = false` until the third-party audit
([#177](https://github.com/sebastienrousseau/kyberlib/issues/177))
closes. Encrypted PKCS#8 (`EncryptedPrivateKeyInfo`) is not enabled.
