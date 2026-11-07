# Architecture

> Last Updated: 2026-11-07

`kyberlib-pkcs8` encodes and decodes kyberlib's ML-KEM keys as PKCS#8,
`SubjectPublicKeyInfo` and PEM, per RFC 9935. Byte layouts are in
[`spec.md`](./spec.md).

## Module map

```text
src/
├── lib.rs      crate docs and re-exports (RustCrypto traits, der/pkcs8/spki)
├── params.rs   sealed `Params` trait for MlKem512/768/1024: OID, sizes,
│               and the checked kyberlib key constructors
├── choice.rs   the RFC 9935 private-key CHOICE (seed / expanded / both)
├── private.rs  `PrivateKey<P>`: generate, from_seed, from_expanded,
│               PKCS#8 encode/decode, consistency checks
└── public.rs   `PublicKey<P>`: SPKI encode/decode
```

## Design choices

- **RustCrypto traits, not a custom API.** `PrivateKey` implements
  `pkcs8::{EncodePrivateKey, DecodePrivateKey}` and `PublicKey`
  implements `spki::{EncodePublicKey, DecodePublicKey}`, so PEM and file
  helpers come from those crates, and the keys plug into code written
  for other RustCrypto algorithms.
- **Keep the seed.** RFC 9935 recommends retaining and exporting the
  seed. `PrivateKey::generate` draws a 64-byte seed and keeps it;
  encoding defaults to the seed form.
- **Checks at import.** The FIPS 203 §7.2 and §7.3 checks run when a
  key is decoded, using `MlKemNEncapKey::validate` and
  `MlKemNDecapKey::try_from_slice` from the core crate, so a bad key
  fails at load rather than at first use.
- **Secrets.** The seed is held in `Zeroizing`; the inner CHOICE is
  built in a pre-sized `Zeroizing<Vec>` so no copy is left in a
  reallocated block; the outer document is a `der::SecretDocument`.
  `Debug` prints no key material.
- **`no_std`.** Decoding needs no allocator; `alloc` (default) adds
  encoding.

## Why a separate crate

The core `kyberlib` crate stays free of the DER stack (`der`, `spki`,
`pkcs8`, `pem-rfc7468`, `base64ct`). Those are RustCrypto crates whose
publishers this repository trusts in `supply-chain/audits.toml`.

## Out of scope

- Encrypted PKCS#8.
- CMS (RFC 9936) and COSE: see #169.
- X.509 certificates and CSRs: use `x509-cert` with the SPKI from here.
