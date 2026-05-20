# Architecture

`kyberlib-pkcs8` provides PKCS#8 `PrivateKeyInfo`,
SubjectPublicKeyInfo (SPKI), and PEM encoding for the ML-
KEM key material produced by `kyberlib`. The encoded
output is intended to interoperate with X.509 chains,
OpenSSL `EVP_PKEY_*` calls, and the IETF LAMPS suite of
drafts.

For the byte-level DER layout and OID assignments see
[`spec.md`](./spec.md); for the per-item API reference see
[docs.rs/kyberlib-pkcs8](https://docs.rs/kyberlib-pkcs8).

## Status

**Skeleton.** `publish = false`. The OID constants and the
trait surface are wired today; the actual DER round-trip
is gated on [#168] (RustCrypto `pkcs8` / `spki` / `der`
dependency vet) and on the FIPS 203 spec migration
settling.

The hold-back is not technical — it's interop. v0.0.6
shipped Round-3-form ML-KEM; v0.0.7 is FIPS 203 final.
Shipping PKCS#8-encoded blobs of v0.0.6 keys would create
on-disk artefacts that no FIPS 203 implementation can
read, and the wire format of the key bytes themselves
(not just the wrapping) needs to settle before the
encoding crate becomes useful.

## Module map (target shape)

```text
crates/kyberlib-pkcs8/src/
├── lib.rs           re-exports of kyberlib::oid + Encoding traits
├── spki.rs          SubjectPublicKeyInfo encode/decode (public keys)
├── pkcs8.rs         PKCS#8 PrivateKeyInfo encode/decode (secret keys)
├── pem.rs           (feature = "pem") pem-rfc7468 wrapper
└── error.rs         pkcs8::Error / der::Error conversion shim
```

At v0.0.7 only `lib.rs` exists; the others are placeholders
in the planned tree.

## OID assignments

ML-KEM OIDs are registered under the NIST CSOR arc
`2.16.840.1.101.3.4.4.*`:

| Algorithm | OID | Hex DER |
|---|---|---|
| ML-KEM-512 | `2.16.840.1.101.3.4.4.1` | `06 0b 60 86 48 01 65 03 04 04 01` |
| ML-KEM-768 | `2.16.840.1.101.3.4.4.2` | `06 0b 60 86 48 01 65 03 04 04 02` |
| ML-KEM-1024 | `2.16.840.1.101.3.4.4.3` | `06 0b 60 86 48 01 65 03 04 04 03` |

These match `draft-ietf-lamps-kyber-certificates` and are
already used by OpenSSL 3.5+, Bouncy Castle 1.78+, and
NSS. The OIDs are re-exported from `kyberlib::oid` (single
source of truth in the core crate; see [#150]).

## Why a dedicated crate

The bare `kyberlib` core stays `#![no_std]` and dependency-
light. The RustCrypto `pkcs8` / `der` / `spki` /
`pem-rfc7468` stack carries a non-trivial transitive
graph — bringing it into the core crate would change the
audit surface, the WASM compilation cost, and the
`no_std` story.

Splitting the encoding into a sidecar:

1. Lets `no_std` consumers depend on `kyberlib` without
   pulling the DER stack.
2. Lets PKI consumers depend on `kyberlib-pkcs8` and get
   the encoding layer without choosing acceleration
   backends.
3. Makes the cargo-vet audit boundary clear — the
   encoding layer is a *different* trust domain than the
   crypto primitive.

This mirrors the workspace layout pattern: safe core
(`kyberlib`) + sidecars (`kyberlib-asm`, `kyberlib-hybrid`,
`kyberlib-pkcs8`, `kyberlib-wasm`).

## Sealed trait pattern

The public surface uses sealed traits for the same reason
`kyberlib-hybrid` does — only this crate gets to add a new
encoding parameter set, because each parameter set is
paired to an OID and a wire format that must round-trip
with OpenSSL et al.:

```rust,ignore
pub trait EncapKeyEncoding: sealed::Sealed {
    fn to_spki_der(&self) -> Result<Vec<u8>, Error>;
    fn from_spki_der(der: &[u8]) -> Result<Self, Error>;
}
mod sealed { pub trait Sealed {} }
```

The `to_spki_pem` / `from_spki_pem` variants are gated
behind the `pem` feature, which will pull `pem-rfc7468`.

## Interop targets

The Phase 2(b) release-gate test set will include:

| Producer | Consumer | Outcome |
|---|---|---|
| `kyberlib-pkcs8` SPKI | OpenSSL 3.5 `EVP_PKEY_pkey_from_subj_pub_key_info_der` | Round-trip OK |
| OpenSSL 3.5 SPKI | `kyberlib-pkcs8::from_spki_der` | Round-trip OK |
| `kyberlib-pkcs8` PKCS#8 | Bouncy Castle 1.78 `KeyFactory.getInstance("ML-KEM-768")` | Round-trip OK |
| `kyberlib-pkcs8` PEM | `openssl genpkey -algorithm ML-KEM-768` round-trip | Round-trip OK |

Each interop case is gated by [#168] sub-tasks.

## What this crate does NOT do

* **CMS / S/MIME encoding** — that's `draft-ietf-lamps-cms-
  kyber` territory and will land as a sibling crate
  (`kyberlib-cms`) once the LAMPS draft is final.
* **CSR generation** — out of scope; use a dedicated PKI
  crate that consumes the SPKI bytes from here.
* **PKCS#11 binding** — out of scope.
* **X.509 certificate parsing** — `kyberlib-pkcs8` provides
  the key-encoding pieces; certificate-level parsing
  belongs in `x509-cert` / equivalent.

[#150]: https://github.com/sebastienrousseau/kyberlib/issues/150
[#168]: https://github.com/sebastienrousseau/kyberlib/issues/168
