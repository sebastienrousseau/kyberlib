# FIPS 140-3 backend

> Feature `fips` · issue [#170](https://github.com/sebastienrousseau/kyberlib/issues/170)

kyberlib is a pure-Rust ML-KEM implementation, and a pure-Rust crate
cannot itself hold a FIPS 140-3 certificate. The `fips` feature moves
the typed ML-KEM API into the AWS-LC FIPS module, through `aws-lc-rs`,
so a workload that must use a validated module can keep kyberlib's API
and key formats.

## Enable it

```toml
[dependencies]
kyberlib = { version = "0.0.13", features = ["fips"] }
```

Building the module needs CMake, Go and a C compiler. Check the module
at start-up and refuse to run if it is not in FIPS mode:

```rust
kyberlib::fips::fips_mode()?;               // Err(FipsModeUnavailable) otherwise
assert!(kyberlib::BACKEND.contains("FIPS")); // which backend this build uses
```

## What runs inside the module

| Operation | `fips` off | `fips` on |
|---|---|---|
| `MlKem512/768/1024::generate` | pure Rust | **AWS-LC module** |
| `…EncapKey::encapsulate` (incl. FIPS 203 §7.2 key check) | pure Rust | **AWS-LC module** |
| `…DecapKey::decapsulate` | pure Rust | **AWS-LC module** |
| `KemCore::generate_from_seed` | pure Rust | pure Rust (AWS-LC has no seeded key generation) |
| legacy `keypair` / `encapsulate` / `decapsulate`, `kex`, `hazmat` | pure Rust | pure Rust |

Notes:

- **Randomness.** On the module path the caller's RNG argument is
  ignored: an approved module draws from its own DRBG. Code that relied
  on a seeded RNG for reproducible output (tests, known-answer replays)
  gets fresh randomness instead.
- **Malformed keys.** A decapsulation key the module rejects can only
  come from the unchecked `from_bytes` constructors. It is decapsulated
  by the pure-Rust code, which applies FIPS 203 implicit rejection. Use
  `try_from_slice`, which runs the §7.3 hash check, for untrusted bytes.
- **Byte compatibility.** Keys and ciphertexts keep the FIPS 203
  encodings, so they move between builds with and without `fips`.
  `crates/kyberlib/tests/test_fips.rs` checks this both ways for all
  three parameter sets, including identical implicit-rejection secrets.

## Is my build covered by a certificate?

That depends on facts this repository cannot assert for you:

1. The `aws-lc-fips-sys` version in your lockfile must build the AWS-LC
   FIPS module version named on a current CMVP certificate. Look it up
   in the [CMVP database](https://csrc.nist.gov/projects/cryptographic-module-validation-program/validated-modules/search)
   and compare it with the version the `aws-lc-fips-sys` documentation
   states.
2. You must run inside one of the certificate's tested operational
   environments (OS and CPU), with the build options its security
   policy requires.
3. `kyberlib::fips::fips_mode()` must return `Ok(())` at start-up.

Record all three in your compliance evidence. kyberlib's CI builds and
tests the backend on `ubuntu-latest` (job `fips`); passing CI is not a
statement of certificate coverage.

## Licence

`aws-lc-fips-sys` is `ISC AND (Apache-2.0 OR ISC) AND OpenSSL`. The
OpenSSL licence carries an attribution clause; `deny.toml` allows it for
that crate only. Check it fits your distribution before shipping.
