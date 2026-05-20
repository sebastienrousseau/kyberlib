# Getting started with kyberlib

A focused walkthrough for someone who just landed on the repo and
wants to *use* the library. The full reference is the
[root README](./README.md); this page is the on-ramp.

## Install

```toml
[dependencies]
kyberlib = "0.0.7"
```

For `no_std` consumers:

```toml
[dependencies]
kyberlib = { version = "0.0.7", default-features = false, features = ["kyber768"] }
```

## First keypair → encapsulate → decapsulate

The recommended surface is the **v0.0.7 typed-state API**, where the
parameter set is a *type*, not a Cargo feature:

```rust
use kyberlib::{KemCore, MlKem768};

fn main() -> Result<(), kyberlib::KyberLibError> {
    let mut rng = rand::thread_rng();

    // Bob generates a (decap, encap) keypair.
    let (bob_dk, bob_ek) = MlKem768::generate(&mut rng)?;

    // Alice encapsulates a shared secret against Bob's encap key.
    let (ciphertext, ss_alice) = bob_ek.encapsulate(&mut rng)?;

    // Bob decapsulates with his decap key. Implicit rejection per
    // FIPS 203 §6.3 — never panics, never branches on validity.
    let ss_bob = bob_dk.decapsulate(&ciphertext);

    assert_eq!(ss_alice, ss_bob);
    Ok(())
}
```

[`MlKem512`], [`MlKem768`], and [`MlKem1024`] all implement the same
[`KemCore`] trait and work concurrently in any single build (since
the const-generic refactor in #130b landed). Pick the parameter set
at the call site, not at build time.

## Choosing a parameter set

| Marker | NIST category | Module rank | Public key | Secret key | Ciphertext |
|---|---|---|---|---|---|
| [`MlKem512`] | 1 (≈ AES-128) | K = 2 | 800 B | 1632 B | 768 B |
| [`MlKem768`] | 3 (≈ AES-192) | K = 3 | 1184 B | 2400 B | 1088 B |
| [`MlKem1024`] | 5 (≈ AES-256) | K = 4 | 1568 B | 3168 B | 1568 B |

Defaults:

* TLS hybrid deployments → ML-KEM-768 (CNSA 2.0 hybrid default).
* CNSA 2.0 standalone for NSS (mandate effective 2027-01-01) →
  ML-KEM-1024.
* Constrained IoT → ML-KEM-512.

## Authenticated key exchange

The [`Uake`] / [`Ake`] wrappers add an authentication layer on top
of the bare KEM. See the [`kex` module documentation][kex] for the
three-message handshake shape.

```rust
use kyberlib::{keypair, Uake};

fn main() -> Result<(), kyberlib::KyberLibError> {
    let mut rng = rand::thread_rng();
    let mut alice = Uake::new();
    let mut bob = Uake::new();
    let bob_keys = keypair(&mut rng)?;

    let client_init = alice.client_init(&bob_keys.public, &mut rng)?;
    let server_send = bob.server_receive(client_init, &bob_keys.secret, &mut rng)?;
    alice.client_confirm(server_send)?;

    assert_eq!(alice.shared_secret, bob.shared_secret);
    Ok(())
}
```

## Migration from kyberlib 0.0.6

* Free functions [`keypair`] / [`encapsulate`] / [`decapsulate`]
  still work — they're now thin shims over the typed API for the
  default `kyber768` configuration. Prefer the typed API in new
  code.
* `KYBER_*_BYTES` constants are retained as `#[doc(hidden)] pub`
  aliases; the canonical names are now on the markers (e.g.
  [`MlKem768::PUBLIC_KEY_BYTES`]).
* The `wasm` and `zeroize` Cargo features were no-op shims and have
  been removed. Replace with the dedicated `kyberlib-wasm` crate and
  the unconditional `ZeroizeOnDrop` derive respectively.
* `Keypair { pub public, pub secret }` is soft-deprecated. Prefer
  [`MlKem768DecapKey`] / [`MlKem768EncapKey`].

## What to read next

* [`README.md`](./README.md) — full feature matrix, security model,
  comparison vs `RustCrypto/ml-kem` / `pqcrypto-kyber` / `oqs-rs`.
* [`SECURITY.md`](./SECURITY.md) — threat model, constant-time
  guarantees, ACVP conformance status.
* [`doc/adr/`](./doc/adr/) — architectural decision records (KyberSlash
  audit, AVX2 quarantine, FIPS 203 migration).
* [`GLOSSARY.md`](./GLOSSARY.md) — FIPS 203 / ML-KEM / lattice-cryptography
  terminology.
* [`PLAN.md`](./PLAN.md) — v0.0.7 audit roadmap and the multi-day
  refactors landed under #130b.

[`KemCore`]: https://docs.rs/kyberlib/latest/kyberlib/trait.KemCore.html
[`MlKem512`]: https://docs.rs/kyberlib/latest/kyberlib/struct.MlKem512.html
[`MlKem768`]: https://docs.rs/kyberlib/latest/kyberlib/struct.MlKem768.html
[`MlKem1024`]: https://docs.rs/kyberlib/latest/kyberlib/struct.MlKem1024.html
[`MlKem768::PUBLIC_KEY_BYTES`]: https://docs.rs/kyberlib/latest/kyberlib/struct.MlKem768.html
[`MlKem768EncapKey`]: https://docs.rs/kyberlib/latest/kyberlib/struct.MlKem768EncapKey.html
[`MlKem768DecapKey`]: https://docs.rs/kyberlib/latest/kyberlib/struct.MlKem768DecapKey.html
[`Uake`]: https://docs.rs/kyberlib/latest/kyberlib/struct.Uake.html
[`Ake`]: https://docs.rs/kyberlib/latest/kyberlib/struct.Ake.html
[`keypair`]: https://docs.rs/kyberlib/latest/kyberlib/fn.keypair.html
[`encapsulate`]: https://docs.rs/kyberlib/latest/kyberlib/fn.encapsulate.html
[`decapsulate`]: https://docs.rs/kyberlib/latest/kyberlib/fn.decapsulate.html
[kex]: https://docs.rs/kyberlib/latest/kyberlib/kex/index.html
