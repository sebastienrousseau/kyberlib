# ADR 0006 — FIPS 140-3 facade via `aws-lc-rs` delegation

* **Status:** Proposed (planned for v0.0.9, branch `feat/v0.0.9-fips`)
* **Date:** 2026-05-20
* **Authors:** sebastienrousseau
* **Tracking issue:** [#170](https://github.com/sebastienrousseau/kyberlib/issues/170)
* **Depends on:** [ADR 0005](./0005-byoe-deterministic-api.md) (deterministic API)

## Context

Two distinct consumer profiles want different things from the same
ML-KEM library:

1. **Default consumers** — Rust application developers who pick
   `kyberlib` for ergonomics, `#![forbid(unsafe_code)]`, and a
   sane `no_std` story. They don't have a regulator looking over
   their shoulder. The pure-Rust backend serves them.
2. **Regulated consumers** — Federal contractors, defence
   suppliers, HIPAA / PCI-DSS auditees who must use a **CMVP-
   validated module** for cryptography. AWS-LC has ML-KEM in CMVP
   validation (track-2); `aws-lc-rs` is the official Rust wrapper.
   These consumers need byte-identical behaviour through a
   validated boundary.

Today these profiles fork the dependency graph: pure-Rust
consumers pick `kyberlib`; FIPS consumers pick `aws-lc-rs` and
write their own glue. The kyberlib `KemCore` ergonomics are wasted
on the second group.

We want a single `KemCore` API surface where the **backend** is
chosen at compile time via Cargo features:

| Feature | Backend | Use case |
|---|---|---|
| (default) | Pure-Rust `kyberlib` reference | Most consumers |
| `fips` | `aws-lc-rs` (AWS-LC C library) | FIPS 140-3 / CMVP-required |
| `verified` | `libcrux-ml-kem` (F* + hax formal proofs) | High-assurance / formal-methods consumers |

The three are **mutually exclusive** — `compile_error!` at the
backends module if more than one is selected.

## Decision

### Internal module structure

The crate root re-exports a stable type / trait surface. The
actual cryptography lives in a backends module that uses
`cfg`-routing to pick exactly one engine:

```text
crates/kyberlib/src/
├── lib.rs               public exports + the API surface
├── error.rs             unified KyberLibError (adds FipsBoundaryError)
├── types.rs             MlKem*DecapKey / EncapKey / Ciphertext (opaque wrappers)
├── core.rs              KemCore trait (per ADR 0005)
├── ml_kem.rs            existing v0.0.7 typed-state surface
└── backends/
    ├── mod.rs           the cfg-routing traffic cop
    ├── pure_rust.rs     today's reference + AVX2 backends (the default)
    ├── fips.rs          aws-lc-rs delegation
    └── verified.rs      libcrux-ml-kem delegation
```

### `backends/mod.rs` — the traffic cop

```rust
// Mutually exclusive backend features.
#[cfg(all(feature = "fips", feature = "verified"))]
compile_error!(
    "Features `fips` and `verified` are mutually exclusive — \
     pick one cryptographic backend."
);

#[cfg(feature = "fips")]
mod fips;
#[cfg(feature = "fips")]
pub(crate) use fips::MlKem768Backend;

#[cfg(feature = "verified")]
mod verified;
#[cfg(feature = "verified")]
pub(crate) use verified::MlKem768Backend;

#[cfg(not(any(feature = "fips", feature = "verified")))]
mod pure_rust;
#[cfg(not(any(feature = "fips", feature = "verified")))]
pub(crate) use pure_rust::MlKem768Backend;
```

### Opaque types via `cfg` swap

The public `MlKem768DecapKey` is a wrapper whose internals differ
per backend, but whose surface is identical:

```rust
#[cfg(not(any(feature = "fips", feature = "verified")))]
pub struct MlKem768DecapKey {
    pub(crate) inner: zeroize::Zeroizing<[u8; 2400]>,
}

#[cfg(feature = "fips")]
pub struct MlKem768DecapKey {
    // Memory lifecycle + zeroization owned by aws-lc-rs.
    // Pulling raw bytes out into our own buffer would yank the
    // secret material from the CMVP-validated boundary.
    pub(crate) inner: aws_lc_rs::kem::DecapsulationKey,
}
```

The `as_bytes()` accessor is the only method that ever surfaces
raw bytes — and even then, under `--features fips` it calls
`inner.serialize()` (aws-lc-rs's CMVP-approved export path).

### Trait implementation per backend

The deterministic methods from ADR 0005 **fail closed** under
`--features fips`:

```rust
#[cfg(feature = "fips")]
impl KemCore for MlKem768 {
    fn generate_deterministic(
        _d: [u8; 32],
        _z: [u8; 32],
    ) -> Result<(MlKem768DecapKey, MlKem768EncapKey), KyberLibError> {
        // FIPS 140-3 forbids injecting external entropy into a
        // validated module. Refuse rather than silently ignore.
        Err(KyberLibError::FipsBoundaryError)
    }

    fn encapsulate_deterministic(
        _ek: &MlKem768EncapKey,
        _m: [u8; 32],
    ) -> Result<(Ciphertext, SharedSecret), KyberLibError> {
        Err(KyberLibError::FipsBoundaryError)
    }

    fn decapsulate(
        dk: &MlKem768DecapKey,
        ct: &Ciphertext,
    ) -> SharedSecret {
        // Decaps is deterministic; pass through cleanly.
        // aws-lc-rs implements FIPS 203 §6.3 implicit rejection
        // internally — we just unwrap the SharedSecret newtype.
        let raw = dk.inner.decapsulate(ct.as_bytes())
            .expect("length pre-validated by typed wrapper");
        SharedSecret(raw.try_into().unwrap())
    }
}
```

Under `--features fips`, the *only* way to keygen is the
convenience method `MlKem768::generate()`, which delegates to the
AWS-LC approved DRBG:

```rust
#[cfg(feature = "fips")]
impl MlKem768 {
    pub fn generate() -> Result<(MlKem768DecapKey, MlKem768EncapKey), KyberLibError> {
        let algo = &aws_lc_rs::kem::ML_KEM_768;
        let dk = aws_lc_rs::kem::DecapsulationKey::generate(algo)
            .map_err(|_| KyberLibError::FipsBoundaryError)?;
        let ek = dk.encapsulation_key()
            .map_err(|_| KyberLibError::FipsBoundaryError)?;
        Ok((
            MlKem768DecapKey { inner: dk },
            MlKem768EncapKey { inner: ek },
        ))
    }
}
```

### Cargo.toml

```toml
[features]
fips     = ["dep:aws-lc-rs", "aws-lc-rs/fips"]
verified = ["dep:libcrux-ml-kem"]

[dependencies]
aws-lc-rs       = { version = "1", optional = true, features = ["unstable"] }
libcrux-ml-kem  = { version = "0.0.3", optional = true }
```

The transitively pulled `aws-lc-rs/fips` feature toggles AWS-LC's
own `FIPS=1` build path, which compiles the validated C code and
gates the internal DRBG to the approved variant.

### Error mapping

`aws-lc-rs` returns `Unspecified` for almost every error (a
deliberate side-channel-leak countermeasure). We map *all* of
them to a single `KyberLibError::FipsBoundaryError`. No richer
discrimination — surfacing more detail would leak information
the CMVP-validated module deliberately hides.

### Implicit rejection (FIPS 203 §6.3)

Critical correctness property: under `--features fips`, decap
must still return a pseudorandom shared secret on a tampered
ciphertext rather than an explicit error. `aws-lc-rs` honours
this internally — its `DecapsulationKey::decapsulate` never
distinguishes tampered from valid input via the error channel.
We pass through cleanly; no branching on our side.

A property test added to `tests/test_properties.rs::implicit_rejection_is_total`
runs under both `--features ""` and `--features fips` to confirm
behavioural parity at the byte level.

## Consequences

### Positive

* **Single integration point for both compliance and ergonomics.**
  Default consumers get pure-Rust kyberlib. FIPS consumers flip
  one feature flag and route through CMVP-validated AWS-LC. The
  application code is identical.
* **No silent RNG override.** The deterministic API from
  ADR 0005 makes the FIPS boundary's `fail-closed` behaviour
  loud rather than silent.
* **CMVP boundary preserved.** Secret material lives inside
  `aws_lc_rs::kem::DecapsulationKey` for the entire key
  lifecycle. We never extract bytes into our own buffer for the
  duration of the key.

### Negative

* **`aws-lc-rs` is C code.** Default-feature consumers won't see
  it; `--features fips` users opt into a non-trivial native build.
  The `aws-lc-rs/fips` feature additionally requires Go +
  Perl + specific clang versions to compile AWS-LC's FIPS module.
  Document loudly.
* **Conditional compilation surface area grows.** Every public
  type definition needs three variants. Mitigated by keeping the
  cfg-routing concentrated in `backends/mod.rs` and `types.rs`.
* **Subtle behaviour drift under `--features fips`.** Specifically:
  - The pure-Rust backend reads `d`, `z`, `m` via the explicit
    BYOE API; FIPS mode picks its own. ACVP harness gating
    (ADR 0005 phase 2) prevents the cross-mode test fail.
  - AWS-LC may version-bump ML-KEM with its own cadence. Our
    `aws-lc-rs` dependency pin documents the validated version.

### Build-graph hygiene

The `fips` feature must hard-disable the pure-Rust backend
features that would otherwise create a split-brain build (e.g.
`avx2`, `nasm`, `hazmat`). We enforce this via additional
`compile_error!` checks in `backends/mod.rs`:

```rust
#[cfg(all(feature = "fips", any(feature = "avx2", feature = "nasm", feature = "hazmat")))]
compile_error!(
    "`fips` is mutually exclusive with pure-Rust SIMD / hazmat \
     features — the FIPS boundary owns the entire crypto surface."
);
```

## Alternatives considered

### Single-backend crate per profile

Three sibling crates: `kyberlib` (pure-Rust), `kyberlib-fips`
(AWS-LC), `kyberlib-verified` (libcrux). Forces downstream
consumers to choose at the `Cargo.toml` dependency line instead
of the feature line.

**Rejected** because the application code becomes non-portable
between profiles — a kyberlib-pinning library can't be reused by
a FIPS-pinning application without rewriting imports.

### Runtime backend dispatch

Pick the backend at process startup via env var or config.
Possible, but breaks the `!Copy + ZeroizeOnDrop` static guarantees
(the type identity has to be uniform across runtime backends).

**Rejected** because static guarantees are the whole point of the
typed API.

### `pqcrypto-mlkem` as a third backend

The `pqcrypto-mlkem` crate wraps the reference C implementation.
Skip it: its main value-add over our pure-Rust backend is FFI
parity with C consumers, which is already covered by the
`aws-lc-rs` (FIPS) backend.

**Rejected** as redundant.

## Implementation phases

* **Phase 1** — Land `backends/mod.rs` with only the `pure_rust`
  module wired. Pure refactor; no behaviour change. CI green.
* **Phase 2** — Add `fips.rs` with `unimplemented!()` stubs.
  Wire `compile_error!` mutual-exclusion guards.
* **Phase 3** — Replace stubs with `aws-lc-rs` calls. ACVP
  harness gated `#![cfg(not(any(feature = "fips", feature = "verified")))]`
  per ADR 0005.
* **Phase 4** — Add `verified.rs` mirror for `libcrux-ml-kem`.
* **Phase 5** — Wire CI matrix jobs: one with `--features fips`,
  one with `--features verified`, both running the workspace
  test suite. Property tests confirm behavioural parity.
* **Phase 6** — Document the CMVP / validation status in
  `SECURITY.md` with the active `aws-lc-rs` version pin.

## References

* [`aws-lc-rs` ML-KEM docs](https://docs.rs/aws-lc-rs/latest/aws_lc_rs/kem/index.html)
* [`libcrux-ml-kem` repository](https://github.com/cryspen/libcrux)
* [NIST CMVP — module-in-process list](https://csrc.nist.gov/projects/cryptographic-module-validation-program/modules-in-process/Modules-In-Process-List)
* [Symbolic Software, eprint 2026/192](https://eprint.iacr.org/2026/192) — found 3 bugs in libcrux's verified code; verification is necessary, not sufficient
* [ADR 0005](./0005-byoe-deterministic-api.md) — deterministic API (prerequisite)
