// Copyright © 2024 kyberlib. All rights reserved.
// SPDX-License-Identifier: Apache-2.0 OR MIT

//! # `kyberlib` — FIPS 203 ML-KEM in Rust
//!
//! Audit-friendly, `no_std`-compatible implementation of **FIPS 203
//! ML-KEM** (the standardised CRYSTALS-Kyber post-quantum key
//! encapsulation mechanism, finalised August 2024). 60/60 ACVP
//! conformance against the NIST test corpus.
//!
//! [![kyberlib logo](https://cloudcdn.pro/kyberlib/v1/logos/kyberlib.svg)](https://kyberlib.com)
//!
//! ## At a glance
//!
//! - **Three parameter sets**: [`MlKem512`], [`MlKem768`] (default),
//!   [`MlKem1024`] — covering NIST security categories 1, 3, 5.
//! - **Two APIs**: the v0.0.7 *typed-state* API ([`KemCore`] trait +
//!   typed wrappers) and the legacy free-function API
//!   ([`keypair`] / [`encapsulate`] / [`decapsulate`]).
//! - **Constant-time**: KyberSlash audit clean (ADR 0003); secrets
//!   carry [`zeroize::Zeroize`]; `dudect` regression gate in
//!   `scripts/dudect.sh`.
//! - **`no_std`**: optional `std` feature. Default features pull in
//!   `std` for ergonomic error types.
//! - **No `unsafe`** in the safe core. The optional `avx2` / `nasm`
//!   backends scope `unsafe` to the SIMD module only.
//!
//! ## Quick start (typed API — recommended)
//!
//! ```
//! # fn main() -> Result<(), kyberlib::KyberLibError> {
//! use kyberlib::{KemCore, MlKem768};
//!
//! let mut rng = rand::thread_rng();
//!
//! // Bob generates a (decap, encap) keypair.
//! let (bob_dk, bob_ek) = MlKem768::generate(&mut rng)?;
//!
//! // Alice encapsulates a shared secret against Bob's encap key.
//! let (ciphertext, ss_alice) = bob_ek.encapsulate(&mut rng)?;
//!
//! // Bob decapsulates with his decap key (implicit rejection per
//! // FIPS 203 §6.3 — never panics, never branches on validity).
//! let ss_bob = bob_dk.decapsulate(&ciphertext);
//!
//! assert_eq!(ss_alice, ss_bob);
//! # Ok(()) }
//! ```
//!
//! ## Quick start (legacy free-function API)
//!
//! ```
//! # fn main() -> Result<(), kyberlib::KyberLibError> {
//! use kyberlib::{keypair, encapsulate, decapsulate};
//!
//! let mut rng = rand::thread_rng();
//! let bob = keypair(&mut rng)?;
//! let (ct, ss_a) = encapsulate(&bob.public, &mut rng)?;
//! let ss_b = decapsulate(&ct, &bob.secret)?;
//! assert_eq!(ss_a, ss_b);
//! # Ok(()) }
//! ```
//!
//! ## Cargo features
//!
//! | Feature | Default | Description |
//! |---|---|---|
//! | `std` | ✅ | Enables the `std` library — required for `std::error::Error` on [`KyberLibError`]. Disable for `no_std` targets. |
//! | `kyber768` | ✅ | NIST security category 3 (≈ AES-192). Default. |
//! | `kyber512` |  | NIST security category 1 (≈ AES-128). Mutually exclusive with `kyber768`/`kyber1024`. |
//! | `kyber1024` |  | NIST security category 5 (≈ AES-256). Required by CNSA 2.0 for NSS by 2027-01-01. Mutually exclusive with `kyber768`/`kyber512`. |
//! | `90s` |  | "Kyber-90s" variant — SHA-2 / AES-CTR instead of SHAKE. Removed in FIPS 203 but retained for pre-spec compatibility. |
//! | `90s-fixslice` |  | `90s` with a bitsliced AES implementation (`aes` + `ctr` crates). |
//! | `avx2` |  | AVX2-accelerated backend (x86_64 only). Compile-errors on other arches. |
//! | `nasm` |  | AVX2 via NASM assembler (instead of GAS). Requires NASM installed. Implies `avx2`. |
//! | `hazmat` |  | Re-exports the IND-CPA primitives (no Fujisaki–Okamoto transform). Advanced use only; the resulting construction is NOT IND-CCA secure. |
//!
//! ## Architecture
//!
//! See [`api`] for the legacy free-function surface, [`ml_kem`] for
//! the v0.0.7 typed-state API, [`kex`] for the Uake/Ake key-exchange
//! wrappers, and [`error`] for the [`KyberLibError`] enum.
//!
//! ## Errors
//!
//! All fallible public functions return [`KyberLibError`]. Variants:
//!
//! - [`KyberLibError::InvalidInput`] — input slice length mismatch.
//!   Typical cause: two peers using different security levels.
//! - [`KyberLibError::InvalidKey`] — imported keypair fails the
//!   encap/decap self-test (the public and secret halves don't
//!   belong together).
//! - [`KyberLibError::InvalidLength`] — buffer length below the
//!   required copy length.
//! - [`KyberLibError::Decapsulation`] — ciphertext failed to
//!   authenticate. *Not* normally returned: the FIPS 203 implicit-
//!   rejection construction returns a pseudorandom shared secret on
//!   invalid input instead.
//! - [`KyberLibError::RandomBytesGeneration`] — external RNG failed
//!   (e.g. hardware RNG fault).
//!
//! ## Macros (legacy compatibility surface)
//!
//! See [`macros`] for the `kyberlib_*` macro family that wraps the
//! free-function API for terser call sites. Prefer the typed API
//! ([`KemCore`]) in new code.
//!
#![doc(
    html_favicon_url = "https://cloudcdn.pro/kyberlib/v1/favicon.ico",
    html_logo_url = "https://cloudcdn.pro/kyberlib/v1/logos/kyberlib.svg",
    html_root_url = "https://docs.rs/kyberlib"
)]
#![crate_name = "kyberlib"]
#![crate_type = "lib"]
#![cfg_attr(not(feature = "std"), no_std)]
#![cfg_attr(docsrs, feature(doc_cfg))]
// Every public item must carry rustdoc. See issue #137.
#![deny(missing_docs)]
// `unsafe` policy:
//   - Default build (no `avx2`, no `nasm`): `forbid(unsafe_code)` —
//     strongest guarantee, no inner `#[allow]` can lift it.
//   - With `--features avx2` or `--features nasm`: crate-level
//     `deny(unsafe_code)` keeps the safe-core modules (api / kex /
//     kem / ml_kem / params / rng / symmetric / oid / error) unsafe-
//     free; only the `mod avx2;` declaration itself carries
//     `#[allow(unsafe_code)]`, so the SIMD intrinsics + assembly
//     trampolines are the only place `unsafe` is permitted.
//   - Phase 1.2 (#143) tracks the full source relocation into a
//     dedicated `kyberlib-asm` workspace crate. The granular gate
//     below gives the same *safety property* (safe core stays
//     unsafe-free under every feature combination) without the
//     cross-crate refactor.
#![cfg_attr(
    not(any(feature = "avx2", feature = "nasm")),
    forbid(unsafe_code)
)]
#![cfg_attr(any(feature = "avx2", feature = "nasm"), deny(unsafe_code))]

// Prevent usage of mutually exclusive features
#[cfg(all(feature = "kyber1024", feature = "kyber512"))]
compile_error!("Only one security level can be specified");

// Phase 5 backend selection. Both backend features are reservations
// only at this stage — they declare the feature name in the manifest
// so downstream consumers can pre-wire `--features fips` or
// `--features verified` against the eventual delegation surface
// (issues #170 / #171). Today they are pure no-ops: the pure-Rust
// path is always used regardless of which is enabled.
//
// The mutual-exclusion guard between `fips` and `verified` lands
// alongside the first feature with a non-trivial implementation.
// Until then we tolerate `--all-features` enabling both for CI's
// sake.

/// Marker for the `fips` backend (skeleton — see issue #170).
#[cfg(feature = "fips")]
#[doc(hidden)]
pub const __FIPS_BACKEND_STUB: &str =
    "kyberlib `fips` feature is a phase-5 placeholder — see issue #170";

/// Marker for the `verified` backend (skeleton — see issue #171).
#[cfg(feature = "verified")]
#[doc(hidden)]
pub const __VERIFIED_BACKEND_STUB: &str =
    "kyberlib `verified` feature is a phase-5 placeholder — see issue #171";

// `#[allow(unsafe_code)]` is the granular exception to the crate-level
// `deny(unsafe_code)` policy (see the policy block above). The safe-core
// modules — declared below this — inherit `deny` and stay unsafe-free
// even under `--features avx2`. Phase 1.2 (#143) relocates this module
// into `kyberlib-asm` so the source layout matches the safety policy
// 1:1.
#[cfg(all(target_arch = "x86_64", feature = "avx2"))]
#[allow(unsafe_code)]
mod avx2;
#[cfg(all(target_arch = "x86_64", feature = "avx2"))]
use avx2::*;

#[cfg(any(not(target_arch = "x86_64"), not(feature = "avx2")))]
/// Reference implementation for the KyberLib library.
pub mod reference;
#[cfg(any(not(target_arch = "x86_64"), not(feature = "avx2")))]
use reference::*;

#[cfg(any(not(target_arch = "x86_64"), not(feature = "avx2")))]
#[cfg(feature = "hazmat")]
pub use reference::indcpa;

// WebAssembly bindings live in the dedicated `kyberlib-wasm` workspace
// crate from v0.0.7 onwards (#144). The `wasm` Cargo feature is retained
// as a no-op for one release for downstream compatibility.

/// API for the KyberLib library.
pub mod api;
/// Error types for the KyberLib library.
pub mod error;
/// Key encapsulation module for the KyberLib library.
pub mod kem;
/// Key exchange structs for the KyberLib library.
pub mod kex;

/// Macro utilities for the KyberLib library.
pub mod macros;
/// Parameters for the KyberLib library.
pub mod params;

/// Random number generators for the KyberLib library.
pub mod rng;
/// Symmetric key encapsulation module for the KyberLib library.
pub mod symmetric;

/// FIPS 203 ML-KEM type-state API (v0.0.7 — see issue #130).
pub mod ml_kem;

/// Parameter-pack trait unifying ML-KEM-512 / 768 / 1024 — foundation
/// for the const-generic refactor tracked as #130b.
pub mod paramsets;

/// Internal test-surface wrappers. **Not part of the public API.**
///
/// Wraps the generic FIPS 203 pipeline functions for integration-test
/// harnesses that need deterministic-seed access across all three
/// parameter sets (e.g. NIST ACVP). Items here may change or
/// disappear without warning — downstream code MUST NOT depend on
/// them.
#[doc(hidden)]
pub mod __testing__ {
    use crate::error::KyberLibError;
    use crate::paramsets::MlKemParams;
    use rand_core::{CryptoRng, RngCore};

    /// Wrapper around the crate-internal `kem_keypair_generic`.
    pub fn kem_keypair_generic<P, R>(
        pk: &mut [u8],
        sk: &mut [u8],
        rng: &mut R,
        seed: Option<(&[u8], &[u8])>,
    ) -> Result<(), KyberLibError>
    where
        P: MlKemParams,
        R: RngCore + CryptoRng,
    {
        crate::kem::kem_keypair_generic::<P, R>(pk, sk, rng, seed)
    }

    /// Wrapper around the crate-internal `kem_enc_generic`.
    pub fn kem_enc_generic<P, R>(
        ct: &mut [u8],
        ss: &mut [u8],
        pk: &[u8],
        rng: &mut R,
        seed: Option<&[u8]>,
    ) -> Result<(), KyberLibError>
    where
        P: MlKemParams,
        R: RngCore + CryptoRng,
    {
        crate::kem::kem_enc_generic::<P, R>(ct, ss, pk, rng, seed)
    }

    /// Wrapper around the crate-internal `kem_dec_generic`.
    pub fn kem_dec_generic<P: MlKemParams>(
        ss: &mut [u8],
        ct: &[u8],
        sk: &[u8],
    ) {
        crate::kem::kem_dec_generic::<P>(ss, ct, sk);
    }
}

/// IETF LAMPS object identifiers for ML-KEM parameter sets (v0.0.7
/// — see issue #150).
pub mod oid;

pub use api::*;
pub use error::KyberLibError;
pub use kex::*;
pub use ml_kem::{
    KemCore, MlKem1024, MlKem1024Ciphertext, MlKem1024DecapKey,
    MlKem1024EncapKey, MlKem512, MlKem512Ciphertext, MlKem512DecapKey,
    MlKem512EncapKey, MlKem768, MlKem768Ciphertext, MlKem768DecapKey,
    MlKem768EncapKey, SharedSecret,
};
pub use params::{
    // Legacy KYBER_* aliases — retained for downstream-consumer
    // migration; will tighten to `#[deprecated]` in a future release.
    KYBER_90S,
    KYBER_CIPHERTEXT_BYTES,
    KYBER_PUBLIC_KEY_BYTES,
    KYBER_SECRET_KEY_BYTES,
    KYBER_SECURITY_PARAMETER,
    KYBER_SHARED_SECRET_BYTES,
    KYBER_SYM_BYTES,
    // v0.0.7 — canonical ML_KEM_* names (preferred in new code).
    ML_KEM_90S,
    ML_KEM_CIPHERTEXT_BYTES,
    ML_KEM_PUBLIC_KEY_BYTES,
    ML_KEM_SECRET_KEY_BYTES,
    ML_KEM_SECURITY_PARAMETER,
    ML_KEM_SHARED_SECRET_BYTES,
    ML_KEM_SYM_BYTES,
};
pub use paramsets::MlKemParams;
pub use rand_core::{CryptoRng, RngCore};

// Feature hack to expose private functions for the Known Answer Tests
// and fuzzing. Will fail to compile if used outside `cargo test` or
// the fuzz binaries.
#[cfg(any(
    KYBER_SECURITY_PARAMETERat,
    fuzzing,
    feature = "benchmarking"
))]
pub use kem::*;
