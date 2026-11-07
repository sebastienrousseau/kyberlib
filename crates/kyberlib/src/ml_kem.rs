// Copyright © 2026 kyberlib. All rights reserved.
// SPDX-License-Identifier: Apache-2.0 OR MIT

//! FIPS 203 ML-KEM type-state API.
//!
//! New surface introduced in v0.0.7 (#130). Parameter set is a *type*,
//! not a Cargo feature: each consumer picks [`MlKem512`], [`MlKem768`],
//! or [`MlKem1024`] at the call site. Secrets and public material
//! travel as distinct types with the right Drop / Zeroize semantics:
//!
//! ```text
//!     KemCore                       — trait, sealed
//!     ├── MlKem512        ✅ implemented
//!     ├── MlKem768        ✅ implemented (default)
//!     └── MlKem1024       ✅ implemented
//!
//!     EncapsulationKey<P>           — `Copy`-safe public bytes
//!     DecapsulationKey<P>           — `!Copy`, `ZeroizeOnDrop`, redacted `Debug`
//!     Ciphertext<P>                 — opaque, fixed-size byte wrapper
//!     SharedSecret                  — 32-byte `ZeroizeOnDrop` secret
//! ```
//!
//! As of Phase 3e of #130b (commit `7…` — search `git log --grep
//! "Phase 3e"`), all three parameter sets implement [`KemCore`]
//! unconditionally. The default build supports `MlKem512`,
//! `MlKem768`, and `MlKem1024` concurrently — pick the right one
//! at the call site:
//!
//! ```
//! # fn main() -> Result<(), kyberlib::KyberLibError> {
//! use kyberlib::{KemCore, MlKem512, MlKem768, MlKem1024};
//! let mut rng = rand::thread_rng();
//! let (dk_512, ek_512)  = MlKem512::generate(&mut rng)?;
//! let (dk_768, ek_768)  = MlKem768::generate(&mut rng)?;
//! let (dk_1024, ek_1024) = MlKem1024::generate(&mut rng)?;
//! # let _ = (dk_512, ek_512, dk_768, ek_768, dk_1024, ek_1024);
//! # Ok(()) }
//! ```
//!
//! ## Migration from the v0.0.6 surface
//!
//! The free functions [`keypair`],
//! [`encapsulate`], [`decapsulate`]
//! and the [`Keypair`] struct from the old surface are
//! retained as `#[deprecated]` shims for `MlKem768` only. They'll be
//! removed in a future release.
//!
//! ## ACVP conformance
//!
//! `MlKem768` is byte-validated against 60/60 NIST ACVP test vectors
//! (see [`tests/test_acvp.rs`][acvp]). `MlKem512` and `MlKem1024`
//! conformance is verified structurally — the generic algorithm
//! pipeline is byte-identical to the cfg-gated reference under each
//! parameter set's feature (#130b commits a77b94b through 3819f7a).
//! The ACVP harness is wired to all three under #130c.
//!
//! [acvp]: ../../tests/test_acvp.rs

#[cfg(doc)]
#[allow(deprecated)]
use crate::{decapsulate, encapsulate, keypair, Keypair};
use crate::{
    error::KyberLibError, KYBER_CIPHERTEXT_BYTES,
    KYBER_PUBLIC_KEY_BYTES, KYBER_SECRET_KEY_BYTES,
    KYBER_SHARED_SECRET_BYTES,
};
use core::fmt;
use rand_core::{CryptoRng, RngCore};
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::backend::{
    backend_decapsulate, backend_encapsulate, backend_keygen,
    keypair_from_seed,
};

mod sealed {
    /// Sealed trait — only this crate may implement [`super::KemCore`].
    pub trait Sealed {}
}

// ---------------------------------------------------------------- KemCore

/// FIPS 203 ML-KEM parameter-set marker trait.
///
/// Implemented by the zero-sized marker types [`MlKem512`], [`MlKem768`],
/// [`MlKem1024`]. Sealed — third-party crates cannot add new
/// implementations.
pub trait KemCore: sealed::Sealed + Sized {
    /// Encapsulation key (public side).
    type EncapsulationKey;
    /// Decapsulation key (secret side). Zeroized on drop.
    type DecapsulationKey;
    /// Ciphertext.
    type Ciphertext;

    /// Stable algorithm identifier per the IETF LAMPS draft —
    /// `"ML-KEM-512"`, `"ML-KEM-768"`, or `"ML-KEM-1024"`.
    const ALGORITHM_ID: &'static str;

    /// Dotted-decimal object identifier per
    /// `2.16.840.1.101.3.4.4.{1,2,3}`.
    const OID: &'static str;

    /// Generate a fresh decapsulation / encapsulation key pair.
    ///
    /// # Errors
    ///
    /// Returns [`KyberLibError::RandomBytesGeneration`] if the supplied
    /// RNG fails to produce randomness. All other errors are
    /// internal-invariant violations and should not occur with a
    /// well-behaved RNG.
    fn generate<R: RngCore + CryptoRng>(
        rng: &mut R,
    ) -> Result<
        (Self::DecapsulationKey, Self::EncapsulationKey),
        KyberLibError,
    >;

    /// Derive a key pair from the seed `(d, z)`: FIPS 203 Algorithm 16,
    /// `ML-KEM.KeyGen_internal(d, z)`.
    ///
    /// `d ‖ z` is the seed form of an ML-KEM private key: keeping these
    /// 64 bytes is enough to rebuild the key pair (for example, X-Wing
    /// stores a 32-byte seed and expands it into `d` and `z`). Both
    /// halves must come from an approved RNG and stay secret.
    ///
    /// # Errors
    ///
    /// None in practice: the seeded path draws no randomness. The
    /// `Result` matches [`KemCore::generate`].
    fn generate_from_seed(
        d: &[u8; 32],
        z: &[u8; 32],
    ) -> Result<
        (Self::DecapsulationKey, Self::EncapsulationKey),
        KyberLibError,
    >;
}

// ---------------------------------------------------------------- markers

/// ML-KEM-512 parameter set marker. NIST security category 1 (≈ AES-128).
///
/// Module rank `k = 2`. Public key 800 B, secret key 1632 B,
/// ciphertext 768 B, shared secret 32 B.
///
/// [`KemCore`] is implemented unconditionally. Works in any build —
/// no `--features kyber512` needed. The default build supports
/// `MlKem512`, [`MlKem768`], and [`MlKem1024`] concurrently (Phase 3e
/// of #130b — see `crates/kyberlib/src/paramsets.rs`).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub struct MlKem512;
impl sealed::Sealed for MlKem512 {}

impl MlKem512 {
    /// Module rank.
    pub const K: usize = 2;
    /// Public encapsulation key length in bytes.
    pub const PUBLIC_KEY_BYTES: usize = 800;
    /// Private decapsulation key length in bytes.
    pub const SECRET_KEY_BYTES: usize = 1632;
    /// Ciphertext length in bytes.
    pub const CIPHERTEXT_BYTES: usize = 768;
    /// Shared-secret length in bytes.
    pub const SHARED_SECRET_BYTES: usize = 32;
    /// Stable algorithm identifier per the IETF LAMPS draft.
    pub const ALGORITHM_ID: &'static str = "ML-KEM-512";
    /// Object identifier — `2.16.840.1.101.3.4.4.1`.
    pub const OID: &'static str = crate::oid::ML_KEM_512;
}

/// ML-KEM-768 parameter set marker. NIST security category 3 (≈ AES-192).
/// Default for CNSA 2.0 hybrid TLS deployments.
///
/// Module rank `k = 3`. Public key 1184 B, secret key 2400 B,
/// ciphertext 1088 B, shared secret 32 B.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub struct MlKem768;
impl sealed::Sealed for MlKem768 {}

impl MlKem768 {
    /// Module rank.
    pub const K: usize = 3;
    /// Public encapsulation key length in bytes.
    pub const PUBLIC_KEY_BYTES: usize = 1184;
    /// Private decapsulation key length in bytes.
    pub const SECRET_KEY_BYTES: usize = 2400;
    /// Ciphertext length in bytes.
    pub const CIPHERTEXT_BYTES: usize = 1088;
    /// Shared-secret length in bytes.
    pub const SHARED_SECRET_BYTES: usize = 32;
    /// Stable algorithm identifier per the IETF LAMPS draft.
    pub const ALGORITHM_ID: &'static str = "ML-KEM-768";
    /// Object identifier — `2.16.840.1.101.3.4.4.2`.
    pub const OID: &'static str = crate::oid::ML_KEM_768;
}

/// ML-KEM-1024 parameter set marker. NIST security category 5 (≈ AES-256).
/// Required by CNSA 2.0 for NSS by 1 Jan 2027.
///
/// Module rank `k = 4`. Public key 1568 B, secret key 3168 B,
/// ciphertext 1568 B, shared secret 32 B.
///
/// [`KemCore`] is implemented unconditionally — works alongside
/// [`MlKem512`] and [`MlKem768`] in any build.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub struct MlKem1024;
impl sealed::Sealed for MlKem1024 {}

impl MlKem1024 {
    /// Module rank.
    pub const K: usize = 4;
    /// Public encapsulation key length in bytes.
    pub const PUBLIC_KEY_BYTES: usize = 1568;
    /// Private decapsulation key length in bytes.
    pub const SECRET_KEY_BYTES: usize = 3168;
    /// Ciphertext length in bytes.
    pub const CIPHERTEXT_BYTES: usize = 1568;
    /// Shared-secret length in bytes.
    pub const SHARED_SECRET_BYTES: usize = 32;
    /// Stable algorithm identifier per the IETF LAMPS draft.
    pub const ALGORITHM_ID: &'static str = "ML-KEM-1024";
    /// Object identifier — `2.16.840.1.101.3.4.4.3`.
    pub const OID: &'static str = crate::oid::ML_KEM_1024;
}

// ---------------------------------------------------------------- ML-KEM-512 + 1024 typed wrappers

macro_rules! sized_wrapper_types {
    ($p:ident, $ek:ident, $dk:ident, $ct:ident, $pk_bytes:expr, $sk_bytes:expr, $ct_bytes:expr) => {
        /// Public encapsulation key.
        #[derive(Clone, Copy, Eq, PartialEq)]
        pub struct $ek([u8; $pk_bytes]);

        impl $ek {
            /// Construct from raw bytes.
            pub fn from_bytes(bytes: [u8; $pk_bytes]) -> Self {
                Self(bytes)
            }
            /// Construct from a borrowed slice, validating the length.
            ///
            /// # Errors
            ///
            /// [`KyberLibError::InvalidLength`] on length mismatch.
            pub fn try_from_slice(
                bytes: &[u8],
            ) -> Result<Self, KyberLibError> {
                if bytes.len() != $pk_bytes {
                    return Err(KyberLibError::InvalidLength);
                }
                let mut buf = [0u8; $pk_bytes];
                buf.copy_from_slice(bytes);
                Ok(Self(buf))
            }
            /// Borrow as raw bytes.
            pub fn as_bytes(&self) -> &[u8; $pk_bytes] {
                &self.0
            }
        }

        impl fmt::Debug for $ek {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.debug_tuple(stringify!($ek))
                    .field(&format_args!(
                        "[{} bytes; not secret]",
                        $pk_bytes
                    ))
                    .finish()
            }
        }

        /// Secret decapsulation key. Zeroized on drop.
        #[derive(Clone, Zeroize, ZeroizeOnDrop, Eq, PartialEq)]
        pub struct $dk([u8; $sk_bytes]);

        impl $dk {
            /// Construct from raw bytes.
            pub fn from_bytes(bytes: [u8; $sk_bytes]) -> Self {
                Self(bytes)
            }
            /// Construct from a borrowed slice, validating the length
            /// and the FIPS 203 §7.3 hash check (the stored `H(ek)`
            /// must match the embedded encapsulation key).
            ///
            /// # Errors
            ///
            /// [`KyberLibError::InvalidLength`] on length mismatch;
            /// [`KyberLibError::InvalidKey`] if the hash check fails.
            pub fn try_from_slice(
                bytes: &[u8],
            ) -> Result<Self, KyberLibError> {
                if bytes.len() != $sk_bytes {
                    return Err(KyberLibError::InvalidLength);
                }
                if !crate::input_check::dk_hash_check::<$p>(bytes) {
                    return Err(KyberLibError::InvalidKey);
                }
                let mut buf = [0u8; $sk_bytes];
                buf.copy_from_slice(bytes);
                Ok(Self(buf))
            }
            /// Borrow as raw bytes. Sparingly — the secret state is
            /// exposed.
            pub fn as_bytes(&self) -> &[u8; $sk_bytes] {
                &self.0
            }
        }

        impl fmt::Debug for $dk {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str(concat!(
                    stringify!($dk),
                    "([REDACTED ",
                    stringify!($sk_bytes),
                    " bytes])"
                ))
            }
        }

        /// Ciphertext.
        #[derive(Clone, Copy, Eq, PartialEq)]
        pub struct $ct([u8; $ct_bytes]);

        impl $ct {
            /// Construct from raw bytes.
            pub fn from_bytes(bytes: [u8; $ct_bytes]) -> Self {
                Self(bytes)
            }
            /// Construct from a borrowed slice, validating the length.
            ///
            /// # Errors
            ///
            /// [`KyberLibError::InvalidLength`] on length mismatch.
            pub fn try_from_slice(
                bytes: &[u8],
            ) -> Result<Self, KyberLibError> {
                if bytes.len() != $ct_bytes {
                    return Err(KyberLibError::InvalidLength);
                }
                let mut buf = [0u8; $ct_bytes];
                buf.copy_from_slice(bytes);
                Ok(Self(buf))
            }
            /// Borrow as raw bytes.
            pub fn as_bytes(&self) -> &[u8; $ct_bytes] {
                &self.0
            }
        }

        impl fmt::Debug for $ct {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.debug_tuple(stringify!($ct))
                    .field(&format_args!(
                        "[{} bytes; opaque]",
                        $ct_bytes
                    ))
                    .finish()
            }
        }
    };
}

sized_wrapper_types!(
    MlKem512,
    MlKem512EncapKey,
    MlKem512DecapKey,
    MlKem512Ciphertext,
    800,
    1632,
    768
);
sized_wrapper_types!(
    MlKem1024,
    MlKem1024EncapKey,
    MlKem1024DecapKey,
    MlKem1024Ciphertext,
    1568,
    3168,
    1568
);

// ---------------------------------------------------------------- shared secret

/// 32-byte shared secret. Zeroized on drop.
///
/// Construct via [`KemCore::generate`] →
/// `EncapsulationKey::encapsulate` → `DecapsulationKey::decapsulate`;
/// never directly by the consumer.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
#[non_exhaustive]
pub struct SharedSecret([u8; KYBER_SHARED_SECRET_BYTES]);

impl SharedSecret {
    /// Wrap bytes produced by a backend in `crate::backend`.
    pub(crate) const fn from_backend(
        bytes: [u8; KYBER_SHARED_SECRET_BYTES],
    ) -> Self {
        Self(bytes)
    }

    /// Borrow the raw 32 bytes. Use sparingly — every borrow expands
    /// the surface that needs to handle the secret carefully.
    pub fn as_bytes(&self) -> &[u8; KYBER_SHARED_SECRET_BYTES] {
        &self.0
    }
}

impl fmt::Debug for SharedSecret {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("SharedSecret([REDACTED 32 bytes])")
    }
}

impl PartialEq for SharedSecret {
    fn eq(&self, other: &Self) -> bool {
        // Constant-time-ish (memcmp loops in stdlib are fixed-length).
        // For provable CT equality on secrets, use `subtle::ConstantTimeEq`.
        self.0 == other.0
    }
}

impl Eq for SharedSecret {}

// ---------------------------------------------------------------- ML-KEM-768

/// ML-KEM-768 encapsulation key (public). 1184 bytes.
#[derive(Clone, Copy, Eq, PartialEq)]
pub struct MlKem768EncapKey([u8; KYBER_PUBLIC_KEY_BYTES]);

impl MlKem768EncapKey {
    /// Construct from raw bytes — typically the receiving side of a
    /// wire-format decode.
    pub fn from_bytes(bytes: [u8; KYBER_PUBLIC_KEY_BYTES]) -> Self {
        Self(bytes)
    }

    /// Construct from a borrowed slice, validating the length.
    ///
    /// # Errors
    ///
    /// Returns [`KyberLibError::InvalidLength`] if `bytes.len() !=
    /// KYBER_PUBLIC_KEY_BYTES`.
    pub fn try_from_slice(bytes: &[u8]) -> Result<Self, KyberLibError> {
        if bytes.len() != KYBER_PUBLIC_KEY_BYTES {
            return Err(KyberLibError::InvalidLength);
        }
        let mut buf = [0u8; KYBER_PUBLIC_KEY_BYTES];
        buf.copy_from_slice(bytes);
        Ok(Self(buf))
    }
}

impl fmt::Debug for MlKem768EncapKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("MlKem768EncapKey")
            .field(&format_args!(
                "[{} bytes; not secret]",
                KYBER_PUBLIC_KEY_BYTES
            ))
            .finish()
    }
}

impl MlKem768EncapKey {
    /// Encapsulate against this public key. Returns the ciphertext
    /// and the resulting shared secret.
    ///
    /// # Errors
    ///
    /// Returns [`KyberLibError::InvalidKey`] if the key fails the
    /// FIPS 203 §7.2 modulus check, or
    /// [`KyberLibError::RandomBytesGeneration`] if the supplied RNG
    /// fails.
    pub fn encapsulate<R: RngCore + CryptoRng>(
        &self,
        rng: &mut R,
    ) -> Result<(MlKem768Ciphertext, SharedSecret), KyberLibError> {
        let (ct, ss) =
            backend_encapsulate::<MlKem768, R, KYBER_CIPHERTEXT_BYTES>(
                &self.0, rng,
            )?;
        Ok((MlKem768Ciphertext(ct), SharedSecret(ss)))
    }

    /// Borrow as raw bytes.
    pub fn as_bytes(&self) -> &[u8; KYBER_PUBLIC_KEY_BYTES] {
        &self.0
    }
}

/// ML-KEM-768 decapsulation key (private). 2400 bytes. Zeroized on drop.
#[derive(Clone, Zeroize, ZeroizeOnDrop, Eq, PartialEq)]
#[non_exhaustive]
pub struct MlKem768DecapKey([u8; KYBER_SECRET_KEY_BYTES]);

impl fmt::Debug for MlKem768DecapKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("MlKem768DecapKey([REDACTED 2400 bytes])")
    }
}

impl MlKem768DecapKey {
    /// Decapsulate a ciphertext under this secret key. Implicit
    /// rejection per FIPS 203 §6.3 — returns a pseudorandom shared
    /// secret on invalid ciphertexts (never panics, never branches on
    /// validity).
    #[must_use]
    pub fn decapsulate(&self, ct: &MlKem768Ciphertext) -> SharedSecret {
        backend_decapsulate::<MlKem768>(&self.0, &ct.0)
    }

    /// Borrow as raw bytes. Sparingly — this exposes the entire 2400-
    /// byte private state.
    pub fn as_bytes(&self) -> &[u8; KYBER_SECRET_KEY_BYTES] {
        &self.0
    }
}

/// ML-KEM-768 ciphertext. 1088 bytes.
#[derive(Clone, Copy, Eq, PartialEq)]
pub struct MlKem768Ciphertext([u8; KYBER_CIPHERTEXT_BYTES]);

impl MlKem768Ciphertext {
    /// Construct from raw bytes — typically the receiving side of a
    /// wire-format decode.
    pub fn from_bytes(bytes: [u8; KYBER_CIPHERTEXT_BYTES]) -> Self {
        Self(bytes)
    }

    /// Construct from a borrowed slice, validating the length.
    ///
    /// # Errors
    ///
    /// Returns [`KyberLibError::InvalidLength`] if `bytes.len() !=
    /// KYBER_CIPHERTEXT_BYTES`.
    pub fn try_from_slice(bytes: &[u8]) -> Result<Self, KyberLibError> {
        if bytes.len() != KYBER_CIPHERTEXT_BYTES {
            return Err(KyberLibError::InvalidLength);
        }
        let mut buf = [0u8; KYBER_CIPHERTEXT_BYTES];
        buf.copy_from_slice(bytes);
        Ok(Self(buf))
    }
}

impl fmt::Debug for MlKem768Ciphertext {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("MlKem768Ciphertext")
            .field(&format_args!(
                "[{} bytes; opaque]",
                KYBER_CIPHERTEXT_BYTES
            ))
            .finish()
    }
}

impl MlKem768Ciphertext {
    /// Borrow as raw bytes — for wire-format serialization.
    pub fn as_bytes(&self) -> &[u8; KYBER_CIPHERTEXT_BYTES] {
        &self.0
    }
}

// ============================== KemCore impls (Phase 3e — generic-wired)
//
// All three impls coexist in a single build, routing through the
// generic FIPS 203 pipeline (`crate::kem::kem_*_generic`). Each
// `generate` / `encapsulate` / `decapsulate` allocates its own
// fixed-size byte buffer and hands a `&mut [u8]` to the generic
// function. The associated `PublicKeyBytes` / `SecretKeyBytes` /
// `CiphertextBytes` types from `MlKemParams` guarantee the array
// sizes match FIPS 203 §6 Table 2.
//
// The old `classic::*` shim path is preserved in `crate::api` for the
// legacy free-function surface (`keypair` / `encapsulate` /
// `decapsulate`); those still consume the cfg-gated reference. The
// typed-state API below is FULLY generic and works across all three
// parameter sets in any single build.

impl KemCore for MlKem768 {
    type EncapsulationKey = MlKem768EncapKey;
    type DecapsulationKey = MlKem768DecapKey;
    type Ciphertext = MlKem768Ciphertext;
    const ALGORITHM_ID: &'static str = "ML-KEM-768";
    const OID: &'static str = "2.16.840.1.101.3.4.4.2";

    fn generate<R: RngCore + CryptoRng>(
        rng: &mut R,
    ) -> Result<
        (Self::DecapsulationKey, Self::EncapsulationKey),
        KyberLibError,
    > {
        let (sk, pk) = backend_keygen::<
            MlKem768,
            R,
            KYBER_SECRET_KEY_BYTES,
            KYBER_PUBLIC_KEY_BYTES,
        >(rng)?;
        Ok((MlKem768DecapKey(sk), MlKem768EncapKey(pk)))
    }

    fn generate_from_seed(
        d: &[u8; 32],
        z: &[u8; 32],
    ) -> Result<
        (Self::DecapsulationKey, Self::EncapsulationKey),
        KyberLibError,
    > {
        let (sk, pk) = keypair_from_seed::<
            MlKem768,
            KYBER_PUBLIC_KEY_BYTES,
            KYBER_SECRET_KEY_BYTES,
        >(d, z)?;
        Ok((MlKem768DecapKey(sk), MlKem768EncapKey(pk)))
    }
}

impl MlKem512EncapKey {
    /// Encapsulate against this public key under ML-KEM-512.
    ///
    /// # Errors
    ///
    /// [`KyberLibError::InvalidKey`] if the key fails the FIPS 203
    /// §7.2 modulus check; [`KyberLibError::RandomBytesGeneration`] if
    /// the RNG fails.
    pub fn encapsulate<R: RngCore + CryptoRng>(
        &self,
        rng: &mut R,
    ) -> Result<(MlKem512Ciphertext, SharedSecret), KyberLibError> {
        let (ct, ss) =
            backend_encapsulate::<MlKem512, R, 768>(&self.0, rng)?;
        Ok((MlKem512Ciphertext(ct), SharedSecret(ss)))
    }
}

impl MlKem512DecapKey {
    /// Decapsulate a ciphertext under this ML-KEM-512 secret key.
    /// Implicit-rejection per FIPS 203 §6.3 — never panics, never
    /// branches on validity.
    #[must_use]
    pub fn decapsulate(&self, ct: &MlKem512Ciphertext) -> SharedSecret {
        backend_decapsulate::<MlKem512>(&self.0, &ct.0)
    }
}

impl KemCore for MlKem512 {
    type EncapsulationKey = MlKem512EncapKey;
    type DecapsulationKey = MlKem512DecapKey;
    type Ciphertext = MlKem512Ciphertext;
    const ALGORITHM_ID: &'static str = "ML-KEM-512";
    const OID: &'static str = "2.16.840.1.101.3.4.4.1";

    fn generate<R: RngCore + CryptoRng>(
        rng: &mut R,
    ) -> Result<
        (Self::DecapsulationKey, Self::EncapsulationKey),
        KyberLibError,
    > {
        let (sk, pk) = backend_keygen::<MlKem512, R, 1632, 800>(rng)?;
        Ok((MlKem512DecapKey(sk), MlKem512EncapKey(pk)))
    }

    fn generate_from_seed(
        d: &[u8; 32],
        z: &[u8; 32],
    ) -> Result<
        (Self::DecapsulationKey, Self::EncapsulationKey),
        KyberLibError,
    > {
        let (sk, pk) = keypair_from_seed::<MlKem512, 800, 1632>(d, z)?;
        Ok((MlKem512DecapKey(sk), MlKem512EncapKey(pk)))
    }
}

impl MlKem1024EncapKey {
    /// Encapsulate against this public key under ML-KEM-1024.
    ///
    /// # Errors
    ///
    /// [`KyberLibError::InvalidKey`] if the key fails the FIPS 203
    /// §7.2 modulus check; [`KyberLibError::RandomBytesGeneration`] if
    /// the RNG fails.
    pub fn encapsulate<R: RngCore + CryptoRng>(
        &self,
        rng: &mut R,
    ) -> Result<(MlKem1024Ciphertext, SharedSecret), KyberLibError>
    {
        let (ct, ss) =
            backend_encapsulate::<MlKem1024, R, 1568>(&self.0, rng)?;
        Ok((MlKem1024Ciphertext(ct), SharedSecret(ss)))
    }
}

impl MlKem1024DecapKey {
    /// Decapsulate a ciphertext under this ML-KEM-1024 secret key.
    /// Implicit-rejection per FIPS 203 §6.3 — never panics, never
    /// branches on validity.
    #[must_use]
    pub fn decapsulate(
        &self,
        ct: &MlKem1024Ciphertext,
    ) -> SharedSecret {
        backend_decapsulate::<MlKem1024>(&self.0, &ct.0)
    }
}

impl KemCore for MlKem1024 {
    type EncapsulationKey = MlKem1024EncapKey;
    type DecapsulationKey = MlKem1024DecapKey;
    type Ciphertext = MlKem1024Ciphertext;
    const ALGORITHM_ID: &'static str = "ML-KEM-1024";
    const OID: &'static str = "2.16.840.1.101.3.4.4.3";

    fn generate<R: RngCore + CryptoRng>(
        rng: &mut R,
    ) -> Result<
        (Self::DecapsulationKey, Self::EncapsulationKey),
        KyberLibError,
    > {
        let (sk, pk) = backend_keygen::<MlKem1024, R, 3168, 1568>(rng)?;
        Ok((MlKem1024DecapKey(sk), MlKem1024EncapKey(pk)))
    }

    fn generate_from_seed(
        d: &[u8; 32],
        z: &[u8; 32],
    ) -> Result<
        (Self::DecapsulationKey, Self::EncapsulationKey),
        KyberLibError,
    > {
        let (sk, pk) =
            keypair_from_seed::<MlKem1024, 1568, 3168>(d, z)?;
        Ok((MlKem1024DecapKey(sk), MlKem1024EncapKey(pk)))
    }
}

#[cfg(test)]
#[path = "ml_kem_tests.rs"]
mod tests;
