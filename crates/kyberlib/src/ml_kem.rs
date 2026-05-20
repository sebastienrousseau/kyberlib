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
//! The free functions [`keypair`](crate::keypair),
//! [`encapsulate`](crate::encapsulate), [`decapsulate`](crate::decapsulate)
//! and the [`Keypair`](crate::Keypair) struct from the old surface are
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

use crate::{
    error::KyberLibError, KYBER_CIPHERTEXT_BYTES,
    KYBER_PUBLIC_KEY_BYTES, KYBER_SECRET_KEY_BYTES,
    KYBER_SHARED_SECRET_BYTES,
};
use core::fmt;
use rand_core::{CryptoRng, RngCore};
use zeroize::{Zeroize, ZeroizeOnDrop};

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
            /// Construct from a borrowed slice, validating the length.
            ///
            /// # Errors
            ///
            /// [`KyberLibError::InvalidLength`] on length mismatch.
            pub fn try_from_slice(
                bytes: &[u8],
            ) -> Result<Self, KyberLibError> {
                if bytes.len() != $sk_bytes {
                    return Err(KyberLibError::InvalidLength);
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
    /// Returns [`KyberLibError::RandomBytesGeneration`] if the supplied
    /// RNG fails.
    pub fn encapsulate<R: RngCore + CryptoRng>(
        &self,
        rng: &mut R,
    ) -> Result<(MlKem768Ciphertext, SharedSecret), KyberLibError> {
        let mut ct = [0u8; KYBER_CIPHERTEXT_BYTES];
        let mut ss = [0u8; KYBER_SHARED_SECRET_BYTES];
        crate::kem::kem_enc_generic::<MlKem768, R>(
            &mut ct, &mut ss, &self.0, rng, None,
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
        let mut ss = [0u8; KYBER_SHARED_SECRET_BYTES];
        crate::kem::kem_dec_generic::<MlKem768>(
            &mut ss, &ct.0, &self.0,
        );
        SharedSecret(ss)
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
        let mut pk = [0u8; KYBER_PUBLIC_KEY_BYTES];
        let mut sk = [0u8; KYBER_SECRET_KEY_BYTES];
        crate::kem::kem_keypair_generic::<MlKem768, R>(
            &mut pk, &mut sk, rng, None,
        )?;
        Ok((MlKem768DecapKey(sk), MlKem768EncapKey(pk)))
    }
}

impl MlKem512EncapKey {
    /// Encapsulate against this public key under ML-KEM-512.
    ///
    /// # Errors
    ///
    /// [`KyberLibError::RandomBytesGeneration`] if the RNG fails.
    pub fn encapsulate<R: RngCore + CryptoRng>(
        &self,
        rng: &mut R,
    ) -> Result<(MlKem512Ciphertext, SharedSecret), KyberLibError> {
        let mut ct = [0u8; 768];
        let mut ss = [0u8; KYBER_SHARED_SECRET_BYTES];
        crate::kem::kem_enc_generic::<MlKem512, R>(
            &mut ct, &mut ss, &self.0, rng, None,
        )?;
        Ok((MlKem512Ciphertext(ct), SharedSecret(ss)))
    }
}

impl MlKem512DecapKey {
    /// Decapsulate a ciphertext under this ML-KEM-512 secret key.
    /// Implicit-rejection per FIPS 203 §6.3 — never panics, never
    /// branches on validity.
    #[must_use]
    pub fn decapsulate(&self, ct: &MlKem512Ciphertext) -> SharedSecret {
        let mut ss = [0u8; KYBER_SHARED_SECRET_BYTES];
        crate::kem::kem_dec_generic::<MlKem512>(
            &mut ss, &ct.0, &self.0,
        );
        SharedSecret(ss)
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
        let mut pk = [0u8; 800];
        let mut sk = [0u8; 1632];
        crate::kem::kem_keypair_generic::<MlKem512, R>(
            &mut pk, &mut sk, rng, None,
        )?;
        Ok((MlKem512DecapKey(sk), MlKem512EncapKey(pk)))
    }
}

impl MlKem1024EncapKey {
    /// Encapsulate against this public key under ML-KEM-1024.
    ///
    /// # Errors
    ///
    /// [`KyberLibError::RandomBytesGeneration`] if the RNG fails.
    pub fn encapsulate<R: RngCore + CryptoRng>(
        &self,
        rng: &mut R,
    ) -> Result<(MlKem1024Ciphertext, SharedSecret), KyberLibError>
    {
        let mut ct = [0u8; 1568];
        let mut ss = [0u8; KYBER_SHARED_SECRET_BYTES];
        crate::kem::kem_enc_generic::<MlKem1024, R>(
            &mut ct, &mut ss, &self.0, rng, None,
        )?;
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
        let mut ss = [0u8; KYBER_SHARED_SECRET_BYTES];
        crate::kem::kem_dec_generic::<MlKem1024>(
            &mut ss, &ct.0, &self.0,
        );
        SharedSecret(ss)
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
        let mut pk = [0u8; 1568];
        let mut sk = [0u8; 3168];
        crate::kem::kem_keypair_generic::<MlKem1024, R>(
            &mut pk, &mut sk, rng, None,
        )?;
        Ok((MlKem1024DecapKey(sk), MlKem1024EncapKey(pk)))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// **THE public-API multi-param headline test.**
    ///
    /// Downstream consumers can now call `MlKem512::generate`,
    /// `MlKem768::generate`, and `MlKem1024::generate` from the same
    /// function under DEFAULT features. Each produces the correct
    /// FIPS 203 §6 byte sizes, each round-trips through encap → decap
    /// to a matching 32-byte shared secret.
    ///
    /// This is the user-visible delivery of #130b: the typed `KemCore`
    /// surface is fully multi-parameter-set in one build.
    #[test]
    fn public_api_all_three_kem_cores_in_one_build() {
        let mut rng = rand::thread_rng();

        // ML-KEM-512
        let (dk_512, ek_512) = MlKem512::generate(&mut rng).unwrap();
        let (ct_512, ss_a_512) = ek_512.encapsulate(&mut rng).unwrap();
        let ss_b_512 = dk_512.decapsulate(&ct_512);
        assert_eq!(ss_a_512, ss_b_512);

        // ML-KEM-768
        let (dk_768, ek_768) = MlKem768::generate(&mut rng).unwrap();
        let (ct_768, ss_a_768) = ek_768.encapsulate(&mut rng).unwrap();
        let ss_b_768 = dk_768.decapsulate(&ct_768);
        assert_eq!(ss_a_768, ss_b_768);

        // ML-KEM-1024
        let (dk_1024, ek_1024) = MlKem1024::generate(&mut rng).unwrap();
        let (ct_1024, ss_a_1024) =
            ek_1024.encapsulate(&mut rng).unwrap();
        let ss_b_1024 = dk_1024.decapsulate(&ct_1024);
        assert_eq!(ss_a_1024, ss_b_1024);

        // Byte sizes match FIPS 203 §6 Table 2.
        assert_eq!(ek_512.as_bytes().len(), 800);
        assert_eq!(ek_768.as_bytes().len(), 1184);
        assert_eq!(ek_1024.as_bytes().len(), 1568);
        assert_eq!(dk_512.as_bytes().len(), 1632);
        assert_eq!(dk_768.as_bytes().len(), 2400);
        assert_eq!(dk_1024.as_bytes().len(), 3168);
        assert_eq!(ct_512.as_bytes().len(), 768);
        assert_eq!(ct_768.as_bytes().len(), 1088);
        assert_eq!(ct_1024.as_bytes().len(), 1568);

        // Three independent secrets.
        assert_ne!(ss_a_512, ss_a_768);
        assert_ne!(ss_a_768, ss_a_1024);
        assert_ne!(ss_a_512, ss_a_1024);
    }

    #[test]
    fn ml_kem_768_round_trip() {
        let mut rng = rand::thread_rng();
        let (dk, ek) = MlKem768::generate(&mut rng).expect("keygen");
        let (ct, ss_a) = ek.encapsulate(&mut rng).expect("encap");
        let ss_b = dk.decapsulate(&ct);
        assert_eq!(ss_a, ss_b);
    }

    #[test]
    fn ml_kem_512_round_trip() {
        let mut rng = rand::thread_rng();
        let (dk, ek) = MlKem512::generate(&mut rng).expect("keygen");
        let (ct, ss_a) = ek.encapsulate(&mut rng).expect("encap");
        let ss_b = dk.decapsulate(&ct);
        assert_eq!(ss_a, ss_b);
    }

    #[test]
    fn ml_kem_1024_round_trip() {
        let mut rng = rand::thread_rng();
        let (dk, ek) = MlKem1024::generate(&mut rng).expect("keygen");
        let (ct, ss_a) = ek.encapsulate(&mut rng).expect("encap");
        let ss_b = dk.decapsulate(&ct);
        assert_eq!(ss_a, ss_b);
    }

    #[test]
    fn ml_kem_768_oid() {
        assert_eq!(MlKem768::OID, "2.16.840.1.101.3.4.4.2");
        assert_eq!(MlKem768::ALGORITHM_ID, "ML-KEM-768");
    }

    // ------- Coverage tests for the sized_wrapper_types! macro --------
    //
    // The MlKem512 and MlKem1024 typed wrappers exist under all feature
    // combinations (the macro that generates them is unconditional);
    // only KemCore impls are feature-gated. The tests below exercise
    // the constructor / accessor / Debug surface across all three
    // parameter sets so the macro expansion lines stay covered.

    #[test]
    fn ml_kem_512_encap_key_constructors() {
        let bytes = [0u8; 800];
        let ek = MlKem512EncapKey::from_bytes(bytes);
        assert_eq!(ek.as_bytes(), &bytes);
        let ek2 = MlKem512EncapKey::try_from_slice(&bytes).unwrap();
        assert_eq!(ek.as_bytes(), ek2.as_bytes());
        assert!(MlKem512EncapKey::try_from_slice(&[0u8; 100]).is_err());
        // Debug should NOT print raw bytes — "[bytes; not secret]" marker.
        #[cfg(feature = "std")]
        assert!(format!("{ek:?}").contains("not secret"));
    }

    #[test]
    fn ml_kem_512_decap_key_constructors() {
        let bytes = [0u8; 1632];
        let dk = MlKem512DecapKey::from_bytes(bytes);
        assert_eq!(dk.as_bytes(), &bytes);
        assert!(MlKem512DecapKey::try_from_slice(&bytes).is_ok());
        assert!(MlKem512DecapKey::try_from_slice(&[0u8; 100]).is_err());
        #[cfg(feature = "std")]
        assert!(format!("{dk:?}").contains("REDACTED"));
    }

    #[test]
    fn ml_kem_512_ciphertext_constructors() {
        let bytes = [0u8; 768];
        let ct = MlKem512Ciphertext::from_bytes(bytes);
        assert_eq!(ct.as_bytes(), &bytes);
        assert!(MlKem512Ciphertext::try_from_slice(&bytes).is_ok());
        assert!(
            MlKem512Ciphertext::try_from_slice(&[0u8; 100]).is_err()
        );
        #[cfg(feature = "std")]
        assert!(format!("{ct:?}").contains("opaque"));
    }

    #[test]
    fn ml_kem_1024_encap_key_constructors() {
        let bytes = [0u8; 1568];
        let ek = MlKem1024EncapKey::from_bytes(bytes);
        assert_eq!(ek.as_bytes(), &bytes);
        assert!(MlKem1024EncapKey::try_from_slice(&bytes).is_ok());
        assert!(MlKem1024EncapKey::try_from_slice(&[0u8; 100]).is_err());
    }

    #[test]
    fn ml_kem_1024_decap_key_constructors() {
        let bytes = [0u8; 3168];
        let dk = MlKem1024DecapKey::from_bytes(bytes);
        assert_eq!(dk.as_bytes(), &bytes);
        assert!(MlKem1024DecapKey::try_from_slice(&bytes).is_ok());
        assert!(MlKem1024DecapKey::try_from_slice(&[0u8; 100]).is_err());
    }

    #[test]
    fn ml_kem_1024_ciphertext_constructors() {
        let bytes = [0u8; 1568];
        let ct = MlKem1024Ciphertext::from_bytes(bytes);
        assert_eq!(ct.as_bytes(), &bytes);
        assert!(MlKem1024Ciphertext::try_from_slice(&bytes).is_ok());
        assert!(
            MlKem1024Ciphertext::try_from_slice(&[0u8; 100]).is_err()
        );
    }

    #[test]
    fn ml_kem_768_encap_key_try_from_slice_wrong_length() {
        assert!(MlKem768EncapKey::try_from_slice(&[0u8; 100]).is_err());
        assert!(MlKem768EncapKey::try_from_slice(&[0u8; 1184]).is_ok());
    }

    #[test]
    fn ml_kem_768_ciphertext_try_from_slice_wrong_length() {
        assert!(
            MlKem768Ciphertext::try_from_slice(&[0u8; 100]).is_err()
        );
        assert!(
            MlKem768Ciphertext::try_from_slice(&[0u8; 1088]).is_ok()
        );
    }

    #[test]
    fn shared_secret_as_bytes() {
        let ss = SharedSecret([0xAB; KYBER_SHARED_SECRET_BYTES]);
        assert_eq!(ss.as_bytes(), &[0xAB; KYBER_SHARED_SECRET_BYTES]);
        let ss2 = ss.clone();
        assert_eq!(ss, ss2);
    }

    #[test]
    fn marker_constants_match_spec() {
        // FIPS 203 sizes, NIST IETF LAMPS OIDs.
        assert_eq!(MlKem512::K, 2);
        assert_eq!(MlKem512::PUBLIC_KEY_BYTES, 800);
        assert_eq!(MlKem512::SECRET_KEY_BYTES, 1632);
        assert_eq!(MlKem512::CIPHERTEXT_BYTES, 768);
        assert_eq!(MlKem512::ALGORITHM_ID, "ML-KEM-512");

        assert_eq!(MlKem768::K, 3);
        assert_eq!(MlKem768::PUBLIC_KEY_BYTES, 1184);
        assert_eq!(MlKem768::SECRET_KEY_BYTES, 2400);
        assert_eq!(MlKem768::CIPHERTEXT_BYTES, 1088);
        assert_eq!(MlKem768::ALGORITHM_ID, "ML-KEM-768");

        assert_eq!(MlKem1024::K, 4);
        assert_eq!(MlKem1024::PUBLIC_KEY_BYTES, 1568);
        assert_eq!(MlKem1024::SECRET_KEY_BYTES, 3168);
        assert_eq!(MlKem1024::CIPHERTEXT_BYTES, 1568);
        assert_eq!(MlKem1024::ALGORITHM_ID, "ML-KEM-1024");
    }

    #[test]
    fn marker_types_are_zst() {
        // The marker types should be zero-sized — they exist only at
        // the type level.
        assert_eq!(size_of::<MlKem512>(), 0);
        assert_eq!(size_of::<MlKem768>(), 0);
        assert_eq!(size_of::<MlKem1024>(), 0);
    }

    #[test]
    #[cfg(feature = "std")]
    fn shared_secret_debug_is_redacted() {
        let ss = SharedSecret([0xAA; KYBER_SHARED_SECRET_BYTES]);
        assert_eq!(
            format!("{ss:?}"),
            "SharedSecret([REDACTED 32 bytes])"
        );
    }

    #[test]
    #[cfg(feature = "std")]
    fn decap_key_debug_is_redacted() {
        let dk = MlKem768DecapKey([0xBB; KYBER_SECRET_KEY_BYTES]);
        assert_eq!(
            format!("{dk:?}"),
            "MlKem768DecapKey([REDACTED 2400 bytes])"
        );
    }
}
