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
//!     ├── MlKem512        (marker — pending #130b)
//!     ├── MlKem768        (marker — wired through to the existing primitives)
//!     └── MlKem1024       (marker — pending #130b)
//!
//!     EncapsulationKey<P>           — `Copy`-safe public bytes
//!     DecapsulationKey<P>           — `!Copy`, `ZeroizeOnDrop`, redacted `Debug`
//!     Ciphertext<P>                  — opaque, fixed-size byte wrapper
//!     SharedSecret                   — 32-byte `ZeroizeOnDrop` secret
//! ```
//!
//! ## Migration from the v0.0.6 surface
//!
//! The free functions [`keypair`](crate::keypair),
//! [`encapsulate`](crate::encapsulate), [`decapsulate`](crate::decapsulate)
//! and the [`Keypair`](crate::Keypair) struct from the old surface are
//! retained as `#[deprecated]` shims and call into the new API
//! internally for `MlKem768`. They'll be removed in a future release.
//!
//! ## Status of the three marker types
//!
//! [`MlKem768`] is fully wired. The implementation delegates to
//! [`crate::keypair`] / [`crate::encapsulate`] / [`crate::decapsulate`]
//! — which since commits `417595a`, `27e4b6b`, `b0f3bfb` are FIPS 203
//! ML-KEM-768 conformant against the NIST ACVP corpus (60 / 60 cases,
//! see [`tests/test_acvp.rs`][acvp]).
//!
//! [`MlKem512`] and [`MlKem1024`] are declared so downstream code can
//! be written against the full type set, but they **do not yet implement
//! [`KemCore`]**. Wiring them through requires the internal const
//! refactor tracked in #130b — the current `crates/kyberlib/src/params.rs`
//! constants are `cfg(feature = ...)`-gated and the build can only
//! support one parameter set at a time. The Phase 3 follow-up lifts
//! those constants into per-type associated values.
//!
//! [acvp]: ../../tests/test_acvp.rs

use crate::{
    api as classic, error::KyberLibError, KYBER_CIPHERTEXT_BYTES,
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
/// [`KemCore`] is implemented under `--features kyber512`. Today the
/// kyberlib internals are configured for one parameter set per build,
/// so to use ML-KEM-512 the consumer disables `kyber768` (the default)
/// and enables `kyber512`. Const-generic unification across all three
/// parameter sets in a single build is tracked as #130b.
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
/// [`KemCore`] is implemented under `--features kyber1024`. See
/// [`MlKem512`] for the per-build-feature-selection rationale.
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
        let (ct, ss) = classic::encapsulate(&self.0, rng)?;
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
    pub fn decapsulate(&self, ct: &MlKem768Ciphertext) -> SharedSecret {
        // The classic API returns Err only on length mismatch; here
        // the type system guarantees the length, so we unwrap-safely.
        let ss = classic::decapsulate(&ct.0, &self.0)
            .expect("typed ciphertext + secret key — length-invariant guaranteed");
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

// ============================== KemCore impls (param-set-feature gated)
//
// Each impl is gated on the corresponding `kyber{512,768,1024}` feature.
// Today the kyberlib internals select ONE parameter set per build via
// the same feature gates (`KYBER_SECURITY_PARAMETER`, `KYBER_PUBLIC_KEY_BYTES`,
// etc. in `params.rs`), so only one impl is active in any single build.
// Downstream code can still be written generically over `P: KemCore` —
// the build picks which `P` is instantiable.
//
// The const-generic refactor that would let all three impls coexist in
// one build is tracked as #130b. When it lands, drop the cfg gates here
// and the algorithm code becomes generic over the parameter pack.

#[cfg(feature = "kyber768")]
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
        let kp = classic::keypair(rng)?;
        Ok((MlKem768DecapKey(kp.secret), MlKem768EncapKey(kp.public)))
    }
}

#[cfg(feature = "kyber512")]
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
        let (ct, ss) = classic::encapsulate(&self.0, rng)?;
        Ok((MlKem512Ciphertext(ct), SharedSecret(ss)))
    }
}

#[cfg(feature = "kyber512")]
impl MlKem512DecapKey {
    /// Decapsulate a ciphertext under this ML-KEM-512 secret key.
    /// Implicit-rejection per FIPS 203 §6.3 — never panics, never
    /// branches on validity.
    pub fn decapsulate(&self, ct: &MlKem512Ciphertext) -> SharedSecret {
        let ss = classic::decapsulate(&ct.0, &self.0)
            .expect("typed ciphertext + secret key — length-invariant guaranteed");
        SharedSecret(ss)
    }
}

#[cfg(feature = "kyber512")]
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
        // Under `--features kyber512`, the classic free functions are
        // configured with KYBER_K=2, KYBER_PUBLIC_KEY_BYTES=800, etc.
        // The typed wrappers' byte arrays match those sizes (declared
        // in the `sized_wrapper_types!` macro invocation).
        let kp = classic::keypair(rng)?;
        Ok((MlKem512DecapKey(kp.secret), MlKem512EncapKey(kp.public)))
    }
}

#[cfg(feature = "kyber1024")]
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
        let (ct, ss) = classic::encapsulate(&self.0, rng)?;
        Ok((MlKem1024Ciphertext(ct), SharedSecret(ss)))
    }
}

#[cfg(feature = "kyber1024")]
impl MlKem1024DecapKey {
    /// Decapsulate a ciphertext under this ML-KEM-1024 secret key.
    /// Implicit-rejection per FIPS 203 §6.3 — never panics, never
    /// branches on validity.
    pub fn decapsulate(
        &self,
        ct: &MlKem1024Ciphertext,
    ) -> SharedSecret {
        let ss = classic::decapsulate(&ct.0, &self.0)
            .expect("typed ciphertext + secret key — length-invariant guaranteed");
        SharedSecret(ss)
    }
}

#[cfg(feature = "kyber1024")]
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
        let kp = classic::keypair(rng)?;
        Ok((MlKem1024DecapKey(kp.secret), MlKem1024EncapKey(kp.public)))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    #[cfg(feature = "kyber768")]
    fn ml_kem_768_round_trip() {
        let mut rng = rand::thread_rng();
        let (dk, ek) = MlKem768::generate(&mut rng).expect("keygen");
        let (ct, ss_a) = ek.encapsulate(&mut rng).expect("encap");
        let ss_b = dk.decapsulate(&ct);
        assert_eq!(ss_a, ss_b);
    }

    #[test]
    #[cfg(feature = "kyber512")]
    fn ml_kem_512_round_trip() {
        let mut rng = rand::thread_rng();
        let (dk, ek) = MlKem512::generate(&mut rng).expect("keygen");
        let (ct, ss_a) = ek.encapsulate(&mut rng).expect("encap");
        let ss_b = dk.decapsulate(&ct);
        assert_eq!(ss_a, ss_b);
    }

    #[test]
    #[cfg(feature = "kyber1024")]
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
