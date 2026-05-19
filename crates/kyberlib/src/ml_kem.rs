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
    ) -> Result<(Self::DecapsulationKey, Self::EncapsulationKey), KyberLibError>;
}

// ---------------------------------------------------------------- markers

/// ML-KEM-512 parameter set marker. NIST security category 1 (≈ AES-128).
///
/// Module rank `k = 2`. Public key 800 B, secret key 1632 B,
/// ciphertext 768 B, shared secret 32 B.
///
/// **`KemCore` not yet implemented** — the typed wrappers
/// ([`MlKem512EncapKey`], [`MlKem512DecapKey`], [`MlKem512Ciphertext`])
/// exist so downstream code can be written generically, but the
/// underlying primitives require the const-generic refactor tracked
/// in #130c to support all three parameter sets in one build.
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
    pub const ALGORITHM_ID_STR: &'static str = "ML-KEM-768";
    /// Object identifier — `2.16.840.1.101.3.4.4.2`.
    pub const OID_STR: &'static str = crate::oid::ML_KEM_768;
}

/// ML-KEM-1024 parameter set marker. NIST security category 5 (≈ AES-256).
/// Required by CNSA 2.0 for NSS by 1 Jan 2027.
///
/// Module rank `k = 4`. Public key 1568 B, secret key 3168 B,
/// ciphertext 1568 B, shared secret 32 B.
///
/// **`KemCore` not yet implemented** — see [`MlKem512`] for the
/// rationale. Tracking: #130c.
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
                    .field(&format_args!("[{} bytes; not secret]", $pk_bytes))
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
                    .field(&format_args!("[{} bytes; opaque]", $ct_bytes))
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
/// [`EncapsulationKey::encapsulate`] →
/// [`DecapsulationKey::decapsulate`]; never directly by the consumer.
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
    pub fn from_bytes(
        bytes: [u8; KYBER_PUBLIC_KEY_BYTES],
    ) -> Self {
        Self(bytes)
    }

    /// Construct from a borrowed slice, validating the length.
    ///
    /// # Errors
    ///
    /// Returns [`KyberLibError::InvalidLength`] if `bytes.len() !=
    /// KYBER_PUBLIC_KEY_BYTES`.
    pub fn try_from_slice(
        bytes: &[u8],
    ) -> Result<Self, KyberLibError> {
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
    pub fn decapsulate(
        &self,
        ct: &MlKem768Ciphertext,
    ) -> SharedSecret {
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
    pub fn from_bytes(
        bytes: [u8; KYBER_CIPHERTEXT_BYTES],
    ) -> Self {
        Self(bytes)
    }

    /// Construct from a borrowed slice, validating the length.
    ///
    /// # Errors
    ///
    /// Returns [`KyberLibError::InvalidLength`] if `bytes.len() !=
    /// KYBER_CIPHERTEXT_BYTES`.
    pub fn try_from_slice(
        bytes: &[u8],
    ) -> Result<Self, KyberLibError> {
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ml_kem_768_round_trip() {
        let mut rng = rand::thread_rng();
        let (dk, ek) = MlKem768::generate(&mut rng).expect("keygen");
        let (ct, ss_a) = ek.encapsulate(&mut rng).expect("encap");
        let ss_b = dk.decapsulate(&ct);
        assert_eq!(ss_a, ss_b);
    }

    #[test]
    fn ml_kem_768_oid() {
        assert_eq!(MlKem768::OID, "2.16.840.1.101.3.4.4.2");
        assert_eq!(MlKem768::ALGORITHM_ID, "ML-KEM-768");
    }

    #[test]
    fn shared_secret_debug_is_redacted() {
        let ss = SharedSecret([0xAA; KYBER_SHARED_SECRET_BYTES]);
        assert_eq!(format!("{ss:?}"), "SharedSecret([REDACTED 32 bytes])");
    }

    #[test]
    fn decap_key_debug_is_redacted() {
        let dk = MlKem768DecapKey([0xBB; KYBER_SECRET_KEY_BYTES]);
        assert_eq!(
            format!("{dk:?}"),
            "MlKem768DecapKey([REDACTED 2400 bytes])"
        );
    }
}
