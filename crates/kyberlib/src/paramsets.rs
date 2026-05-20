// Copyright © 2026 kyberlib. All rights reserved.
// SPDX-License-Identifier: Apache-2.0 OR MIT

//! Parameter-pack trait for the three FIPS 203 ML-KEM parameter sets.
//!
//! ## Motivation
//!
//! The existing reference backend in [`crate::reference`] selects its
//! parameter set at compile time via Cargo feature gates (`kyber512`,
//! `kyber768`, `kyber1024`). That means a single build can support
//! exactly one parameter set: an application that wants to negotiate
//! between ML-KEM-512 and ML-KEM-1024 at runtime has to either pick
//! one or link two kyberlib copies.
//!
//! This module introduces [`MlKemParams`] — a sealed trait whose
//! associated constants and associated types pin down everything a
//! generic FIPS 203 algorithm needs:
//!
//! - **Numeric parameters** — module rank `K`, noise widths `ETA1`/`ETA2`,
//!   compression bit-widths `DU`/`DV`, byte-length constants for keys
//!   and ciphertexts.
//! - **Concrete buffer types** — `PublicKeyBytes`, `SecretKeyBytes`,
//!   `CiphertextBytes` are associated *types* that each impl
//!   instantiates as the correct `[u8; N]` length for the spec. This
//!   sidesteps the stable-Rust restriction that prevents
//!   `[u8; K * Self::POLY_BYTES]` in generic contexts.
//!
//! ## Implementation strategy
//!
//! Three marker types [`MlKem512`](crate::MlKem512),
//! [`MlKem768`](crate::MlKem768), [`MlKem1024`](crate::MlKem1024)
//! implement [`MlKemParams`]. Algorithm code that takes
//! `P: MlKemParams` then has access to `P::K`, `P::ETA1`, etc. as
//! `const` values and uses `P::PublicKeyBytes` as the concrete byte
//! array type for keys.
//!
//! ## Migration status (v0.0.7)
//!
//! This module ships the **trait + impls** so downstream code can be
//! written against the unified parameter surface, but the algorithm
//! code in [`crate::reference`] has NOT yet been ported to consume
//! the trait. The three [`KemCore`](crate::KemCore) impls remain
//! Cargo-feature-gated for now. The mechanical port of the reference
//! backend — `indcpa_keypair`, `indcpa_enc`, `indcpa_dec`,
//! `crypto_kem_keypair`, `crypto_kem_enc`, `crypto_kem_dec`, plus the
//! polynomial-arithmetic primitives in `poly.rs`, `polyvec.rs`,
//! `cbd.rs` — is a multi-day focused PR tracked as **#130b**.
//!
//! ## Why the trait lands now
//!
//! 1. **Downstream code can begin writing generic algorithms**
//!    targeting `fn foo<P: MlKemParams>(...)` immediately, with the
//!    understanding that the body currently has to specialise
//!    internally.
//! 2. **It pins down the API contract** for the parameter pack so the
//!    eventual algorithm refactor has a fixed target to land against.
//! 3. **Const accessors** — `<MlKem768 as MlKemParams>::PUBLIC_KEY_BYTES`
//!    is now resolvable at compile time, useful for downstream
//!    `const fn` size calculations.

use crate::error::KyberLibError;
use core::fmt::Debug;

mod sealed {
    /// Sealed marker — only this crate may add new ML-KEM parameter sets.
    pub trait Sealed {}
}

// =============================================================================
// MlKemParams — the unified parameter-pack trait
// =============================================================================

/// FIPS 203 parameter pack — every constant and type the algorithm
/// needs to specialise to one of the three ML-KEM variants.
///
/// Implemented by the zero-sized marker types
/// [`MlKem512`](crate::MlKem512), [`MlKem768`](crate::MlKem768),
/// [`MlKem1024`](crate::MlKem1024). Sealed: third-party crates cannot
/// add new implementations.
///
/// All associated constants come from FIPS 203 §6 ("Parameter sets")
/// and the IETF LAMPS draft for the OIDs / algorithm identifiers.
///
/// # Example
///
/// ```
/// use kyberlib::{MlKem768, MlKemParams};
///
/// const PK_LEN: usize = <MlKem768 as MlKemParams>::PUBLIC_KEY_BYTES;
/// const CT_LEN: usize = <MlKem768 as MlKemParams>::CIPHERTEXT_BYTES;
/// assert_eq!(PK_LEN, 1184);
/// assert_eq!(CT_LEN, 1088);
/// ```
pub trait MlKemParams:
    sealed::Sealed + Sized + Copy + Debug + 'static
{
    // --- Numeric parameters (FIPS 203 §6) ---

    /// Module rank `k`. 2 / 3 / 4 for ML-KEM-512 / 768 / 1024.
    const K: usize;

    /// Centred-binomial width η₁ for the secret-key sampling.
    /// 3 for ML-KEM-512, 2 for ML-KEM-768 and ML-KEM-1024.
    const ETA1: usize;

    /// Centred-binomial width η₂ for the ciphertext-noise sampling.
    /// Always 2.
    const ETA2: usize = 2;

    /// Polynomial degree N. Always 256.
    const N: usize = 256;

    /// Modulus q. Always 3329.
    const Q: usize = 3329;

    /// Ciphertext compression bit-width for the u half. 10 for
    /// ML-KEM-512/768, 11 for ML-KEM-1024.
    const DU: usize;

    /// Ciphertext compression bit-width for the v half. 4 for
    /// ML-KEM-512/768, 5 for ML-KEM-1024.
    const DV: usize;

    // --- Byte-length constants (computed from the spec) ---

    /// Shared-secret length in bytes. Always 32.
    const SHARED_SECRET_BYTES: usize = 32;

    /// Symmetric primitive byte length (seeds, hashes). Always 32.
    const SYM_BYTES: usize = 32;

    /// Public encapsulation-key byte length.
    /// `K * 384 + 32` per FIPS 203 §6.
    const PUBLIC_KEY_BYTES: usize;

    /// Secret decapsulation-key byte length.
    /// `24*K*N/8 + 96` per FIPS 203 §6.1.
    const SECRET_KEY_BYTES: usize;

    /// Ciphertext byte length.
    /// `32*(K*DU + DV)` per FIPS 203 §6.
    const CIPHERTEXT_BYTES: usize;

    // --- Stable identifiers (IETF LAMPS) ---

    /// Stable algorithm identifier — `"ML-KEM-512"`, `"ML-KEM-768"`,
    /// or `"ML-KEM-1024"`.
    const ALGORITHM_ID: &'static str;

    /// Object identifier — `2.16.840.1.101.3.4.4.{1,2,3}`.
    const OID: &'static str;

    // --- Associated buffer types ---

    /// Concrete encapsulation-key byte buffer type. Each impl
    /// instantiates as `[u8; PUBLIC_KEY_BYTES]`.
    type PublicKeyBytes: AsRef<[u8]> + AsMut<[u8]> + Copy + Debug;

    /// Concrete decapsulation-key byte buffer type. Each impl
    /// instantiates as `[u8; SECRET_KEY_BYTES]`. Zeroized on drop
    /// at the wrapper level (see [`crate::ml_kem`]).
    type SecretKeyBytes: AsRef<[u8]> + AsMut<[u8]> + Copy + Debug;

    /// Concrete ciphertext byte buffer type. Each impl instantiates
    /// as `[u8; CIPHERTEXT_BYTES]`.
    type CiphertextBytes: AsRef<[u8]> + AsMut<[u8]> + Copy + Debug;

    /// Create a new zeroed public-key buffer. Helper so generic code
    /// can construct buffers without naming the concrete array size.
    #[must_use]
    fn zero_public_key() -> Self::PublicKeyBytes;

    /// Create a new zeroed secret-key buffer.
    #[must_use]
    fn zero_secret_key() -> Self::SecretKeyBytes;

    /// Create a new zeroed ciphertext buffer.
    #[must_use]
    fn zero_ciphertext() -> Self::CiphertextBytes;
}

// =============================================================================
// Marker types + MlKemParams impls
// =============================================================================
//
// These markers are the same types exposed in `crate::ml_kem` as
// `MlKem512` / `MlKem768` / `MlKem1024`. We re-implement the sealed
// marker here and add the MlKemParams impl. The KemCore impl that
// wires through to the actual algorithm code stays in `ml_kem.rs`.

impl sealed::Sealed for crate::MlKem512 {}
impl sealed::Sealed for crate::MlKem768 {}
impl sealed::Sealed for crate::MlKem1024 {}

impl MlKemParams for crate::MlKem512 {
    const K: usize = 2;
    const ETA1: usize = 3;
    const DU: usize = 10;
    const DV: usize = 4;
    const PUBLIC_KEY_BYTES: usize = 800;
    const SECRET_KEY_BYTES: usize = 1632;
    const CIPHERTEXT_BYTES: usize = 768;
    const ALGORITHM_ID: &'static str = "ML-KEM-512";
    const OID: &'static str = "2.16.840.1.101.3.4.4.1";

    type PublicKeyBytes = [u8; 800];
    type SecretKeyBytes = [u8; 1632];
    type CiphertextBytes = [u8; 768];

    fn zero_public_key() -> Self::PublicKeyBytes {
        [0u8; 800]
    }
    fn zero_secret_key() -> Self::SecretKeyBytes {
        [0u8; 1632]
    }
    fn zero_ciphertext() -> Self::CiphertextBytes {
        [0u8; 768]
    }
}

impl MlKemParams for crate::MlKem768 {
    const K: usize = 3;
    const ETA1: usize = 2;
    const DU: usize = 10;
    const DV: usize = 4;
    const PUBLIC_KEY_BYTES: usize = 1184;
    const SECRET_KEY_BYTES: usize = 2400;
    const CIPHERTEXT_BYTES: usize = 1088;
    const ALGORITHM_ID: &'static str = "ML-KEM-768";
    const OID: &'static str = "2.16.840.1.101.3.4.4.2";

    type PublicKeyBytes = [u8; 1184];
    type SecretKeyBytes = [u8; 2400];
    type CiphertextBytes = [u8; 1088];

    fn zero_public_key() -> Self::PublicKeyBytes {
        [0u8; 1184]
    }
    fn zero_secret_key() -> Self::SecretKeyBytes {
        [0u8; 2400]
    }
    fn zero_ciphertext() -> Self::CiphertextBytes {
        [0u8; 1088]
    }
}

impl MlKemParams for crate::MlKem1024 {
    const K: usize = 4;
    const ETA1: usize = 2;
    const DU: usize = 11;
    const DV: usize = 5;
    const PUBLIC_KEY_BYTES: usize = 1568;
    const SECRET_KEY_BYTES: usize = 3168;
    const CIPHERTEXT_BYTES: usize = 1568;
    const ALGORITHM_ID: &'static str = "ML-KEM-1024";
    const OID: &'static str = "2.16.840.1.101.3.4.4.3";

    type PublicKeyBytes = [u8; 1568];
    type SecretKeyBytes = [u8; 3168];
    type CiphertextBytes = [u8; 1568];

    fn zero_public_key() -> Self::PublicKeyBytes {
        [0u8; 1568]
    }
    fn zero_secret_key() -> Self::SecretKeyBytes {
        [0u8; 3168]
    }
    fn zero_ciphertext() -> Self::CiphertextBytes {
        [0u8; 1568]
    }
}

// =============================================================================
// Generic-over-Params convenience surface
// =============================================================================

/// Length of the public encapsulation key for the parameter set `P`,
/// as a `const fn` so it can be used in array dimensions inside
/// `const` contexts.
///
/// # Example
///
/// ```
/// use kyberlib::{MlKem768, MlKemParams, paramsets::public_key_len};
///
/// const PK_LEN: usize = public_key_len::<MlKem768>();
/// assert_eq!(PK_LEN, MlKem768::PUBLIC_KEY_BYTES);
/// ```
#[must_use]
pub const fn public_key_len<P: MlKemParams>() -> usize {
    P::PUBLIC_KEY_BYTES
}

/// Length of the decapsulation secret key for parameter set `P`.
#[must_use]
pub const fn secret_key_len<P: MlKemParams>() -> usize {
    P::SECRET_KEY_BYTES
}

/// Length of the ciphertext for parameter set `P`.
#[must_use]
pub const fn ciphertext_len<P: MlKemParams>() -> usize {
    P::CIPHERTEXT_BYTES
}

/// Length of the shared secret. Always 32 bytes per FIPS 203 §6, but
/// exposed via `P` to keep call sites uniform.
#[must_use]
pub const fn shared_secret_len<P: MlKemParams>() -> usize {
    P::SHARED_SECRET_BYTES
}

// =============================================================================
// Generic length-validated byte→typed-buffer conversion
// =============================================================================

/// Validate a borrowed byte slice and copy it into the parameter-set's
/// concrete `PublicKeyBytes` buffer.
///
/// # Errors
///
/// [`KyberLibError::InvalidLength`] if `bytes.len() != P::PUBLIC_KEY_BYTES`.
///
/// # Example
///
/// ```
/// use kyberlib::{MlKem768, paramsets::public_key_from_slice};
///
/// let pk_bytes = [0u8; 1184];
/// let buf = public_key_from_slice::<MlKem768>(&pk_bytes).unwrap();
/// assert_eq!(buf.len(), 1184);
/// ```
pub fn public_key_from_slice<P: MlKemParams>(
    bytes: &[u8],
) -> Result<P::PublicKeyBytes, KyberLibError> {
    if bytes.len() != P::PUBLIC_KEY_BYTES {
        return Err(KyberLibError::InvalidLength);
    }
    let mut buf = P::zero_public_key();
    buf.as_mut().copy_from_slice(bytes);
    Ok(buf)
}

/// Validate a borrowed byte slice and copy it into the parameter-set's
/// concrete `SecretKeyBytes` buffer.
///
/// # Errors
///
/// [`KyberLibError::InvalidLength`] if
/// `bytes.len() != P::SECRET_KEY_BYTES`.
pub fn secret_key_from_slice<P: MlKemParams>(
    bytes: &[u8],
) -> Result<P::SecretKeyBytes, KyberLibError> {
    if bytes.len() != P::SECRET_KEY_BYTES {
        return Err(KyberLibError::InvalidLength);
    }
    let mut buf = P::zero_secret_key();
    buf.as_mut().copy_from_slice(bytes);
    Ok(buf)
}

/// Validate a borrowed byte slice and copy it into the parameter-set's
/// concrete `CiphertextBytes` buffer.
///
/// # Errors
///
/// [`KyberLibError::InvalidLength`] if
/// `bytes.len() != P::CIPHERTEXT_BYTES`.
pub fn ciphertext_from_slice<P: MlKemParams>(
    bytes: &[u8],
) -> Result<P::CiphertextBytes, KyberLibError> {
    if bytes.len() != P::CIPHERTEXT_BYTES {
        return Err(KyberLibError::InvalidLength);
    }
    let mut buf = P::zero_ciphertext();
    buf.as_mut().copy_from_slice(bytes);
    Ok(buf)
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{MlKem1024, MlKem512, MlKem768};

    #[test]
    fn ml_kem_512_params_match_spec() {
        // FIPS 203 §6 ML-KEM-512 numerical parameters.
        assert_eq!(MlKem512::K, 2);
        assert_eq!(MlKem512::ETA1, 3);
        assert_eq!(MlKem512::ETA2, 2);
        assert_eq!(MlKem512::DU, 10);
        assert_eq!(MlKem512::DV, 4);
        assert_eq!(MlKem512::PUBLIC_KEY_BYTES, 800);
        assert_eq!(MlKem512::SECRET_KEY_BYTES, 1632);
        assert_eq!(MlKem512::CIPHERTEXT_BYTES, 768);
        assert_eq!(MlKem512::SHARED_SECRET_BYTES, 32);
    }

    #[test]
    fn ml_kem_768_params_match_spec() {
        assert_eq!(MlKem768::K, 3);
        assert_eq!(MlKem768::ETA1, 2);
        assert_eq!(MlKem768::ETA2, 2);
        assert_eq!(MlKem768::DU, 10);
        assert_eq!(MlKem768::DV, 4);
        assert_eq!(MlKem768::PUBLIC_KEY_BYTES, 1184);
        assert_eq!(MlKem768::SECRET_KEY_BYTES, 2400);
        assert_eq!(MlKem768::CIPHERTEXT_BYTES, 1088);
    }

    #[test]
    fn ml_kem_1024_params_match_spec() {
        assert_eq!(MlKem1024::K, 4);
        assert_eq!(MlKem1024::ETA1, 2);
        assert_eq!(MlKem1024::ETA2, 2);
        assert_eq!(MlKem1024::DU, 11);
        assert_eq!(MlKem1024::DV, 5);
        assert_eq!(MlKem1024::PUBLIC_KEY_BYTES, 1568);
        assert_eq!(MlKem1024::SECRET_KEY_BYTES, 3168);
        assert_eq!(MlKem1024::CIPHERTEXT_BYTES, 1568);
    }

    #[test]
    fn public_key_size_formula() {
        // FIPS 203: PK_BYTES = 32 * K * N/8 + 32 = K * 384 + 32.
        assert_eq!(
            <MlKem512 as MlKemParams>::PUBLIC_KEY_BYTES,
            MlKem512::K * 384 + 32
        );
        assert_eq!(
            <MlKem768 as MlKemParams>::PUBLIC_KEY_BYTES,
            MlKem768::K * 384 + 32
        );
        assert_eq!(
            <MlKem1024 as MlKemParams>::PUBLIC_KEY_BYTES,
            MlKem1024::K * 384 + 32
        );
    }

    #[test]
    fn ciphertext_size_formula() {
        // FIPS 203: CT_BYTES = 32 * (K * DU + DV).
        // ML-KEM-512:  32*(2*10 + 4)  =  768. ✓
        // ML-KEM-768:  32*(3*10 + 4)  = 1088. ✓
        // ML-KEM-1024: 32*(4*11 + 5)  = 1568. ✓
        assert_eq!(
            <MlKem512 as MlKemParams>::CIPHERTEXT_BYTES,
            32 * (MlKem512::K * MlKem512::DU + MlKem512::DV)
        );
        assert_eq!(
            <MlKem768 as MlKemParams>::CIPHERTEXT_BYTES,
            32 * (MlKem768::K * MlKem768::DU + MlKem768::DV)
        );
        assert_eq!(
            <MlKem1024 as MlKemParams>::CIPHERTEXT_BYTES,
            32 * (MlKem1024::K * MlKem1024::DU + MlKem1024::DV)
        );
    }

    #[test]
    fn const_len_helpers() {
        assert_eq!(public_key_len::<MlKem512>(), 800);
        assert_eq!(public_key_len::<MlKem768>(), 1184);
        assert_eq!(public_key_len::<MlKem1024>(), 1568);

        assert_eq!(secret_key_len::<MlKem512>(), 1632);
        assert_eq!(secret_key_len::<MlKem768>(), 2400);
        assert_eq!(secret_key_len::<MlKem1024>(), 3168);

        assert_eq!(ciphertext_len::<MlKem512>(), 768);
        assert_eq!(ciphertext_len::<MlKem768>(), 1088);
        assert_eq!(ciphertext_len::<MlKem1024>(), 1568);

        assert_eq!(shared_secret_len::<MlKem512>(), 32);
        assert_eq!(shared_secret_len::<MlKem768>(), 32);
        assert_eq!(shared_secret_len::<MlKem1024>(), 32);
    }

    #[test]
    fn from_slice_round_trip() {
        let pk = [0xABu8; 1184];
        let buf = public_key_from_slice::<MlKem768>(&pk).unwrap();
        assert_eq!(buf.as_ref(), &pk);

        // Wrong length → InvalidLength.
        let bad = [0u8; 100];
        let err = public_key_from_slice::<MlKem768>(&bad);
        assert!(matches!(err, Err(KyberLibError::InvalidLength)));

        // ML-KEM-512 with 768's length → InvalidLength (size mismatch).
        let pk_768 = [0xCDu8; 1184];
        let err = public_key_from_slice::<MlKem512>(&pk_768);
        assert!(matches!(err, Err(KyberLibError::InvalidLength)));
    }

    #[test]
    fn algorithm_id_and_oid() {
        assert_eq!(
            <MlKem512 as MlKemParams>::ALGORITHM_ID,
            "ML-KEM-512"
        );
        assert_eq!(
            <MlKem768 as MlKemParams>::ALGORITHM_ID,
            "ML-KEM-768"
        );
        assert_eq!(
            <MlKem1024 as MlKemParams>::ALGORITHM_ID,
            "ML-KEM-1024"
        );

        assert_eq!(
            <MlKem512 as MlKemParams>::OID,
            "2.16.840.1.101.3.4.4.1"
        );
        assert_eq!(
            <MlKem768 as MlKemParams>::OID,
            "2.16.840.1.101.3.4.4.2"
        );
        assert_eq!(
            <MlKem1024 as MlKemParams>::OID,
            "2.16.840.1.101.3.4.4.3"
        );
    }

    #[test]
    fn zero_constructors_correct_size() {
        let pk_512 = MlKem512::zero_public_key();
        let pk_768 = MlKem768::zero_public_key();
        let pk_1024 = MlKem1024::zero_public_key();
        assert_eq!(pk_512.len(), 800);
        assert_eq!(pk_768.len(), 1184);
        assert_eq!(pk_1024.len(), 1568);
        assert!(pk_768.iter().all(|&b| b == 0));
    }

    /// Demonstrates the intended generic-algorithm pattern: a function
    /// generic over `P: MlKemParams` accessing both compile-time
    /// constants and the associated buffer type.
    fn pk_size_string<P: MlKemParams>() -> (usize, &'static str) {
        (P::PUBLIC_KEY_BYTES, P::ALGORITHM_ID)
    }

    #[test]
    fn generic_function_dispatches_correctly() {
        assert_eq!(pk_size_string::<MlKem512>(), (800, "ML-KEM-512"));
        assert_eq!(pk_size_string::<MlKem768>(), (1184, "ML-KEM-768"));
        assert_eq!(
            pk_size_string::<MlKem1024>(),
            (1568, "ML-KEM-1024")
        );
    }
}
