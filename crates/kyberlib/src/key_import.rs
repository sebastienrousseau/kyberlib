// Copyright © 2026 kyberlib. All rights reserved.
// SPDX-License-Identifier: Apache-2.0 OR MIT

//! Importing typed keys from bytes with the FIPS 203 input checks, so a
//! decoder (for example `kyberlib-pkcs8`) rejects a bad key at import
//! rather than at first use: `validate()` on encapsulation keys (§7.2)
//! and `MlKem768DecapKey::try_from_slice` (§7.3; ML-KEM-512 and -1024
//! define theirs in `ml_kem.rs`).

use crate::error::KyberLibError;
use crate::input_check::{coefficients_reduced, dk_hash_check};
use crate::ml_kem::{
    MlKem1024EncapKey, MlKem512EncapKey, MlKem768, MlKem768DecapKey,
    MlKem768EncapKey,
};
use crate::params::KYBER_SECRET_KEY_BYTES;

/// Length of the public seed `rho` that ends every encapsulation key.
const RHO_BYTES: usize = 32;

macro_rules! impl_validate {
    ($($ek:ty),*) => {$(
        impl $ek {
            /// Runs the FIPS 203 §7.2 encapsulation-key check: every
            /// encoded 12-bit coefficient must be below q = 3329. The
            /// length (type) check is enforced by the type itself.
            ///
            /// [`Self::encapsulate`] runs the same check; call this to
            /// reject a key when it is imported.
            ///
            /// # Errors
            ///
            /// [`KyberLibError::InvalidKey`] if a coefficient is not
            /// reduced modulo q.
            pub fn validate(&self) -> Result<(), KyberLibError> {
                let bytes = self.as_bytes();
                if coefficients_reduced(&bytes[..bytes.len() - RHO_BYTES]) {
                    Ok(())
                } else {
                    Err(KyberLibError::InvalidKey)
                }
            }
        }
    )*};
}

impl_validate!(MlKem512EncapKey, MlKem768EncapKey, MlKem1024EncapKey);

impl MlKem768DecapKey {
    /// Construct from a borrowed slice, validating the length and the
    /// FIPS 203 §7.3 hash check (the stored `H(ek)` must match the
    /// embedded encapsulation key).
    ///
    /// # Errors
    ///
    /// [`KyberLibError::InvalidLength`] on length mismatch;
    /// [`KyberLibError::InvalidKey`] if the hash check fails.
    pub fn try_from_slice(bytes: &[u8]) -> Result<Self, KyberLibError> {
        let buf: [u8; KYBER_SECRET_KEY_BYTES] = bytes
            .try_into()
            .map_err(|_| KyberLibError::InvalidLength)?;
        if !dk_hash_check::<MlKem768>(&buf) {
            return Err(KyberLibError::InvalidKey);
        }
        Ok(Self(buf))
    }
}
