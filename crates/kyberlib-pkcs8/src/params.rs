// Copyright © 2026 kyberlib. All rights reserved.
// SPDX-License-Identifier: Apache-2.0 OR MIT

//! Per-parameter-set constants and key conversions.

use kyberlib::{
    KemCore, KyberLibError, MlKem1024, MlKem1024DecapKey,
    MlKem1024EncapKey, MlKem512, MlKem512DecapKey, MlKem512EncapKey,
    MlKem768, MlKem768DecapKey, MlKem768EncapKey,
};
use spki::ObjectIdentifier;

mod sealed {
    pub trait Sealed {}
}

/// An ML-KEM parameter set that has an RFC 9935 encoding:
/// [`MlKem512`], [`MlKem768`] or [`MlKem1024`]. Sealed.
pub trait Params: KemCore + sealed::Sealed {
    /// Algorithm identifier, `2.16.840.1.101.3.4.4.{1,2,3}`.
    const OBJECT_ID: ObjectIdentifier;
    /// Encapsulation-key length in bytes.
    const EK_LEN: usize;
    /// Expanded decapsulation-key length in bytes.
    const DK_LEN: usize;

    /// Encapsulation key from bytes, with the FIPS 203 §7.2 check.
    #[doc(hidden)]
    fn ek_from_slice(
        bytes: &[u8],
    ) -> Result<Self::EncapsulationKey, KyberLibError>;
    /// Raw encapsulation-key bytes.
    #[doc(hidden)]
    fn ek_bytes(ek: &Self::EncapsulationKey) -> &[u8];
    /// Decapsulation key from bytes, with the FIPS 203 §7.3 check.
    #[doc(hidden)]
    fn dk_from_slice(
        bytes: &[u8],
    ) -> Result<Self::DecapsulationKey, KyberLibError>;
    /// Raw expanded decapsulation-key bytes.
    #[doc(hidden)]
    fn dk_bytes(dk: &Self::DecapsulationKey) -> &[u8];
}

macro_rules! params {
    ($p:ty, $ek:ty, $dk:ty, $oid:literal, $ek_len:literal, $dk_len:literal) => {
        impl sealed::Sealed for $p {}
        impl Params for $p {
            const OBJECT_ID: ObjectIdentifier =
                ObjectIdentifier::new_unwrap($oid);
            const EK_LEN: usize = $ek_len;
            const DK_LEN: usize = $dk_len;

            fn ek_from_slice(
                bytes: &[u8],
            ) -> Result<$ek, KyberLibError> {
                let ek = <$ek>::try_from_slice(bytes)?;
                ek.validate()?;
                Ok(ek)
            }
            fn ek_bytes(ek: &$ek) -> &[u8] {
                ek.as_bytes()
            }
            fn dk_from_slice(
                bytes: &[u8],
            ) -> Result<$dk, KyberLibError> {
                <$dk>::try_from_slice(bytes)
            }
            fn dk_bytes(dk: &$dk) -> &[u8] {
                dk.as_bytes()
            }
        }
    };
}

params!(
    MlKem512,
    MlKem512EncapKey,
    MlKem512DecapKey,
    "2.16.840.1.101.3.4.4.1",
    800,
    1632
);
params!(
    MlKem768,
    MlKem768EncapKey,
    MlKem768DecapKey,
    "2.16.840.1.101.3.4.4.2",
    1184,
    2400
);
params!(
    MlKem1024,
    MlKem1024EncapKey,
    MlKem1024DecapKey,
    "2.16.840.1.101.3.4.4.3",
    1568,
    3168
);

/// The encapsulation key embedded in an expanded decapsulation key:
/// `dk = dk_PKE ‖ ek ‖ H(ek) ‖ z`, with `H(ek)` and `z` 32 bytes each.
pub(crate) fn embedded_ek<P: Params>(dk: &[u8]) -> &[u8] {
    let end = P::DK_LEN - 64;
    &dk[end - P::EK_LEN..end]
}

/// Equality without an early exit, for comparing secret encodings.
pub(crate) fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    a.len() == b.len()
        && a.iter().zip(b).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}

#[cfg(test)]
mod tests {
    use super::*;

    fn oid_of<P: Params>() -> ObjectIdentifier {
        ObjectIdentifier::new(<P as KemCore>::OID).unwrap()
    }

    #[test]
    fn oids_match_the_core_crate() {
        assert_eq!(MlKem512::OBJECT_ID, oid_of::<MlKem512>());
        assert_eq!(MlKem768::OBJECT_ID, oid_of::<MlKem768>());
        assert_eq!(MlKem1024::OBJECT_ID, oid_of::<MlKem1024>());
    }

    #[test]
    fn ct_eq_compares_whole_slices() {
        assert!(ct_eq(b"abc", b"abc"));
        assert!(!ct_eq(b"abc", b"abd"));
        assert!(!ct_eq(b"abc", b"ab"));
    }
}
