// Copyright © 2026 kyberlib. All rights reserved.
// SPDX-License-Identifier: Apache-2.0 OR MIT

//! `SubjectPublicKeyInfo` for ML-KEM encapsulation keys (RFC 9935 §4).

use crate::params::Params;
use core::fmt;
use spki::{AlgorithmIdentifierRef, SubjectPublicKeyInfoRef};

/// An ML-KEM encapsulation key that encodes to and decodes from
/// `SubjectPublicKeyInfo` (DER, and PEM with the `pem` feature) through
/// [`spki::EncodePublicKey`] and [`spki::DecodePublicKey`].
///
/// Decoding enforces RFC 9935: the algorithm OID must match `P`, the
/// parameters field must be absent, the key must have the exact length,
/// and it must pass the FIPS 203 §7.2 modulus check.
#[non_exhaustive]
pub struct PublicKey<P: Params>(P::EncapsulationKey);

impl<P: Params> PublicKey<P> {
    /// Wraps an encapsulation key.
    pub const fn new(ek: P::EncapsulationKey) -> Self {
        Self(ek)
    }

    /// The encapsulation key.
    pub const fn key(&self) -> &P::EncapsulationKey {
        &self.0
    }

    /// Unwraps the encapsulation key.
    pub fn into_key(self) -> P::EncapsulationKey {
        self.0
    }
}

impl<P: Params> Clone for PublicKey<P>
where
    P::EncapsulationKey: Clone,
{
    fn clone(&self) -> Self {
        Self(self.0.clone())
    }
}

impl<P: Params> PartialEq for PublicKey<P> {
    fn eq(&self, other: &Self) -> bool {
        P::ek_bytes(&self.0) == P::ek_bytes(&other.0)
    }
}

impl<P: Params> Eq for PublicKey<P> {}

impl<P: Params> fmt::Debug for PublicKey<P> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "PublicKey<{}>", P::ALGORITHM_ID)
    }
}

#[cfg(feature = "alloc")]
pub(crate) fn algorithm<'a, P: Params>() -> AlgorithmIdentifierRef<'a> {
    AlgorithmIdentifierRef {
        oid: P::OBJECT_ID,
        parameters: None,
    }
}

/// RFC 9935: the OID names the parameter set and parameters MUST be absent.
pub(crate) fn check_algorithm<P: Params>(
    alg: &AlgorithmIdentifierRef<'_>,
) -> spki::Result<()> {
    alg.assert_algorithm_oid(P::OBJECT_ID)?;
    if alg.parameters.is_some() {
        return Err(spki::Error::KeyMalformed);
    }
    Ok(())
}

impl<P: Params> TryFrom<SubjectPublicKeyInfoRef<'_>> for PublicKey<P> {
    type Error = spki::Error;

    fn try_from(
        spki: SubjectPublicKeyInfoRef<'_>,
    ) -> spki::Result<Self> {
        check_algorithm::<P>(&spki.algorithm)?;
        let bytes = spki
            .subject_public_key
            .as_bytes()
            .ok_or(spki::Error::KeyMalformed)?;
        P::ek_from_slice(bytes)
            .map(Self)
            .map_err(|_| spki::Error::KeyMalformed)
    }
}

#[cfg(feature = "alloc")]
impl<P: Params> spki::EncodePublicKey for PublicKey<P> {
    fn to_public_key_der(&self) -> spki::Result<der::Document> {
        let spki = SubjectPublicKeyInfoRef {
            algorithm: algorithm::<P>(),
            subject_public_key: der::asn1::BitStringRef::from_bytes(
                P::ek_bytes(&self.0),
            )?,
        };
        Ok(der::Document::encode_msg(&spki)?)
    }
}
