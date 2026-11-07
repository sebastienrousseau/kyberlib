// Copyright © 2026 kyberlib. All rights reserved.
// SPDX-License-Identifier: Apache-2.0 OR MIT

//! Backend plumbing for the typed ML-KEM API (`ml_kem.rs`): the seeded
//! key-generation path and the dispatch that lets the `fips` feature
//! (issue #170) route calls into the AWS-LC FIPS module.

use crate::error::KyberLibError;
use crate::ml_kem::SharedSecret;
use crate::params::KYBER_SHARED_SECRET_BYTES;
use rand_core::{CryptoRng, RngCore};

/// RNG handed to the seeded key-generation path, which never draws
/// from it. `try_fill_bytes` fails, so if a future change made that
/// path draw randomness it would return an error, not weak keys.
#[derive(Clone, Copy, Debug)]
struct SeededOnly;

/// `rand_core` error code for [`SeededOnly`]: the first custom code.
const SEEDED_ONLY_CODE: core::num::NonZeroU32 =
    match core::num::NonZeroU32::new(rand_core::Error::CUSTOM_START) {
        Some(code) => code,
        None => core::num::NonZeroU32::MIN,
    };

impl CryptoRng for SeededOnly {}

impl RngCore for SeededOnly {
    fn next_u32(&mut self) -> u32 {
        0
    }
    fn next_u64(&mut self) -> u64 {
        0
    }
    fn fill_bytes(&mut self, _dest: &mut [u8]) {}
    fn try_fill_bytes(
        &mut self,
        _dest: &mut [u8],
    ) -> Result<(), rand_core::Error> {
        Err(SEEDED_ONLY_CODE.into())
    }
}

/// Shared body of every [`KemCore::generate_from_seed`] impl.
pub(crate) fn keypair_from_seed<
    P: crate::paramsets::MlKemParams,
    const PK: usize,
    const SK: usize,
>(
    d: &[u8; 32],
    z: &[u8; 32],
) -> Result<([u8; SK], [u8; PK]), KyberLibError> {
    let mut pk = [0u8; PK];
    let mut sk = [0u8; SK];
    crate::kem::kem_keypair_generic::<P, SeededOnly>(
        &mut pk,
        &mut sk,
        &mut SeededOnly,
        Some((&d[..], &z[..])),
    )?;
    Ok((sk, pk))
}

// ------------------------------------------------------------ backend dispatch
//
// The typed API funnels through these three helpers so the `fips`
// feature (issue #170) can route it into the AWS-LC FIPS module. See
// `crate::fips` for what stays outside the module boundary.

/// Key generation for parameter set `P`: `(dk, ek)`.
pub(crate) fn backend_keygen<P, R, const SK: usize, const PK: usize>(
    rng: &mut R,
) -> Result<([u8; SK], [u8; PK]), KyberLibError>
where
    P: crate::paramsets::MlKemParams,
    R: RngCore + CryptoRng,
{
    #[cfg(feature = "fips")]
    {
        let _ = rng;
        crate::fips::generate::<SK, PK>(crate::fips::algorithm(P::K))
    }
    #[cfg(not(feature = "fips"))]
    {
        let mut pk = [0u8; PK];
        let mut sk = [0u8; SK];
        crate::kem::kem_keypair_generic::<P, R>(
            &mut pk, &mut sk, rng, None,
        )?;
        Ok((sk, pk))
    }
}

/// Encapsulation for parameter set `P`: `(ct, ss)`.
pub(crate) fn backend_encapsulate<P, R, const CT: usize>(
    ek: &[u8],
    rng: &mut R,
) -> Result<([u8; CT], [u8; KYBER_SHARED_SECRET_BYTES]), KyberLibError>
where
    P: crate::paramsets::MlKemParams,
    R: RngCore + CryptoRng,
{
    #[cfg(feature = "fips")]
    {
        let _ = rng;
        crate::fips::encapsulate::<CT>(crate::fips::algorithm(P::K), ek)
    }
    #[cfg(not(feature = "fips"))]
    {
        let mut ct = [0u8; CT];
        let mut ss = [0u8; KYBER_SHARED_SECRET_BYTES];
        crate::kem::kem_enc_generic::<P, R>(
            &mut ct, &mut ss, ek, rng, None,
        )?;
        Ok((ct, ss))
    }
}

/// Decapsulation for parameter set `P` (implicit rejection, infallible).
pub(crate) fn backend_decapsulate<P: crate::paramsets::MlKemParams>(
    dk: &[u8],
    ct: &[u8],
) -> SharedSecret {
    #[cfg(feature = "fips")]
    if let Some(ss) =
        crate::fips::decapsulate(crate::fips::algorithm(P::K), dk, ct)
    {
        return SharedSecret::from_backend(ss);
    }
    let mut ss = [0u8; KYBER_SHARED_SECRET_BYTES];
    crate::kem::kem_dec_generic::<P>(&mut ss, ct, dk);
    SharedSecret::from_backend(ss)
}
