// Copyright © 2026 kyberlib. All rights reserved.
// SPDX-License-Identifier: Apache-2.0 OR MIT

//! FIPS 140-3 backend (issue #170).
//!
//! With the `fips` feature, the typed ML-KEM API
//! ([`crate::KemCore::generate`] and each
//! parameter set's `encapsulate` and `decapsulate`) runs inside the
//! AWS-LC FIPS module through `aws-lc-rs`, instead of kyberlib's
//! pure-Rust code. Keys and ciphertexts keep the FIPS 203 byte
//! layouts, so they move freely between the two backends.
//!
//! What stays outside the module, and why:
//! - The caller's RNG is ignored on this path: an approved module must
//!   draw from its own DRBG.
//! - [`crate::KemCore::generate_from_seed`],
//!   the legacy [`crate::api`] functions, the [`crate::kex`]
//!   exchanges and the `hazmat` IND-CPA primitives always use the
//!   pure-Rust code; AWS-LC exposes no seeded key generation.
//! - A decapsulation key the module rejects as malformed (possible only
//!   through the unchecked `from_bytes` constructors) is decapsulated
//!   by the pure-Rust code, which applies FIPS 203 implicit rejection.
//!
//! Whether this build is covered by a CMVP certificate depends on the
//! AWS-LC FIPS module version and on running inside its tested
//! operational environment; check [`crate::fips::fips_mode`] at start-up and
//! read `docs/FIPS.md`.

use crate::error::KyberLibError;
use aws_lc_rs::kem::{
    Algorithm, AlgorithmId, Ciphertext, DecapsulationKey,
    EncapsulationKey,
};

/// Name of the backend that serves the typed ML-KEM API in this build.
pub const BACKEND: &str = "aws-lc-rs (AWS-LC FIPS module)";

/// Returns `Ok(())` when the AWS-LC module is running in FIPS mode
/// (its power-on self tests passed and the build is the FIPS build).
///
/// # Errors
///
/// [`KyberLibError::FipsModeUnavailable`] when the module is not in
/// FIPS mode.
pub fn fips_mode() -> Result<(), KyberLibError> {
    aws_lc_rs::try_fips_mode()
        .map_err(|_| KyberLibError::FipsModeUnavailable)
}

/// The AWS-LC algorithm for a parameter set, by ML-KEM rank `k`.
pub(crate) fn algorithm(k: usize) -> &'static Algorithm<AlgorithmId> {
    match k {
        2 => &aws_lc_rs::kem::ML_KEM_512,
        3 => &aws_lc_rs::kem::ML_KEM_768,
        _ => &aws_lc_rs::kem::ML_KEM_1024,
    }
}

/// Key generation inside the module. Returns `(dk, ek)` as FIPS 203
/// byte strings.
pub(crate) fn generate<const SK: usize, const PK: usize>(
    alg: &'static Algorithm<AlgorithmId>,
) -> Result<([u8; SK], [u8; PK]), KyberLibError> {
    let dk = DecapsulationKey::generate(alg)
        .map_err(|_| KyberLibError::RandomBytesGeneration)?;
    let ek = dk
        .encapsulation_key()
        .map_err(|_| KyberLibError::InvalidKey)?;
    let dk_bytes =
        dk.key_bytes().map_err(|_| KyberLibError::InvalidKey)?;
    let ek_bytes =
        ek.key_bytes().map_err(|_| KyberLibError::InvalidKey)?;
    let sk: [u8; SK] = dk_bytes
        .as_ref()
        .try_into()
        .map_err(|_| KyberLibError::InvalidLength)?;
    let pk: [u8; PK] = ek_bytes
        .as_ref()
        .try_into()
        .map_err(|_| KyberLibError::InvalidLength)?;
    Ok((sk, pk))
}

/// Encapsulation inside the module. The module performs the FIPS 203
/// §7.2 key check itself and rejects with an error.
pub(crate) fn encapsulate<const CT: usize>(
    alg: &'static Algorithm<AlgorithmId>,
    ek: &[u8],
) -> Result<([u8; CT], [u8; 32]), KyberLibError> {
    let key = EncapsulationKey::new(alg, ek)
        .map_err(|_| KyberLibError::InvalidKey)?;
    let (ct, ss) =
        key.encapsulate().map_err(|_| KyberLibError::InvalidKey)?;
    let ct: [u8; CT] = ct
        .as_ref()
        .try_into()
        .map_err(|_| KyberLibError::InvalidLength)?;
    let ss: [u8; 32] = ss
        .as_ref()
        .try_into()
        .map_err(|_| KyberLibError::InvalidLength)?;
    Ok((ct, ss))
}

/// Decapsulation inside the module. `None` if the module rejects the
/// decapsulation key; the caller then falls back (see module docs).
pub(crate) fn decapsulate(
    alg: &'static Algorithm<AlgorithmId>,
    dk: &[u8],
    ct: &[u8],
) -> Option<[u8; 32]> {
    let key = DecapsulationKey::new(alg, dk).ok()?;
    let ss = key.decapsulate(Ciphertext::from(ct)).ok()?;
    ss.as_ref().try_into().ok()
}
