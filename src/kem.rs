// Copyright © 2024 kyberlib. All rights reserved.
// SPDX-License-Identifier: Apache-2.0 OR MIT

use crate::{
    error::KyberLibError, indcpa::*, params::*, rng::randombytes, symmetric::*, verify::*,
};
use rand_core::{CryptoRng, RngCore};

/// Generates a public and private key pair for CCA-secure Kyber key encapsulation mechanism.
///
/// # Arguments
///
/// * `pk` - Output public key (an already allocated array of CRYPTO_PUBLICKEYBYTES bytes).
/// * `sk` - Output private key (an already allocated array of CRYPTO_SECRETKEYBYTES bytes).
/// * `_rng` - Random number generator implementing RngCore + CryptoRng.
/// * `_seed` - Optional seed for key generation.
///
/// # Errors
///
/// Returns a `KyberLibError` on failure.
pub fn generate_key_pair<R>(
    pk: &mut [u8],
    sk: &mut [u8],
    _rng: &mut R,
    _seed: Option<(&[u8], &[u8])>,
) -> Result<(), KyberLibError>
where
    R: RngCore + CryptoRng,
{
    const PK_START: usize = KYBER_SECRET_KEY_BYTES - (2 * KYBER_SYM_BYTES);
    const SK_START: usize = KYBER_SECRET_KEY_BYTES - KYBER_SYM_BYTES;
    const END: usize = KYBER_INDCPA_PUBLICKEYBYTES + KYBER_INDCPA_SECRETKEYBYTES;

    indcpa_keypair(pk, sk, _seed, _rng)?;

    sk[KYBER_INDCPA_SECRETKEYBYTES..END].copy_from_slice(&pk[..KYBER_INDCPA_PUBLICKEYBYTES]);
    hash_h(&mut sk[PK_START..], pk, KYBER_PUBLIC_KEY_BYTES);

    if let Some(s) = _seed {
        sk[SK_START..].copy_from_slice(s.1);
    } else {
        randombytes(&mut sk[SK_START..], KYBER_SYM_BYTES, _rng)?;
    }

    Ok(())
}

/// Generates cipher text and a shared secret for a given public key.
///
/// # Arguments
///
/// * `ct` - Output cipher text (an already allocated array of CRYPTO_CIPHERTEXTBYTES bytes).
/// * `ss` - Output shared secret (an already allocated array of CRYPTO_BYTES bytes).
/// * `pk` - Input public key (an already allocated array of CRYPTO_PUBLICKEYBYTES bytes).
/// * `_rng` - Random number generator implementing RngCore + CryptoRng.
/// * `_seed` - Optional seed for random number generation.
///
/// # Errors
///
/// Returns a `KyberLibError` on failure.
pub fn encrypt_message<R>(
    ct: &mut [u8],
    ss: &mut [u8],
    pk: &[u8],
    _rng: &mut R,
    _seed: Option<&[u8]>,
) -> Result<(), KyberLibError>
where
    R: RngCore + CryptoRng,
{
    let mut kr = [0u8; 2 * KYBER_SYM_BYTES];
    let mut buf = [0u8; 2 * KYBER_SYM_BYTES];
    let mut randbuf = [0u8; 2 * KYBER_SYM_BYTES];

    // Deterministic randbuf for Known Answer Tests (KATs)
    if let Some(s) = _seed {
        randbuf[..KYBER_SYM_BYTES].copy_from_slice(s);
    } else {
        randombytes(&mut randbuf, KYBER_SYM_BYTES, _rng)?;
    }

    // Don't release system RNG output
    hash_h(&mut buf, &randbuf, KYBER_SYM_BYTES);

    // Multitarget countermeasure for coins + contributory KEM
    hash_h(&mut buf[KYBER_SYM_BYTES..], pk, KYBER_PUBLIC_KEY_BYTES);
    hash_g(&mut kr, &buf, 2 * KYBER_SYM_BYTES);

    // Coins are in kr[KYBER_SYM_BYTES..]
    indcpa_enc(ct, &buf, pk, &kr[KYBER_SYM_BYTES..]);

    // Overwrite coins in kr with H(c)
    hash_h(&mut kr[KYBER_SYM_BYTES..], ct, KYBER_CIPHERTEXT_BYTES);

    // Hash concatenation of pre-k and H(c) to derive the shared secret
    kdf(ss, &kr, 2 * KYBER_SYM_BYTES);

    Ok(())
}

/// Generates a shared secret for a given cipher text and private key.
///
/// # Arguments
///
/// * `ss` - Output shared secret (an already allocated array of CRYPTO_BYTES bytes).
/// * `ct` - Input cipher text (an already allocated array of CRYPTO_CIPHERTEXTBYTES bytes).
/// * `sk` - Input private key (an already allocated array of CRYPTO_SECRETKEYBYTES bytes).
///
/// On failure, `ss` will contain a pseudo-random value.
pub fn decrypt_message(ss: &mut [u8], ct: &[u8], sk: &[u8]) {
    let mut buf = [0u8; 2 * KYBER_SYM_BYTES];
    let mut kr = [0u8; 2 * KYBER_SYM_BYTES];
    let mut cmp = [0u8; KYBER_CIPHERTEXT_BYTES];
    let mut pk = [0u8; KYBER_INDCPA_PUBLICKEYBYTES];

    pk.copy_from_slice(&sk[KYBER_INDCPA_SECRETKEYBYTES..][..KYBER_INDCPA_PUBLICKEYBYTES]);

    indcpa_dec(&mut buf, ct, sk);

    // Multitarget countermeasure for coins + contributory KEM
    const START: usize = KYBER_SECRET_KEY_BYTES - 2 * KYBER_SYM_BYTES;
    const END: usize = KYBER_SECRET_KEY_BYTES - KYBER_SYM_BYTES;
    buf[KYBER_SYM_BYTES..].copy_from_slice(&sk[START..END]);
    hash_g(&mut kr, &buf, 2 * KYBER_SYM_BYTES);

    // Coins are in kr[KYBER_SYM_BYTES..]
    indcpa_enc(&mut cmp, &buf, &pk, &kr[KYBER_SYM_BYTES..]);
    let fail = verify(ct, &cmp, KYBER_CIPHERTEXT_BYTES);

    // Overwrite coins in kr with H(c)
    hash_h(&mut kr[KYBER_SYM_BYTES..], ct, KYBER_CIPHERTEXT_BYTES);

    // Overwrite pre-k with z on re-encryption failure
    cmov(&mut kr, &sk[END..], KYBER_SYM_BYTES, fail);

    // Hash concatenation of pre-k and H(c) to derive the shared secret
    kdf(ss, &kr, 2 * KYBER_SYM_BYTES);
}
