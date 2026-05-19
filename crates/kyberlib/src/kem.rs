// Copyright © 2024 kyberlib. All rights reserved.
// SPDX-License-Identifier: Apache-2.0 OR MIT

use crate::{
    error::KyberLibError, indcpa::*, params::*, rng::randombytes,
    symmetric::*, verify::*,
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
    const PK_START: usize =
        KYBER_SECRET_KEY_BYTES - (2 * KYBER_SYM_BYTES);
    const SK_START: usize = KYBER_SECRET_KEY_BYTES - KYBER_SYM_BYTES;
    const END: usize =
        KYBER_INDCPA_PUBLIC_KEY_BYTES + KYBER_INDCPA_SECRET_KEY_BYTES;

    indcpa_keypair(pk, sk, _seed, _rng)?;

    sk[KYBER_INDCPA_SECRET_KEY_BYTES..END]
        .copy_from_slice(&pk[..KYBER_INDCPA_PUBLIC_KEY_BYTES]);
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

    // FIPS 203 §6.2 — `m` flows directly into `G(m || H(ek))`.
    // Kyber Round 3 first hashed `m' = H(m)` and then used `m'` in
    // place of `m`. NIST removed that step in the final standard.
    buf[..KYBER_SYM_BYTES].copy_from_slice(&randbuf[..KYBER_SYM_BYTES]);

    // Multitarget countermeasure for coins + contributory KEM
    hash_h(&mut buf[KYBER_SYM_BYTES..], pk, KYBER_PUBLIC_KEY_BYTES);
    hash_g(&mut kr, &buf, 2 * KYBER_SYM_BYTES);

    // Coins are in kr[KYBER_SYM_BYTES..]
    indcpa_enc(ct, &buf, pk, &kr[KYBER_SYM_BYTES..]);

    // FIPS 203 §6.2 — the shared secret `K` is the first half of `G`'s
    // output directly. Kyber Round 3 ran a final KDF over `K_bar || H(c)`;
    // that step was removed in the final standard.
    ss[..KYBER_SHARED_SECRET_BYTES]
        .copy_from_slice(&kr[..KYBER_SHARED_SECRET_BYTES]);

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
    let mut pk = [0u8; KYBER_INDCPA_PUBLIC_KEY_BYTES];

    pk.copy_from_slice(
        &sk[KYBER_INDCPA_SECRET_KEY_BYTES..]
            [..KYBER_INDCPA_PUBLIC_KEY_BYTES],
    );

    indcpa_dec(&mut buf, ct, sk);

    // Multitarget countermeasure for coins + contributory KEM
    const START: usize = KYBER_SECRET_KEY_BYTES - 2 * KYBER_SYM_BYTES;
    const END: usize = KYBER_SECRET_KEY_BYTES - KYBER_SYM_BYTES;
    buf[KYBER_SYM_BYTES..].copy_from_slice(&sk[START..END]);
    hash_g(&mut kr, &buf, 2 * KYBER_SYM_BYTES);

    // Coins are in kr[KYBER_SYM_BYTES..]
    indcpa_enc(&mut cmp, &buf, &pk, &kr[KYBER_SYM_BYTES..]);
    let fail = verify(ct, &cmp, KYBER_CIPHERTEXT_BYTES);

    // FIPS 203 §6.3 — implicit rejection.
    //   Success path: K = K' = kr[..32] (from `G(m' || h)`).
    //   Failure path: K = J(z || c) = SHAKE256(z || c, 32).
    // Kyber Round 3 used `KDF(K_bar || H(c))` on success and
    // `KDF(z || H(c))` on failure. The final standard replaced the
    // post-KDF entirely and switched the rejection input from
    // `z || H(c)` to `z || c`.
    let mut k_reject_input =
        [0u8; KYBER_SYM_BYTES + KYBER_CIPHERTEXT_BYTES];
    k_reject_input[..KYBER_SYM_BYTES].copy_from_slice(&sk[END..]);
    // `ct` may be a slice into a longer buffer (kex.rs concatenates
    // additional payload after the KEM ciphertext); only the first
    // `KYBER_CIPHERTEXT_BYTES` are the ciphertext proper.
    k_reject_input[KYBER_SYM_BYTES..]
        .copy_from_slice(&ct[..KYBER_CIPHERTEXT_BYTES]);
    let mut k_reject = [0u8; KYBER_SHARED_SECRET_BYTES];
    kdf(
        &mut k_reject,
        &k_reject_input,
        KYBER_SYM_BYTES + KYBER_CIPHERTEXT_BYTES,
    );

    ss[..KYBER_SHARED_SECRET_BYTES]
        .copy_from_slice(&kr[..KYBER_SHARED_SECRET_BYTES]);
    cmov(ss, &k_reject, KYBER_SHARED_SECRET_BYTES, fail);
}
