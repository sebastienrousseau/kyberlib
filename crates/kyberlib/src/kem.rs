// Copyright © 2024 kyberlib. All rights reserved.
// SPDX-License-Identifier: Apache-2.0 OR MIT

use crate::input_check::coefficients_reduced;
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
    if !coefficients_reduced(&pk[..KYBER_POLYVEC_BYTES]) {
        return Err(KyberLibError::InvalidKey);
    }
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

// =============================================================================
// Generic ports over MlKemParams (#130b — KEM layer with FO transform)
// =============================================================================

use crate::indcpa::{
    indcpa_dec_generic, indcpa_enc_generic, indcpa_keypair_generic,
};
use crate::poly::poly_compressed_len;
use crate::polyvec::polyvec_compressed_len;

/// Public encapsulation-key byte length: `polyvec_bytes_len + 32`.
#[allow(dead_code)]
pub(crate) const fn ek_bytes<P: crate::paramsets::MlKemParams>() -> usize
{
    P::K * KYBER_POLY_BYTES + KYBER_SYM_BYTES
}

/// Ciphertext byte length: `polyvec_compressed_len + poly_compressed_len`.
#[allow(dead_code)]
pub(crate) const fn ct_bytes<P: crate::paramsets::MlKemParams>() -> usize
{
    polyvec_compressed_len::<P>() + poly_compressed_len::<P>()
}

/// Secret decapsulation-key byte length:
///   indcpa_sk (polyvec_bytes) ‖ ek (polyvec_bytes + 32) ‖ H(ek) (32) ‖ z (32)
/// = 2*polyvec_bytes + 96
#[allow(dead_code)]
pub(crate) const fn dk_bytes<P: crate::paramsets::MlKemParams>() -> usize
{
    2 * P::K * KYBER_POLY_BYTES + 96
}

/// Generic port of [`generate_key_pair`].
#[allow(dead_code)]
pub(crate) fn kem_keypair_generic<P, R>(
    pk: &mut [u8],
    sk: &mut [u8],
    rng: &mut R,
    seed: Option<(&[u8], &[u8])>,
) -> Result<(), KyberLibError>
where
    P: crate::paramsets::MlKemParams,
    R: RngCore + CryptoRng,
{
    let indcpa_pk_bytes = ek_bytes::<P>();
    let indcpa_sk_bytes = P::K * KYBER_POLY_BYTES;
    let pk_start = dk_bytes::<P>() - 2 * KYBER_SYM_BYTES;
    let sk_start = dk_bytes::<P>() - KYBER_SYM_BYTES;
    let pk_end = indcpa_sk_bytes + indcpa_pk_bytes;

    indcpa_keypair_generic::<P, R>(pk, sk, seed, rng)?;

    sk[indcpa_sk_bytes..pk_end].copy_from_slice(&pk[..indcpa_pk_bytes]);
    hash_h(&mut sk[pk_start..sk_start], pk, indcpa_pk_bytes);

    if let Some(s) = seed {
        sk[sk_start..].copy_from_slice(s.1);
    } else {
        randombytes(&mut sk[sk_start..], KYBER_SYM_BYTES, rng)?;
    }

    Ok(())
}

/// Generic port of [`encrypt_message`].
#[allow(dead_code)]
pub(crate) fn kem_enc_generic<P, R>(
    ct: &mut [u8],
    ss: &mut [u8],
    pk: &[u8],
    rng: &mut R,
    seed: Option<&[u8]>,
) -> Result<(), KyberLibError>
where
    P: crate::paramsets::MlKemParams,
    R: RngCore + CryptoRng,
{
    if !coefficients_reduced(
        &pk[..crate::polyvec::polyvec_bytes_len::<P>()],
    ) {
        return Err(KyberLibError::InvalidKey);
    }
    let mut kr = [0u8; 2 * KYBER_SYM_BYTES];
    let mut buf = [0u8; 2 * KYBER_SYM_BYTES];
    let mut randbuf = [0u8; 2 * KYBER_SYM_BYTES];

    if let Some(s) = seed {
        randbuf[..KYBER_SYM_BYTES].copy_from_slice(s);
    } else {
        randombytes(&mut randbuf, KYBER_SYM_BYTES, rng)?;
    }

    buf[..KYBER_SYM_BYTES].copy_from_slice(&randbuf[..KYBER_SYM_BYTES]);
    hash_h(&mut buf[KYBER_SYM_BYTES..], pk, ek_bytes::<P>());
    hash_g(&mut kr, &buf, 2 * KYBER_SYM_BYTES);

    indcpa_enc_generic::<P>(ct, &buf, pk, &kr[KYBER_SYM_BYTES..]);

    ss[..KYBER_SHARED_SECRET_BYTES]
        .copy_from_slice(&kr[..KYBER_SHARED_SECRET_BYTES]);
    Ok(())
}

/// Generic port of [`decrypt_message`]. Implements FIPS 203 §6.3
/// implicit rejection — never panics, never branches on validity.
#[allow(dead_code)]
pub(crate) fn kem_dec_generic<P: crate::paramsets::MlKemParams>(
    ss: &mut [u8],
    ct: &[u8],
    sk: &[u8],
) {
    debug_assert!(P::K <= 4);

    let mut buf = [0u8; 2 * KYBER_SYM_BYTES];
    let mut kr = [0u8; 2 * KYBER_SYM_BYTES];
    // MAX_K-sized comparison buffer (~1.5 KB worst-case for ML-KEM-1024).
    let mut cmp = [0u8; 32 * (4 * 11 + 5)]; // = 1568 (kyber1024 max)

    let indcpa_pk_bytes = ek_bytes::<P>();
    let indcpa_sk_bytes = P::K * KYBER_POLY_BYTES;
    let dk_len = dk_bytes::<P>();
    let ct_len = ct_bytes::<P>();

    let mut pk = [0u8; 1568]; // MAX ek bytes (kyber1024)
    pk[..indcpa_pk_bytes].copy_from_slice(
        &sk[indcpa_sk_bytes..indcpa_sk_bytes + indcpa_pk_bytes],
    );

    indcpa_dec_generic::<P>(&mut buf, ct, sk);

    let h_start = dk_len - 2 * KYBER_SYM_BYTES;
    let h_end = dk_len - KYBER_SYM_BYTES;
    buf[KYBER_SYM_BYTES..].copy_from_slice(&sk[h_start..h_end]);
    hash_g(&mut kr, &buf, 2 * KYBER_SYM_BYTES);

    indcpa_enc_generic::<P>(
        &mut cmp[..ct_len],
        &buf,
        &pk[..indcpa_pk_bytes],
        &kr[KYBER_SYM_BYTES..],
    );
    let fail = verify(&ct[..ct_len], &cmp[..ct_len], ct_len);

    // Implicit rejection: K_reject = SHAKE256(z ‖ c, 32).
    let mut k_reject_input = [0u8; KYBER_SYM_BYTES + 1568]; // max ct
    k_reject_input[..KYBER_SYM_BYTES].copy_from_slice(&sk[h_end..]);
    k_reject_input[KYBER_SYM_BYTES..KYBER_SYM_BYTES + ct_len]
        .copy_from_slice(&ct[..ct_len]);
    let mut k_reject = [0u8; KYBER_SHARED_SECRET_BYTES];
    kdf(
        &mut k_reject,
        &k_reject_input[..KYBER_SYM_BYTES + ct_len],
        KYBER_SYM_BYTES + ct_len,
    );

    ss[..KYBER_SHARED_SECRET_BYTES]
        .copy_from_slice(&kr[..KYBER_SHARED_SECRET_BYTES]);
    cmov(ss, &k_reject, KYBER_SHARED_SECRET_BYTES, fail);
}

#[cfg(test)]
#[path = "kem_tests.rs"]
mod tests;
