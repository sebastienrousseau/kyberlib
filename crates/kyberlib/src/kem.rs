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
mod kem_generic_tests {
    #![allow(unused_imports)]
    use super::*;
    use crate::paramsets::MlKemParams;

    #[test]
    #[cfg(feature = "kyber768")]
    fn kem_keypair_generic_matches_existing_kyber768() {
        use crate::MlKem768;
        use rand::rngs::StdRng;
        use rand::SeedableRng;

        let seed = [0x42u8; 64];

        let mut rng = StdRng::from_seed([3u8; 32]);
        let mut pk_e = [0u8; KYBER_PUBLIC_KEY_BYTES];
        let mut sk_e = [0u8; KYBER_SECRET_KEY_BYTES];
        generate_key_pair(
            &mut pk_e,
            &mut sk_e,
            &mut rng,
            Some((&seed[..32], &seed[32..])),
        )
        .unwrap();

        let mut rng2 = StdRng::from_seed([3u8; 32]);
        let mut pk_g = [0u8; KYBER_PUBLIC_KEY_BYTES];
        let mut sk_g = [0u8; KYBER_SECRET_KEY_BYTES];
        kem_keypair_generic::<MlKem768, _>(
            &mut pk_g,
            &mut sk_g,
            &mut rng2,
            Some((&seed[..32], &seed[32..])),
        )
        .unwrap();

        assert_eq!(pk_e.as_slice(), pk_g.as_slice());
        assert_eq!(sk_e.as_slice(), sk_g.as_slice());
    }

    /// **End-to-end full-FIPS-203 round-trip via the all-generic path.**
    #[test]
    #[cfg(feature = "kyber768")]
    fn kem_round_trip_all_generic_kyber768() {
        use crate::MlKem768;
        use rand::rngs::StdRng;
        use rand::SeedableRng;

        let mut rng = StdRng::from_seed([9u8; 32]);
        let seed = [0xCCu8; 64];

        let mut pk = [0u8; KYBER_PUBLIC_KEY_BYTES];
        let mut sk = [0u8; KYBER_SECRET_KEY_BYTES];
        kem_keypair_generic::<MlKem768, _>(
            &mut pk,
            &mut sk,
            &mut rng,
            Some((&seed[..32], &seed[32..])),
        )
        .unwrap();

        let mut ct = [0u8; KYBER_CIPHERTEXT_BYTES];
        let mut ss_a = [0u8; KYBER_SHARED_SECRET_BYTES];
        let encap_seed = [0x44u8; 32];
        kem_enc_generic::<MlKem768, _>(
            &mut ct,
            &mut ss_a,
            &pk,
            &mut rng,
            Some(&encap_seed),
        )
        .unwrap();

        let mut ss_b = [0u8; KYBER_SHARED_SECRET_BYTES];
        kem_dec_generic::<MlKem768>(&mut ss_b, &ct, &sk);

        assert_eq!(
            ss_a, ss_b,
            "all-generic full-FIPS-203 KEM round-trip failed"
        );
    }

    #[test]
    #[cfg(feature = "kyber512")]
    fn kem_keypair_generic_matches_existing_kyber512() {
        use crate::MlKem512;
        use rand::rngs::StdRng;
        use rand::SeedableRng;

        let seed = [0x42u8; 64];
        let mut rng = StdRng::from_seed([3u8; 32]);
        let mut pk_e = [0u8; KYBER_PUBLIC_KEY_BYTES];
        let mut sk_e = [0u8; KYBER_SECRET_KEY_BYTES];
        generate_key_pair(
            &mut pk_e,
            &mut sk_e,
            &mut rng,
            Some((&seed[..32], &seed[32..])),
        )
        .unwrap();

        let mut rng2 = StdRng::from_seed([3u8; 32]);
        let mut pk_g = [0u8; KYBER_PUBLIC_KEY_BYTES];
        let mut sk_g = [0u8; KYBER_SECRET_KEY_BYTES];
        kem_keypair_generic::<MlKem512, _>(
            &mut pk_g,
            &mut sk_g,
            &mut rng2,
            Some((&seed[..32], &seed[32..])),
        )
        .unwrap();

        assert_eq!(pk_e.as_slice(), pk_g.as_slice());
        assert_eq!(sk_e.as_slice(), sk_g.as_slice());
    }

    #[test]
    #[cfg(feature = "kyber1024")]
    fn kem_keypair_generic_matches_existing_kyber1024() {
        use crate::MlKem1024;
        use rand::rngs::StdRng;
        use rand::SeedableRng;

        let seed = [0x42u8; 64];
        let mut rng = StdRng::from_seed([3u8; 32]);
        let mut pk_e = [0u8; KYBER_PUBLIC_KEY_BYTES];
        let mut sk_e = [0u8; KYBER_SECRET_KEY_BYTES];
        generate_key_pair(
            &mut pk_e,
            &mut sk_e,
            &mut rng,
            Some((&seed[..32], &seed[32..])),
        )
        .unwrap();

        let mut rng2 = StdRng::from_seed([3u8; 32]);
        let mut pk_g = [0u8; KYBER_PUBLIC_KEY_BYTES];
        let mut sk_g = [0u8; KYBER_SECRET_KEY_BYTES];
        kem_keypair_generic::<MlKem1024, _>(
            &mut pk_g,
            &mut sk_g,
            &mut rng2,
            Some((&seed[..32], &seed[32..])),
        )
        .unwrap();

        assert_eq!(pk_e.as_slice(), pk_g.as_slice());
        assert_eq!(sk_e.as_slice(), sk_g.as_slice());
    }

    /// Cross-check: the all-generic encap result must match the
    /// existing implementation byte-for-byte under the active feature.
    #[test]
    #[cfg(feature = "kyber768")]
    fn kem_enc_generic_matches_existing_kyber768() {
        use crate::MlKem768;
        use rand::rngs::StdRng;
        use rand::SeedableRng;

        let mut rng = StdRng::from_seed([11u8; 32]);
        let kp_seed = [0xDDu8; 64];
        let mut pk = [0u8; KYBER_PUBLIC_KEY_BYTES];
        let mut sk = [0u8; KYBER_SECRET_KEY_BYTES];
        generate_key_pair(
            &mut pk,
            &mut sk,
            &mut rng,
            Some((&kp_seed[..32], &kp_seed[32..])),
        )
        .unwrap();

        let enc_seed = [0x55u8; 32];

        let mut ct_e = [0u8; KYBER_CIPHERTEXT_BYTES];
        let mut ss_e = [0u8; KYBER_SHARED_SECRET_BYTES];
        encrypt_message(
            &mut ct_e,
            &mut ss_e,
            &pk,
            &mut rng,
            Some(&enc_seed),
        )
        .unwrap();

        let mut ct_g = [0u8; KYBER_CIPHERTEXT_BYTES];
        let mut ss_g = [0u8; KYBER_SHARED_SECRET_BYTES];
        kem_enc_generic::<MlKem768, _>(
            &mut ct_g,
            &mut ss_g,
            &pk,
            &mut rng,
            Some(&enc_seed),
        )
        .unwrap();

        assert_eq!(ct_e.as_slice(), ct_g.as_slice(), "ct diverges");
        assert_eq!(ss_e, ss_g, "shared secret diverges");
    }
}

#[cfg(test)]
mod all_three_in_one_build_kem {
    #![allow(unused_imports)]
    use super::*;
    use crate::paramsets::MlKemParams;
    use crate::{MlKem1024, MlKem512, MlKem768};
    use rand::rngs::StdRng;
    use rand::SeedableRng;

    /// **THE multi-day-refactor headline test**: a SINGLE function
    /// under default features runs the full FIPS 203 KEM pipeline —
    /// keygen, encapsulate, decapsulate — for ML-KEM-512, ML-KEM-768,
    /// AND ML-KEM-1024 in sequence. Each produces differently-sized
    /// outputs per FIPS 203 §6 Table 2. Each round-trip yields a
    /// matching 32-byte shared secret.
    ///
    /// This compiles and passes under default features (kyber768),
    /// proving that the const-generic refactor delivers genuine
    /// multi-parameter-set support at the algorithm level — three
    /// distinct FIPS 203 ML-KEM monomorphizations coexisting in one
    /// binary, each operating on its own concrete byte sizes.
    #[test]
    fn all_three_full_kem_pipelines_in_one_build() {
        // ---- ML-KEM-512: 800 / 1632 / 768 byte sizes ----
        let mut rng = StdRng::from_seed([1u8; 32]);
        let kp_seed_512 = [0x52u8; 64];
        let mut pk_512 =
            [0u8; <MlKem512 as MlKemParams>::PUBLIC_KEY_BYTES];
        let mut sk_512 =
            [0u8; <MlKem512 as MlKemParams>::SECRET_KEY_BYTES];
        kem_keypair_generic::<MlKem512, _>(
            &mut pk_512,
            &mut sk_512,
            &mut rng,
            Some((&kp_seed_512[..32], &kp_seed_512[32..])),
        )
        .unwrap();
        let mut ct_512 =
            [0u8; <MlKem512 as MlKemParams>::CIPHERTEXT_BYTES];
        let mut ss_a_512 =
            [0u8; <MlKem512 as MlKemParams>::SHARED_SECRET_BYTES];
        let enc_seed_512 = [0xA2u8; 32];
        kem_enc_generic::<MlKem512, _>(
            &mut ct_512,
            &mut ss_a_512,
            &pk_512,
            &mut rng,
            Some(&enc_seed_512),
        )
        .unwrap();
        let mut ss_b_512 =
            [0u8; <MlKem512 as MlKemParams>::SHARED_SECRET_BYTES];
        kem_dec_generic::<MlKem512>(&mut ss_b_512, &ct_512, &sk_512);
        assert_eq!(ss_a_512, ss_b_512, "ML-KEM-512 round-trip failed");

        // ---- ML-KEM-768: 1184 / 2400 / 1088 byte sizes ----
        let mut rng = StdRng::from_seed([3u8; 32]);
        let kp_seed_768 = [0x76u8; 64];
        let mut pk_768 =
            [0u8; <MlKem768 as MlKemParams>::PUBLIC_KEY_BYTES];
        let mut sk_768 =
            [0u8; <MlKem768 as MlKemParams>::SECRET_KEY_BYTES];
        kem_keypair_generic::<MlKem768, _>(
            &mut pk_768,
            &mut sk_768,
            &mut rng,
            Some((&kp_seed_768[..32], &kp_seed_768[32..])),
        )
        .unwrap();
        let mut ct_768 =
            [0u8; <MlKem768 as MlKemParams>::CIPHERTEXT_BYTES];
        let mut ss_a_768 = [0u8; 32];
        let enc_seed_768 = [0xB7u8; 32];
        kem_enc_generic::<MlKem768, _>(
            &mut ct_768,
            &mut ss_a_768,
            &pk_768,
            &mut rng,
            Some(&enc_seed_768),
        )
        .unwrap();
        let mut ss_b_768 = [0u8; 32];
        kem_dec_generic::<MlKem768>(&mut ss_b_768, &ct_768, &sk_768);
        assert_eq!(ss_a_768, ss_b_768, "ML-KEM-768 round-trip failed");

        // ---- ML-KEM-1024: 1568 / 3168 / 1568 byte sizes ----
        let mut rng = StdRng::from_seed([5u8; 32]);
        let kp_seed_1024 = [0x10u8; 64];
        let mut pk_1024 =
            [0u8; <MlKem1024 as MlKemParams>::PUBLIC_KEY_BYTES];
        let mut sk_1024 =
            [0u8; <MlKem1024 as MlKemParams>::SECRET_KEY_BYTES];
        kem_keypair_generic::<MlKem1024, _>(
            &mut pk_1024,
            &mut sk_1024,
            &mut rng,
            Some((&kp_seed_1024[..32], &kp_seed_1024[32..])),
        )
        .unwrap();
        let mut ct_1024 =
            [0u8; <MlKem1024 as MlKemParams>::CIPHERTEXT_BYTES];
        let mut ss_a_1024 = [0u8; 32];
        let enc_seed_1024 = [0xC1u8; 32];
        kem_enc_generic::<MlKem1024, _>(
            &mut ct_1024,
            &mut ss_a_1024,
            &pk_1024,
            &mut rng,
            Some(&enc_seed_1024),
        )
        .unwrap();
        let mut ss_b_1024 = [0u8; 32];
        kem_dec_generic::<MlKem1024>(
            &mut ss_b_1024,
            &ct_1024,
            &sk_1024,
        );
        assert_eq!(
            ss_a_1024, ss_b_1024,
            "ML-KEM-1024 round-trip failed"
        );

        // Sizes diverge per FIPS 203 §6:
        assert_eq!(pk_512.len(), 800);
        assert_eq!(pk_768.len(), 1184);
        assert_eq!(pk_1024.len(), 1568);
        assert_eq!(sk_512.len(), 1632);
        assert_eq!(sk_768.len(), 2400);
        assert_eq!(sk_1024.len(), 3168);
        assert_eq!(ct_512.len(), 768);
        assert_eq!(ct_768.len(), 1088);
        assert_eq!(ct_1024.len(), 1568);

        // All shared secrets are 32 bytes but are DIFFERENT across the
        // three parameter sets (different seeds, different keys).
        assert_ne!(ss_a_512, ss_a_768);
        assert_ne!(ss_a_768, ss_a_1024);
        assert_ne!(ss_a_512, ss_a_1024);
    }
}
