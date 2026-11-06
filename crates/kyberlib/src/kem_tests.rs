// Copyright © 2026 kyberlib. All rights reserved.
// SPDX-License-Identifier: Apache-2.0 OR MIT

//! Unit tests for `kem.rs`: the generic FIPS 203 pipeline against the
//! fixed-parameter one. A child module of `kem`, so private items stay
//! in reach through `super::super`.

mod kem_generic_tests {
    #![allow(unused_imports)]
    use super::super::*;
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

mod all_three_in_one_build_kem {
    #![allow(unused_imports)]
    use super::super::*;
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
