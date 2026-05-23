//! Coverage-gap unit tests: exercise public-surface code paths that
//! the existing test suite leaves untested. Targets paramsets's
//! per-set `zero_*()` and `*_from_slice` helpers, the legacy
//! `Keypair::import` + `derive` surface in `api.rs`, and the
//! parameter-set explicit constructors.

use kyberlib::{
    KyberLibError, MlKem1024, MlKem512, MlKem768, MlKemParams,
};

#[test]
fn mlkem512_param_constants_match_fips203() {
    assert_eq!(MlKem512::K, 2);
    assert_eq!(MlKem512::ETA1, 3);
    assert_eq!(MlKem512::ETA2, 2);
    assert_eq!(MlKem512::DU, 10);
    assert_eq!(MlKem512::DV, 4);
    assert_eq!(MlKem512::PUBLIC_KEY_BYTES, 800);
    assert_eq!(MlKem512::SECRET_KEY_BYTES, 1632);
    assert_eq!(MlKem512::CIPHERTEXT_BYTES, 768);
    assert_eq!(MlKem512::ALGORITHM_ID, "ML-KEM-512");
    assert_eq!(MlKem512::OID, "2.16.840.1.101.3.4.4.1");
}

#[test]
fn mlkem768_param_constants_match_fips203() {
    assert_eq!(MlKem768::K, 3);
    assert_eq!(MlKem768::ETA1, 2);
    assert_eq!(MlKem768::ETA2, 2);
    assert_eq!(MlKem768::DU, 10);
    assert_eq!(MlKem768::DV, 4);
    assert_eq!(MlKem768::PUBLIC_KEY_BYTES, 1184);
    assert_eq!(MlKem768::SECRET_KEY_BYTES, 2400);
    assert_eq!(MlKem768::CIPHERTEXT_BYTES, 1088);
    assert_eq!(MlKem768::ALGORITHM_ID, "ML-KEM-768");
    assert_eq!(MlKem768::OID, "2.16.840.1.101.3.4.4.2");
}

#[test]
fn mlkem1024_param_constants_match_fips203() {
    assert_eq!(MlKem1024::K, 4);
    assert_eq!(MlKem1024::ETA1, 2);
    assert_eq!(MlKem1024::ETA2, 2);
    assert_eq!(MlKem1024::DU, 11);
    assert_eq!(MlKem1024::DV, 5);
    assert_eq!(MlKem1024::PUBLIC_KEY_BYTES, 1568);
    assert_eq!(MlKem1024::SECRET_KEY_BYTES, 3168);
    assert_eq!(MlKem1024::CIPHERTEXT_BYTES, 1568);
    assert_eq!(MlKem1024::ALGORITHM_ID, "ML-KEM-1024");
    assert_eq!(MlKem1024::OID, "2.16.840.1.101.3.4.4.3");
}

#[test]
fn zero_constructors_yield_correct_lengths_per_set() {
    let pk512 = MlKem512::zero_public_key();
    let sk512 = MlKem512::zero_secret_key();
    let ct512 = MlKem512::zero_ciphertext();
    assert_eq!(pk512.len(), 800);
    assert_eq!(sk512.len(), 1632);
    assert_eq!(ct512.len(), 768);
    assert!(pk512.iter().all(|&b| b == 0));
    assert!(sk512.iter().all(|&b| b == 0));
    assert!(ct512.iter().all(|&b| b == 0));

    let pk768 = MlKem768::zero_public_key();
    let sk768 = MlKem768::zero_secret_key();
    let ct768 = MlKem768::zero_ciphertext();
    assert_eq!(pk768.len(), 1184);
    assert_eq!(sk768.len(), 2400);
    assert_eq!(ct768.len(), 1088);

    let pk1024 = MlKem1024::zero_public_key();
    let sk1024 = MlKem1024::zero_secret_key();
    let ct1024 = MlKem1024::zero_ciphertext();
    assert_eq!(pk1024.len(), 1568);
    assert_eq!(sk1024.len(), 3168);
    assert_eq!(ct1024.len(), 1568);
}

#[test]
fn public_key_from_slice_round_trips() {
    use kyberlib::paramsets::public_key_from_slice;
    let bytes = vec![0xAAu8; 1184];
    let buf = public_key_from_slice::<MlKem768>(&bytes).unwrap();
    assert_eq!(buf.as_ref(), &bytes[..]);
}

#[test]
fn public_key_from_slice_rejects_short() {
    use kyberlib::paramsets::public_key_from_slice;
    let too_short = vec![0u8; 1183];
    let err =
        public_key_from_slice::<MlKem768>(&too_short).unwrap_err();
    assert!(matches!(err, KyberLibError::InvalidLength));
}

#[test]
fn public_key_from_slice_rejects_long() {
    use kyberlib::paramsets::public_key_from_slice;
    let too_long = vec![0u8; 1185];
    let err = public_key_from_slice::<MlKem768>(&too_long).unwrap_err();
    assert!(matches!(err, KyberLibError::InvalidLength));
}

#[test]
fn secret_key_from_slice_round_trips_all_sets() {
    use kyberlib::paramsets::secret_key_from_slice;
    let bytes512 = vec![0x11u8; 1632];
    let bytes768 = vec![0x22u8; 2400];
    let bytes1024 = vec![0x33u8; 3168];
    let b512 = secret_key_from_slice::<MlKem512>(&bytes512).unwrap();
    let b768 = secret_key_from_slice::<MlKem768>(&bytes768).unwrap();
    let b1024 = secret_key_from_slice::<MlKem1024>(&bytes1024).unwrap();
    assert_eq!(b512.as_ref(), &bytes512[..]);
    assert_eq!(b768.as_ref(), &bytes768[..]);
    assert_eq!(b1024.as_ref(), &bytes1024[..]);
}

#[test]
fn secret_key_from_slice_rejects_wrong_length() {
    use kyberlib::paramsets::secret_key_from_slice;
    let bad = vec![0u8; 100];
    assert!(matches!(
        secret_key_from_slice::<MlKem512>(&bad),
        Err(KyberLibError::InvalidLength)
    ));
    assert!(matches!(
        secret_key_from_slice::<MlKem768>(&bad),
        Err(KyberLibError::InvalidLength)
    ));
    assert!(matches!(
        secret_key_from_slice::<MlKem1024>(&bad),
        Err(KyberLibError::InvalidLength)
    ));
}

#[test]
fn ciphertext_from_slice_round_trips_all_sets() {
    use kyberlib::paramsets::ciphertext_from_slice;
    let bytes512 = vec![0x44u8; 768];
    let bytes768 = vec![0x55u8; 1088];
    let bytes1024 = vec![0x66u8; 1568];
    let c512 = ciphertext_from_slice::<MlKem512>(&bytes512).unwrap();
    let c768 = ciphertext_from_slice::<MlKem768>(&bytes768).unwrap();
    let c1024 = ciphertext_from_slice::<MlKem1024>(&bytes1024).unwrap();
    assert_eq!(c512.as_ref(), &bytes512[..]);
    assert_eq!(c768.as_ref(), &bytes768[..]);
    assert_eq!(c1024.as_ref(), &bytes1024[..]);
}

#[test]
fn ciphertext_from_slice_rejects_wrong_length() {
    use kyberlib::paramsets::ciphertext_from_slice;
    let bad = vec![0u8; 1];
    assert!(matches!(
        ciphertext_from_slice::<MlKem512>(&bad),
        Err(KyberLibError::InvalidLength)
    ));
    assert!(matches!(
        ciphertext_from_slice::<MlKem768>(&bad),
        Err(KyberLibError::InvalidLength)
    ));
    assert!(matches!(
        ciphertext_from_slice::<MlKem1024>(&bad),
        Err(KyberLibError::InvalidLength)
    ));
}

#[test]
fn const_len_helpers_match_associated_consts() {
    use kyberlib::paramsets::{
        ciphertext_len, public_key_len, secret_key_len,
        shared_secret_len,
    };
    assert_eq!(public_key_len::<MlKem512>(), 800);
    assert_eq!(public_key_len::<MlKem768>(), 1184);
    assert_eq!(public_key_len::<MlKem1024>(), 1568);
    assert_eq!(secret_key_len::<MlKem512>(), 1632);
    assert_eq!(secret_key_len::<MlKem768>(), 2400);
    assert_eq!(secret_key_len::<MlKem1024>(), 3168);
    assert_eq!(ciphertext_len::<MlKem512>(), 768);
    assert_eq!(ciphertext_len::<MlKem768>(), 1088);
    assert_eq!(ciphertext_len::<MlKem1024>(), 1568);
    assert_eq!(shared_secret_len::<MlKem512>(), 32);
    assert_eq!(shared_secret_len::<MlKem768>(), 32);
    assert_eq!(shared_secret_len::<MlKem1024>(), 32);
}

#[test]
fn legacy_keypair_import_round_trips_byte_buffers() {
    use kyberlib::{
        keypair, Keypair, KYBER_PUBLIC_KEY_BYTES,
        KYBER_SECRET_KEY_BYTES,
    };
    let mut rng = rand::thread_rng();
    let original = keypair(&mut rng).unwrap();

    let mut pub_buf: [u8; KYBER_PUBLIC_KEY_BYTES] = original.public;
    let mut sec_buf: [u8; KYBER_SECRET_KEY_BYTES] = original.secret;

    let imported =
        Keypair::import(&mut pub_buf, &mut sec_buf, &mut rng)
            .expect("import should succeed");

    assert_eq!(imported.public, original.public);
    assert_eq!(imported.secret, original.secret);
    assert!(
        sec_buf.iter().all(|&b| b == 0),
        "import should zeroize the caller's secret buffer"
    );
}

#[test]
fn legacy_derive_rejects_wrong_seed_length() {
    let too_short = vec![0u8; 32];
    let too_long = vec![0u8; 65];
    assert!(matches!(
        kyberlib::derive(&too_short),
        Err(KyberLibError::InvalidInput)
    ));
    assert!(matches!(
        kyberlib::derive(&too_long),
        Err(KyberLibError::InvalidInput)
    ));
}

#[test]
fn legacy_derive_is_deterministic_in_seed() {
    let seed = [0x42u8; 64];
    let k1 = kyberlib::derive(&seed).unwrap();
    let k2 = kyberlib::derive(&seed).unwrap();
    assert_eq!(k1.public, k2.public);
    assert_eq!(k1.secret, k2.secret);
}

#[test]
fn legacy_extract_public_from_secret_matches_keypair_public() {
    use kyberlib::{keypair, public};
    let mut rng = rand::thread_rng();
    let kp = keypair(&mut rng).unwrap();
    let extracted = public(&kp.secret);
    assert_eq!(extracted, kp.public);
}
